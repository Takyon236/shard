"""Shard's memory layer — hybrid recall, working/session memory, context-fence isolation.

The engine's ``CognitiveStore`` ranks purely by ACT-R activation (recency × frequency × trust ×
provenance) over a TF-IDF relevance. It has **no exact-term layer**, so a recall for a literal token
the activation score happens to under-weight — a CWE id, a sink/function name, a header — can miss a
record that names it verbatim. This module adds, *without touching the engine store*:

1. **Hybrid retrieval** (`HybridRetriever`) — a keyword/BM25-style pass fused with the store's own
   activation ranking. Fusion reranks *within* the already-recalled, trust-floored set; it never
   promotes a quarantined record or weakens the trust gate. The store stays the source of truth for
   what is eligible; we only reorder what it returned and (optionally) widen the candidate pool.

2. **Working/session memory** (`SessionMemory`) — a short-term, per-run scratchpad that accumulates
   the run's own observations and persists across runs as append-only JSONL, **distinct** from the
   long-term store. Session notes are *untrusted by construction*: they surface as tentative context
   only, and never enter the engine store except via the normal extract→PROBATION→corroborate path.

3. **Context fence** (`fence` / `strip_fence`) — recalled content is wrapped in
   ``<memory-context>…</memory-context>`` before it enters the prompt, so a poisoned memory cannot
   inject loop instructions; fence tags are stripped from any text that flows back into the store.

Design constraints (see the maintainers' notes): pure + dependency-free + deterministically testable. The engine
``CognitiveStore`` is reached only through the ``StoreLike`` protocol, lazy-bound at the edge, so the
whole suite runs with an in-memory fake and no engine install.

.. SPLIT SURFACE — two halves with different roles; do not confuse them.

   EXTERNAL-CONTRACT half (advisory-only, net-zero measured):
     ``HybridRetriever`` and ``_record_text`` are consumed by the offline retrieval-memory
     harnesses (three offline scripts under the predecessor project's
     `maintenance tooling`, none of them in this tree). The hybrid BM25 × activation
     approach these symbols implement was rigorously measured and found net-zero-to-negative
     (see the design notes); it is kept advisory-only. Their signatures are pinned by
     `the maintainers' suite`.

   LIVE-SOLVER half (used by the benchmark solver):
     ``SessionMemory``, ``fence``, and ``tokenize`` are imported directly by `the predecessor project`
     (line 40: ``from shard.memory import SessionMemory, fence, tokenize``). These are
     load-bearing for every benchmark run; do not delete or rename them without tracing all
     callers in `the predecessor project` and the agentloop.
"""

from __future__ import annotations

import json
import math
import re
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Protocol, Sequence, runtime_checkable

from .artefactfs import append_file, read_file, trusted_directory

# Only the newest ``max_recall`` (50 by default) notes can enter a prompt. 64 MiB is already orders
# above that useful window and refuses a sparse or indefinitely accumulated file before allocation.
_MAX_SESSION_MEMORY_BYTES = 64 * 1024 * 1024

# --- context fence ----------------------------------------------------------
FENCE_OPEN = "<memory-context>"
FENCE_CLOSE = "</memory-context>"
# Any fence-like tag (recalled, untrusted) is stripped from text re-entering the store, so a
# memory can never smuggle a fence (or a forged role tag) back through the write path.
# Covers both fence variants (hyphen + underscore) and every role/tool tag a model might act on,
# including Claude's native tool-use tags (tool_use / tool_result), so a poisoned memory can't
# smuggle any of them back through the write path or out into the rendered context.
# ``\b[^>]*>`` after the tag name strips tags that carry attributes (e.g. <tool_use name="x">),
# not just bare <tool_use>; the \b keeps it from matching an unrelated word like <systemfoo>.
_FENCE_RE = re.compile(
    r"</?\s*(memory[-_]context|system|assistant|user|tool_call|function_call|tool_use|tool_result)\b[^>]*>",
    re.IGNORECASE)


def fence(text: str) -> str:
    """Wrap recalled (untrusted) content so it cannot be read as loop instructions."""
    if not text:
        return ""
    return f"{FENCE_OPEN}\n{strip_fence(text)}\n{FENCE_CLOSE}"


_STRIP_FENCE_MAX_PASSES = 8   # benign text converges on pass 1; the cap bounds the cost
                              # of an adversarial split-tag nest (a naive unbounded
                              # re-scan is O(n²) — a DoS on untrusted memory content).


def strip_fence(text: str) -> str:
    """Remove fence/role tags from text. Applied to anything flowing back INTO the store.

    Re-scans to a fixpoint so split/overlapping tags can't reconstruct a live tag from the
    fragments a single pass leaves behind: ``</mem</memory-context>ory-context>`` becomes a
    real ``</memory-context>`` once the inner match is removed, and ``<sy<system>stem>``
    becomes ``<system>``. The loop is BOUNDED: benign text has no such fragments and settles
    on the first pass (returned byte-identical), so the cap is only ever reached by a crafted
    adversarial nest — for which an unbounded re-scan would be O(n²) (each pass reconstructs
    one tag), a DoS on untrusted content. On the cap we strip the angle brackets outright,
    which guarantees no ``_FENCE_RE`` tag can survive and touches nothing but that payload."""
    out = text or ""
    for _ in range(_STRIP_FENCE_MAX_PASSES):
        stripped = _FENCE_RE.sub("", out)
        if stripped == out:
            return stripped
        out = stripped
    return out.replace("<", "").replace(">", "")


# --- tokenization (shared by keyword scoring) -------------------------------
_TOKEN_RE = re.compile(r"[A-Za-z0-9_]+")
# A few stopwords keep the keyword signal from being dominated by glue words; deliberately tiny
# (security queries are mostly content words, and the store's TF-IDF already handles IDF properly).
_STOP = frozenset("the a an of to in on for and or is are be with at by from this that it as".split())


def tokenize(text: str) -> list[str]:
    return [t for t in (m.group(0).lower() for m in _TOKEN_RE.finditer(text or "")) if t not in _STOP]


# --- the record surface we depend on ----------------------------------------
@runtime_checkable
class RecordLike(Protocol):
    """The slice of an engine ``MemoryRecord`` the retriever reads. The real record has many more
    fields; we touch only these so the fake in tests stays small."""

    id: str
    content: str
    detail: str
    tags: list[str]
    keywords: list[str]


@runtime_checkable
class StoreLike(Protocol):
    """The slice of the engine ``CognitiveStore`` we call. ``recall`` returns activation-ranked
    records (already trust-floored); we never bypass it to fetch quarantined records ourselves."""

    def recall(self, language: str = "", tags: list[str] | None = None, top_n: int = 3,
               query_text: str | None = None, **kw: Any) -> list[Any]: ...


def _record_text(rec: Any) -> str:
    """Flatten a record's recall-time surface into one bag-of-words string."""
    parts = [getattr(rec, "content", "") or "", getattr(rec, "detail", "") or ""]
    parts += list(getattr(rec, "tags", None) or [])
    parts += list(getattr(rec, "keywords", None) or [])
    return " ".join(parts)


# --- hybrid retrieval -------------------------------------------------------
@dataclass
class Scored:
    """A recalled record with its fused score and the per-signal breakdown (for journaling/debug)."""

    record: Any
    rank_score: float          # activation rank signal in [0, 1] (1 = top of the store's order)
    keyword_score: float       # BM25-style exact-term signal in [0, 1]
    fused: float


class HybridRetriever:
    """Fuses the store's activation ranking with an exact-term (BM25-style) keyword score.

    The store decides *eligibility* (trust floor, quarantine) and supplies the candidate pool; we
    only reorder it and surface literal-match records the activation order under-weighted. Set
    ``overfetch`` > 1 to ask the store for a wider pool than the caller wants, then return the
    best ``top_n`` after fusion — this is how a verbatim keyword hit that sat at rank 8 can be
    pulled into the top 4 without ever touching a record the store refused to return.
    """

    # BM25 constants (Robertson/Sparck-Jones). k1 saturates term frequency; b is length
    # normalization. Defaults are the standard, conservative values.
    K1 = 1.5
    B = 0.75

    def __init__(self, store: StoreLike, *, alpha: float = 0.5, overfetch: int = 3) -> None:
        # alpha = weight on the activation-rank signal; (1-alpha) on the keyword signal.
        self.store = store
        self.alpha = max(0.0, min(1.0, alpha))
        self.overfetch = max(1, overfetch)

    def recall(self, query_text: str, *, language: str = "", tags: list[str] | None = None,
               top_n: int = 4, **store_kw: Any) -> list[Scored]:
        pool = max(top_n * self.overfetch, top_n)
        records = self.store.recall(language=language, tags=tags, top_n=pool,
                                    query_text=query_text, **store_kw) or []
        if not records:
            return []
        # Tokenize the tag VALUES too (not just lowercase them): the document side is tokenized, so a
        # hyphenated/compound tag like "cwe-89" must split to ["cwe","89"] to match a doc token — the
        # exact literal-id match the keyword layer exists to provide. Bare .lower() never matched.
        query_terms = tokenize(query_text) + tokenize(" ".join(tags or []))
        kw = self._bm25(query_terms, records)
        n = len(records)
        scored: list[Scored] = []
        for i, rec in enumerate(records):
            # The store already ranked the pool; map position → a [0,1] signal (top=1.0, bottom=0.0).
            # Divide by (n-1) so the range is a true [0,1] matching keyword_score — dividing by n
            # left a floor of 1/n, biasing fusion toward rank over keyword for large pools.
            rank = (1.0 - i / (n - 1)) if n > 1 else 1.0
            fused = self.alpha * rank + (1.0 - self.alpha) * kw[i]
            scored.append(Scored(record=rec, rank_score=rank, keyword_score=kw[i], fused=fused))
        # Sort by fused score desc; break ties by the keyword signal so a verbatim exact-term match
        # still surfaces ahead of an equal-fused record the store merely ranked higher (this is the
        # whole point of hybrid recall). Remaining ties keep the store's original activation order.
        scored.sort(key=lambda s: (s.fused, s.keyword_score), reverse=True)
        return scored[:top_n]

    def _bm25(self, query_terms: Sequence[str], records: Sequence[Any]) -> list[float]:
        """BM25 score per record for the query terms, normalized to [0, 1] across the pool."""
        if not query_terms:
            return [0.0] * len(records)
        q = set(query_terms)
        docs = [tokenize(_record_text(r)) for r in records]
        n = len(docs)
        avgdl = (sum(len(d) for d in docs) / n) if n else 0.0
        # Document frequency per query term.
        df = {t: sum(1 for d in docs if t in d) for t in q}
        raw: list[float] = []
        for d in docs:
            dl = len(d)
            tf = {t: d.count(t) for t in q}
            s = 0.0
            for t in q:
                f = tf[t]
                if f == 0:
                    continue
                # Smoothed IDF (always positive; a term in every doc still carries a little signal).
                idf = math.log(1 + (n - df[t] + 0.5) / (df[t] + 0.5))
                denom = f + self.K1 * (1 - self.B + self.B * (dl / avgdl if avgdl else 0.0))
                s += idf * (f * (self.K1 + 1)) / denom if denom else 0.0
            raw.append(s)
        hi = max(raw) if raw else 0.0
        return [r / hi if hi > 0 else 0.0 for r in raw]


# --- working / session memory -----------------------------------------------
@dataclass
class SessionNote:
    """One short-term observation. Untrusted by construction — never authoritative."""

    text: str
    kind: str = "obs"          # obs | hypothesis | dead_end | finding
    run_id: str = ""
    tags: list[str] = field(default_factory=list)
    ts: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return asdict(self)


class SessionMemory:
    """A per-run scratchpad that persists across runs as append-only JSONL.

    This is the working memory the long-term ``CognitiveStore`` is NOT: it holds the run's own raw
    observations (what was tried, what dead-ended, interim hypotheses) so the loop — and the next
    run — can build on them. It is deliberately second-class: notes render under a tentative heading
    and only graduate into the engine store through the normal extract→PROBATION→corroborate path,
    never by being written here.
    """

    def __init__(self, path: Path | None = None, *, run_id: str = "", now=time.time,
                 max_recall: int = 50) -> None:
        self.path = Path(path) if path else None
        self.run_id = run_id
        self._now = now
        self.max_recall = max_recall
        self.notes: list[SessionNote] = []
        self._directory = None
        self._parent_fd: int | None = None
        if self.path:
            directory = trusted_directory(self.path.parent.resolve(), create=True)
            _path, self._parent_fd = directory.__enter__()
            self._directory = directory
            try:
                try:
                    raw = read_file(
                        self._parent_fd, self.path.name, max_bytes=_MAX_SESSION_MEMORY_BYTES,
                    )
                except FileNotFoundError:
                    raw = None
            except Exception:
                self.close()
                raise
            if raw is not None:
                self._load(raw)

    def _load(self, raw: bytes) -> None:
        for line in raw.decode("utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(data, dict):
                continue
            # Keep only known fields so a schema change (an added field, a manual annotation) doesn't
            # make the whole note unconstructable and silently drop a run's working memory.
            known = {k: data[k] for k in SessionNote.__dataclass_fields__ if k in data}
            if "text" in known:
                self.notes.append(SessionNote(**known))

    def add(self, text: str, *, kind: str = "obs", tags: Sequence[str] | None = None) -> SessionNote:
        """Record an observation. Fence tags are stripped so a recalled memory can't smuggle one in."""
        note = SessionNote(text=strip_fence(text).strip(), kind=kind, run_id=self.run_id,
                           tags=list(tags or []), ts=self._now())
        self.notes.append(note)
        if self._parent_fd is not None:
            encoded = (json.dumps(note.to_dict(), default=str) + "\n").encode("utf-8")
            append_file(self._parent_fd, self.path.name, encoded)
        return note

    def close(self) -> None:
        """Release the persistence-directory descriptor retained across hostile tools."""
        if self._directory is not None:
            directory, self._directory = self._directory, None
            self._parent_fd = None
            directory.__exit__(None, None, None)

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    def recall(self, query_text: str, *, top_n: int = 5, kinds: Sequence[str] | None = None) -> list[SessionNote]:
        """Keyword recall over the scratchpad. Most-recent wins ties so fresh context surfaces."""
        cand = [n for n in self.notes if not kinds or n.kind in kinds][: -self.max_recall - 1: -1]
        terms = set(tokenize(query_text))
        if not terms:
            return cand[:top_n]
        def score(n: SessionNote) -> int:
            return len(terms & set(tokenize(n.text + " " + " ".join(n.tags))))
        ranked = sorted(cand, key=lambda n: (score(n), n.ts), reverse=True)
        return [n for n in ranked if score(n) > 0][:top_n]


# --- prompt rendering (the loop-facing surface) -----------------------------
_SESSION_HEADING = ("## Session scratchpad (this run's own notes — UNTRUSTED working memory; "
                    "corroborate before acting, never file a finding on these alone)")


def render_session(notes: Sequence[SessionNote]) -> str:
    if not notes:
        return ""
    lines = [_SESSION_HEADING]
    for n in notes:
        tag = f" [{', '.join(n.tags)}]" if n.tags else ""
        lines.append(f"- ({n.kind}){tag} {n.text}")
    return "\n".join(lines)


def build_context(store_block: str, session_notes: Sequence[SessionNote]) -> str:
    """Assemble the fenced memory context block injected before a loop step.

    ``store_block`` is the engine's trust-aware ``format_records_for_prompt`` output (authoritative /
    curated / tentative headings, decided by ``TrustTier``). Session notes append under their own
    explicitly-untrusted heading. The whole thing is fenced so none of it can be read as instructions.
    """
    parts = [p for p in (store_block or "", render_session(session_notes)) if p]
    if not parts:
        return ""
    return fence("\n\n".join(parts))
