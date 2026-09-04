"""Shared tool primitives — the registry types and the sandboxed read tools.

This module is the dependency-free base every registry builder in this tree imports, on both tiers.
It has no imports from within ``shard``.

What lives here: ``ToolContext``, ``ToolResult``, ``Tool``, the ``ToolRegistry``, schema helpers
(``_param_schema``, ``tool_to_openai``), and the three sandboxed read tools (``_read_file``,
``_grep``, ``_list_dir``) together with the index machinery that makes ``_read_file`` jump-capable
on large files.

What USED to live here: ``Branch`` / ``BranchResult``, the structural sub-agent contract the
orchestration primitives spoke. Removed as code and kept as the note below, because every module they
named was severed and none exists in this tree.

What does NOT live here: benchmark / scoring tools, engine cognitive-memory tools, the promotion
gate, and the human-gated mutators. **None of them lives anywhere in this tree.** Until 2026-09-02
this docstring named three modules as their homes and as this module's importers, and not one of the
three has ever existed in this repository or in any artefact built from it — they were carried over
from the predecessor repo with the file. A live clone test of the published free package found one
of them still here, where a reader cannot tell a stale pointer from a paid module withheld by the
build. Deleted rather than redacted, for that exact reason: redacting a name that never existed
would have made the misreading official.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable


# ── the severed ReAct contract, kept as the RECORD it is ────────────────────────────────────────────
# `Branch` and `BranchResult` used to sit here: a structural sub-agent Protocol and its result record.
# They are gone as CODE and kept as this note, because every module they described — `orchestrator`,
# `loop.ShardLoop`/`LoopResult`, `policy`, `swarm.py` — was severed and does not exist in this tree.
# A Protocol whose referenced types 404 is not documentation; it is a stub that reads as live API.
#
# THE TRAP THEY WERE BUILT TO CLOSE IS WORTH KEEPING, because it is the reason the severance was hard.
# the maintainers' notes states the solver imports no part of the ReAct agent. That was true of the direct edge
# and transitively FALSE: `the benchmark` lazy-imported `orchestrator`, which imported `loop` for
# `ShardLoop`/`LoopResult`, which imports `policy` — so enabling `verify_n`, `oracle`, `specialist` or
# the staged path loaded the agent's core into a solver run. Nothing caught it because IMPORT TIME
# STAYED CLEAN; the edge only existed once a flag was on.
#
# The fix was to notice the dependency was on a NAME rather than a behaviour — `orchestrator` used
# `ShardLoop` purely as an annotation — so a structural type removed it. The maintainers' notes now records the
# outcome: "The two systems stay separate" and "the ReAct self-improve loop is retired here, not
# carried over." The contract itself has no consumer left in this repository.

#: What a root the caller did not set is worth: NOTHING. It has to be a real ``Path`` rather than
#: ``None`` because ``_read_allowed_roots`` calls ``.resolve()`` on all three (verified: ``None`` raises
#: ``AttributeError`` there), and it is deliberately a path that exists nowhere, so an unset root grants
#: no reads instead of granting whatever the old literal happened to name.
_UNSET_ROOT = Path("/nonexistent/shard-toolcontext-unset")


@dataclass
class ToolContext:
    """Where the tools operate. **Every root must be set by the caller; the defaults are a trap.**

    ``_read_allowed_roots`` returns all three, so a caller that sets one silently gets the other two.
    Both shipping call sites — ``simple.run_simple`` on this tier, and the separate capability's
    solver entry point on the other — collapse all three onto the tree under review, and
    `the maintainers' suite::test_every_shipping_ToolContext_sets_all_three_roots``
    is what stops a fourth being written the short way. It exists because the short way SHIPPED: simple
    mode set only ``engine_root`` and handed the free-tier agent read access to ``witness.py``, the
    module that decides ``gate_eligible`` (`an internal audit` Finding 2).

    **Those defaults used to be absolute paths on the maintainer's machine, and this file is the free
    image's bulk, so they SHIPPED — verbatim, as dataclass defaults, inside the artefact a customer
    pulls.** Four literals naming a home directory and three unrelated private projects, plus one more
    quoting a fifth in this docstring. Measured 2026-08-19 on the tree
    `a maintenance script` emits: 17 occurrences across 6 modules, 6 of them here.

    The literals bought nothing. Both shipping paths set all three roots explicitly — read at
    ``shard/simple.py`` (``run_simple``) and, on the other tier, the solver's own constructor — whose
    registry builder reuses that same context rather than building a second — and the three bench
    contexts in `a maintenance script` never exercise a read tool through a defaulted root. So no shipping
    behaviour depended on them, which is what made replacing them safe rather than delicate.

    **``python`` and ``store_path`` are GONE, not neutralised.** Two more of the same literals with
    **zero readers repo-wide** — the check `the design notes` asks for before deleting them, re-run
    2026-08-19 across ``shard/``, ``scripts/`` and ``tests/`` and against the out-of-repo benchmark
    driver `the maintainers' notes` trap 1 names, which imports five modules of this tree and never constructs
    a context. A field nothing reads, whose value is a private path, is not configuration. Nothing
    constructs this positionally, so removing two middle fields moves no argument.

    ``shard_root`` is Shard's OWN repo, and it is here for the WRITE side: mutators may write under
    either the engine or the shard root, with writes to safety-critical files (gate logic, budget caps)
    classified SENSITIVE by the policy and escalated rather than applied autonomously. It is computed
    from ``__file__`` rather than written down, which is why it was never part of the leak.

    **It used to say "self-edit is in scope (the agent may improve its own code)". That system is
    RETIRED** — the maintainers' notes, "the ReAct self-improve loop is retired here, not carried over" — and the
    sentence outlived it as a live statement of intent about a capability nothing offers. Removed
    rather than rewritten, because the honest reading of a self-edit clause on a security gate running
    inside a customer's CI is that it should never have been inherited."""

    engine_root: Path = _UNSET_ROOT
    audit_root: Path = _UNSET_ROOT
    shard_root: Path = Path(__file__).resolve().parent.parent
    # LEVER 1 (code_query / weggli): path to the weggli binary, or None to let _code_query resolve it
    # (vendored path → shutil.which → degrade). Injected by the harness; None on the deterministic path
    # (tests fake the subprocess), so the default suite never needs the binary.
    weggli: Path | None = None


@dataclass
class ToolResult:
    ok: bool
    data: Any = None
    error: str = ""

    def to_dict(self) -> dict:
        return {"ok": self.ok, "data": self.data, "error": self.error}


@dataclass
class Tool:
    name: str
    kind: str            # maps to policy action kind
    description: str
    fn: Callable[..., ToolResult]
    args_schema: dict = field(default_factory=dict)
    priority: int = 0    # NATIVE-FC list position lever (higher = listed EARLIER to the model); default 0
    #                      preserves the prior alphabetical order. See ToolRegistry.openai_tools.


# args_schema atom → JSON-Schema type. Mirrors the tiny DSL the registry already uses ("str", "int?",
# "list"). A trailing "?" means optional. Unknown atoms fall back to string (safe for an LLM arg).
_JSON_TYPES = {"str": "string", "int": "integer", "float": "number", "bool": "boolean", "list": "array"}


def _param_schema(spec: str) -> tuple[dict, bool]:
    """(json-schema, optional?) for one ``args_schema`` value like "int?" or "list"."""
    optional = spec.endswith("?")
    atom = spec[:-1] if optional else spec
    schema: dict = {"type": _JSON_TYPES.get(atom, "string")}
    if schema["type"] == "array":
        schema["items"] = {"type": "string"}   # the registry's list params are id/tag string lists
    return schema, optional


def tool_to_openai(tool: Tool) -> dict:
    """One Tool → an OpenAI/OpenRouter function-calling tool definition."""
    props: dict = {}
    required: list[str] = []
    for name, spec in tool.args_schema.items():
        schema, optional = _param_schema(str(spec))
        props[name] = schema
        if not optional:
            required.append(name)
    return {"type": "function", "function": {
        "name": tool.name, "description": tool.description,
        "parameters": {"type": "object", "properties": props, "required": required},
    }}


class ToolRegistry:
    def __init__(self, ctx: ToolContext) -> None:
        self.ctx = ctx
        self._tools: dict[str, Tool] = {}

    def register(self, tool: Tool) -> None:
        self._tools[tool.name] = tool

    def get(self, name: str) -> Tool | None:
        return self._tools.get(name)

    def names(self) -> list[str]:
        return sorted(self._tools)

    def spec(self) -> str:
        """Human/LLM-readable tool catalogue for the system prompt (the text-JSON-action loop)."""
        return "\n".join(
            f"- {t.name}({', '.join(t.args_schema) or ''}) [{t.kind}] — {t.description}"
            for t in (self._tools[n] for n in self.names())
        )

    def openai_tools(self, only: list[str] | None = None) -> list[dict]:
        """The registry as OpenAI/OpenRouter function-calling `tools=[...]` — the NATIVE tool-calling
        path (vs the text-JSON `spec()`). Each tool's ``args_schema`` (e.g. {"path":"str",
        "offset":"int?"}) becomes a JSON-Schema; a trailing "?" marks an OPTIONAL param (omitted from
        ``required``). Pass ``only`` to expose a subset (e.g. the solver's tools, not the gated git stubs)."""
        # NATIVE-FC ORDER LEVER ("Tool Preferences in Agentic LLMs are Unreliable", 2025): a weak model's
        # choice among comparable tools is driven by LIST POSITION as much as by the description — the
        # first-listed of two competing tools dominates (open-proxy Qwen-7B: 76.7% vs 0.0% first-vs-second).
        # names() is ALPHABETICAL, scattering the high-value construction tools by accident (build_emit early
        # on 'b', use_corpus near the bottom on 'u'). Order the GLM-facing native list by DESCENDING priority
        # (ties alphabetical, stable) so the tools we want a tool-shy model to reach for lead intentionally.
        # With every tool at the default priority==0 this is byte-identical to the old alphabetical order, so
        # names()/spec() (the text-JSON path) and existing callers are unaffected.
        names = [n for n in (only if only is not None else self.names()) if n in self._tools]
        names.sort(key=lambda n: (-self._tools[n].priority, n))
        return [tool_to_openai(self._tools[n]) for n in names]

    def call(self, name: str, args: dict) -> ToolResult:
        tool = self._tools.get(name)
        if tool is None:
            return ToolResult(False, error=f"unknown tool: {name}")
        try:
            return tool.fn(self.ctx, **(args or {}))
        except TypeError as e:
            return ToolResult(False, error=f"bad args for {name}: {e}")
        except Exception as e:  # tools are best-effort; never crash the loop
            return ToolResult(False, error=f"{type(e).__name__}: {e}")


# --- read-only tools (P1) ---------------------------------------------------
def _is_within(p: Path, root: Path) -> bool:
    """True iff ``p`` resolves inside ``root``. ``resolve()`` collapses ``..`` and follows symlinks,
    so neither a ``../`` traversal nor a symlink out of the tree can slip past this check."""
    try:
        p.resolve().relative_to(root)
        return True
    except ValueError:
        return False


def _read_allowed_roots(ctx: ToolContext) -> tuple[Path, ...]:
    """Roots the READ tools may read under. Broader than the mutators' write allowlist because reads
    legitimately span the whole audit tree (results/scripts for self-improve, the engine + Shard's own
    source). Deliberately NOT home/ssh/aws: the autonomous loop has no business reading ~/.ssh or
    ~/.claude.json, so an absolute path or ``..`` traversal outside these three roots is refused."""
    return (ctx.engine_root.resolve(), ctx.shard_root.resolve(), ctx.audit_root.resolve())


# --- Large-file INDEX: the "where am I" instrument --------------------------------------------------
# Measured over 29 real solver runs (the benchmark audit corpus, `temp0` sweep — the corpus is not in
# this repository and its location is not this artefact's business): 831 of 1022 ``read_file``
# calls carried ``offset``+``max_lines`` — the agent PAGES through source rather than reading it — and
# the paging THRASHES. One observed sequence on a single file: whole-file → offset 301 → offset 0/200 →
# offset 200/250 → offset 80/120 → offset 200/250 AGAIN, i.e. it re-fetched a window it had already seen
# two calls earlier. Another: offset 707/140 → offset 707/100, the same start with a narrower window.
#
# That is not confusion about the CODE, it is having no map of the FILE: grep says a symbol exists, and
# the only instrument for finding where it lives is a scroll bar. Each scroll costs a whole turn, and a
# turn re-sends the entire transcript — the quadratic term that dominates this loop's token bill.
#
# So a PARTIAL read appends a cheap index of the file's definitions with their line numbers: the agent
# jumps once with ``offset=<line>`` instead of binary-searching. Deliberately a regex heuristic and not
# a parser — the core stays dependency-free, and an index must never be able to fail a read. It is
# LABELLED heuristic in the output so the agent treats it as a map to verify, not as ground truth (a
# confidently wrong index the agent trusts is worse than no index at all).
_IDX_MAX_ENTRIES = 24
_IDX_MAX_CHARS = 900
_IDX_SIG_CHARS = 76
# A definition-looking line at column 0: an identifier-led signature carrying '(' and NOT terminated by
# ';' (which would make it a prototype or a bare call). '}' / '#' / comment-led lines can never match.
_IDX_CALLABLE = re.compile(r"^[A-Za-z_][A-Za-z0-9_ \t*&:<>,\[\]]*\([^;]*$")
_IDX_TYPE = re.compile(r"^(?:typedef\s+)?(?:struct|union|enum|class|namespace)\s+[A-Za-z_]\w*")
# Function-like macros ONLY — the '(' must abut the name. Allowing whitespace before it swept in plain
# constants (`#define EOF (-1)`, `# define RENAME_NOREPLACE (1 << 0)`), which are noise at this budget:
# an index entry has to be somewhere worth jumping TO.
_IDX_DEFINE = re.compile(r"^#\s*define\s+[A-Za-z_]\w*\(")
_IDX_PY = re.compile(r"^[ \t]{0,4}(?:async\s+)?(?:def|class)\s+[A-Za-z_]\w*")


# Pattern set BY LANGUAGE, not a union. Validated against real sources: running the C signature pattern
# over a .py file matched prose inside docstrings ("recall_techniques(query) to look up more (...)" — a
# column-0 English sentence containing '(' and not ending in ';'), producing an index of documentation
# instead of code. A union is not merely noisy, it is CONFIDENTLY WRONG, which is the one thing an
# orientation aid must never be. Unknown extensions get NO index rather than a guessed one.
_IDX_BY_SUFFIX: "dict[str, tuple]" = {
    **{s: (_IDX_CALLABLE, _IDX_TYPE, _IDX_DEFINE)
       for s in (".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".hxx", ".inc")},
    **{s: (_IDX_PY,) for s in (".py", ".pyi")},
}


def _file_index(lines: "list[str]", suffix: str = "") -> str:
    """A bounded, heuristic map of ``lines`` -> the appended ``...[index ...]`` block, or "" when the
    language is unknown or there is nothing worth indexing (<2 hits). Never raises: a bad index must
    degrade to NO index, never to a wrong one."""
    pats = _IDX_BY_SUFFIX.get(suffix.lower())
    if not pats:
        return ""
    hits: list[str] = []
    total = 0
    for i, line in enumerate(lines):
        if not line or (line[0] in " \t" and pats is not _IDX_BY_SUFFIX[".py"]):
            continue                                    # indented => not a top-level C definition
        if not any(p.match(line) for p in pats):
            continue
        total += 1
        if len(hits) < _IDX_MAX_ENTRIES:
            hits.append(f"{i}:{line.strip()[:_IDX_SIG_CHARS]}")
    if len(hits) < 2:
        return ""
    shown = f" ({len(hits)} of {total})" if total > len(hits) else ""
    body = " | ".join(hits)
    if len(body) > _IDX_MAX_CHARS:
        body = body[:_IDX_MAX_CHARS].rsplit(" | ", 1)[0]
    return (f"\n...[index{shown}, HEURISTIC — line:definition; re-call read_file with that offset= to "
            f"jump. Verify before relying on it]\n{body}")


#: A FLOOR under the window the model asks `read_file` for, or 0 for "take it at its word".
#:
#: **SHIPS AT 0 — OFF — AND THE MEASUREMENT THAT WOULD TURN IT ON IS NAMED BELOW.** the maintainers' notes's rule
#: is that an unmeasured lever lands off, and this one has an argument rather than a number.
#:
#: The argument, from four real repositories on 2026-08-18. As context fills and old tool results are
#: stubbed out, the model asks for SMALLER reads — the window it chose collapsed from the 12,000
#: default to a median of 900 and a floor of 420 — apparently to conserve context. The arithmetic says
#: that is backwards: one extra call re-bills the entire accumulated conversation, which on these runs
#: was tens of thousands of tokens, to save at most 11KB of observation. Measured on
#: `suitenumerique/docs` #2576: `viewsets.py` (3,339 lines) read **64 times** in windows about six
#: lines apart, 206,732 bytes of content retrieved for 1,479,494 tokens, and the run still hit its step
#: ceiling with nothing proposed.
#:
#: **MEASURED 2026-08-18 ON TWO MATCHED PAIRS. THEY DISAGREE, AND THAT IS THE RESULT.** Byte-identical
#: invocations and ceilings, control against `MIN_READ_BYTES = 4000`:
#:
#:                              tokens              status            findings   median max_bytes
#:     suitenumerique/docs   1,479,494 -> 978,401   maxsteps -> done   0 -> 2      900 ->  4,200
#:     mistralai/client-py   1,162,726 -> 1,226,377 done -> maxsteps   3 -> 0    2,800 ->  3,000
#:
#: **A FIXED FLOOR IS THE WRONG SHAPE, and the median column says why.** It helps only where the model
#: had already collapsed its window: on `docs` the median was 900, the floor bound hard, and read calls
#: fell 110 -> 68. On `client-python` the median was ALREADY 2,800 — near the floor — so it barely
#: bound, calls went UP 106 -> 116, content retrieved rose 34%, and the extra bytes bought nothing but
#: cost a run that had previously completed with three findings.
#:
#: The predicted risk was also real on both: compactions rose (28 -> 45 and 55 -> 62). On `docs` that
#: lost to a 38% cut in CALLS, because the transcript is re-billed per call rather than per byte. On
#: `client-python` there was no cut in calls for it to lose to.
#:
#: So this stays **0** — and the reason is now a measurement rather than caution. A correct version
#: would be ADAPTIVE: raise the window only once the requests have collapsed relative to the default,
#: which is a different lever nobody has built and which must not be inferred from these two pairs.
#:
#: It can only ever RAISE a request toward the default, never lower one, so it cannot shrink what a
#: caller asked for and cannot blow the observation window that `max_bytes` already bounds.
MIN_READ_BYTES = 0


# The loop's observation-window bound, in characters. This is the ONE source: every default that must
# match the window — the read tool's `max_bytes`, the loop's `max_obs_chars`, the deep plan's copy, the
# sandbox's half-window output cap — derives from this symbol rather than restating the literal, so the
# window cannot drift out from under a reader that only edited one of them.
OBS_WINDOW_CHARS = 12000

# The read tool's per-call LINE cap — the other of `_read_file`'s two ceilings (the first is the byte
# window above). Also the single source: the separate package's in-image reader windows to the SAME line
# count and derives it from here instead of restating 400 beside a comment that only says it should match.
READ_MAX_LINES = 400


def _read_file(ctx: ToolContext, path: str, offset: int = 0, max_bytes: int = OBS_WINDOW_CHARS,
               max_lines: int = READ_MAX_LINES) -> ToolResult:
    """Read a window of a text file, BY LINE. ``offset`` is a 0-based START LINE — NOT a char index.
    The previous char-offset semantics were routinely misread by the agent as a line number, which
    silently returned the file header on every large file (a dominant budget-drain: dozens of ``sed``
    fallbacks). Emits ``lines[offset:]`` until ``max_lines`` lines OR the ``max_bytes`` char ceiling
    (the loop's observation-window bound, aligned to max_obs_chars) is hit — whichever comes first —
    then appends a marker naming the exact next START LINE to re-call with. A single line longer than
    ``max_bytes`` is char-truncated with an explicit note so the observation window is never blown."""
    p = Path(path)
    if not p.is_absolute():
        p = ctx.engine_root / path
    if not any(_is_within(p, r) for r in _read_allowed_roots(ctx)):
        return ToolResult(False, error=f"refused: read outside allowed roots ({p})")
    if not p.is_file():
        return ToolResult(False, error=f"not a file: {p}")
    lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
    n = len(lines)
    start = max(0, int(offset))
    cap = max(1, int(max_lines))
    if start >= n:
        return ToolResult(True, "" if n == 0 else f"[offset {start} past end of file ({n} lines)]")
    # Reserve headroom below max_bytes for the paging marker AND the loop's JSON-envelope escaping: the
    # ToolCallingLoop clamps `json.dumps(result.to_dict())[:max_obs_chars]` and max_bytes defaults to that
    # same max_obs_chars — so a page filled to max_bytes has its trailing `offset=` marker (emitted LAST)
    # clipped off, silently re-breaking paging on dense files (Devil-review). 85% covers the ~55-char marker
    # + the `{"ok":true,"data":"..."}` envelope + newline/quote escaping expansion with margin.
    # THE FLOOR, applied before the headroom split so everything below sees one number. Raises only:
    # `max` can never shrink what the caller asked for. See `MIN_READ_BYTES` for what it is for and
    # for the measurement that has to happen before it is turned on.
    max_bytes = max(int(max_bytes), MIN_READ_BYTES)
    full_budget = max(256, (int(max_bytes) * 85) // 100)
    # The index is for ORIENTATION, so it earns its bytes only on a read the agent will have to page
    # around. That is EITHER truncation path — line-capped or BYTE-capped — plus any call already
    # scrolling. Testing only the line cap missed the byte case entirely (a 2400-line file read with
    # max_lines=10000 truncates on bytes, gets an `offset=` marker, and is precisely the read that
    # provokes scrolling), so the window's char count is measured against the pre-index budget. It is
    # budgeted BEFORE the content — subtracted from content_cap, never added on top — or it would
    # re-break the headroom invariant the marker fix below established.
    window_chars = sum(len(ln) + 1 for ln in lines[start:start + cap])
    partial = (start + cap) < n or start > 0 or window_chars > full_budget
    index_txt = _file_index(lines, p.suffix) if partial else ""
    content_cap = max(256, full_budget - len(index_txt))
    out: list[str] = []
    used = 0
    i = start
    while i < n and (i - start) < cap:
        line = lines[i]
        if not out and len(line) > content_cap:
            # Pathological single long line (minified/one-liner): char-truncate THIS line so we never
            # blow the observation window; advance past it so the next page starts on a fresh line.
            out.append(line[:content_cap] + f"\n...[line {i} truncated to {content_cap} chars of {len(line)}]")
            i += 1
            break
        if out and used + len(line) + 1 > content_cap:
            break
        out.append(line)
        used += len(line) + 1
        i += 1
    chunk = "\n".join(out)
    if i < n:
        chunk += f"\n...[truncated: {n - i} more lines; re-call read_file with offset={i}]"
    return ToolResult(True, chunk + index_txt)


# Cap on files scanned by one _grep call — a bounded tool call, not an unbounded whole-tree crawl.
_GREP_MAX_FILES = 5000

# VCS metadata directories excluded from whole-tree grep walks, by PATH COMPONENT.
# Excluded BEFORE the _GREP_MAX_FILES cap so the budget is actually available for source files.
#
# Why this matters: `.` sorts before every letter and digit, so `.git` is enumerated FIRST in a
# sorted walk. On a customer checkout with more than 5000 total files the cap is consumed by packed
# git objects before a single source file is scanned — the agent receives a truncation marker over
# a scan that found nothing real, and reads it as ABSENCE of the bug (a silent capability kill,
# not cosmetic noise; measured at 68.7% of files under `.git` on this repo).
#
# The exclusion is by PATH COMPONENT, not prefix or substring: ``mygit.c`` and ``gitweb/main.c``
# are legitimate source and remain in scope. Dotfiles such as ``.gitignore`` and ``.gitattributes``
# are also NOT excluded — only the VCS DIRECTORIES carrying the metadata are.
#
# Extend here when a new VCS needs covering. Searching INSIDE a VCS directory is still possible by
# passing an explicit ``path=`` targeting that directory: when ``base`` is already inside (or IS)
# the VCS dir, ``f.relative_to(base)`` carries no VCS component and the filter does not fire.
_VCS_DIRS: frozenset[str] = frozenset({".git", ".hg", ".svn"})


def _grep(ctx: ToolContext, pattern: str, path: str = ".", max_matches: int = 50) -> ToolResult:
    """Regex-search files under ``path``, confined to the read-allowed roots.

    Returns a flat ``list[str]`` of ``"<file>:<line>: <text>"`` hits. Anything that made the scan
    INCOMPLETE (match cap, file cap, skipped files) is reported as a synthetic trailing entry using
    ``_read_file``'s ``...[...]`` marker convention — never by changing the return shape, because
    ``the benchmark`` registers this same function as its own ``grep`` tool.

    Why the markers matter: a silently truncated scan returns an empty list, and the agent reads
    "no matches" as evidence of ABSENCE having searched a fraction of the tree.
    """
    base = Path(path)
    if not base.is_absolute():
        base = ctx.engine_root / path
    roots = _read_allowed_roots(ctx)
    if not any(_is_within(base, r) for r in roots):
        return ToolResult(False, error=f"refused: read outside allowed roots ({base})")
    rx = re.compile(pattern)
    # Confining the BASE does NOT confine the WALK. `rglob` refuses to DESCEND into a symlinked
    # directory, but it still YIELDS a symlinked FILE, and `read_text` follows it — so a symlink
    # planted under an allowed root (the solver's `run_bash` can create one) would read any file the
    # process can, defeating the whole point of `_read_allowed_roots`. The real invariant is therefore
    # per-candidate, not per-base: every file is re-resolved and re-checked inside the loop.
    #
    # LIMIT, stated so it is not over-claimed: this closes SYMLINK escape, not HARDLINK escape. A hard
    # link has no separate target to resolve — `os.link(outside, base/x)` makes `base/x` genuinely a
    # name for that inode — so `resolve()` is blind to it and the read is allowed. Closing it needs
    # st_dev/st_ino identity checks against the roots. `_read_file` shares the same blind spot.
    # SORTED, because the scan is capped. `rglob` yields in directory order, so WHICH 5000 of a larger
    # tree got searched was not reproducible — two identical greps could return different results, and
    # the agent has no way to tell that apart from a real change in the code it is reading.
    if base.is_file():
        files: list[Path] = [base]
        vcs_skipped: int = 0
    else:
        # PRUNED WALK, not rglob-then-filter. `rglob` descends into `.git` and stats every packed
        # object, and only then does the filter throw them away — measured on this repository, 2,906
        # paths enumerated to keep 436, 106ms against 3.2ms for the pruned walk: 33x. The wrong
        # variable was driving it: the cost scaled with the customer's git HISTORY rather than with
        # their source, on the tool the agent calls most (1,022 `read_file`-class calls over 29 runs,
        # 18 greps in a single diff run).
        #
        # `os.walk` honours mutation of `dirnames`, so this STOPS the descent rather than hiding the
        # results — the same pattern `target.profile_repo` already uses and documents for the same
        # reason. Directories are still matched by exact NAME, so `mygit.c` and `gitweb/index.c` are
        # untouched, exactly as the component filter left them.
        #
        # An explicit `path=".git"` is still honoured and still needs no special case: base IS that
        # directory, the walk starts inside it, and only a NESTED VCS directory would be pruned.
        #
        # SORTED, because the scan is capped and directory order is not reproducible — two identical
        # greps must not return different results.
        files = []
        vcs_skipped = 0
        for dirpath, dirnames, filenames in os.walk(base, onerror=lambda _e: None):
            vcs_skipped += sum(1 for d in dirnames if d in _VCS_DIRS)
            dirnames[:] = [d for d in dirnames if d not in _VCS_DIRS]
            here = Path(dirpath)
            # `is_file()` kept: `filenames` includes broken symlinks, which `rglob(...)+is_file()`
            # excluded, and they must not consume the file cap. It is now one stat per KEPT file
            # rather than one per walked path, which is where the saving is.
            files.extend(p for p in (here / n for n in filenames) if p.is_file())
        files.sort()
    unscanned = max(0, len(files) - _GREP_MAX_FILES)
    hits: list[str] = []
    escaped = unreadable = 0
    capped = False
    for f in files[:_GREP_MAX_FILES]:
        if not any(_is_within(f, r) for r in roots):
            escaped += 1
            continue
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except Exception:
            unreadable += 1          # binary/permission/vanished — counted, never silently dropped
            continue
        for i, line in enumerate(text.splitlines(), 1):
            if rx.search(line):
                hits.append(f"{f}:{i}: {line.strip()[:200]}")
                if len(hits) >= max_matches:
                    capped = True
                    break
        if capped:
            break
    notes: list[str] = []
    if capped:
        notes.append(f"...[stopped at max_matches={max_matches}; more matches may exist — "
                     f"narrow `path` or raise max_matches]")
    if unscanned:
        notes.append(f"...[truncated: scanned {_GREP_MAX_FILES} of {len(files)} files; {unscanned} not "
                     f"searched — an empty/short result is NOT proof of absence; narrow `path`]")
    if vcs_skipped:
        notes.append(f"...[skipped {vcs_skipped} VCS metadata director(ies) "
                     f"({', '.join(sorted(_VCS_DIRS))}); pass an explicit path to search within one]")
    if escaped:
        notes.append(f"...[skipped {escaped} file(s) resolving outside the allowed roots (symlinks)]")
    if unreadable:
        notes.append(f"...[skipped {unreadable} unreadable file(s)]")
    # Notes go FIRST, not last. The loop truncates a serialized observation with a plain head-slice
    # (agentloop/loop `[:max_obs_chars]`), so anything appended at the end is the FIRST thing dropped —
    # and `max_matches` is model-controlled and uncapped, so a large result silently loses exactly the
    # warning that says the result is incomplete. An "incomplete scan" caveat the agent never sees is
    # worse than no caveat: it reads an empty/short result as proof of absence.
    return ToolResult(True, notes + hits)


def _list_dir(ctx: ToolContext, path: str = ".") -> ToolResult:
    p = Path(path)
    if not p.is_absolute():
        p = ctx.engine_root / path
    if not any(_is_within(p, r) for r in _read_allowed_roots(ctx)):
        return ToolResult(False, error=f"refused: read outside allowed roots ({p})")
    if not p.is_dir():
        return ToolResult(False, error=f"not a dir: {p}")
    return ToolResult(True, sorted(x.name + ("/" if x.is_dir() else "") for x in p.iterdir()))
