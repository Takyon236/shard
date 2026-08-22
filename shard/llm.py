"""LLM backend — single-shot completions (NOT an internal tool loop).

Shard owns the ReAct loop itself (see loop.py): the model proposes ONE action as JSON,
Shard's policy gates it and Shard executes it. That is deliberate — if we let ``claude -p``
run its own tool loop, Shard's human-gate would never see the individual tool calls. So this
backend is a stateless `complete(system, user) -> text`; the loop re-sends the running
transcript each turn.

Backends, all stdlib-only:
  ``ClaudeCliBackend``   — the ``claude`` CLI in `-p` mode (subscription, $0). Default for the
                           ReAct loop.
  ``OpenRouterBackend``  — the one the benchmark solver actually runs on (GLM-5.2 via Z.AI); it
                           also implements ``ToolCallingBackend`` for the native loop.
  ``NativeClientBackend``— the engine's multi-provider ``AsyncLLMClient``, lazy-imported.
  ``EchoBackend`` / ``ScriptedChatBackend`` — the deterministic test doubles. Use these in tests.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import threading
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol

from shard.diag import get_logger

_log = get_logger(__name__)

if TYPE_CHECKING:
    from collections.abc import Mapping

# Shard model tiers → `claude -p --model` aliases. Opus 4.8 for the top reasoner / final
# judge; Sonnet for workers; Haiku for cheap mechanical sub-steps. (Matches the cost-tiering
# the human session used: Opus localizer, cheaper audit sub-agents.)
MODEL_TIERS = {"reasoner": "opus", "worker": "sonnet", "cheap": "haiku"}

# Default tier → concrete Anthropic model id for the multi-provider backend (the CLI backend
# resolves these aliases itself). Override per provider via NativeClientBackend(model_map=...).
DEFAULT_ANTHROPIC_MODELS = {
    "opus": "claude-opus-4-8",
    "sonnet": "claude-sonnet-4-6",
    "haiku": "claude-haiku-4-5-20251001",
}
# OpenRouter (openrouter.ai) is OpenAI-compatible and proxies every major model behind ONE key,
# so the harness is truly any-LLM and — unlike the `claude -p` subscription — has no shared-quota
# throttle, which is what makes parallel cloud runs possible. Tier aliases map to Anthropic slugs
# for the first (Claude) test; pass a full slug (e.g. "openai/gpt-4o", "google/gemini-2.5-pro") to
# switch providers without touching code.
DEFAULT_OPENROUTER_MODELS = {
    # THE DEFAULT, and the model every test run uses. Open weights the customer controls, which is
    # the maintainers' notes's first sentence rather than a preference. Pinned to the canonical slug on purpose:
    # OpenRouter does resolve the bare `glm-5.2` today (measured 2026-08-08), but a default that
    # depends on somebody else's shorthand resolution is a default that can change without us.
    "glm": "z-ai/glm-5.2",
    "glm-5.2": "z-ai/glm-5.2",
    # `opus` REFUSES this workload. Measured 2026-08-08 on the real opening turn, four attempts out of
    # four: `finish_reason=content_filter`, `native_finish_reason=refusal`, "This request triggered
    # cyber-related safeguards", 9,003 prompt tokens spent before any tool call. `sonnet` and `haiku`
    # both accept. The alias stays because it is the measured frontier baseline and the comparison is
    # the whole cost argument — it is simply no longer something to default to.
    # See the design notes, "Found by the FIRST REAL RUN".
    "opus": "anthropic/claude-opus-4.8",      # the LATEST (matches the claude-opus-4-8 baseline);
    "sonnet": "anthropic/claude-sonnet-4.6",  # `anthropic/claude-opus-4` is opus-4.0 — much weaker
    "haiku": "anthropic/claude-haiku-4.5",
}

# Where to read each provider's key from, when one isn't passed explicitly.
_PROVIDER_ENV = {
    "anthropic": "ANTHROPIC_API_KEY",
    "openai": "OPENAI_API_KEY",
    "google": "GEMINI_API_KEY",
    "openrouter": "OPENROUTER_API_KEY",
    "ollama": "",  # local; no key needed
}

#: **WHY A RUN ENDED `error`, when the reason is the customer's to fix.**
#:
#: `status: error` is one word for every terminal transport failure, and on 2026-08-22 a real run ended
#: exactly that way because the API key died mid-run (`http 401: {"error":{"message":"User not
#: found"}}`). A customer whose key has expired, whose credits have run out, or who has named a model
#: their endpoint does not serve sees the same bare word as one whose provider fell over — and only the
#: first three are things they can do anything about.
#:
#: **PATTERNS OVER THE ERROR TEXT, NOT OVER HTTP CODES ALONE.** The code is present in the string this
#: module builds (`http 401: …`) but not in every route: `no OPENROUTER_API_KEY` never reaches the wire
#: at all, and a provider can return 200 with a refusal body. Matching the text covers both, and the
#: text is what the run already records.
#:
#: Ordered, because the first match wins and the specific cases must be tried before the general ones.
#: Each entry is `(kind, compiled pattern)`. A kind is a stable token — `shard/report.py` keys its
#: customer-facing advice off these exact strings, and the maintainers' suite pins that
#: the two vocabularies agree, so a new kind here without advice there fails rather than rendering a
#: row nobody wrote.
TRANSPORT_ERROR_KINDS: tuple[tuple[str, "re.Pattern[str]"], ...] = (
    # 402 is OpenRouter's insufficient-credit code, and the word appears in several providers' bodies.
    # Tried BEFORE `auth` because some gateways answer a spent account with 401 and say why in the body.
    ("credit", re.compile(r"http 402|insufficient[_ ]?(?:credit|quota|balance|funds)"
                          r"|exceeded your current quota|billing", re.I)),
    # THE ONE THAT MOTIVATED THIS TABLE. 401/403, a missing key, and the provider phrasings that carry
    # no code — "User not found" is what a revoked OpenRouter key returns.
    ("auth", re.compile(r"http 40[13]\b|no [A-Z_]*API_KEY|no api_key for provider"
                        r"|user not found|invalid[_ ]api[_ ]key|authentication|unauthorized"
                        r"|permission denied", re.I)),
    ("rate", re.compile(r"http 429|rate[_ ]?limit|too many requests", re.I)),
    # A model the endpoint will not serve, and OpenRouter's phrasing for a routing dead end. This is a
    # configuration error every bit as fixable as a dead key, and it also ended runs as a bare `error`.
    ("model", re.compile(r"http 404|no endpoint|model[_ ]not[_ ]found|is not a valid model"
                         r"|unknown model", re.I)),
    # Ours, from `_post`: an idle gap or the absolute-ceiling backstop, after the retry ladder gave up.
    ("stall", re.compile(r"idle/stall timeout|throughput|min_tps", re.I)),
    ("upstream", re.compile(r"http 5\d\d|http 5[02][0-9]\b", re.I)),
)


def classify_transport_error(text: str) -> str:
    """A stable token naming WHY a run's model calls failed, or `""` when nothing matches.

    Pure, so it is testable without a network and without a provider. The caller decides what to say
    about the token — see `shard/report.py`'s `TRANSPORT_ERROR_ADVICE`, which owns the customer-facing
    wording for the same reason `RunFacts.step_flag` is passed in rather than derived: the renderer
    cannot know which secret a particular installation reads its key from.
    """
    for kind, pattern in TRANSPORT_ERROR_KINDS:
        if pattern.search(text or ""):
            return kind
    return ""


@dataclass
class LLMResult:
    text: str
    cost_usd: float = 0.0
    model: str = ""
    ok: bool = True
    error: str = ""
    tokens: int = 0          # total tokens for this call (the native backend reports usage; the
                             # CLI backend reports cost instead). The loop meters whichever is set.
    finish_reason: str = ""  # provider stop reason (e.g. "length" = truncated at max_tokens). Lets the
                             # loop tell a CUT-OFF JSON action from real prose so it can reprompt sharply
                             # instead of blindly re-truncating. Empty for backends that don't report it.


class LLMBackend(Protocol):
    def complete(self, system: str, user: str, *, model: str = "sonnet", timeout: int = 600) -> LLMResult: ...


# --- native tool-calling (the SOTA agent loop: the model emits tool_calls, the harness runs them and
# returns role:"tool" results, repeat — exactly how Claude Code itself operates). Distinct from the
# single-JSON-action ReAct path above, which serializes one action as text per turn. -----------------
@dataclass
class ToolCall:
    id: str
    name: str
    arguments: dict          # parsed from the function-call arguments JSON (best-effort)


@dataclass
class ChatResult:
    text: str = ""                                   # assistant content (often empty when calling tools)
    tool_calls: list = field(default_factory=list)   # list[ToolCall]
    raw_message: dict = field(default_factory=dict)  # the assistant message, appended verbatim to history
    ok: bool = True
    error: str = ""
    tokens: int = 0
    model: str = ""
    finish_reason: str = ""  # provider stop reason (e.g. "length" = cut off at max_tokens). Lets the
                             # native loop tell a reasoning turn TRUNCATED before it emitted its tool call
                             # from a genuine no-tools finish. Empty for backends that don't report it.
    cost_usd: float = 0.0    # what the PROVIDER says this one request cost, in dollars. Rides beside
                             # `tokens` for exactly one reason: `agentloop._meter` spends both against
                             # the governor, and a dollar ceiling nothing debits is decorative — which
                             # is what `--max-spend-usd` was on every run before 2026-08-08. 0.0 from a
                             # backend that does not price its responses; see `_accumulate_usage` on why
                             # "priced 0.0" and "not priced" must not be reported as the same number.


class ToolCallingBackend(Protocol):
    def chat(self, messages: list, tools: list, *, model: str = "sonnet",
             timeout: int = 600, tool_choice=None) -> ChatResult: ...


class ClaudeCliBackend:
    """`claude -p` single-shot completion. No `--allowedTools` → the model responds, it does
    not act; Shard does the acting."""

    def __init__(self, binary: str = "claude", *, retries: int = 3, backoff: float = 3.0,
                 sleep=time.sleep, prefer_subscription: bool = True) -> None:
        self.binary = binary
        self.retries = retries          # transient `claude -p` failures (rate-limit / exit 1 / timeout)
        self.backoff = backoff          # exponential: backoff * 2**attempt seconds
        self._sleep = sleep
        # Keep `claude -p` on the $0 SUBSCRIPTION, not metered API billing. See `_child_env`.
        self.prefer_subscription = prefer_subscription

    def _child_env(self, base: "Mapping[str, str] | None" = None) -> dict[str, str]:
        """The environment `claude -p` runs under — with the metered-API keys stripped.

        This backend's entire reason to exist is that `claude -p` bills $0 against the Claude
        subscription (the same engine the benchmark localizer uses). But `claude` silently switches
        to METERED API billing the moment it finds ``ANTHROPIC_API_KEY`` / ``ANTHROPIC_AUTH_TOKEN`` /
        ``ANTHROPIC_BASE_URL`` in its environment — and those are routinely exported on a dev box that
        also drives the multi-provider `NativeClientBackend`. A child spawned with the inherited
        parent env would then quietly route onto the API and break the "$0 on the subscription"
        invariant the whole default backend rests on, with no error to notice.

        So we hand the subprocess a COPY of the environment (default ``os.environ``) with exactly
        those three keys removed. Copy-then-``pop`` (missing-key-safe): we never mutate the caller's
        mapping, and stripping an already-absent key is a no-op. Set ``prefer_subscription=False`` to
        pass the environment through untouched (deliberately opt in to metered billing)."""
        env = dict(os.environ if base is None else base)
        if self.prefer_subscription:
            for key in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL"):
                env.pop(key, None)
        return env

    def _once(self, system: str, user: str, model: str, timeout: int) -> LLMResult:
        # The prompt goes in on STDIN, not argv. `claude -p` reads the prompt from stdin when no
        # positional prompt is given (`--input-format text` is its documented default, and it is the
        # pipe usage `-p` exists for), and that matters for two reasons:
        #   1. ShardLoop._render re-concatenates the ENTIRE transcript every step, so the user prompt
        #      grows without bound. Past ARG_MAX, execve fails and subprocess.run raises
        #      `OSError: [Errno 7] Argument list too long` — which used to escape complete() and
        #      ShardLoop.run() and kill an unattended run outright.
        #   2. argv is world-readable via `ps`; stdin is not. The transcript carries target source and
        #      the agent's reasoning, so keeping it off the process table is worth having anyway.
        # The system prompt stays on argv: it is fixed-size per run, so it cannot drive the growth.
        cmd = [
            self.binary, "-p",
            "--model", model,
            "--append-system-prompt", system,
            "--output-format", "json",
            "--max-turns", "1",
        ]
        try:
            # errors="replace" for the reason the OSError arm below states: an unattended agent must
            # DEGRADE, never terminate. `text=True` alone decodes strict utf-8, and a single byte the
            # child emits that is not utf-8 — a multi-byte sequence cut at a pipe-buffer boundary, a
            # tool result echoed back through the model — raises UnicodeDecodeError, which none of
            # these three `except` clauses catches. The run would die where the design says it should
            # journal a failure and retry.
            proc = subprocess.run(cmd, input=user, capture_output=True, text=True, errors="replace",
                                  timeout=timeout, env=self._child_env())
        except subprocess.TimeoutExpired:
            return LLMResult("", 0.0, model, False, f"timeout after {timeout}s")
        except FileNotFoundError:
            return LLMResult("", 0.0, model, False, f"{self.binary!r} not found")
        except OSError as e:
            # Defence in depth for everything else the spawn itself can raise (E2BIG on an
            # oversized system prompt, EAGAIN/ENOMEM under fork pressure). An unattended agent must
            # DEGRADE — a failed result the loop can journal and retry — never terminate with a
            # traceback. Deliberately below FileNotFoundError, which is an OSError subclass and stays
            # the permanent, no-retry case; the rest are plausibly transient, so they keep the ladder.
            return LLMResult("", 0.0, model, False, f"spawn failed: {type(e).__name__}: {e}")
        if proc.returncode != 0:
            # returncode 1 with empty stderr is typically a transient subscription throttle
            return LLMResult("", 0.0, model, False, f"claude exited {proc.returncode}: {proc.stderr[:300]}")
        try:
            events = json.loads(proc.stdout)
        except json.JSONDecodeError:
            return LLMResult("", 0.0, model, False, f"unparseable output: {proc.stdout[:200]}")
        rv = next((e for e in reversed(events) if e.get("type") == "result"), None)
        if not rv:
            return LLMResult("", 0.0, model, False, "no result event")
        return LLMResult(rv.get("result", ""), float(rv.get("total_cost_usd", 0.0) or 0.0), model, True)

    def complete(self, system: str, user: str, *, model: str = "sonnet", timeout: int = 600) -> LLMResult:
        # Retry transient failures (rate-limit / exit-1 / timeout) with exponential backoff —
        # an unattended agent must survive the throttling this session repeatedly hit. A
        # `not found` error is permanent and breaks out immediately.
        last = LLMResult("", 0.0, model, False, "no attempt")
        for attempt in range(self.retries + 1):
            last = self._once(system, user, model, timeout)
            if last.ok or "not found" in last.error:
                return last
            if attempt < self.retries:
                self._sleep(self.backoff * (2 ** attempt))
        return last




# --- OpenRouter SSE reassembly — the moving parts of `OpenRouterBackend._read_sse`, one per concern --
def _sse_data(raw) -> str | None:
    """The payload of one SSE ``data:`` line, else None for framing noise the reader skips: blank
    separators, ``:``-prefixed comment keepalives (OpenRouter interleaves ``: OPENROUTER PROCESSING``
    during prefill) and non-data fields. Lines arrive as bytes from urllib; decode with
    errors="replace" so one bad byte cannot kill a live stream."""
    line = raw.decode("utf-8", "replace") if isinstance(raw, (bytes, bytearray)) else raw
    line = line.strip()
    if not line or line[0] == ":" or not line.startswith("data:"):
        return None
    return line[5:].strip()                                # past the "data:" prefix


class _StreamPace:
    """Watchdog for one SSE stream: the ABSOLUTE ceiling always, plus the CLIENT-SIDE PER-STREAM
    THROUGHPUT floor when ``min_tps`` is set. The rate origin is the FIRST OUTPUT TOKEN, NOT the
    connection: TTFT/prefill (which spikes under 12-worker load) is dead-time that must NOT count
    against the streaming rate — else a healthy stream whose first token is merely slow to arrive gets
    false-aborted (it would measure e.g. 20s of window with only ~9s of actual streaming). A token-less
    stall BEFORE the first token is not this guard's job: it's already bounded by idle_timeout (no
    bytes) and the absolute ceiling. Tumbling window: O(1), no per-chunk buffer. Both aborts raise
    ``TimeoutError``, which ``_post`` converts to the retryable 598."""

    def __init__(self, backend: OpenRouterBackend, deadline: float) -> None:
        self.backend = backend
        self.deadline = deadline
        self.tps_on = backend.min_tps is not None and backend.min_tps > 0
        self.t_first: float | None = None                  # wall-clock of the 1st output token = the rate origin
        self.t_anchor = 0.0                                # tumbling-window anchor (stamped at the 1st token)
        self.chars_anchor = 0

    def tick(self, now: float, out_chars: int) -> None:
        """Once per raw stream line, BEFORE parsing it: abort past the absolute ceiling; then, when the
        floor is armed and a full window has elapsed since the rate clock started, abort a stream
        dripping below ``min_tps`` — else tumble the window forward."""
        if now > self.deadline:                            # absolute-ceiling backstop (slow-drip)
            raise TimeoutError(f"absolute stream ceiling {self.backend.absolute_timeout}s exceeded")
        if self.tps_on and self.t_first is not None and (now - self.t_first) >= self.backend.tps_grace \
                and (now - self.t_anchor) >= self.backend.tps_window:
            # Tokens streamed since the anchor / elapsed STREAMING time (TTFT excluded, anchored at the 1st
            # token). Sub-floor → retryable 598 (relax/reroute in ~tps_window, not the 900s ceiling).
            tps = ((out_chars - self.chars_anchor) / self.backend._CHARS_PER_TOK) / (now - self.t_anchor)
            if tps < self.backend.min_tps:
                raise TimeoutError(
                    f"stream throughput ~{tps:.0f} tok/s < {self.backend.min_tps:.0f} floor over "
                    f"{now - self.t_anchor:.0f}s (slow-drip → reroute)")
            self.t_anchor, self.chars_anchor = now, out_chars   # tumble the window forward

    def mark_output(self, now: float, out_chars: int) -> None:
        """Start the rate clock at the FIRST output token. ``now`` is the same reading ``tick`` got for
        this line, so arming adds no clock call. ``chars_anchor`` deliberately stays 0: the chars that
        arrived WITH the first token count toward the first window."""
        if self.tps_on and self.t_first is None and out_chars > 0:
            self.t_first = self.t_anchor = now             # 1st output token arrived: start the rate clock here


@dataclass
class _SseAssembly:
    """One response reassembled from OpenRouter SSE chunks into the NON-streaming shape the parsers
    consume. Accumulates ``delta.content``/``reasoning``/``refusal``, merges the FRAGMENTED
    ``delta.tool_calls`` by ``index`` (``id`` + ``function.name`` arrive once; ``arguments`` stream as
    string fragments that concatenate), and captures the final ``usage`` chunk. ``out_chars`` counts
    every output character whatever field it streamed in — it feeds ``_StreamPace``'s throughput
    floor."""

    content: list[str] = field(default_factory=list)
    reasoning: list[str] = field(default_factory=list)
    refusal: str | None = None
    finish: str = ""
    native: str = ""
    usage: dict = field(default_factory=dict)
    frags: dict[int, dict] = field(default_factory=dict)   # tool_call index -> {id, name, args:[fragments]}
    out_chars: int = 0

    def add(self, chunk: dict) -> None:
        """Fold one parsed chunk in: usage, then the first choice's delta and finish reasons."""
        if chunk.get("usage"):
            self.usage = chunk["usage"]                    # rides on the final chunk (include_usage)
        choices = chunk.get("choices") or []
        if not choices:
            return
        ch = choices[0]
        self._add_delta(ch.get("delta") or {})
        if ch.get("finish_reason"):
            self.finish = ch["finish_reason"]
        if ch.get("native_finish_reason"):
            self.native = ch["native_finish_reason"]

    def _add_delta(self, delta: dict) -> None:
        """Append this delta's text fields and tool-call fragments, counting every output char."""
        if delta.get("content"):
            self.content.append(delta["content"])
            self.out_chars += len(delta["content"])        # feeds the min_tps guard (all output counts)
        if delta.get("reasoning"):
            self.reasoning.append(delta["reasoning"])
            self.out_chars += len(delta["reasoning"])      # GLM streams reasoning heavily — it IS output
        if delta.get("refusal"):
            self.refusal = (self.refusal or "") + delta["refusal"]
            self.out_chars += len(delta["refusal"])
        for tc in (delta.get("tool_calls") or []):
            self._merge_tool_call(tc)

    def _merge_tool_call(self, tc: dict) -> None:
        """One fragment of one tool call, slotted by its stream ``index``: ``id`` and ``name`` land
        once; ``arguments`` fragments concatenate in arrival order."""
        slot = self.frags.setdefault(tc.get("index", 0), {"id": None, "name": None, "args": []})
        if tc.get("id"):
            slot["id"] = tc["id"]
        fn = tc.get("function") or {}
        if fn.get("name"):
            slot["name"] = fn["name"]
        if fn.get("arguments"):
            slot["args"].append(fn["arguments"])
            self.out_chars += len(fn["arguments"])

    def response(self) -> dict:
        """The finished non-streaming response — exactly the ``{choices: [{message, finish_reason,
        native_finish_reason}], usage}`` shape a non-streaming request would have returned."""
        # Reassemble into the non-streaming message shape _once/_chat_once already consume. role="assistant" is
        # REQUIRED: this message becomes raw_message and is re-sent verbatim in the next turn's history — a provider
        # that strictly validates message roles (SiliconFlow/Kimi: HTTP 400 "Input tag '' ... does not match
        # 'system','user','assistant','tool'"; baidu/GLM under tool_choice=required: 422 "role invalid literal")
        # rejects a role-less assistant message. Omitting it silently broke every multi-turn tool call on those.
        message: dict = {"role": "assistant", "content": "".join(self.content)}
        if self.reasoning:
            message["reasoning"] = "".join(self.reasoning)
        if self.refusal is not None:
            message["refusal"] = self.refusal
        if self.frags:
            message["tool_calls"] = [
                {"id": f["id"] or f"call_{i}", "type": "function",
                 "function": {"name": f["name"] or "", "arguments": "".join(f["args"])}}
                for i, f in enumerate(self.frags[k] for k in sorted(self.frags))]
        choice: dict = {"message": message, "finish_reason": self.finish}
        if self.native:
            choice["native_finish_reason"] = self.native
        return {"choices": [choice], "usage": self.usage}


class OpenRouterBackend:
    """Any-LLM backend over OpenRouter's OpenAI-compatible /chat/completions endpoint.

    Stdlib-only (urllib) so the Docker image stays lean and Shard keeps zero runtime deps. OpenRouter
    has no shared-quota throttle (unlike the `claude -p` subscription), so this is the backend the
    parallel cloud benchmark uses. Single-shot `complete(system, user) -> LLMResult` (Shard owns the
    ReAct loop); retries transient 429/5xx with exponential backoff; reports usage.total_tokens.

    HANG RESILIENCE — STREAMING + IDLE TIMEOUT (the 12-worker stall fix, correctly). A provider can
    accept the connection then STALL the response mid-stream (observed with z-ai/glm-5.2 fp8 under
    concurrent load). The naive fix — a small NON-streaming `request_timeout` — is wrong: a non-streaming
    read's socket timeout ≈ time-to-FULL-response ≈ total generation time, so it FALSE-times-out a large
    but healthy completion (GLM-5.2 legitimately streams many thousands of tokens over minutes at
    max_tokens=32768). So this backend STREAMS the response (OpenRouter SSE) and times out on an IDLE GAP
    instead of on total time: the socket timeout is set to `idle_timeout` (default 90s = max seconds with
    NO new bytes), applied by urllib per-recv, so a completion that keeps emitting tokens never trips it
    however long it runs — only a real mid-stream stall (no bytes for idle_timeout) aborts. `absolute_timeout`
    (default 900s) is a final backstop against a pathological byte-every-89s slow-drip (still ≪ the 2h task
    wall). A stall/abort is a RETRYABLE transient (code 598, in the retry set), and on any retry the provider
    routing is RELAXED (a hard pin becomes an order-preference with `allow_fallbacks=True`, quantization floor
    kept) so OpenRouter reroutes off the hung provider — first try keeps the exact fp8 pin, a hang opens the
    whole fp8 pool. The SSE stream is reassembled into the same non-streaming response shape the parsers
    already consume, so the completion/tool-calling/refusal/finish_reason logic is unchanged."""

    ENDPOINT = "https://openrouter.ai/api/v1/chat/completions"
    # Retryable transient HTTP/transport codes, shared by complete() and chat() so both paths agree:
    # 429 rate-limit, 5xx upstream, 598 = local read/connect TIMEOUT (the hang), 599 = empty/malformed body.
    # 520-524 = Cloudflare edge/origin errors (unknown-error / down / timeout / SSL / origin-timeout). Providers
    # fronted by Cloudflare (e.g. Z.AI first-party) emit these under sustained load — they are transient origin
    # blips, NOT terminal. Omitting them aborted whole tasks on a single blip (a 117-step run zeroed by one 520).
    _RETRY_CODES = (429, 500, 502, 503, 504, 520, 521, 522, 523, 524, 598, 599)

    # Approx chars-per-output-token for the client-side `min_tps` guard. A coarse estimate is fine (the
    # guard only distinguishes a <10 tps drip from a 50+ tps healthy stream), never a billing figure.
    _CHARS_PER_TOK = 4.0

    def __init__(self, *, api_key: str | None = None, model_map: dict[str, str] | None = None,
                 base_url: str | None = None, max_tokens: int = 32768, retries: int = 4,
                 backoff: float = 2.0, sleep=time.sleep, idle_timeout: int = 90,
                 absolute_timeout: int = 900, monotonic=time.monotonic,
                 provider_only: str | list[str] | None = None, allow_fallbacks: bool = False,
                 provider_sort: str | None = None,
                 provider_order: str | list[str] | None = None,
                 provider_quantizations: list[str] | None = None,
                 provider_min_throughput: dict | int | None = None,
                 provider_max_price: dict | None = None,
                 min_tps: float | None = None, tps_grace: float = 12.0, tps_window: float = 20.0,
                 temperature: float = 0.0, seed: int | None = None,
                 # **THESE TWO GO OVER THE WIRE ON EVERY REQUEST**, as `HTTP-Referer` and `X-Title`,
                 # and until 2026-08-22 they named a PRIVATE repository. Every model call a customer
                 # made — on the free tier as well as the paid one — announced the name of a tree they
                 # cannot see, to a third party, from their own runner. That is not a leak of their
                 # code, but it is our internal project name on someone else's infrastructure, and it
                 # was also simply wrong branding on the one identifier a provider displays back.
                 referer: str = "https://github.com/Takyon236/shard",
                 title: str = "Shard") -> None:
        self.api_key = api_key if api_key is not None else os.environ.get("OPENROUTER_API_KEY", "")
        self.model_map = model_map or DEFAULT_OPENROUTER_MODELS
        self.endpoint = (base_url.rstrip("/") + "/chat/completions") if base_url else self.ENDPOINT
        self.max_tokens = max_tokens
        # Cost/efficiency accounting (benchmark SUBMISSION.md schema). One backend instance serves a whole
        # task — the main solver loop AND every sub-agent (verifier/oracle/specialist reuse this backend) —
        # so accumulating here gives an exact per-task total without threading fields through the loop /
        # AgentResult / solve_task. cloud_sweep reads it via usage_summary() after the solve. cached_tokens
        # is OpenRouter's prompt_tokens_details.cached_tokens (0 when the provider does not cache, e.g. GLM).
        self._usage = {"input_tokens": 0, "output_tokens": 0, "cached_tokens": 0,
                       "total_tokens": 0, "llm_requests": 0, "generation_sec": 0.0,
                       "cost_usd": 0.0, "cache_write_tokens": 0,   # B3 — SUBMISSION.md cost fields
                       # How many of those `llm_requests` came back carrying a price at all. `cost_usd`
                       # alone cannot tell "this run really cost $0.00" from "no response priced
                       # anything", and the two must not print as the same sentence to a customer
                       # reconciling a bill against the ceiling they set.
                       "priced_requests": 0}
        # A single backend instance serves the solver loop AND concurrent sub-agent panels (verifier/oracle/
        # specialist fan out on a ThreadPoolExecutor and reuse this instance), so the accumulate is a shared
        # read-modify-write across threads — guard it, or concurrent `+=` drops updates and under-counts cost.
        self._usage_lock = threading.Lock()
        self.retries = retries
        self.backoff = backoff
        self._sleep = sleep
        # IDLE (inter-read) TIMEOUT — the streaming hang fix. The response is STREAMED (SSE), and this is
        # the socket timeout urllib applies per blocking recv: the max seconds with NO new bytes before a
        # read aborts. A completion that keeps streaming tokens NEVER trips it, however long the whole
        # generation runs (the false-timeout fix — a non-streaming read made the socket timeout ≈ total
        # generation time and killed large healthy completions). Only a real mid-stream STALL (no bytes for
        # idle_timeout) aborts → retry+failover. It CAPS whatever the caller threads into complete()/chat()
        # (the loop passes 600), so cloud_sweep gets the safe value with no caller change.
        self.idle_timeout = idle_timeout
        # ABSOLUTE CEILING — a final backstop measured across the WHOLE stream, so a pathological slow-drip
        # (a byte every 89s, never tripping idle_timeout) still can't run forever. Generous (default 900s,
        # ≫ any legit turn but ≪ the 2h task wall); hitting it aborts as a retryable stall (598).
        self.absolute_timeout = absolute_timeout
        self._monotonic = monotonic  # injectable wall-clock for the absolute ceiling (deterministic tests)
        # OpenRouter PROVIDER ROUTING: pin the upstream provider(s) that serve a model (e.g. AkashML
        # for z-ai/glm-5.2). With allow_fallbacks=False the request goes ONLY to those providers (no
        # silent reroute), so the benchmark is reproducible against one provider.
        self.provider_only = [provider_only] if isinstance(provider_only, str) else (provider_only or None)
        self.allow_fallbacks = allow_fallbacks
        # "Best possible provider": instead of a hard single-provider pin (the AkashML mistake),
        # sort the eligible providers (e.g. "throughput" = fastest, "price", "latency") and allow
        # fallback — so a hiccup on one reroutes to another rather than killing the task.
        self.provider_sort = provider_sort
        # PREFERRED providers (order): try these first, then fall back to the rest of the eligible
        # (quantization-filtered) pool. Unlike `only`, `order` does NOT fail when the preferred
        # provider is down/429 — it reroutes. This is the reliable way to favor a fast fp8 provider
        # (e.g. "parasail/fp8") while keeping the other fp8 providers as overflow capacity, so high
        # worker-concurrency spreads across the whole fp8 pool instead of 429-stalling on one provider.
        self.provider_order = [provider_order] if isinstance(provider_order, str) else (provider_order or None)
        # Restrict to providers serving a model at >= these quantizations (e.g. ["fp8","fp16","bf16",
        # "fp32"]). NEVER fp4/int4 for a benchmark — low quant degrades reasoning and produces a
        # misleadingly low capability score (the cheapest GLM providers are fp4/unknown). Excluding a
        # quant also excludes "unknown", which could be fp4. Composes with sort/only.
        self.provider_quantizations = provider_quantizations
        # SERVER-SIDE THROUGHPUT FLOOR — OpenRouter's `preferred_min_throughput` filter. It routes to the
        # cheapest endpoint meeting >= N tok/s at the given percentile (off OpenRouter's own rolling 5-min
        # p50/p90/p99 stats), DEPRIORITIZING (not excluding) slower ones to the fallback tail. This is the
        # proactive half of "keep latency above 50 tps": pick a provider that's fast in aggregate. An int is
        # shorthand for {"p90": N} (the sane default percentile — 90% of requests hit the floor or better).
        if isinstance(provider_min_throughput, int):
            provider_min_throughput = {"p90": provider_min_throughput}
        self.provider_min_throughput = provider_min_throughput
        # SERVER-SIDE COST CEILING — OpenRouter's `max_price` ({"prompt": $/M, "completion": $/M}). Routes
        # only to endpoints at or under the cap; paired with sort=throughput it's "fastest provider under a
        # hard budget". Kept on relax too — a cheap-fp8 GLM pool sits well under any sane cap, so failover
        # never silently jumps to a premium endpoint. Leave None to let order/sort optimize cost instead.
        self.provider_max_price = provider_max_price
        # CLIENT-SIDE PER-STREAM THROUGHPUT GUARD — the reactive half, and the real "12 workers easily" fix.
        # `preferred_min_throughput` is a GLOBAL 5-min aggregate: it picks a provider fast *on average*, but
        # MY specific stream under high concurrency can still slow-drip while that provider's global p90 looks
        # fine (exactly the freeze — quick test calls returned in ~1s while the concurrent streaming/tool
        # requests stalled). `min_tps` measures the ACTUAL token rate of THIS stream over a tumbling window
        # (`tps_window`, after a `tps_grace` warmup that absorbs TTFT + ramp) and aborts a sub-floor stream as
        # a retryable 598 → the retry relaxes routing and reroutes off the drip in ~tps_window seconds instead
        # of grinding to absolute_timeout (900s). None = off (default; existing runs unchanged). Token count
        # is approximate (chars / _CHARS_PER_TOK) — coarse is fine: a drip is <10 tps, a healthy GLM stream
        # 50-150+, so the estimate trivially separates them.
        self.min_tps = min_tps
        self.tps_grace = tps_grace
        self.tps_window = tps_window
        # DETERMINISM: temperature 0 = greedy decoding — the #1 lever against the 47-77% run-to-run
        # swing on identical tasks (the provider default temperature ~0.6-1.0 samples fresh every turn,
        # so two runs diverge on step 1 and compound). `seed` is best-effort only (OpenRouter forwards
        # it; a GLM/fp8 MoE won't honor it bitwise under production batching) — a weak add-on, not a
        # guarantee. NB: for full reproducibility ALSO pin a single provider (provider_only) — throughput
        # + fallback routing serves different runs from different providers, a variance source temp=0
        # can't remove.
        self.temperature = temperature
        self.seed = seed
        self.referer = referer
        self.title = title

    def _resolve(self, model: str) -> str:
        return self.model_map.get(model, model)  # tier alias → slug, else pass the slug through

    def _accumulate_usage(self, usage: dict, gen_sec: float = 0.0) -> None:
        """Add one response's token usage to the per-task running total (SUBMISSION.md cost schema). Called
        once per completed request (streaming or not); each call = one billed llm_request. Robust to a
        provider that omits fields (they default 0).

        **THE REQUEST IS COUNTED EVEN WHEN THE PROVIDER REPORTS NO USAGE, and that is the whole point of
        the early return moving.** It used to return before `llm_requests += 1`, so an endpoint that
        omits `usage` — a self-hosted vLLM, which `cli.py` calls "the guaranteed EU-residency path" —
        left the counter at 0 after N real billed requests. `_cost_line` reads that counter to decide
        between "cost not reported by this endpoint" and "no inference", so a run that made 200 requests
        rendered as **"0 tokens of 400,000, no inference"**: the report asserted the opposite of what
        happened, and a customer reconciling it against their provider bill had nothing to reconcile
        with. Counting the request is what makes the tri-state able to tell "we spent nothing" apart
        from "we cannot see what we spent"."""
        with self._usage_lock:
            self._usage["llm_requests"] += 1
        if not usage:
            return
        with self._usage_lock:
            self._usage["input_tokens"] += int(usage.get("prompt_tokens", 0) or 0)
            self._usage["output_tokens"] += int(usage.get("completion_tokens", 0) or 0)
            _ptd = usage.get("prompt_tokens_details") or {}
            self._usage["cached_tokens"] += int(_ptd.get("cached_tokens", 0) or 0)
            self._usage["total_tokens"] += int(usage.get("total_tokens", 0) or 0)
            # `llm_requests` is counted ABOVE, before the no-usage early return — see the docstring.
            self._usage["generation_sec"] += float(gen_sec or 0.0)
            # B3 — the two fields SUBMISSION.md asks for that we were discarding, both of which OpenRouter
            # already returns on every response:
            #   * `cost` is the REAL billed amount. Reporting it beats `est_usd_cost`'s price-times-tokens
            #     estimate, which cannot know the provider's actual rate or discounts.
            #   * `cache_write_tokens` is the schema's `cache_creation_tokens`, which we hardcoded to 0.
            # ⚠ `input_tokens` above stays the RAW prompt_tokens on purpose — it INCLUDES cache reads. The
            # schema wants NON-cached input, and that subtraction belongs in the reporter (make_submission),
            # not here, so this dict keeps meaning exactly what the provider said. Getting that backwards is
            # what made the submission overstate input cost by 6.5x.
            self._usage["cost_usd"] += float(usage.get("cost", 0.0) or 0.0)
            self._usage["cache_write_tokens"] += int(_ptd.get("cache_write_tokens", 0) or 0)
            # PRESENCE, not amount: a response that omits `cost` is one this endpoint did not price, and
            # summing it as 0.0 silently understates the run. Counted here so a reporter can say "not
            # priced" instead of "$0.00" — the same class of decorative number as the ceiling that never
            # fired. `is not None` rather than truthiness: a genuine free-tier 0.0 IS a price.
            if usage.get("cost") is not None:
                self._usage["priced_requests"] += 1

    def usage_summary(self) -> dict:
        """Per-task token/request totals accumulated across every request this backend served (the solver
        loop plus any sub-agents that reuse this instance). Read by cloud_sweep after the solve."""
        with self._usage_lock:
            return dict(self._usage)

    def _post(self, payload: dict, timeout: int, relax: bool = False) -> tuple[dict | None, int, str]:
        """POST a STREAMING chat-completions request and reassemble the SSE stream into the SAME
        non-streaming response shape the parsers already consume (``{choices:[{message, finish_reason,
        native_finish_reason}], usage}``) — so ``_once``/``_chat_once`` (and all the refusal/reasoning/
        finish_reason logic) are unchanged. Returns ``(data, http_code, error)``: on success ``(data, 200,
        "")``; on an HTTP error ``(None, code, detail)``; on an IDLE STALL or the absolute-ceiling backstop
        ``(None, 598, detail)``; on a truncated/malformed stream ``(None, 599, detail)``; on any other
        transport error ``(None, 503, detail)``.

        Why stream: a NON-streaming read makes the socket timeout ≈ total generation time, so a large but
        HEALTHY completion false-times-out. Streaming lets the socket timeout be the IDLE (inter-read) gap
        (``idle_timeout``) — a completion that keeps emitting tokens never trips it however long it runs;
        only a real mid-stream stall aborts. ``absolute_timeout`` backstops a pathological slow-drip. Both
        aborts are retryable (598) and the retry (``relax=True``) opens provider routing to reroute off the
        bad provider. The caller builds its own domain result so the completion and tool-calling paths stay
        type-distinct (LLMResult vs ChatResult)."""
        import http.client
        import json as _json
        import socket
        import urllib.error
        import urllib.request

        prov = self._provider_block(relax)
        if prov:
            payload["provider"] = prov
        # STREAM so the socket timeout can be an IDLE gap, not the total-generation cap (the false-timeout
        # fix). include_usage → the final SSE chunk carries usage.total_tokens.
        payload["stream"] = True
        payload["stream_options"] = {"include_usage": True}
        # The per-recv socket timeout = the IDLE (no-new-bytes) gap. urllib applies it to EACH blocking read
        # (connect + each recv), so a stream that keeps flowing never trips it; a stall beyond idle_timeout
        # aborts fast. min(caller, idle_timeout): the loop threads in 600, we still cap the read-gap.
        idle = min(int(timeout), self.idle_timeout)
        req = urllib.request.Request(self.endpoint, data=_json.dumps(payload).encode("utf-8"),
                                     method="POST", headers={
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": self.referer,
            "X-Title": self.title,
        })
        try:
            with urllib.request.urlopen(req, timeout=idle) as resp:
                # ABSOLUTE ceiling: a final backstop measured across the whole stream so a byte-every-89s
                # slow-drip can't run forever (still ≪ the task wall); hitting it aborts as a retryable stall.
                deadline = self._monotonic() + self.absolute_timeout
                return self._read_sse(resp, deadline), 200, ""
        except urllib.error.HTTPError as e:
            return None, e.code, f"http {e.code}: {e.read().decode('utf-8', 'replace')[:300]}"
        except (TimeoutError, socket.timeout) as e:
            # The STALL: an idle gap (no bytes for idle_timeout) or the absolute-ceiling backstop. 598 is in
            # the retry set, and the retry relaxes provider routing so we reroute off the stalled provider.
            return None, 598, f"idle/stall timeout after {idle}s: {type(e).__name__}: {e}"
        except urllib.error.URLError as e:
            # A connect-phase timeout can arrive wrapped in URLError — still route it down the 598 path.
            if isinstance(e.reason, (TimeoutError, socket.timeout)):
                return None, 598, f"idle/stall timeout after {idle}s: {e.reason}"
            return None, 503, f"{type(e).__name__}: {e}"
        except (_json.JSONDecodeError, http.client.IncompleteRead, TypeError) as e:
            # A truncated/malformed stream (connection dropped mid-SSE, a non-JSON chunk) must NOT raise —
            # an uncaught error here propagated all the way up and killed the whole task as an errored MISS.
            # Convert it to the same retryable 599 the empty-completion path uses, so the backoff handles it.
            #
            # `TypeError` is the WELL-FORMED-JSON, WRONG-TYPE case, and it was the one class this arm
            # promised to cover and did not. A provider streaming `"content": 42` or `"arguments": 7`
            # parses fine and then reaches `len(...)` and `"".join(...)` in the reassembler. **The
            # customer supplies inference on every tier**, so a self-hosted vLLM or a proxy that
            # serialises a number where the spec says string is a configuration we neither control nor
            # can test against — and it killed a paid run outright while every other malformed-stream
            # case retried. Coercing instead was rejected: it would silently turn a bool into the text
            # "True" inside the model's own output, which is a fabricated answer rather than a refused
            # one. A non-conforming chunk IS a transport fault, so it gets the transport's answer.
            return None, 599, f"malformed stream: {type(e).__name__}: {e}"
        except OSError as e:
            # Any other transport error (connection reset/abort, DNS, broken pipe) — transient, retryable.
            # Belt-and-braces: a single hung/broken request must NEVER propagate and kill the task.
            return None, 503, f"{type(e).__name__}: {e}"

    def _read_sse(self, resp, deadline: float) -> dict:
        """Consume an OpenRouter SSE stream and reassemble it into the NON-streaming response shape the
        callers already parse — ``_sse_data`` peels the framing, ``_SseAssembly`` accumulates the
        message, ``_StreamPace`` polices the pace. ``data: [DONE]`` terminates; SSE comment/keepalive
        lines and unparseable chunks are skipped (tolerated). A completion that keeps streaming never
        stalls; a slow-drip past ``deadline`` raises ``TimeoutError`` (the absolute ceiling), caught as
        a retryable 598 by ``_post``."""
        import json as _json

        assembly = _SseAssembly()
        pace = _StreamPace(self, deadline)
        for raw in resp:
            now = self._monotonic()                        # ONE clock read per line, shared by both checks
            pace.tick(now, assembly.out_chars)
            body = _sse_data(raw)
            if body is None:
                continue                                   # blank separator / SSE comment / non-data field
            if body == "[DONE]":
                break
            try:
                chunk = _json.loads(body)
            except _json.JSONDecodeError:
                continue                                   # tolerate a corrupt keepalive / padding line
            assembly.add(chunk)
            pace.mark_output(now, assembly.out_chars)      # the 1st output token starts the rate clock
        return assembly.response()

    def _once(self, system: str, user: str, model: str, timeout: int,
              relax: bool = False) -> tuple["LLMResult", int]:
        payload = {
            "model": model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
        }
        if self.seed is not None:
            payload["seed"] = self.seed
        _gen_t0 = time.monotonic()
        data, code, err = self._post(payload, timeout, relax)
        _gen_sec = time.monotonic() - _gen_t0
        if data is None:
            return LLMResult("", 0.0, model, False, err, tokens=0), code
        # OpenAI-compatible shape. A reasoning model (e.g. GLM-5.2) can return empty `content` — fall
        # back to `reasoning`. Bind `choice` first so finish_reason/native/refusal are reachable.
        choice = (data.get("choices") or [{}])[0]
        msg = choice.get("message", {}) or {}
        finish = choice.get("finish_reason") or ""
        native = choice.get("native_finish_reason") or ""
        refusal = msg.get("refusal")
        _usage = data.get("usage") or {}
        tokens = int(_usage.get("total_tokens", 0) or 0)
        self._accumulate_usage(_usage, _gen_sec)
        # A refusal is NEVER a success: detect it BEFORE it can be laundered into `text` (the mistake
        # that made a structured refusal look ok=True), and return terminal 403 (∉ retry set →
        # complete() returns at once instead of grinding the ~30s backoff ladder) with the refusal
        # text surfaced in `error`. Mirrors _chat_once so the two paths agree.
        text = msg.get("content") or msg.get("reasoning") or ""
        if not text and (refusal or finish == "content_filter" or native == "refusal"):
            err = f"model refused the prompt (finish={finish or native})"
            return LLMResult("", 0.0, model, False, f"{err}: {refusal}" if refusal else err,
                             tokens=tokens, finish_reason=finish), 403
        if not text:
            # Empty content + no refusal signal → a TRANSIENT glitch (AkashML/GLM does this
            # intermittently) — retry via 599. finish_reason rides along so the loop can tell a
            # max_tokens TRUNCATION ("length") from a genuinely empty turn.
            return LLMResult("", 0.0, model, False, f"empty response: {str(data)[:200]}",
                             tokens=tokens, finish_reason=finish), 599
        return LLMResult(text, 0.0, model, True, "", tokens=tokens, finish_reason=finish), 200

    def complete(self, system: str, user: str, *, model: str = "sonnet", timeout: int = 600) -> "LLMResult":
        resolved = self._resolve(model)
        if not self.api_key:
            return LLMResult("", 0.0, resolved, False, "no OPENROUTER_API_KEY")
        last = LLMResult("", 0.0, resolved, False, "no attempt")
        for attempt in range(self.retries + 1):
            # After the FIRST failure, RELAX provider routing (relax=attempt>0) so a hung/429 provider
            # reroutes to a healthy one — the first try keeps the exact fp8 pin/preference.
            last, code = self._once(system, user, resolved, timeout, relax=attempt > 0)
            if last.ok or code not in self._RETRY_CODES:  # 598 = timeout/hang, 599 = empty completion
                return last      # success, or a permanent error (4xx other than 429)
            if attempt < self.retries:
                # ADAPT-G: the single most useful diagnostic line this package can emit. A sweep that
                # slows to a crawl is almost always transport — a stalled provider being rerouted (598),
                # a rate limit (429), or empty completions (599) — and none of that reaches the journal,
                # so without this the only symptom is a task taking 17x its median with no explanation.
                _log.warning("provider %s failed with %d (%s); retry %d/%d in %.1fs, routing relaxed",
                             resolved, code, (last.error or "")[:120], attempt + 1, self.retries,
                             self.backoff * (2 ** attempt))
                self._sleep(self.backoff * (2 ** attempt))
        if not last.ok:
            _log.error("provider %s exhausted %d retries; last code %d (%s)",
                       resolved, self.retries, code, (last.error or "")[:200])
        return last

    def _provider_block(self, relax: bool = False) -> dict | None:
        """The OpenRouter `provider` routing block: quantization floor + sort/pin. Shared by complete()
        and chat() so both paths honor the same routing (esp. the >= fp8 quantization floor).

        ``relax=True`` (a RETRY after a hang/transient) opens the routing so we reroute off a stalled/429
        provider: a hard ``only`` pin is downgraded to an ``order`` PREFERENCE with ``allow_fallbacks``,
        and fallbacks are forced on. The quantization floor is ALWAYS kept — failover must never drop to
        fp4/int4. The default (relax=False) is byte-for-byte the original first-try routing."""
        block: dict = {}
        if self.provider_only and not relax:            # hard allow-list — fail outside it (first try only)
            block["only"] = self.provider_only
            block["allow_fallbacks"] = self.allow_fallbacks
        else:
            # On relax, a hard pin becomes a mere PREFERENCE (order) so a hung pinned provider reroutes.
            order = self.provider_order or (self.provider_only if relax else None)
            if order:                                   # prefer these first, then fall back
                block["order"] = order
                block["allow_fallbacks"] = True         # the point of order: reroute, don't fail
            if self.provider_sort:                      # sort the fallback pool (throughput = :nitro)
                block["sort"] = self.provider_sort
                block.setdefault("allow_fallbacks", True)
            if relax:                                   # force reroute even with no order/sort configured
                block["allow_fallbacks"] = True
        if self.provider_quantizations:                 # filter out fp4/int4/unknown (constrains fallbacks)
            block["quantizations"] = self.provider_quantizations
        # Throughput floor + price ceiling are QUALITY/COST invariants kept on BOTH the first try and relax
        # (like the quant floor): failover must stay fast AND cheap, never reroute onto a slow or premium
        # endpoint. Deprioritize-not-exclude semantics mean these never leave the request unfulfillable.
        if self.provider_min_throughput:
            block["preferred_min_throughput"] = self.provider_min_throughput
        if self.provider_max_price:
            block["max_price"] = self.provider_max_price
        return block or None

    def _chat_once(self, messages: list, tools: list, model: str, timeout: int,
                   relax: bool = False, tool_choice=None) -> tuple["ChatResult", int]:
        import json as _json

        payload: dict = {"model": model, "messages": messages, "max_tokens": self.max_tokens,
                         "temperature": self.temperature}
        if self.seed is not None:
            payload["seed"] = self.seed
        if tools:
            payload["tools"] = tools
            # tool_choice: None → "auto" (model decides). A caller may FORCE a call — "required" (any tool) or
            # {"type":"function","function":{"name":...}} (a specific tool) — to break a weak model's default of
            # answering in prose (measured: GLM reads source, ~never constructs). OpenRouter rejects an
            # unsupported value with a hard 404 (not a silent drop), so a bad force surfaces loudly, not silently.
            payload["tool_choice"] = tool_choice or "auto"
        _gen_t0 = time.monotonic()
        data, code, err = self._post(payload, timeout, relax)
        _gen_sec = time.monotonic() - _gen_t0
        if data is None:
            return ChatResult(ok=False, error=err, model=model), code
        choice = (data.get("choices") or [{}])[0]
        msg = choice.get("message", {}) or {}
        _usage = data.get("usage") or {}
        tokens = int(_usage.get("total_tokens", 0) or 0)
        # The provider's own billed amount for THIS request, carried out on every return path that has a
        # response — including the refusal and the empty-turn glitch below. Both were already charged for
        # (opus-4.8's refusal burned 9,003 prompt tokens before refusing), so a meter that skipped them
        # would under-report exactly the turns a customer most wants to see on the bill.
        cost = float(_usage.get("cost", 0.0) or 0.0)
        self._accumulate_usage(_usage, _gen_sec)
        calls = []
        for tc in (msg.get("tool_calls") or []):
            fn = tc.get("function") or {}
            try:
                args = _json.loads(fn.get("arguments") or "{}")
            except (_json.JSONDecodeError, TypeError):
                args = {}
            if not isinstance(args, dict):
                args = {}
            calls.append(ToolCall(id=tc.get("id") or f"call_{len(calls)}", name=fn.get("name") or "", arguments=args))
        # Detect a SAFETY REFUSAL *before* folding it into text. A structured refusal
        # ({content:null, refusal:"..."}) must not be laundered into a success ChatResult — that
        # returns ok=True and makes the terminal-403 branch dead for exactly that case. Retrying a
        # refusal is pure waste (opus-4.8 content_filters the exploit-PoC prompt); GLM/Bedrock signal
        # it via finish_reason instead. Terminal when there are no tool_calls and any refusal signal.
        refusal = msg.get("refusal")
        finish = choice.get("finish_reason") or ""
        native = choice.get("native_finish_reason") or ""
        if not calls and (refusal or finish == "content_filter" or native == "refusal"):
            return ChatResult(ok=False, error=f"model refused the prompt (finish={finish or native})",
                              model=model, tokens=tokens, cost_usd=cost,
                              finish_reason=finish), 403  # 403 ∉ retry set → terminal
        text = msg.get("content") or msg.get("reasoning") or ""            # refusal dropped from success text
        if not text and not calls:
            # empty content + no tool calls + no refusal signal → a transient glitch (retry via 599).
            # finish_reason rides along so the loop can tell a max_tokens TRUNCATION ("length") apart.
            return ChatResult(ok=False, error=f"empty response: {str(data)[:200]}", model=model,
                              tokens=tokens, cost_usd=cost, finish_reason=finish), 599
        return ChatResult(text=text, tool_calls=calls, raw_message=msg, ok=True, model=model,
                          tokens=tokens, cost_usd=cost, finish_reason=finish), 200

    def chat(self, messages: list, tools: list, *, model: str = "sonnet", timeout: int = 600,
             tool_choice=None) -> ChatResult:
        """Native tool-calling turn: send the message history + tool schemas, get back the assistant
        message (content and/or tool_calls). Same retry/provider-routing policy as `complete`. ``tool_choice``
        (None→"auto", "required", or a {function:{name}} dict) FORCES a tool call when the caller wants to break
        a prose-answer default."""
        resolved = self._resolve(model)
        if not self.api_key:
            return ChatResult(ok=False, error="no OPENROUTER_API_KEY", model=resolved)
        last = ChatResult(ok=False, error="no attempt", model=resolved)
        for attempt in range(self.retries + 1):
            # relax=attempt>0: reroute off a hung/429 provider on retry (first try keeps the fp8 pin).
            last, code = self._chat_once(messages, tools, resolved, timeout, relax=attempt > 0,
                                         tool_choice=tool_choice)
            if last.ok or code not in self._RETRY_CODES:
                return last
            if attempt < self.retries:
                self._sleep(self.backoff * (2 ** attempt))
        return last


@dataclass
class EchoBackend:
    """Deterministic test double: returns scripted responses in order, ignoring the prompt."""

    scripted: list[str] = field(default_factory=list)
    calls: list[tuple[str, str]] = field(default_factory=list)

    def complete(self, system: str, user: str, *, model: str = "sonnet", timeout: int = 600) -> LLMResult:
        self.calls.append((system, user))
        if not self.scripted:
            return LLMResult("", 0.0, model, False, "EchoBackend exhausted")
        return LLMResult(self.scripted.pop(0), 0.0, model, True)


@dataclass
class ScriptedChatBackend:
    """Deterministic tool-calling double for ToolCallingLoop tests. Each scripted turn is either
    a ``str`` (assistant finishes with that text, no tool calls), a ``list[(name, args)]`` (the
    assistant calls those tools), ``None`` (an empty-response glitch), or a ``ChatResult`` passed
    through verbatim — the escape hatch for scripting a turn that carries a ``finish_reason``
    (e.g. a max_tokens TRUNCATION: ``ChatResult(text="...", finish_reason="length", ok=True)``).
    Ignores the prompt; records each message history it was sent."""

    scripted: list = field(default_factory=list)
    calls: list = field(default_factory=list)
    tool_choices: list = field(default_factory=list)     # records the per-turn tool_choice (for forcing tests)

    def chat(self, messages: list, tools: list, *, model: str = "sonnet", timeout: int = 600,
             tool_choice=None) -> ChatResult:
        self.calls.append(list(messages))
        self.tool_choices.append(tool_choice)
        if not self.scripted:
            return ChatResult(ok=False, error="ScriptedChatBackend exhausted", model=model)
        turn = self.scripted.pop(0)
        if isinstance(turn, ChatResult):                      # verbatim (carries finish_reason etc.)
            return turn
        if turn is None:                                      # scripted empty-response glitch
            return ChatResult(ok=False, error="empty response: simulated glitch", model=model, tokens=1)
        if isinstance(turn, str):
            return ChatResult(text=turn, tool_calls=[], raw_message={"role": "assistant", "content": turn},
                              ok=True, model=model, tokens=1)
        tcs = [ToolCall(id=f"call_{i}", name=name, arguments=args) for i, (name, args) in enumerate(turn)]
        raw = {"role": "assistant", "content": None, "tool_calls": [
            {"id": tc.id, "type": "function",
             "function": {"name": tc.name, "arguments": json.dumps(tc.arguments)}} for tc in tcs]}
        return ChatResult(text="", tool_calls=tcs, raw_message=raw, ok=True, model=model, tokens=1)


# --- JSON-action extraction -------------------------------------------------
_FENCE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL)
# Reasoning models (GLM-5.2, etc.) wrap output in <think>…</think> and prepend prose before the
# JSON action. Strip the reasoning, then pick the ACTIONABLE object — not just the first `{` in prose.
_THINK_TAG = re.compile(r"(</?)think(?:ing)?>", re.IGNORECASE)


def _strip_reasoning(text: str) -> str:
    """Remove <think>/<thinking> regions — including one the model never CLOSED.

    A regex over `<think>.*?</think>` handles the well-formed case but silently fails the dangerous
    one: a turn the provider cut off at max_tokens (finish_reason="length") ends mid-reasoning with
    the opener dangling, nothing matches, and the entire chain-of-thought flows into the object
    scanner below — which returns the LAST JSON object in it. Reasoning text ENUMERATES options
    before discarding them ("I could just call write_file … but that would be wrong; let me read
    first"), so the loop would execute a hypothesis the model explicitly REJECTED. loop.py's
    finish_reason=="length" branch cannot catch that: it runs only when extraction FAILS, and here
    extraction succeeded — wrongly. Dropping an unfinished thought instead yields no action, and the
    loop takes its truncation-specific re-prompt.

    So this walks the tags with a depth counter rather than pattern-matching pairs. Depth is what
    makes the awkward shapes come out right: a *nested* opener whose outer block is unterminated is
    still unterminated (regex pairing would let the inner `</think>` close the outer one and release
    the reasoning), while a reply that closes one block, emits a real action and then re-opens
    another keeps the action — only the trailing unfinished region is dropped. An unmatched CLOSING
    tag is ignored rather than treated as a strip boundary."""
    spans: list[tuple[int, int]] = []
    depth = 0
    start = 0
    for m in _THINK_TAG.finditer(text):
        if m.group(1) == "<":
            if depth == 0:
                start = m.start()          # outermost opener: where this region begins
            depth += 1
        elif depth:                        # a closer with no open region is stray text, not a boundary
            depth -= 1
            if depth == 0:
                spans.append((start, m.end()))
    if depth:                              # opener(s) never closed → the turn was cut off mid-thought
        spans.append((start, len(text)))
    if not spans:
        return text
    kept: list[str] = []
    prev = 0
    for a, b in spans:
        kept.append(text[prev:a])
        prev = b
    kept.append(text[prev:])
    return "".join(kept)


def _balanced_objects(text: str):
    """Yield every top-level balanced {...} substring (skips nested objects).

    Uses ``json.JSONDecoder().raw_decode``, which honors JSON string literals — a naive
    brace-depth counter miscounts a ``{``/``}`` INSIDE a string value (e.g. a grep pattern
    ``"if (x) {"``), truncates the object, and makes extract_json drop the whole action.
    ``raw_decode`` consumes the entire top-level object, so ``text.find("{", end)`` resumes
    *after* it — preserving the top-level-only, skip-nested behavior."""
    dec = json.JSONDecoder()
    idx = text.find("{")
    while idx != -1:
        try:
            _, end = dec.raw_decode(text, idx)    # end = index just past this top-level object
            yield text[idx:end]
            idx = text.find("{", end)             # skip this object's interior
        except ValueError:                        # not a valid object here — try the next `{`
            idx = text.find("{", idx + 1)


def extract_json(text: str) -> dict | None:
    """Pull the ReAct action object out of a model response — robust to reasoning-model output.

    Strips <think> regions via ``_strip_reasoning`` (closed blocks AND an unclosed, truncated one),
    so only text the model actually committed to is searched — which is also what makes "prefer what
    comes after the last ``</think>``" fall out for free. Then collects every parseable JSON object
    (fenced or bare) and returns the LAST one carrying an ``action`` or ``final`` key (the real
    decision), falling back to the last valid dict. This avoids grabbing a stray ``{`` in a model's
    prose preamble or an example object inside its reasoning. None only if nothing parses — the loop
    re-prompts on that."""
    if not text:
        return None
    text = _strip_reasoning(text)
    candidates: list = []
    for m in _FENCE.finditer(text):
        try:
            candidates.append(json.loads(m.group(1)))
        except json.JSONDecodeError:
            pass
    for chunk in _balanced_objects(text):
        try:
            candidates.append(json.loads(chunk))
        except json.JSONDecodeError:
            pass
    dicts = [c for c in candidates if isinstance(c, dict)]
    actionable = [c for c in dicts if "action" in c or "final" in c]
    if actionable:
        return actionable[-1]
    return dicts[-1] if dicts else None


# --- the endpoint probe, PRODUCT-AUDIT P6/P7 ---------------------------------------------------------

#: The one tool the probe offers. Trivial on purpose: what is being measured is whether the endpoint
#: can emit a `tool_calls` structure at all, not whether the model is clever. A schema with required
#: arguments would let a capable endpoint fail the probe for getting the ARGUMENT wrong, which is a
#: different question and not the one §6c asks.
PROBE_TOOL = [{
    "type": "function",
    "function": {"name": "shard_probe", "description": "Call this with any string to confirm the "
                                                       "endpoint supports native tool calling.",
                 "parameters": {"type": "object",
                                "properties": {"note": {"type": "string"}}}},
}]

VALIDATED, COMPATIBLE, UNSUPPORTED = "validated", "compatible", "unsupported"


def probe_endpoint(backend, *, model: str = "", validated_model: str = "",
                   timeout: int = 60) -> dict:
    """One tool-calling round trip. Returns a verdict, a reason, and what was observed.

    **the integration guidec promises this in a sentence the product did not keep:** *"Preflight
    refuses rather than producing a bad run."* It refused nothing, because nothing probed anything —
    an internal audit's third item and the enforcement half of P7. The
    supported-configuration matrix was a table rather than something the product checked.

    **NATIVE TOOL CALLING IS THE HARD REQUIREMENT, and it is a closed decision** (the maintainers' notes: *"the
    solver requires a backend exposing `.chat`. This is enforced in code, not documented as advice"*).
    An endpoint that answers with prose instead of a `tool_calls` structure does not fail loudly at
    the start of a run — it fails as a review that finds nothing, which is indistinguishable from a
    clean repository. That is the whole reason to spend one cheap request before a whole scan.

    Three verdicts, because two would collapse a real distinction:

        validated    the round trip worked AND the model is one this project has measured
        compatible   the round trip worked; the model is not one we have numbers for
        unsupported  no tool call came back, or the request failed

    **`compatible` is not a warning.** the design notes closes "the customer always supplies
    inference", so running an unmeasured model is a supported choice; what the customer is owed is
    knowing which of the two they are in. Deciding that for them by refusing would be operating their
    endpoint policy for them.

    Costs one request — a few hundred tokens. Never raises: a probe that throws is `unsupported` with
    the exception as its reason, because every failure here has the same answer for the customer.
    """
    observed: dict = {"tool_calls": 0, "model": "", "error": ""}
    try:
        result = backend.chat(
            [{"role": "user", "content": "Call shard_probe with any note to confirm this endpoint "
                                         "supports native tool calling."}],
            PROBE_TOOL, model=model, timeout=timeout, tool_choice="auto")
    except Exception as e:                                              # noqa: BLE001
        # BROAD: a connection refused, a 404 on a base URL missing /v1, an auth failure and a provider
        # returning HTML all mean the same thing to the customer — this endpoint will not run a scan.
        return {"verdict": UNSUPPORTED, "why": f"the request failed ({e.__class__.__name__}: {e})",
                "observed": observed | {"error": str(e)[:200]}}

    observed["model"] = getattr(result, "model", "") or ""
    observed["tool_calls"] = len(getattr(result, "tool_calls", ()) or ())
    if not getattr(result, "ok", False):
        return {"verdict": UNSUPPORTED,
                "why": f"the endpoint answered with an error: {getattr(result, 'error', '')[:200]}",
                "observed": observed}
    if not observed["tool_calls"]:
        return {"verdict": UNSUPPORTED,
                "why": "the endpoint answered without a tool call, so it does not support native "
                       "tool calling. Shard's solver requires it — a review here would find nothing "
                       "and look like a clean repository.",
                "observed": observed}

    # `validated_model` is PASSED IN rather than imported. `DEFAULT_MODEL` lives in `shard/cli.py`
    # and this module sits below it; reaching upward for it would invert the layering to save one
    # argument, and which model this project has measured is a fact the CLI already owns.
    measured = (observed["model"] or model or "").split("/")[-1] or "the endpoint's default"
    if validated_model and measured.startswith(validated_model.split("/")[-1]):
        return {"verdict": VALIDATED,
                "why": f"native tool calling works and {measured} is the configuration this project "
                       f"has measured", "observed": observed}
    return {"verdict": COMPATIBLE,
            "why": f"native tool calling works. {measured} is not a model this project has numbers "
                   f"for, which is a supported choice and not a warning — you supply the inference.",
            "observed": observed}
