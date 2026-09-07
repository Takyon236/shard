"""LLM backend — single-shot completions (NOT an internal tool loop).

Shard owns the ReAct loop itself: the model proposes ONE action as JSON,
Shard's policy gates it and Shard executes it. That is deliberate — if we let ``claude -p``
run its own tool loop, Shard's human-gate would never see the individual tool calls. So this
backend is a stateless `complete(system, user) -> text`; the loop re-sends the running
transcript each turn.

Backends, all stdlib-only:
  ``ClaudeCliBackend``   — the ``claude`` CLI in `-p` mode (subscription, $0). Default for the
                           ReAct loop.
  ``OpenRouterBackend``  — the one the benchmark solver actually runs on (GLM-5.2 via Z.AI); it
                           also implements ``ToolCallingBackend`` for the native loop.
  ``EchoBackend`` / ``ScriptedChatBackend`` — the deterministic test doubles. Use these in tests.

That list is exactly what this file defines. A backend whose class the build removes is described in
its own docstring instead, so the description leaves with the code rather than outliving it.
"""

from __future__ import annotations

import json
import math
import os
import re
import subprocess
import threading
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, Protocol

from shard.diag import get_logger

_log = get_logger(__name__)


@dataclass(frozen=True)
class _ProviderUsage:
    input_tokens: int
    output_tokens: int
    cached_tokens: int
    total_tokens: int
    cost_usd: float
    cache_write_tokens: int
    unpriced: int
    reported: bool
    tokens_reported: bool


class _UsageIntegrityError(ValueError):
    """A streamed usage record contradicted another record in the same response."""


class _StreamIntegrityError(ValueError):
    """A streamed response crossed a bound or contradicted its own identity."""


class _WallTimerStartError(RuntimeError):
    """The deadline watchdog could not start, so no unbounded operation may begin."""


# Internal parser state, deliberately outside the HTTP status space. A provider may legitimately
# answer 422 when it rejects `tool_choice`; conflating that response with our integrity rejection
# suppressed the known-unbilled attempt and disabled the loop's established unforced fallback.
_USAGE_INTEGRITY_CODE = -1
_STREAM_INTEGRITY_CODE = -2
_TURN_CEILING_CODE = -3
_PRE_WIRE_TRANSIENT_CODE = -4
_POST_WIRE_TIMEOUT_CODE = -5
_POST_WIRE_TRANSPORT_CODE = -6
_MALFORMED_STREAM_CODE = -7
_PRE_WIRE_CONFIG_CODE = -8
_PRE_WIRE_TIMEOUT_CODE = -9
_PRE_WIRE_CODES = (_PRE_WIRE_TRANSIENT_CODE, _PRE_WIRE_CONFIG_CODE, _PRE_WIRE_TIMEOUT_CODE)
_NO_ABANDON_CODES = (_TURN_CEILING_CODE, *_PRE_WIRE_CODES)
_TOOL_CHOICE_REJECTION_CODES = frozenset({400, 404, 422})

# `getaddrinfo` has no cancellable timeout. A timed-out daemon may therefore remain inside libc,
# but it may not make thread growth unbounded: the fixed admission stays occupied until that daemon
# really exits. Calls beyond the measured concurrency ceiling fail before starting another thread.
_MAX_DNS_THREADS = 4
_DNS_THREAD_SLOTS = threading.BoundedSemaphore(_MAX_DNS_THREADS)


def _tool_choice_rejection(code: int, error: str, tool_choice) -> bool:
    """Whether one HTTP error explicitly rejected the forced-choice field itself."""
    if tool_choice is None or code not in _TOOL_CHOICE_REJECTION_CODES:
        return False
    prefix = f"http {code}: "
    if not error.casefold().startswith(prefix):
        return False
    detail = error[len(prefix):].strip()
    try:
        document = json.loads(detail)
    except (json.JSONDecodeError, RecursionError, ValueError):
        pass
    else:
        provider_error = document.get("error") if isinstance(document, dict) else None
        if isinstance(provider_error, dict) and isinstance(provider_error.get("message"), str):
            detail = provider_error["message"]
        elif isinstance(provider_error, str):
            detail = provider_error
    normalized = re.sub(r"[_-]+", " ", detail.casefold()).strip()
    normalized = normalized.removesuffix(".")
    patterns = (
        r"(?:the )?(?:provided )?tool choice(?: parameter| field)?(?: [:=] \S+)? "
        r"(?:is |was )?(?:not supported|unsupported|invalid|not allowed|rejected)",
        r"(?:invalid|unsupported|unrecognized) (?:value for )?(?:the )?(?:provided )?"
        r"tool choice(?: parameter| field)?",
        r"no endpoints? (?:were )?(?:found (?:that )?)?supports? (?:the )?(?:provided )?"
        r"tool choice",
    )
    return any(re.fullmatch(pattern, normalized) for pattern in patterns)


def _usage_integer(value, field_name: str) -> int:
    """Accept only JSON numbers whose value is a finite, nonnegative integer."""
    if value is None:
        return 0
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{field_name} is not an integer")
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError(f"{field_name} is not finite")
    integer = int(value)
    if value < 0 or value != integer:
        raise ValueError(f"{field_name} is negative or fractional")
    return integer


def _optional_usage_integer(usage: dict, field_name: str) -> tuple[bool, int]:
    """Whether a token field was present, and its validated integer value."""
    value = usage.get(field_name)
    return (False, 0) if value is None else (True, _usage_integer(value, field_name))


def _provider_usage(usage) -> _ProviderUsage:
    """Validate one provider usage record atomically before any counter can be changed."""
    if usage is None:
        usage = {}
    if not isinstance(usage, dict):
        raise ValueError("usage is not an object")
    details = usage.get("prompt_tokens_details")
    if details is None:
        details = {}
    if not isinstance(details, dict):
        raise ValueError("prompt_tokens_details is not an object")
    raw_cost = usage.get("cost")
    if isinstance(raw_cost, bool) or (raw_cost is not None and not isinstance(raw_cost, (int, float))):
        raise ValueError("cost is not a number")
    try:
        cost = float(raw_cost or 0.0)
    except OverflowError as e:
        raise ValueError("cost is not finite") from e
    if not math.isfinite(cost) or cost < 0:
        raise ValueError("cost is non-finite or negative")
    input_reported, input_tokens = _optional_usage_integer(usage, "prompt_tokens")
    output_reported, output_tokens = _optional_usage_integer(usage, "completion_tokens")
    total_reported, total_tokens = _optional_usage_integer(usage, "total_tokens")
    if not total_reported and input_reported and output_reported:
        total_tokens = input_tokens + output_tokens
        total_reported = True
    if total_reported and total_tokens < input_tokens + output_tokens:
        raise ValueError(
            f"total_tokens {total_tokens} is less than prompt_tokens + completion_tokens "
            f"({input_tokens + output_tokens})")
    return _ProviderUsage(
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        cached_tokens=_usage_integer(details.get("cached_tokens"), "cached_tokens"),
        total_tokens=total_tokens,
        cost_usd=cost,
        cache_write_tokens=_usage_integer(details.get("cache_write_tokens"), "cache_write_tokens"),
        unpriced=int(raw_cost is None),
        reported=bool(usage),
        tokens_reported=total_reported,
    )


def _provider_result_fields(usage: _ProviderUsage, served: str,
                            identity_verdict: str) -> dict:
    """Fields shared by completion and chat results for one provider response."""
    return {
        "cost_usd": usage.cost_usd,
        "tokens": usage.total_tokens,
        "unpriced_attempts": usage.unpriced,
        "served_model": served,
        "identity_verdict": identity_verdict,
        "tokens_reported": usage.tokens_reported,
        "cost_reported": not usage.unpriced,
    }


def _combined_reported(flags: list[bool | None]) -> bool | None:
    """False if any attempt was unmeasured, true only when every attempt was measured."""
    if any(flag is False for flag in flags):
        return False
    return True if flags and all(flag is True for flag in flags) else None

if TYPE_CHECKING:
    from collections.abc import Mapping

# Shard model tiers → `claude -p --model` aliases. Opus 4.8 for the top reasoner / final
# judge; Sonnet for workers; Haiku for cheap mechanical sub-steps. (Matches the cost-tiering
# the human session used: Opus localizer, cheaper audit sub-agents.)
MODEL_TIERS = {"reasoner": "opus", "worker": "sonnet", "cheap": "haiku"}

# Default tier → concrete Anthropic model id for the multi-provider backend (the CLI backend
# resolves these aliases itself); that backend takes `model_map=` to override it per provider.
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
    # the maintainers' notes' first sentence rather than a preference. Pinned to the canonical slug on purpose:
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


def _is_openrouter_endpoint(url: str) -> bool:
    """Whether a resolved chat-completions URL is OpenRouter's own — the guard on the table above.

    HOST EQUALITY, NOT A SUBSTRING. `https://openrouter.ai.vllm.internal/v1` and any path carrying the
    string are somebody else's server, and what turns on this answer is whether a customer's declared
    model identifier is rewritten to a slug only OpenRouter resolves.
    """
    try:
        host = (urllib.parse.urlsplit(url).hostname or "").lower()
    except (TypeError, ValueError):
        # Endpoint validation belongs to the request result, where callers receive a controlled
        # configuration failure. Alias selection must not make construction itself the uncaught path.
        return False
    return host == "openrouter.ai" or host.endswith(".openrouter.ai")


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
#:
#: **TEN STRINGS REACH THIS TABLE AND ONE OF THEM CARRIES AN HTTP CODE.** Read that before reading the
#: order argument below, which was measured on the one and written as though it were the population.
#: `_post` returns six error strings — `http {code}: {body}` from `HTTPError`, `idle/stall timeout
#: after {n}s: …` twice (a `TimeoutError` and a `URLError` whose reason is one), `{ExcName}: {e}` twice
#: (a `URLError` that is not a timeout, and any other `OSError`), and `malformed stream: {ExcName}:
#: {e}` — of which only the first has a status line. `_chat_once` adds `model refused the prompt
#: (finish=…)` and `empty response: {str(data)[:200]}`; `chat` adds `no OPENROUTER_API_KEY` and
#: `no attempt`; an eleventh shape appends `(turn ceiling …s reached after N attempt(s))` to whichever
#: of the ten the ladder ended on. This header said the code-less cases were two, and a comment that
#: under-counts the ways into a table sends the next reader to the wrong branch.
#:
#: The nine code-less shapes are also where the customer-supplied endpoint fails. An unreachable vLLM,
#: a base URL that does not resolve and a cert the runner will not accept all arrive as
#: `{ExcName}: {e}`; a stream cut mid-response arrives as `malformed stream: {ExcName}: {e}`. All four
#: classify as `""`, so `shard-result.json` carries `"error_kind": ""` and the report names no cause.
#: **That is unclosed and it needs a KIND this table does not have** — `upstream` says "returned a
#: server error", which is false of a socket that was never accepted — so it is a row in
#: `report.TRANSPORT_ERROR_ADVICE` first and a pattern here second.
#:
#: **`upstream` IS FIRST, AND IT WAS LAST UNTIL 2026-09-02. ORDER, NOT ANCHORING, AND THE MEASUREMENT
#: SETTLED IT IN BOTH POPULATIONS.** The table has 6 entries, 24 top-level alternatives and 27 branches
#: once the inner `(?:…)` groups are expanded. Over all three forms of every branch (`x<phrase>`,
#: `<phrase>x`, and the phrase alone), 2026-09-02:
#:
#:     variant                                5xx bodies wrong   mid-token eats   real matches lost
#:     upstream FIRST, one anchor (shipped)          0 of 78            50                0
#:     upstream LAST,  one anchor                   76 of 78            50                0
#:     upstream LAST,  anchor EVERY branch          27 of 78             1                1
#:     upstream FIRST, anchor EVERY branch           0 of 78             1                1
#:
#: Column 1 is the population WITH a status line, and order takes it to zero while anchoring every
#: branch leaves 27 — because those 27 are the bare phrase with nothing glued on, which no boundary can
#: reach. `billing` inside a 500 body is a perfectly word-bounded match, and it outranked the row that
#: is certainly right purely because that row sat at the bottom of the table.
#:
#: Column 2 is the population WITHOUT one, where order is inert by construction: there is no status
#: line to outrank anything. Anchoring is the only instrument there, and the 50 it closes are
#: CONSTRUCTED strings, not observed ones. What that population actually produces was enumerated
#: instead of imagined — `os.strerror` over the 130 errno values this platform defines, in each of the
#: three shapes `_post` builds, is 390 strings, and after `permission denied` was deleted from `auth`
#: exactly **0 of 390** classify. Column 3 is the price: a right `\b` stops `rate[_ ]?limit` matching
#: `rate_limits` and a left one stops `userRateLimitExceeded`, which is a real phrasing.
#:
#: So the order stays and nothing further is anchored. The one anchor on `model` stays because it is
#: the only branch whose match can BEGIN mid-token (`\w*` after the literal) and it has an observed
#: string: `remodelling pipeline does not exist`, with no HTTP code, where order cannot help.
#:
#: **WHY A 5xx OUTRANKS EVERY PHRASE.** `_post` builds that string as `http {code}: {body}`, so its
#: status line is the one fact about the exchange rather than a word inside it. Every customer-fixable
#: kind arrives under its own code — 402, 401/403, 429, 400/404 — so a 5xx is the provider failing
#: after accepting the request, and the body is theirs to explain. None of the other nine shapes
#: contains an `http 5xx`, so the move changed nothing about them.
#:
#: **NEITHER POPULATION ABOVE IS OBSERVED, AND THAT IS THE FIRST THING TO KNOW BEFORE RE-OPENING
#: THIS.** The order was challenged on 2026-09-03 with a second constructed set — `http 500:
#: insufficient_quota`, `http 503: rate limit exceeded`, `http 500: billing issue` — which reads
#: `upstream` and would have read `credit`/`rate` with the row last. Both sets are written by the
#: person making the argument. Searched for a real one: **zero** strings matching `http 5\d\d: ` exist
#: anywhere in this tree or in the predecessor repository outside test fixtures and this comment,
#: across every `.md`, `.py`, `.json`, `.jsonl`, `.log` and `.txt` — this product has never recorded a
#: 5xx body from a real provider. So there is no measurement that decides it, and the tie-break is the
#: table's OWN policy, already written two rows down for `http 400`: when the string admits two
#: readings, prefer the answer that claims nothing over the actionable one that may be wrong.
#: `upstream` sends nobody to change a setting; `credit` on a genuine outage sends a customer to top
#: up an account that is fine. **Do not re-open this without a real 5xx body**; the disagreement it
#: settles is between two sets of invented strings, and a third set will not settle it either.
TRANSPORT_ERROR_KINDS: tuple[tuple[str, "re.Pattern[str]"], ...] = (
    # ONE ALTERNATIVE, not two. `http 5[02][0-9]\b` sat beside `http 5\d\d` and was unreachable:
    # enumerated all 100 `http 5XY` strings 2026-09-02, and the set the second matches and the first
    # does not is empty. A dead alternative in an ordered table reads as a deliberate narrowing.
    #
    # `\A`, ADDED 2026-09-03, AND IT IS WHAT THE ROW'S OWN ARGUMENT ALWAYS SAID. The header below
    # justifies first place with "its STATUS LINE is the one fact about the exchange rather than a
    # word inside it" — and then matched `http 5\d\d` anywhere in the string, so a 5xx quoted INSIDE
    # somebody else's body outranked the real status. `_post` builds `f"http {e.code}: {body}"` and
    # is the only shape carrying a code, so the status line is at offset 0 and nowhere else; the
    # eleventh shape APPENDS a turn-ceiling clause and cannot move it. Measured over five bodies whose
    # status is 402/403/404/429 and whose body quotes a 5xx (a gateway echoing what its pool returned,
    # which is how a provider explains a rate limit): 5 of 5 read `upstream` unanchored, 0 of 5
    # anchored. The 78-string population the order was settled on is unmoved at 0 wrong, and none of
    # the twelve pinned classifications changes — this anchor costs nothing measured, which is what
    # distinguishes it from the per-branch anchoring the table below still refuses.
    ("upstream", re.compile(r"\Ahttp 5\d\d", re.I)),
    # 402 is OpenRouter's insufficient-credit code, and the word appears in several providers' bodies.
    # Tried BEFORE `auth` because some gateways answer a spent account with 401 and say why in the body.
    ("credit", re.compile(r"http 402|insufficient[_ ]?(?:credit|quota|balance|funds)"
                          r"|exceeded your current quota|billing", re.I)),
    # THE ONE THAT MOTIVATED THIS TABLE. 401/403, a missing key, and the provider phrasings that carry
    # no code — "User not found" is what a revoked OpenRouter key returns.
    #
    # `permission denied` WAS AN ALTERNATIVE HERE AND WAS DELETED 2026-09-02, because it was the only
    # one in the table that OUR OWN failure could satisfy. `_post`'s two 503 arms stringify a local
    # exception into the field a provider body goes into, so `PermissionError: [Errno 13] Permission
    # denied` — a socket the runner's egress policy refused — classified as `auth` and sent that
    # customer to check their API key. Swept the whole space rather than patching the one string:
    # `os.strerror` over the 130 errno values this platform defines, in each of the three shapes
    # `_post` builds, is 390 strings and EACCES was the only one that classified at all. The deletion
    # costs nothing measured — every provider that says it says it under a 403, which `http 40[13]\b`
    # already carries, and Vertex's own spelling is `PERMISSION_DENIED`, which this alternative never
    # matched.
    ("auth", re.compile(r"http 40[13]\b|no [A-Z_]*API_KEY|no api_key for provider"
                        r"|user not found|invalid[_ ]api[_ ]key|authentication|unauthorized", re.I)),
    ("rate", re.compile(r"http 429|rate[_ ]?limit|too many requests", re.I)),
    # A model the endpoint will not serve, and OpenRouter's phrasing for a routing dead end. This is a
    # configuration error every bit as fixable as a dead key, and it also ended runs as a bare `error`.
    #
    # THE LAST ALTERNATIVE IS THERE BECAUSE THIS TABLE ONLY KNEW THE 404. A refused model does not
    # always come back as one: measured 2026-09-02, Z.ai's coding endpoint answers `http 400:
    # {"error":{"code":"1214","message":"modelCode: does not exist"}}` and a stock OpenAI-compatible
    # server answers ``The model `x` does not exist``. Nothing here matched either, so
    # `classify_transport_error` returned "", `report.TRANSPORT_ERROR_ADVICE` selected no row, and the
    # customer's `shard-result.json` carried `"error_kind": ""` with the provider's own sentence
    # surviving only in the journal — which `cliemit.py` documents as un-forwardable because it holds
    # excerpts of their source. `http 400` ALONE IS DELIBERATELY NOT MATCHED: a 400 is equally a
    # context overflow or a malformed tool schema, and telling that customer to check their model name
    # would be a confident wrong answer. The phrase carries the match, not the code.
    #
    # `\b` ON THAT ALTERNATIVE, and it is the only anchor in the table. It matches from `model` into
    # `\w*`, so without a left boundary it starts inside a longer token: `remodelling pipeline does not
    # exist` classified as `model`. Order does not reach that string — it carries no HTTP code — which
    # is what distinguishes this branch from the other 26 and why the anchor stays here and nowhere
    # else. See the table's own header for the both-direction measurement that settled the rest.
    #
    # `unknown model` HAS NO RIGHT BOUNDARY AND IS NOT GETTING ONE — a declared limit, not an oversight.
    # `unknown modelling error` under a 5xx reads `upstream` because order reaches it; with no status
    # line it reads `model`. The only shape that can deliver such a string is `empty response:
    # {str(data)[:200]}`, which carries the provider's own object, and a right `\b` there would cost
    # `unknown models` in a batch error. Neither side is measured, so the cheaper wrong answer stays.
    ("model", re.compile(r"http 404|no endpoint|model[_ ]not[_ ]found|is not a valid model"
                         r"|unknown model|\bmodel\w*\b[^\n]{0,40}?does not exist", re.I)),
    # Ours, from `_post`: an idle gap or the absolute-ceiling backstop, after the retry ladder gave up.
    ("stall", re.compile(r"idle/stall timeout|throughput|min_tps", re.I)),
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
    abandoned_attempts: int = 0  # attempts inside THIS completion whose stream ended before `usage`.
                             # The provider served them, but their token count and price are unknowable.
    unpriced_attempts: int = 0  # completed attempts whose response omitted `usage.cost`. A real 0.0
                             # price is not unpriced; presence, not truthiness, decides this count.
    served_model: str = ""     # what the response said answered; `model` remains the requested id
    identity_verdict: str = "" # matched / missing / substituted / conflicting for provider responses
    tokens_reported: bool | None = None  # None = backend exposes no completeness metadata
    cost_reported: bool | None = None


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


def _parsed_tool_calls(message: dict) -> tuple[list[ToolCall], str]:
    """Parse a complete native-call batch atomically, returning its stable error when malformed."""
    calls = []
    call_ids = set()
    for raw in (message.get("tool_calls") or []):
        if not isinstance(raw, dict):
            raise _StreamIntegrityError("tool call is not an object")
        call_type = raw.get("type", "function")
        if call_type != "function":
            raise _StreamIntegrityError(f"tool call carried unsupported type {call_type!r}")
        call_id = raw.get("id")
        if not isinstance(call_id, str) or not call_id:
            raise _StreamIntegrityError("tool call has no nonempty id")
        if call_id in call_ids:
            raise _StreamIntegrityError(f"tool call id {call_id!r} is duplicated")
        call_ids.add(call_id)
        function = raw.get("function") or {}
        try:
            arguments = json.loads(function.get("arguments") or "{}")
        except RecursionError as e:
            raise _StreamIntegrityError(
                "tool-call arguments exceeded the JSON nesting limit") from e
        except json.JSONDecodeError:
            return [], "malformed tool-call arguments"
        except ValueError as e:
            raise _StreamIntegrityError(
                f"tool-call arguments exceeded the JSON value limit: {e}") from e
        except TypeError:
            return [], "malformed tool-call arguments"
        if not isinstance(arguments, dict):
            return [], "tool-call arguments were not an object"
        calls.append(ToolCall(id=call_id, name=function.get("name") or "", arguments=arguments))
    return calls, ""


@dataclass
class ChatResult:
    text: str = ""                                   # assistant content (often empty when calling tools)
    tool_calls: list = field(default_factory=list)   # list[ToolCall]
    raw_message: dict = field(default_factory=dict)  # the assistant message, appended verbatim to history
    ok: bool = True
    error: str = ""
    tokens: int = 0
    model: str = ""          # what we ASKED for, after alias resolution. Never what answered.
    #: What the RESPONSE BODY said answered, or `""` when the provider named nothing.
    #:
    #: **A ROUTE MAY SERVE A DIFFERENT MODEL AND SAY SO IN THE FIELD WE WERE THROWING AWAY.** Measured
    #: on the wire against `api/coding/paas/v4`, 2026-09-03: `glm-5.2` is served `glm-5.3` and
    #: `glm-4.5-air` is served `glm-5.3-flash`, both under HTTP 200. Every artefact this product writes
    #: named the requested identifier — `probe_endpoint` stamped `validated … the configuration this
    #: project has measured` on a run of a model this project has no numbers for — because `model` was
    #: the only field there was and it is an echo of the request.
    #:
    #: Carried on both result types because discovery/remedy still use `.complete`; the mandatory
    #: native agent path is not the only provider exchange that can silently substitute weights.
    served_model: str = ""
    finish_reason: str = ""  # provider stop reason (e.g. "length" = cut off at max_tokens). Lets the
                             # native loop tell a reasoning turn TRUNCATED before it emitted its tool call
                             # from a genuine no-tools finish. Empty for backends that don't report it.
    cost_usd: float = 0.0    # what the PROVIDER says this one request cost, in dollars. Rides beside
                             # `tokens` for exactly one reason: `agentloop._meter` spends both against
                             # the governor, and a dollar ceiling nothing debits is decorative — which
                             # is what `--max-spend-usd` was on every run before 2026-08-08. 0.0 from a
                             # backend that does not price its responses; see `_accumulate_usage` on why
                             # "priced 0.0" and "not priced" must not be reported as the same number.
                             #
                             # SINCE 2026-08-24 THIS IS THE COST OF THE TURN, not of the last attempt
                             # in it — see `chat`, which folds the attempts it threw away back in.
    abandoned_attempts: int = 0  # attempts inside THIS turn whose bill we could not see at all: the
                             # stream was aborted before any `usage` arrived. The provider still
                             # generated tokens and still charges for them, so this is the part of the
                             # turn's real cost that `cost_usd` above is KNOWN not to include.
    unpriced_attempts: int = 0
    identity_verdict: str = "" # matched / missing / substituted / conflicting for provider responses
    tokens_reported: bool | None = None
    cost_reported: bool | None = None
    # Opt-in proof that THIS failure explicitly rejected the forced choice itself. A generic backend
    # error, credential failure or policy refusal must never buy an unrelated second request.
    forcing_retry_safe: bool = False
    # Opt-in proof that THIS failure was a structurally empty successful provider response. Error
    # prose is untrusted: a terminal 400 saying "messages must not be empty" must not buy another turn.
    empty_retry_safe: bool = False
    # Opt-in proof that THIS failure was a timeout raised by our transport. Provider response bodies
    # can quote every stall phrase this client emits, so their text carries no retry authority.
    stall_retry_safe: bool = False


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
        also drives a multi-provider client. A child spawned with the inherited
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


class _RejectRedirects(urllib.request.HTTPRedirectHandler):
    """Turn every redirect into the original HTTP error instead of issuing a second request.

    The request carries a customer-supplied bearer credential. urllib's default redirect handler
    copies ordinary headers onto the redirected request, including ``Authorization``; a provider (or
    a compromised proxy in front of it) could therefore send that credential to a different origin.
    There is no useful redirect in this API contract: the customer configures the final endpoint and
    an HTTP redirect is configuration drift that must be reported rather than followed.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: PLR0913
        return None


def _owned_http_connection(owner):
    """Build the request-private HTTP connection class used by urllib's handler."""
    import http.client

    class OwnedHTTPConnection(http.client.HTTPConnection):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._shard_ready = False
            self._create_connection = lambda address, timeout, source_address: (  # noqa: SLF001
                _owned_create_connection(owner, address, timeout, source_address))
            owner.own(self)

        def connect(self):
            owner.require_open()
            super().connect()
            owner.require_open()
            self._shard_ready = True

        def send(self, data):
            if self.sock is None and self.auto_open:
                self.connect()
            if self.sock is not None and self._shard_ready:
                owner.require_open()
                owner.mark_sent()
            return super().send(data)

    return OwnedHTTPConnection


def _owned_https_connection(owner):
    """Build the request-private HTTPS connection class used by urllib's handler."""
    import http.client

    class OwnedHTTPSConnection(http.client.HTTPSConnection):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._shard_ready = False
            self._create_connection = lambda address, timeout, source_address: (  # noqa: SLF001
                _owned_create_connection(owner, address, timeout, source_address))
            owner.own(self)

        def connect(self):
            owner.require_open()
            super().connect()
            owner.require_open()
            self._shard_ready = True

        def send(self, data):
            if self.sock is None and self.auto_open:
                self.connect()
            if self.sock is not None and self._shard_ready:
                owner.require_open()
                owner.mark_sent()
            return super().send(data)

    return OwnedHTTPSConnection


def _open_stream(req, timeout: float):
    """Open one model stream without redirects and expose its connection to the wall owner.

    ``OpenerDirector.open`` does not return until ``HTTPResponse.begin`` has parsed the complete
    status and header block. A socket timeout bounds one idle ``recv``, not that whole operation, so
    a peer can otherwise drip an unterminated header forever before the response-level watchdog has
    anything it can close. The request-private owner is registered with the connection immediately
    after construction, before ``request`` or ``getresponse`` can block.
    """
    owner = getattr(req, "_shard_wall_owner", None)
    if owner is None:
        return urllib.request.build_opener(_RejectRedirects()).open(req, timeout=timeout)
    http_connection = _owned_http_connection(owner)
    https_connection = _owned_https_connection(owner)

    class _OwnedHTTPHandler(urllib.request.HTTPHandler):
        def http_open(self, request):
            return self.do_open(http_connection, request)

    class _OwnedHTTPSHandler(urllib.request.HTTPSHandler):
        def https_open(self, request):
            return self.do_open(https_connection, request, context=self._context)

    return urllib.request.build_opener(
        _RejectRedirects(), _OwnedHTTPHandler(), _OwnedHTTPSHandler()).open(req, timeout=timeout)


def _response_socket(response):
    """Find urllib's socket through both HTTPResponse and HTTPError wrapper shapes."""
    current = response
    seen = set()
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        raw = getattr(current, "raw", None)
        sock = (getattr(raw, "_sock", None) or getattr(current, "_sock", None)
                or getattr(current, "sock", None))
        if sock is not None:
            return sock
        current = getattr(current, "fp", None)
    return None


class _WallResponseOwner:
    """Close a connection during status/header acquisition or its later response stream."""

    def __init__(self, remaining: float, message: str) -> None:
        self._lock = threading.Lock()
        self._targets = []
        self._closed = False
        self._sent = False
        self._wake = threading.Event()
        self._deadline = time.monotonic() + remaining
        self._message = message

    @staticmethod
    def _close(target) -> None:
        import socket

        sock = _response_socket(target)
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        close = getattr(target, "close", None)
        if callable(close):
            try:
                close()
            except OSError:
                pass

    def own(self, target):
        """Register an object the timer may close; reject objects arriving after expiry."""
        if time.monotonic() >= self._deadline:
            self.close()
        with self._lock:
            closed = self._closed
            if not closed:
                self._targets.append(target)
        if closed:
            self._close(target)
            raise TimeoutError(self._message)
        return target

    def require_open(self) -> float:
        """Return real wall time left, or stop work before it can open or write a socket."""
        remaining = self._deadline - time.monotonic()
        with self._lock:
            closed = self._closed
        if closed or remaining <= 0:
            self.close()
            raise TimeoutError(self._message)
        return remaining

    def timeout(self) -> TimeoutError:
        return TimeoutError(self._message)

    def mark_sent(self) -> None:
        """Record that model-request bytes are about to leave an established connection."""
        with self._lock:
            if self._closed:
                raise TimeoutError(self._message)
            self._sent = True

    @property
    def sent(self) -> bool:
        with self._lock:
            return self._sent

    def wake(self) -> None:
        self._wake.set()

    def wait(self) -> None:
        self._wake.wait(self.require_open())
        self.require_open()

    def close(self) -> None:
        with self._lock:
            self._closed = True
            targets = tuple(reversed(self._targets))
            self._targets.clear()
        self._wake.set()
        for target in targets:
            self._close(target)


def _owned_getaddrinfo(owner, address):
    """Resolve within fixed global admission and give a late result no socket authority."""
    import queue
    import socket

    if not _DNS_THREAD_SLOTS.acquire(timeout=owner.require_open()):
        raise owner.timeout()
    resolved = queue.Queue(maxsize=1)

    def resolve() -> None:
        try:
            try:
                answer = socket.getaddrinfo(address[0], address[1], 0, socket.SOCK_STREAM)
            except OSError as error:
                answer = error
            try:
                resolved.put_nowait(answer)
            except queue.Full:
                pass
        finally:
            _DNS_THREAD_SLOTS.release()
            owner.wake()

    thread = threading.Thread(target=resolve, name="shard-model-dns", daemon=True)
    try:
        thread.start()
    except (OSError, RuntimeError) as error:
        _DNS_THREAD_SLOTS.release()
        raise OSError(f"could not start bounded model DNS resolver: {error}") from error
    try:
        owner.wait()
        answer = resolved.get_nowait()
    except queue.Empty as error:  # only a close/resolve race can wake without one result
        raise owner.timeout() from error
    if isinstance(answer, OSError):
        raise answer
    return answer


def _owned_create_connection(owner, address, timeout, source_address=None):
    """Connect within the response owner's wall deadline.

    ``socket.getaddrinfo`` has no cancellable timeout. Resolve on one daemon whose only authority is
    to return addresses; if the deadline wins, the caller returns without creating a socket and the
    late resolver result cannot send the request. Every created socket is owned before ``connect``.
    """
    import socket

    failures = []
    for family, socktype, proto, _canonname, socket_address in _owned_getaddrinfo(owner, address):
        owner.require_open()
        sock = None
        try:
            sock = owner.own(socket.socket(family, socktype, proto))
            connect_timeout = owner.require_open()
            if timeout is not None and timeout is not socket._GLOBAL_DEFAULT_TIMEOUT:
                connect_timeout = min(connect_timeout, float(timeout))
            sock.settimeout(connect_timeout)
            if source_address:
                sock.bind(source_address)
            sock.connect(socket_address)
            owner.require_open()
            return sock
        except OSError as error:
            failures.append(error)
            if sock is not None:
                sock.close()
    if not failures:
        raise OSError("getaddrinfo returned no stream addresses")
    raise failures[-1]


def _call_before_wall_deadline(response, remaining: float, operation, message: str):
    """Run one blocking response operation while an independent wall timer owns its socket.

    A socket timeout is an idle timeout, not a wall deadline: a peer can send one byte just before
    each recv expires and keep ``BufferedReader.readline`` inside one unterminated line forever.  The
    timer shuts the socket down from another thread, so the caller regains control even when no line
    has returned for the ordinary monotonic check to observe.
    """
    import socket

    if remaining <= 0:
        raise TimeoutError(message)
    expired = threading.Event()

    def abort() -> None:
        expired.set()
        sock = _response_socket(response)
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        close = getattr(response, "close", None)
        if callable(close):
            try:
                close()
            except OSError:
                pass

    timer = threading.Timer(remaining, abort)
    timer.daemon = True
    try:
        timer.start()
    except RuntimeError as e:
        raise _WallTimerStartError(f"could not start model wall timer: {e}") from e
    try:
        result = operation()
    except BaseException as e:
        if expired.is_set():
            raise TimeoutError(message) from e
        raise
    finally:
        timer.cancel()
    if expired.is_set():
        raise TimeoutError(message)
    return result


def _bounded_sse_lines(resp, max_bytes: int, max_lines: int, before_read=None):
    """Yield a stream without allocating or retaining an unbounded provider response."""
    readline = getattr(resp, "readline", None)
    iterator = None if callable(readline) else iter(resp)
    total = 0
    count = 0
    while True:
        if iterator is None:
            if before_read is not None:
                before_read()
            raw = readline(max_bytes + 1)
            if not raw:
                break
        else:
            try:
                raw = next(iterator)
            except StopIteration:
                break
        count += 1
        if count > max_lines:
            raise _StreamIntegrityError(f"SSE response exceeded {max_lines} lines")
        if isinstance(raw, str):
            total += len(raw.encode("utf-8", "replace"))
        elif isinstance(raw, (bytes, bytearray)):
            total += len(raw)
        else:
            raise TypeError("SSE line is not bytes or text")
        if total > max_bytes:
            raise _StreamIntegrityError(f"SSE response exceeded {max_bytes} bytes")
        yield raw


class _StreamPace:
    """Watchdog for one SSE stream: the ABSOLUTE ceiling always, plus the CLIENT-SIDE PER-STREAM
    THROUGHPUT floor when ``min_tps`` is set. The rate origin is the FIRST OUTPUT TOKEN, NOT the
    connection: TTFT/prefill (which spikes under 12-worker load) is dead-time that must NOT count
    against the streaming rate — else a healthy stream whose first token is merely slow to arrive gets
    false-aborted (it would measure e.g. 20s of window with only ~9s of actual streaming). A token-less
    stall BEFORE the first token is not this guard's job: it's already bounded by idle_timeout (no
    bytes) and the absolute ceiling. Tumbling window: O(1), no per-chunk buffer. Both aborts raise
    ``TimeoutError``, which ``_post`` converts to a retryable post-wire timeout."""

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
            # token). Sub-floor → retryable post-wire timeout (reroute in ~tps_window, not 900s).
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
    usage: object = field(default_factory=dict)
    _validated_usage: _ProviderUsage | None = field(default=None, repr=False)
    _usage_seen: bool = field(default=False, repr=False)
    frags: dict[int, dict] = field(default_factory=dict)   # tool_call index -> {id, name, args:[fragments]}
    out_chars: int = 0
    #: The model the PROVIDER says answered, off the chunks' own `model` field. Every chunk carries it
    #: and this reassembly discarded all of them, which is why no artefact this product writes could
    #: name the weights that produced it — the fact was in the bytes we already parse.
    model: str = ""
    response_id: str = ""
    role: str = ""
    _models: list[str] = field(default_factory=list, repr=False)
    _model_error: str = field(default="", repr=False)
    _choice_index: int | None = field(default=None, repr=False)

    def add(self, chunk: dict) -> None:
        """Fold one parsed chunk in: usage, then the first choice's delta and finish reasons."""
        if not isinstance(chunk, dict):
            raise TypeError("SSE chunk is not an object")
        chunk_response_id = self._add_metadata(chunk)
        choice = self._choice(chunk)
        if choice is None:
            return
        if not chunk_response_id:
            raise _StreamIntegrityError("SSE choice carried no response id")
        delta, finish, native = choice
        if self.finish:
            self._check_after_finish(delta, finish, native)
            return
        self._add_delta(delta)
        if finish:
            self.finish = finish
        if native:
            self.native = native

    def _add_metadata(self, chunk: dict) -> str:
        """Capture usage and the response-wide identities which may not change mid-stream."""
        if chunk.get("usage") is not None:
            try:
                candidate = _provider_usage(chunk["usage"])
            except ValueError as e:
                raise _UsageIntegrityError(str(e)) from e
            if self._usage_seen and candidate != self._validated_usage:
                raise _UsageIntegrityError("conflicting SSE usage records")
            self.usage = chunk["usage"]                    # rides on the final chunk (include_usage)
            self._validated_usage = candidate
            self._usage_seen = True
        named = chunk.get("model")
        if named is not None and not isinstance(named, str):
            self._model_error = "carried a non-string SSE model identity"
        elif named:
            if named not in self._models:
                self._models.append(named)
            if len(self._models) > 1:
                self._model_error = f"named conflicting SSE models: {self._models!r}"
            if not self.model:
                self.model = named
        response_id = chunk.get("id")
        if response_id is not None and not isinstance(response_id, str):
            raise _StreamIntegrityError("SSE response id is not a string")
        if response_id:
            if self.response_id and response_id != self.response_id:
                raise _StreamIntegrityError(
                    f"SSE response id changed from {self.response_id!r} to {response_id!r}")
            self.response_id = response_id
        return response_id or ""

    def _choice(self, chunk: dict) -> tuple[dict, str, str] | None:
        """Return one structurally valid choice, or ``None`` for a usage-only chunk."""
        choices = chunk.get("choices")
        if choices is None:
            choices = []
        if not isinstance(choices, list):
            raise TypeError("SSE choices is not a list")
        if not choices:
            return None
        if len(choices) != 1:
            raise _StreamIntegrityError("SSE chunk carried more than one choice")
        ch = choices[0]
        if not isinstance(ch, dict):
            raise TypeError("SSE choice is not an object")
        index = ch.get("index", 0)
        if isinstance(index, bool) or not isinstance(index, int):
            raise _StreamIntegrityError("SSE choice index is not an integer")
        if self._choice_index is None:
            self._choice_index = index
        elif index != self._choice_index:
            raise _StreamIntegrityError(
                f"SSE choice index changed from {self._choice_index} to {index}")
        delta = ch.get("delta")
        if delta is None:
            delta = {}
        if not isinstance(delta, dict):
            raise TypeError("SSE choice delta is not an object")
        finish = ch.get("finish_reason") or ""
        native = ch.get("native_finish_reason") or ""
        if not isinstance(finish, str) or not isinstance(native, str):
            raise TypeError("SSE finish reason is not a string")
        return delta, finish, native

    def _check_after_finish(self, delta: dict, finish: str, native: str) -> None:
        """A choice may not alter output or terminal fields after it declares completion."""
        if delta:
            raise TypeError("SSE choice carried a nonempty delta after finish_reason")
        if finish and finish != self.finish:
            raise TypeError("SSE choice changed finish_reason after completion")
        if native and native != self.native:
            raise TypeError("SSE choice changed native_finish_reason after completion")

    def _add_delta(self, delta: dict) -> None:
        """Append this delta's text fields and tool-call fragments, counting every output char."""
        role = delta.get("role")
        if role is not None and not isinstance(role, str):
            raise _StreamIntegrityError("SSE delta role is not a string")
        if role:
            if role != "assistant":
                raise _StreamIntegrityError(f"SSE delta carried unsupported role {role!r}")
            if self.role and role != self.role:
                raise _StreamIntegrityError(
                    f"SSE delta role changed from {self.role!r} to {role!r}")
            self.role = role
        if delta.get("content"):
            self.content.append(delta["content"])
            self.out_chars += len(delta["content"])        # feeds the min_tps guard (all output counts)
        if delta.get("reasoning"):
            self.reasoning.append(delta["reasoning"])
            self.out_chars += len(delta["reasoning"])      # GLM streams reasoning heavily — it IS output
        if delta.get("refusal"):
            self.refusal = (self.refusal or "") + delta["refusal"]
            self.out_chars += len(delta["refusal"])
        tool_calls = delta.get("tool_calls")
        if tool_calls is None:
            tool_calls = []
        if not isinstance(tool_calls, list):
            raise TypeError("SSE tool_calls is not a list")
        for tc in tool_calls:
            self._merge_tool_call(tc)

    def _merge_tool_call(self, tc: dict) -> None:
        """One fragment of one tool call, slotted by its stream ``index``: ``id`` and ``name`` land
        once; ``arguments`` fragments concatenate in arrival order."""
        index, slot = self._tool_call_slot(tc)
        fn = tc.get("function")
        if fn is None:
            fn = {}
        if not isinstance(fn, dict):
            raise TypeError("SSE tool-call function is not an object")
        name = fn.get("name")
        if name is not None and not isinstance(name, str):
            raise _StreamIntegrityError("SSE tool-call name is not a string")
        if name:
            if slot["name"] is not None and slot["name"] != name:
                raise _StreamIntegrityError(
                    f"SSE tool-call index {index} changed name from {slot['name']!r} to {name!r}")
            slot["name"] = name
        arguments = fn.get("arguments")
        if arguments is not None and not isinstance(arguments, str):
            raise TypeError("SSE tool-call arguments are not a string")
        if arguments:
            slot["args"].append(arguments)
            self.out_chars += len(arguments)

    def _tool_call_slot(self, tc: dict) -> tuple[int, dict]:
        """Validate and retain the discriminators which identify one fragmented tool call."""
        if not isinstance(tc, dict):
            raise TypeError("SSE tool call is not an object")
        index = tc.get("index", 0)
        if isinstance(index, bool) or not isinstance(index, int):
            raise _StreamIntegrityError("SSE tool-call index is not an integer")
        slot = self.frags.setdefault(index, {"id": None, "type": None, "name": None, "args": []})
        call_id = tc.get("id")
        if call_id is not None and not isinstance(call_id, str):
            raise _StreamIntegrityError("SSE tool-call id is not a string")
        if call_id:
            if slot["id"] is not None and slot["id"] != call_id:
                raise _StreamIntegrityError(
                    f"SSE tool-call index {index} changed id from {slot['id']!r} to {call_id!r}")
            if any(other_index != index and other["id"] == call_id
                   for other_index, other in self.frags.items()):
                raise _StreamIntegrityError(f"SSE tool-call id {call_id!r} is duplicated")
            slot["id"] = call_id
        call_type = tc.get("type")
        if call_type is not None and not isinstance(call_type, str):
            raise _StreamIntegrityError("SSE tool-call type is not a string")
        if call_type is not None:
            if call_type != "function":
                raise _StreamIntegrityError(
                    f"SSE tool-call index {index} carried unsupported type {call_type!r}")
            if slot["type"] is not None and slot["type"] != call_type:
                raise _StreamIntegrityError(
                    f"SSE tool-call index {index} changed type from {slot['type']!r} "
                    f"to {call_type!r}")
            slot["type"] = call_type
        return index, slot

    def _assembled_tool_calls(self) -> list[dict]:
        """Build calls only after their IDs form a complete one-to-one correlation key."""
        calls = []
        call_ids = set()
        for index in sorted(self.frags):
            fragment = self.frags[index]
            call_id = fragment["id"]
            if not call_id:
                raise _StreamIntegrityError(f"SSE tool-call index {index} has no nonempty id")
            if call_id in call_ids:
                raise _StreamIntegrityError(f"SSE tool-call id {call_id!r} is duplicated")
            call_ids.add(call_id)
            calls.append({
                "id": call_id,
                "type": fragment["type"] or "function",
                "function": {"name": fragment["name"] or "",
                             "arguments": "".join(fragment["args"])},
            })
        return calls

    def response(self) -> dict:
        """The finished non-streaming response — exactly the ``{choices: [{message, finish_reason,
        native_finish_reason}], usage}`` shape a non-streaming request would have returned."""
        # Reassemble into the non-streaming message shape _once/_chat_once already consume. role="assistant" is
        # REQUIRED: this message becomes raw_message and is re-sent verbatim in the next turn's history — a provider
        # that strictly validates message roles (SiliconFlow/Kimi: HTTP 400 "Input tag '' ... does not match
        # 'system','user','assistant','tool'"; baidu/GLM under tool_choice=required: 422 "role invalid literal")
        # rejects a role-less assistant message. Omitting it silently broke every multi-turn tool call on those.
        message: dict = {"role": self.role or "assistant", "content": "".join(self.content)}
        if self.reasoning:
            message["reasoning"] = "".join(self.reasoning)
        if self.refusal is not None:
            message["refusal"] = self.refusal
        if self.frags:
            message["tool_calls"] = self._assembled_tool_calls()
        choice: dict = {"message": message, "finish_reason": self.finish}
        if self.native:
            choice["native_finish_reason"] = self.native
        # `model` LAST so the truncated `empty response: {str(data)[:200]}` diagnostic keeps leading
        # with the fields it was written to show. `""` when no chunk named one, which is the same
        # thing a non-streaming response with no `model` key gives the parsers — they read it with
        # `.get`, so an absent key and an empty one are one case and only one of them needs a branch.
        response = {"choices": [choice], "usage": self.usage, "model": self.model}
        if self.response_id:
            response["id"] = self.response_id
        if self._model_error:
            # Keep reading after the conflict so a final, internally consistent usage record can be
            # billed. The parser rejects this marker before it exposes any assembled tool call.
            response["_model_identity_error"] = self._model_error
            response["_model_identities"] = list(self._models)
        return response


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
    wall). A stall/abort is a RETRYABLE local transport result, and on any retry the provider
    routing is RELAXED (a hard pin becomes an order-preference with `allow_fallbacks=True`, quantization floor
    kept) so OpenRouter reroutes off the hung provider — first try keeps the exact fp8 pin, a hang opens the
    whole fp8 pool. The SSE stream is reassembled into the same non-streaming response shape the parsers
    already consume, so the completion/tool-calling/refusal/finish_reason logic is unchanged."""

    ENDPOINT = "https://openrouter.ai/api/v1/chat/completions"
    # Retryable transient HTTP/transport results, shared by complete() and chat() so both paths agree.
    # Positive values are completed HTTP responses. Negative values are local outcomes, separated so a
    # DNS failure cannot be billed as a request and a real HTTP 503 cannot be called an abandoned stream.
    # 520-524 = Cloudflare edge/origin errors (unknown-error / down / timeout / SSL / origin-timeout). Providers
    # fronted by Cloudflare (e.g. Z.AI first-party) emit these under sustained load — they are transient origin
    # blips, NOT terminal. Omitting them aborted whole tasks on a single blip (a 117-step run zeroed by one 520).
    _RETRY_CODES = (429, 500, 502, 503, 504, 520, 521, 522, 523, 524, 598, 599,
                    _PRE_WIRE_TRANSIENT_CODE, _PRE_WIRE_TIMEOUT_CODE, _POST_WIRE_TIMEOUT_CODE,
                    _POST_WIRE_TRANSPORT_CODE, _MALFORMED_STREAM_CODE)

    # Approx chars-per-output-token for the client-side `min_tps` guard. A coarse estimate is fine (the
    # guard only distinguishes a <10 tps drip from a 50+ tps healthy stream), never a billing figure.
    _CHARS_PER_TOK = 4.0

    # 32,768 output tokens are normally about 128 KiB. Four MiB leaves 128 wire bytes per maximum
    # output token, including SSE framing and usage, while refusing the multi-megabyte response a
    # non-conforming endpoint can send despite `max_tokens`. Four lines per possible output token
    # likewise preserves token-at-a-time streaming while bounding keepalive/chunk CPU.
    _MAX_STREAM_BYTES = 4 * 1024 * 1024
    _MAX_STREAM_LINES = 4 * 32768
    _MAX_ERROR_BYTES = 4096

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
        self.endpoint = (base_url.rstrip("/") + "/chat/completions") if base_url else self.ENDPOINT
        # **THE ALIAS TABLE IS OPENROUTER'S, SO IT APPLIES ONLY WHEN THE REQUEST GOES TO OPENROUTER.**
        # It used to be applied on every endpoint, and the shipped default is what that cost. Measured
        # 2026-09-02 against a vLLM-shaped server serving exactly the identifier the customer declared:
        # the wire carried `z-ai/glm-5.2` and the server answered ``http 404: The model `z-ai/glm-5.2`
        # does not exist``. Against Z.ai's coding endpoint the same substitution answers `http 400
        # {"error":{"code":"1214","message":"modelCode: does not exist"}}`. So a customer who copies
        # README's self-hosted workflow — the one it calls the guaranteed EU-residency path, which sets
        # `model_endpoint` and leaves `model` at its default — asks their own server for a model they
        # never named, and the run dies before it reads a file. A default alias table belongs to the
        # endpoint it was measured against, and is empty everywhere else.
        self.model_map = model_map or (DEFAULT_OPENROUTER_MODELS
                                       if _is_openrouter_endpoint(self.endpoint) else {})
        self.max_tokens = max_tokens
        # Cost/efficiency accounting (the benchmark's result schema). One backend instance serves a whole
        # task — the main solver loop AND every sub-agent (verifier/oracle/specialist reuse this backend) —
        # so accumulating here gives an exact per-task total without threading fields through the loop /
        # AgentResult / solve_task. The benchmark harness reads it via usage_summary() after the solve. cached_tokens
        # is OpenRouter's prompt_tokens_details.cached_tokens (0 when the provider does not cache, e.g. GLM).
        self._usage = {"input_tokens": 0, "output_tokens": 0, "cached_tokens": 0,
                       "total_tokens": 0, "llm_requests": 0, "generation_sec": 0.0,
                       "cost_usd": 0.0, "cache_write_tokens": 0,   # B3 — the benchmark's cost schema
                       # How many of those `llm_requests` came back carrying a price at all. `cost_usd`
                       # alone cannot tell "this run really cost $0.00" from "no response priced
                       # anything", and the two must not print as the same sentence to a customer
                       # reconciling a bill against the ceiling they set.
                       "priced_requests": 0,
                       # Token totals can be absent independently of price. This count lets the
                       # customer-facing artefact say when a total is only a floor.
                       "token_reported_requests": 0,
                       # REQUESTS THE PROVIDER SERVED AND WE NEVER SAW THE END OF. A stream aborted by
                       # the idle guard, the throughput floor or the absolute ceiling produced tokens
                       # the provider generated and bills for, and returns a post-wire local outcome — no body,
                       # no `usage`, nothing to accumulate. Counted here rather than left out, because
                       # a ledger that silently omits them reports a run as cheaper than the invoice
                       # will say it was, and the omission grows with exactly the provider trouble a
                       # customer would want to see. These are a subset of `llm_requests`, not an
                       # alternative counter: submission exports `llm_requests` as the request total.
                       "abandoned_requests": 0}
        # The absolute deadline of the turn in flight ON THIS THREAD. See `_turn_ceiling`.
        self._turn = threading.local()
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
        # (the loop passes 600), so the benchmark harness gets the safe value with no caller change.
        self.idle_timeout = idle_timeout
        # ABSOLUTE CEILING — a final backstop measured across the WHOLE stream, so a pathological slow-drip
        # (a byte every 89s, never tripping idle_timeout) still can't run forever. Generous (default 900s,
        # ≫ any legit turn but ≪ the 2h task wall); hitting it aborts as a retryable post-wire stall.
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
        # a retryable local timeout → reroute off the drip in ~tps_window seconds instead
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

    def _accumulate_usage(self, usage: _ProviderUsage, gen_sec: float = 0.0) -> None:
        """Add one response's token usage to the per-task running total (the benchmark's cost schema). Called
        once per completed request (streaming or not); each call = one billed llm_request. Robust to a
        provider that omits fields (they default 0).

        **THE REQUEST AND ITS LOCALLY MEASURED TIME ARE COUNTED EVEN WHEN THE PROVIDER REPORTS NO
        USAGE.** It used to return before either field, so a self-hosted vLLM — which need not emit a
        usage object — made real requests but rendered as "no inference" and erased every measured
        generation second. Provider token and price fields remain conditional; the two facts observed
        by this process do not depend on provider metadata."""
        with self._usage_lock:
            self._usage["llm_requests"] += 1
            self._usage["generation_sec"] += float(gen_sec or 0.0)
            if not usage.reported:
                return
            self._usage["input_tokens"] += usage.input_tokens
            self._usage["output_tokens"] += usage.output_tokens
            self._usage["cached_tokens"] += usage.cached_tokens
            self._usage["total_tokens"] += usage.total_tokens
            # `llm_requests` and `generation_sec` are counted ABOVE — see the docstring.
            # B3 — the two fields the benchmark's cost schema asks for that we were discarding, both of which OpenRouter
            # already returns on every response:
            #   * `cost` is the REAL billed amount. Reporting it beats `est_usd_cost`'s price-times-tokens
            #     estimate, which cannot know the provider's actual rate or discounts.
            #   * `cache_write_tokens` is the schema's `cache_creation_tokens`, which we hardcoded to 0.
            # ⚠ `input_tokens` above stays the RAW prompt_tokens on purpose — it INCLUDES cache reads. The
            # schema wants NON-cached input, and that subtraction belongs in the reporter (make_submission),
            # not here, so this dict keeps meaning exactly what the provider said. Getting that backwards is
            # what made the submission overstate input cost by 6.5x.
            self._usage["cost_usd"] += usage.cost_usd
            self._usage["cache_write_tokens"] += usage.cache_write_tokens
            if usage.tokens_reported:
                self._usage["token_reported_requests"] += 1
            # PRESENCE, not amount: a response that omits `cost` is one this endpoint did not price, and
            # summing it as 0.0 silently understates the run. Counted here so a reporter can say "not
            # priced" instead of "$0.00" — the same class of decorative number as the ceiling that never
            # fired. `is not None` rather than truthiness: a genuine free-tier 0.0 IS a price.
            if not usage.unpriced:
                self._usage["priced_requests"] += 1

    def _data_less_accounting(self, code: int, gen_sec: float) -> tuple[int, int]:
        """Return ``(abandoned, unpriced)`` and book a completed HTTP response exactly once."""
        if code > 0:
            usage = _provider_usage(None)
            self._accumulate_usage(usage, gen_sec)
            return 0, usage.unpriced
        if code in _NO_ABANDON_CODES:
            return 0, 0
        self._record_abandoned(gen_sec)
        return 1, 0

    def _record_abandoned(self, gen_sec: float) -> None:
        """Book one post-wire attempt whose provider usage never became trustworthy."""
        with self._usage_lock:
            self._usage["llm_requests"] += 1
            self._usage["generation_sec"] += float(gen_sec or 0.0)
            self._usage["abandoned_requests"] += 1

    def _account_abandoned(self, result) -> int:
        """Return abandoned attempts already booked where their transport outcome was observed."""
        return int(result.abandoned_attempts or 0)

    def _turn_ceiling(self):
        """A context manager stamping ONE absolute deadline for a whole retry ladder.

        **`absolute_timeout` was a ceiling on an ATTEMPT, and `chat`/`complete` make up to five.** With
        the backoff ladder that is over an hour for a single step, while the run's wall ceiling is only
        ever consulted BETWEEN steps (`agentloop._budget_stop`) — so `--max-minutes 60` bounded a run
        that one turn could overrun by itself, and `max_minutes` is a ceiling this product sells.

        **THREAD-LOCAL, not an attribute, and not a parameter.** One backend instance serves the solver
        loop AND the sub-agent panels that fan out on a thread pool (`_accumulate_usage` carries the
        same note about its lock), so a plain attribute would have concurrent turns overwriting each
        other's deadline — the shorter one silently truncating the longer turn. A parameter would have
        been the other honest answer and was tried; it puts a fifth argument through `_post`, `_once`
        and `_chat_once`, which are the seams the deterministic transport tests stub, for a value none
        of those functions has any decision to make about.
        """
        import contextlib

        @contextlib.contextmanager
        def _stamped():
            previous = getattr(self._turn, "deadline", None)
            self._turn.deadline = self._monotonic() + self.absolute_timeout
            try:
                yield self._turn.deadline
            finally:
                self._turn.deadline = previous

        return _stamped()

    def _turn_deadline(self, now: float | None = None) -> float:
        """When the turn in flight on THIS thread must be over. A fresh per-attempt ceiling when there
        is no turn — a direct `_post` caller keeps the behaviour this class always had."""
        deadline = getattr(self._turn, "deadline", None)
        if deadline is not None:
            return deadline
        return (self._monotonic() if now is None else now) + self.absolute_timeout

    def _wait_for_retry(self, deadline: float, attempt: int, model: str, code: int,
                        error: str) -> bool:
        """Wait only when both the backoff and the next request fit inside this turn."""
        delay = self.backoff * (2 ** attempt)
        remaining = deadline - self._monotonic()
        if remaining <= 0 or delay >= remaining:
            return False
        # This is the only diagnostic a provider stall/reroute emits: none of it reaches the run
        # journal. Emit it before sleeping so a long backoff does not look like a silent worker hang.
        route = "" if code in _PRE_WIRE_CODES else ", routing relaxed"
        _log.warning("provider %s failed with %d (%s); retry %d/%d in %.1fs%s",
                     model, code, error[:120], attempt + 1, self.retries, delay, route)
        self._sleep(delay)
        if self._monotonic() >= deadline:
            return False
        return True

    def usage_summary(self) -> dict:
        """Per-task token/request totals accumulated across every request this backend served (the solver
        loop plus any sub-agents that reuse this instance). Read by the benchmark harness after the solve."""
        with self._usage_lock:
            return dict(self._usage)

    def _http_error(self, error, deadline: float, idle: float) -> tuple[None, int, str]:
        """Read one bounded provider error without letting its body escape the turn deadline."""
        import http.client
        import socket

        ceiling_error = f"absolute error-body ceiling {self.absolute_timeout}s exceeded"
        try:
            raw = _call_before_wall_deadline(
                error, deadline - self._monotonic(),
                lambda: error.read(self._MAX_ERROR_BYTES + 1),
                ceiling_error)
            # The read can complete as the timer becomes runnable but before its callback is
            # scheduled. The production clock closes that narrow race; the timer owns the blocking
            # case where no Python instruction can make this check.
            if self._monotonic() >= deadline:
                raise TimeoutError(ceiling_error)
        except (TimeoutError, socket.timeout) as body_error:
            return None, error.code, (
                f"http {error.code}: response body exceeded its bound: "
                f"{type(body_error).__name__}: {body_error}")
        except (http.client.HTTPException, OSError, _WallTimerStartError) as body_error:
            # Status and headers completed, so this remains the provider's positive HTTP response even
            # when its diagnostic body is truncated or framed illegally. Calling it abandoned would
            # count one complete request twice; letting the body exception escape would lose it whole.
            return None, error.code, (
                f"http {error.code}: response body could not be read within its bound: "
                f"{type(body_error).__name__}: {body_error}")
        decoded = raw[:self._MAX_ERROR_BYTES].decode("utf-8", "replace")
        detail = decoded[:300]
        if len(raw) > self._MAX_ERROR_BYTES or len(decoded) > len(detail):
            detail += " [response body truncated]"
        return None, error.code, f"http {error.code}: {detail}"

    def _read_stream_response(self, req, idle: float, deadline: float,
                              owner: _WallResponseOwner, ceiling_error: str) -> dict:
        """Own connect, headers and body under one timer while preserving per-read idle limits."""
        previous_timeout = getattr(self._turn, "read_timeout", None)
        self._turn.read_timeout = idle

        def consume():
            with _open_stream(req, timeout=idle) as response:
                # A returned HTTPResponse proves the request crossed the wire even when a custom
                # opener bypasses the owned connection classes used by production urllib.
                owner.mark_sent()
                owner.own(response)
                return self._read_sse(response, deadline)

        try:
            return _call_before_wall_deadline(
                owner, deadline - self._monotonic(), consume, ceiling_error)
        finally:
            self._turn.read_timeout = previous_timeout

    def _stream_request(self, payload: dict, timeout: int, relax: bool, deadline: float):
        """Serialize one streaming request and return its fresh pre-I/O ceiling."""
        import json as _json
        import urllib.request

        if deadline - self._monotonic() <= 0:
            return None, 0.0, 0.0
        endpoint = urllib.parse.urlsplit(self.endpoint)
        if endpoint.scheme not in ("http", "https") or not endpoint.hostname:
            raise ValueError("model endpoint must be an absolute HTTP(S) URL")
        if endpoint.username is not None or endpoint.password is not None:
            raise ValueError("model endpoint must not contain credentials")
        _port = endpoint.port  # access validates an explicitly supplied port before any socket work
        provider = self._provider_block(relax)
        if provider:
            payload["provider"] = provider
        payload["stream"] = True
        payload["stream_options"] = {"include_usage": True}
        request_body = _json.dumps(payload).encode("utf-8")
        remaining = deadline - self._monotonic()
        if remaining <= 0:
            return None, 0.0, remaining
        idle = min(float(timeout), float(self.idle_timeout), remaining)
        request = urllib.request.Request(self.endpoint, data=request_body, method="POST", headers={
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": self.referer,
            "X-Title": self.title,
        })
        return request, idle, remaining

    @staticmethod
    def _postwire_or_config(owner: _WallResponseOwner, error: Exception,
                            post_code: int, post_detail: str) -> tuple[None, int, str]:
        if not owner.sent:
            return None, _PRE_WIRE_CONFIG_CODE, (
                f"invalid provider request: {type(error).__name__}: {error}")
        return None, post_code, post_detail

    @staticmethod
    def _url_error_result(error, owner: _WallResponseOwner,
                          idle: float) -> tuple[None, int, str]:
        import socket

        if isinstance(error.reason, (TimeoutError, socket.timeout)):
            code = _POST_WIRE_TIMEOUT_CODE if owner.sent else _PRE_WIRE_TIMEOUT_CODE
            return None, code, f"idle/stall timeout after {idle:g}s: {error.reason}"
        code = _POST_WIRE_TRANSPORT_CODE if owner.sent else _PRE_WIRE_TRANSIENT_CODE
        return None, code, f"{type(error).__name__}: {error}"

    @staticmethod
    def _http_parser_result(error, owner: _WallResponseOwner) -> tuple[None, int, str]:
        """Separate local request defects from a proxy's failed pre-wire negotiation."""
        import http.client

        if not owner.sent:
            if isinstance(error, http.client.InvalidURL):
                return None, _PRE_WIRE_CONFIG_CODE, (
                    f"invalid provider request: {type(error).__name__}: {error}")
            # HTTPS proxy CONNECT is parsed before the model request exists. A malformed proxy
            # response is therefore retryable without billing or relaxing provider routing; treating
            # every pre-send parser error as local configuration made one bad proxy edge terminal.
            return None, _PRE_WIRE_TRANSIENT_CODE, (
                f"pre-wire HTTP negotiation failed: {type(error).__name__}: {error}")
        return None, _MALFORMED_STREAM_CODE, (
            f"malformed HTTP response: {type(error).__name__}: {error}")

    def _post_open(self, req, idle: float, deadline: float, owner: _WallResponseOwner,
                   ceiling_error: str) -> tuple[dict | None, int, str]:
        """Open and parse one prepared request, translating only transport/parser failures."""
        import http.client
        import json as _json
        import socket
        import urllib.error

        try:
            # Ownership starts before connect/status/header work. urllib exposes a response only after
            # parsing its headers, so a response-level timer would leave that whole phase unbounded.
            data = self._read_stream_response(req, idle, deadline, owner, ceiling_error)
            return data, 200, ""
        except urllib.error.HTTPError as e:
            try:
                return self._http_error(e, deadline, idle)
            finally:
                try:
                    e.close()
                except OSError:
                    pass
        except (TimeoutError, socket.timeout) as e:
            code = _POST_WIRE_TIMEOUT_CODE if owner.sent else _PRE_WIRE_TIMEOUT_CODE
            return None, code, f"idle/stall timeout after {idle:g}s: {type(e).__name__}: {e}"
        except urllib.error.URLError as e:
            return self._url_error_result(e, owner, idle)
        except _UsageIntegrityError as e:
            return None, _USAGE_INTEGRITY_CODE, f"invalid provider usage: {e}"
        except _StreamIntegrityError as e:
            return None, _STREAM_INTEGRITY_CODE, f"invalid provider stream: {e}"
        except RecursionError as e:
            return None, _STREAM_INTEGRITY_CODE, f"invalid provider stream: JSON nesting limit: {e}"
        except _WallTimerStartError as e:
            code = _POST_WIRE_TRANSPORT_CODE if owner.sent else _PRE_WIRE_TRANSIENT_CODE
            return None, code, f"{type(e).__name__}: {e}"
        except (_json.JSONDecodeError, http.client.IncompleteRead, EOFError, TypeError) as e:
            return self._postwire_or_config(
                owner, e, _MALFORMED_STREAM_CODE,
                f"malformed stream: {type(e).__name__}: {e}")
        except ValueError as e:
            return self._postwire_or_config(
                owner, e, _STREAM_INTEGRITY_CODE,
                f"invalid provider stream: JSON value limit: {e}")
        except http.client.HTTPException as e:
            return self._http_parser_result(e, owner)
        except OSError as e:
            code = _POST_WIRE_TRANSPORT_CODE if owner.sent else _PRE_WIRE_TRANSIENT_CODE
            return None, code, f"{type(e).__name__}: {e}"

    def _post(self, payload: dict, timeout: int, relax: bool = False) -> tuple[dict | None, int, str]:
        """POST a STREAMING chat-completions request and reassemble the SSE stream into the SAME
        non-streaming response shape the parsers already consume (``{choices:[{message, finish_reason,
        native_finish_reason}], usage}``) — so ``_once``/``_chat_once`` (and all the refusal/reasoning/
        finish_reason logic) are unchanged. Returns ``(data, code, error)``: positive codes are completed
        HTTP responses; negative codes are local outcomes that distinguish pre-wire failures, post-wire
        timeouts, other post-wire transport loss, malformed streams, and integrity rejection.

        Why stream: a NON-streaming read makes the socket timeout ≈ total generation time, so a large but
        HEALTHY completion false-times-out. Streaming lets the socket timeout be the IDLE (inter-read) gap
        (``idle_timeout``) — a completion that keeps emitting tokens never trips it however long it runs;
        only a real mid-stream stall aborts. ``absolute_timeout`` backstops a pathological slow-drip. Both
        aborts are retryable and the retry (``relax=True``) opens provider routing to reroute off the
        bad provider. The caller builds its own domain result so the completion and tool-calling paths stay
        type-distinct (LLMResult vs ChatResult)."""
        import http.client
        now = self._monotonic()
        deadline = self._turn_deadline(now)
        # STREAM so the socket timeout can be an IDLE gap, not the total-generation cap (the false-timeout
        # fix). include_usage → the final SSE chunk carries usage.total_tokens.
        # The per-recv socket timeout = the IDLE (no-new-bytes) gap. urllib applies it to EACH blocking read
        # (connect + each recv), so a stream that keeps flowing never trips it; a stall beyond idle_timeout
        # aborts fast. The remaining TURN time is the third bound: a connect or blocking read cannot
        # outlive the ceiling merely because no response bytes arrived for `_read_sse` to examine.
        try:
            req, idle, remaining = self._stream_request(payload, timeout, relax, deadline)
        except (RecursionError, TypeError, ValueError, http.client.HTTPException) as e:
            # URL/header/request JSON construction happened before a socket could be opened. A bad
            # endpoint, control-bearing credential or unserialisable local payload is configuration,
            # not a provider attempt and not a transient reason to reroute or buy another request.
            return None, _PRE_WIRE_CONFIG_CODE, f"invalid provider request: {type(e).__name__}: {e}"
        if req is None:
            return None, _TURN_CEILING_CODE, (
                f"turn ceiling {self.absolute_timeout}s reached before provider request")
        ceiling_error = f"absolute stream ceiling {self.absolute_timeout}s exceeded"
        owner = _WallResponseOwner(remaining, ceiling_error)
        req._shard_wall_owner = owner
        # THE TURN'S CEILING WHERE THERE IS ONE, and this attempt's otherwise. `chat` and `complete`
        # stamp a deadline for the whole ladder, so retries cannot multiply this bound.
        return self._post_open(req, idle, deadline, owner, ceiling_error)

    def _read_sse(self, resp, deadline: float) -> dict:
        """Consume an OpenRouter SSE stream and reassemble it into the NON-streaming response shape the
        callers already parse — ``_sse_data`` peels the framing, ``_SseAssembly`` accumulates the
        message, ``_StreamPace`` polices the pace. ``data: [DONE]`` or an explicit
        ``finish_reason`` proves completion; SSE comment/keepalive lines are skipped. A malformed
        ``data:`` value or clean EOF before either terminal signal is a retryable malformed stream,
        never a partial answer. A completion that keeps streaming never stalls; a slow-drip past
        ``deadline`` raises ``TimeoutError`` (the absolute ceiling), caught as a retryable local timeout by
        ``_post``."""
        import json as _json

        assembly = _SseAssembly()
        pace = _StreamPace(self, deadline)
        done = False

        def refresh_read_timeout():
            remaining = deadline - self._monotonic()
            if remaining <= 0:
                raise TimeoutError(f"absolute stream ceiling {self.absolute_timeout}s exceeded")
            configured = getattr(self._turn, "read_timeout", None)
            limit = min(float(self.idle_timeout if configured is None else configured), remaining)
            sock = getattr(getattr(getattr(resp, "fp", None), "raw", None), "_sock", None)
            if sock is not None:
                sock.settimeout(limit)

        lines = _bounded_sse_lines(resp, self._MAX_STREAM_BYTES, self._MAX_STREAM_LINES,
                                   refresh_read_timeout)
        for raw in lines:
            now = self._monotonic()                        # ONE clock read per line, shared by both checks
            pace.tick(now, assembly.out_chars)
            body = _sse_data(raw)
            if body is None:
                continue                                   # blank separator / SSE comment / non-data field
            if body == "[DONE]":
                done = True
                break
            chunk = _json.loads(body)                      # malformed data is not framing noise
            assembly.add(chunk)
            pace.mark_output(now, assembly.out_chars)      # the 1st output token starts the rate clock
        pace.tick(self._monotonic(), assembly.out_chars)    # EOF/read completion may itself cross the ceiling
        if not done and not assembly.finish:
            # Clean socket EOF is not proof that the provider finished the turn. Before this check a
            # valid-looking tool call followed by a closed connection was returned as executable.
            raise EOFError("SSE ended before [DONE] or finish_reason")
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
            abandoned, unpriced = self._data_less_accounting(code, _gen_sec)
            return LLMResult("", 0.0, model, False, err, tokens=0,
                             abandoned_attempts=abandoned,
                             unpriced_attempts=unpriced,
                             tokens_reported=False, cost_reported=False), code
        # OpenAI-compatible shape. A reasoning model (e.g. GLM-5.2) can return empty `content` — fall
        # back to `reasoning`. Bind `choice` first so finish_reason/native/refusal are reachable.
        choice = (data.get("choices") or [{}])[0]
        msg = choice.get("message", {}) or {}
        finish = choice.get("finish_reason") or ""
        native = choice.get("native_finish_reason") or ""
        refusal = msg.get("refusal")
        served, identity, identity_detail = _response_model_identity(data, model)
        try:
            usage = _provider_usage(data.get("usage"))
        except ValueError as e:
            self._record_abandoned(_gen_sec)
            return LLMResult("", 0.0, model, False, f"invalid provider usage: {e}",
                             abandoned_attempts=1, served_model=served,
                             identity_verdict=identity, tokens_reported=False,
                             cost_reported=False), _USAGE_INTEGRITY_CODE
        self._accumulate_usage(usage, _gen_sec)
        fields = _provider_result_fields(usage, served, identity)
        identity_error = identity_detail or _model_identity_error(model, served, identity)
        if identity_error:
            return LLMResult(text="", model=model, ok=False, error=identity_error,
                             **fields), 409
        # A refusal is NEVER a success: detect it BEFORE it can be laundered into `text` (the mistake
        # that made a structured refusal look ok=True), and return terminal 403 (∉ retry set →
        # complete() returns at once instead of grinding the ~30s backoff ladder) with the refusal
        # text surfaced in `error`. Mirrors _chat_once so the two paths agree.
        text = msg.get("content") or msg.get("reasoning") or ""
        if refusal or finish == "content_filter" or native == "refusal":
            err = f"model refused the prompt (finish={finish or native})"
            return LLMResult(text="", model=model, ok=False,
                             error=f"{err}: {refusal}" if refusal else err,
                             finish_reason=finish, **fields), 403
        if not text:
            # Empty content + no refusal signal → a TRANSIENT glitch (AkashML/GLM does this
            # intermittently) — retry via 599. finish_reason rides along so the loop can tell a
            # max_tokens TRUNCATION ("length") from a genuinely empty turn.
            return LLMResult(text="", model=model, ok=False,
                             error=f"empty response: {str(data)[:200]}",
                             finish_reason=finish, **fields), 599
        return LLMResult(text=text, model=model, ok=True, finish_reason=finish, **fields), 200

    def complete(self, system: str, user: str, *, model: str = "sonnet", timeout: int = 600) -> "LLMResult":
        resolved = self._resolve(model)
        if not self.api_key:
            return LLMResult("", 0.0, resolved, False, "no OPENROUTER_API_KEY")
        last = LLMResult("", 0.0, resolved, False, "no attempt")
        # One completion may make several provider requests. The response which survives the ladder
        # must carry the whole invoice, because discovery debits this object against the run governor.
        # `_accumulate_usage` already keeps the backend-wide copy; these totals are the per-call copy.
        made, spent_usd, spent_tokens, abandoned, unpriced = 0, 0.0, 0, 0, 0
        token_flags: list[bool | None] = []
        cost_flags: list[bool | None] = []
        retry_window_closed = False
        # ONE CEILING FOR THE LADDER, not one per rung. `chat` carries the reasoning; this path gets the
        # same treatment because it makes the same requests against the same provider.
        with self._turn_ceiling() as deadline:
            for attempt in range(self.retries + 1):
                # After the FIRST failure, RELAX provider routing (relax=attempt>0) so a hung/429
                # provider reroutes to a healthy one — the first try keeps the exact fp8 pin.
                candidate, code = self._once(system, user, resolved, timeout, relax=made > 0)
                if code == _TURN_CEILING_CODE:
                    # `_post` checked the shared deadline immediately before opening the wire. This
                    # is not an attempt: folding its synthetic zeroes over an earlier reported
                    # response changed a fully measured bill into an unmeasured one.
                    if made:
                        last = replace(last, error=f"{last.error} ({candidate.error})")
                    else:
                        last = candidate
                    retry_window_closed = True
                    break
                last = candidate
                if code not in _PRE_WIRE_CODES:
                    made += 1
                    spent_usd += float(last.cost_usd or 0.0)
                    spent_tokens += int(last.tokens or 0)
                    unpriced += int(last.unpriced_attempts or 0)
                    token_flags.append(last.tokens_reported)
                    cost_flags.append(last.cost_reported)
                    # A stream can end before usage while still being billable. The shared helper keeps
                    # completion and native-chat accounting on one rule.
                    abandoned += self._account_abandoned(last)
                if last.ok or code not in self._RETRY_CODES:  # success or permanent 4xx
                    tokens_reported = _combined_reported(token_flags)
                    cost_reported = _combined_reported(cost_flags)
                    return self._completion_bill(last, made, spent_usd, spent_tokens,
                                                 abandoned, unpriced,
                                                 tokens_reported, cost_reported)
                if attempt >= self.retries:
                    break
                if not self._wait_for_retry(deadline, attempt, resolved, code, last.error or ""):
                    last = replace(last, error=f"{last.error} (turn ceiling {self.absolute_timeout}s "
                                               f"leaves no retry window after {attempt + 1} attempt(s))")
                    retry_window_closed = True
                    _log.error("provider %s: turn ceiling %ds leaves no retry window after %d "
                               "attempt(s)", resolved, self.absolute_timeout, attempt + 1)
                    break
        if not last.ok and not retry_window_closed:
            _log.error("provider %s exhausted %d retries; last code %d (%s)",
                       resolved, self.retries, code, (last.error or "")[:200])
        return self._completion_bill(last, made, spent_usd, spent_tokens, abandoned, unpriced,
                                     _combined_reported(token_flags),
                                     _combined_reported(cost_flags))

    @staticmethod
    def _completion_bill(result: LLMResult, made: int, spent_usd: float, spent_tokens: int,
                         abandoned: int, unpriced: int, tokens_reported: bool | None,
                         cost_reported: bool | None) -> LLMResult:
        """Return one completion carrying every attempt it caused, preserving one-attempt identity."""
        if (made <= 1 and result.abandoned_attempts == abandoned
                and result.tokens_reported is tokens_reported
                and result.cost_reported is cost_reported):
            return result
        return replace(result, cost_usd=spent_usd, tokens=spent_tokens,
                       abandoned_attempts=abandoned,
                       unpriced_attempts=unpriced,
                       tokens_reported=tokens_reported,
                       cost_reported=cost_reported)

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
            abandoned, unpriced = self._data_less_accounting(code, _gen_sec)
            return ChatResult(ok=False, error=err, model=model,
                              abandoned_attempts=abandoned,
                              unpriced_attempts=unpriced,
                              tokens_reported=False, cost_reported=False,
                              stall_retry_safe=code in (
                                  _PRE_WIRE_TIMEOUT_CODE, _POST_WIRE_TIMEOUT_CODE),
                              forcing_retry_safe=_tool_choice_rejection(
                                  code, err, tool_choice)), code
        choice = (data.get("choices") or [{}])[0]
        msg = choice.get("message", {}) or {}
        # WHAT ACTUALLY ANSWERED. Read on every path that has a body, including the two that fail,
        # because a route that substitutes does it on the refusal and the empty turn as well.
        served, identity, identity_detail = _response_model_identity(data, model)
        # The provider's own billed amount for THIS request, carried out on every return path that has a
        # response — including the refusal and the empty-turn glitch below. Both were already charged for
        # (opus-4.8's refusal burned 9,003 prompt tokens before refusing), so a meter that skipped them
        # would under-report exactly the turns a customer most wants to see on the bill.
        try:
            usage = _provider_usage(data.get("usage"))
        except ValueError as e:
            self._record_abandoned(_gen_sec)
            return ChatResult(ok=False, error=f"invalid provider usage: {e}", model=model,
                              served_model=served, identity_verdict=identity,
                              abandoned_attempts=1, tokens_reported=False,
                              cost_reported=False, forcing_retry_safe=False), _USAGE_INTEGRITY_CODE
        self._accumulate_usage(usage, _gen_sec)
        fields = _provider_result_fields(usage, served, identity)
        identity_error = identity_detail or _model_identity_error(model, served, identity)
        if identity_error:
            return ChatResult(ok=False, error=identity_error, model=model,
                              forcing_retry_safe=False, **fields), 409
        refusal = msg.get("refusal")
        finish = choice.get("finish_reason") or ""
        native = choice.get("native_finish_reason") or ""
        text = msg.get("content") or msg.get("reasoning") or ""            # refusal dropped from success text

        # A provider's safety verdict dominates every payload field beside it. Some gateways preserve
        # a partially generated native call while replacing the turn's finish signal with
        # `content_filter`/`refusal`; parsing and returning that call turned a refusal into a side
        # effect in ToolCallingLoop. Keep neither the call nor its assistant protocol message.
        if refusal or finish == "content_filter" or native == "refusal":
            return ChatResult(ok=False, error=f"model refused the prompt (finish={finish or native})",
                              model=model, finish_reason=finish, tool_calls=[], raw_message={},
                              forcing_retry_safe=False, **fields), 403

        # A max-token response is not a completed native call even when its current prefix happens to
        # be valid JSON. Measured adversarially: ``{"path":"victim"}`` arrived before the provider
        # stopped with ``finish_reason=length`` and the loop executed it as a complete write tool. Drop
        # the entire call structure here; the loop owns the bounded continuation and must never expose
        # an incomplete call to any other ``chat`` consumer in the meantime.
        if finish == "length":
            return ChatResult(text=text, tool_calls=[], raw_message={}, ok=True, model=model,
                              finish_reason=finish, **fields), 200

        try:
            calls, call_error = _parsed_tool_calls(msg)
        except _StreamIntegrityError as e:
            return (ChatResult(ok=False, error=f"invalid provider stream: {e}", model=model,
                               finish_reason=finish, forcing_retry_safe=False, **fields),
                    _STREAM_INTEGRITY_CODE)
        if call_error:
            return ChatResult(ok=False, error=call_error, model=model,
                              finish_reason=finish, **fields), 599
        if not text and not calls:
            # empty content + no tool calls + no refusal signal → a transient glitch (retry via 599).
            # finish_reason rides along so the loop can tell a max_tokens TRUNCATION ("length") apart.
            return ChatResult(ok=False, error=f"empty response: {str(data)[:200]}", model=model,
                              finish_reason=finish, empty_retry_safe=True, **fields), 599
        return ChatResult(text=text, tool_calls=calls, raw_message=msg, ok=True, model=model,
                          finish_reason=finish, **fields), 200

    def chat(self, messages: list, tools: list, *, model: str = "sonnet", timeout: int = 600,
             tool_choice=None) -> ChatResult:
        """Native tool-calling turn: send the message history + tool schemas, get back the assistant
        message (content and/or tool_calls). Same retry/provider-routing policy as `complete`. ``tool_choice``
        (None→"auto", "required", or a {function:{name}} dict) FORCES a tool call when the caller wants to break
        a prose-answer default.

        ## THE TURN IS BILLED, NOT THE ATTEMPT THAT SURVIVED IT

        This ladder makes up to ``retries + 1`` requests and returned only the last one, so every
        attempt it threw away entered ``agentloop._meter`` at **$0 and zero tokens** — while the
        provider charged for all of them. Two of the three discard paths carry a real invoice:

        * a **refusal** (403) and an **empty completion** (599) both arrive with a body and a `usage`
          block. `opus-4.8` burned 9,003 prompt tokens refusing, which `_chat_once` already reads onto
          the result — and this loop then dropped the result on the floor.
        * a **stall or malformed stream** (a negative local outcome with no body) has no `usage` at all: the provider
          generated tokens and we never saw the end of them. That cost is unknowable from here, so it
          is COUNTED instead, on the result as `abandoned_attempts` and on the backend's own ledger as
          `abandoned_requests`.

        The consequence was not confined to the ledger. ``--max-spend-usd`` reserves the price of the
        most expensive call this run has made (`agentloop._unaffordable_next_call`), and that guard was
        calibrated on the same understated numbers — so a run whose provider was retrying cheerfully
        under-reserved by exactly the factor by which it was under-billed. Folding the discarded
        attempts in fixes the ledger and the guard in one place, because they read the same field.

        ## ONE 900s CEILING PER TURN, NOT PER ATTEMPT

        ``absolute_timeout`` backstops a pathological slow-drip inside one stream. Five attempts of it
        plus the backoff ladder is **over an hour for a single step**, and the run's wall ceiling is
        only ever consulted BETWEEN steps (`agentloop._budget_stop`) — so `--max-minutes 60` bounded a
        run that one turn could overrun on its own. The deadline is therefore stamped once, here, and
        shared by every attempt: the ceiling means what its name says, and a ladder cannot multiply it.
        """
        resolved = self._resolve(model)
        if not self.api_key:
            return ChatResult(ok=False, error="no OPENROUTER_API_KEY", model=resolved)
        last = ChatResult(ok=False, error="no attempt", model=resolved)
        # THE TURN'S RUNNING TOTAL, over EVERY attempt rather than over the discarded ones. Summing
        # only the discards and adding `last` back at the end double-counts the final attempt on the
        # paths that fall out of the loop rather than returning from inside it — which is one of the
        # two ways this arithmetic can be wrong, and the harder one to see.
        made, spent_usd, spent_tokens, abandoned, unpriced = 0, 0.0, 0, 0, 0
        token_flags: list[bool | None] = []
        cost_flags: list[bool | None] = []
        with self._turn_ceiling() as deadline:
            for attempt in range(self.retries + 1):
                # A local DNS/connect failure did not reach a provider and therefore cannot justify
                # relaxing its routing policy on the next local try.
                candidate, code = self._chat_once(
                    messages, tools, resolved, timeout, relax=made > 0,
                    tool_choice=tool_choice)
                if code == _TURN_CEILING_CODE:
                    # A deadline race after the retry check opened no wire and therefore contributes
                    # no zero-valued request to the bill or completeness flags.
                    if made:
                        last = replace(last, error=f"{last.error} ({candidate.error})")
                    else:
                        last = candidate
                    break
                last = candidate
                if code not in _PRE_WIRE_CODES:
                    made += 1
                    spent_usd += float(last.cost_usd or 0.0)
                    spent_tokens += int(last.tokens or 0)
                    unpriced += int(last.unpriced_attempts or 0)
                    token_flags.append(last.tokens_reported)
                    cost_flags.append(last.cost_reported)
                    # A stream can end before usage while still being billable. The shared helper keeps
                    # completion and native-chat accounting on one rule.
                    abandoned += self._account_abandoned(last)
                if last.ok or code not in self._RETRY_CODES or attempt >= self.retries:
                    break
                # A ladder that outlives the turn's own ceiling buys nothing: the next attempt shares
                # the deadline and would be cut off before it could produce anything.
                if not self._wait_for_retry(deadline, attempt, resolved, code, last.error or ""):
                    last = replace(last, error=f"{last.error} (turn ceiling {self.absolute_timeout}s "
                                               f"leaves no retry window after {attempt + 1} attempt(s))")
                    break
        return self._billed(last, made, spent_usd, spent_tokens, abandoned, unpriced,
                            _combined_reported(token_flags), _combined_reported(cost_flags))

    @staticmethod
    def _billed(result: ChatResult, made: int, spent_usd: float, spent_tokens: int,
                abandoned: int, unpriced: int, tokens_reported: bool | None,
                cost_reported: bool | None) -> ChatResult:
        """The turn's result carrying the turn's whole bill. See `chat`.

        Returned UNCHANGED when the turn made one attempt, which is every ordinary turn: the totals
        are then the surviving attempt's own numbers by construction, and rebuilding the object would
        only create a second way for them to disagree.
        """
        if (made <= 1 and result.abandoned_attempts == abandoned
                and result.tokens_reported is tokens_reported
                and result.cost_reported is cost_reported):
            return result
        return replace(result, cost_usd=spent_usd, tokens=spent_tokens,
                       abandoned_attempts=abandoned, unpriced_attempts=unpriced,
                       tokens_reported=tokens_reported, cost_reported=cost_reported)


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
            return ChatResult(ok=False, error="empty response: simulated glitch", model=model, tokens=1,
                              empty_retry_safe=True)
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
    first"), so the loop would execute a hypothesis the model explicitly REJECTED. The loop's
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


# --- the endpoint probe, an internal audit P6/P7 ---------------------------------------------------------

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


def _model_identity_parts(identity: str) -> tuple[str, str]:
    parts = (identity or "").rsplit("/", 1)
    return (parts[0], parts[1]) if len(parts) == 2 else ("", parts[0])


def _explicit_vendor_mismatch(left: str, right: str) -> bool:
    left_vendor, _ = _model_identity_parts(left)
    right_vendor, _ = _model_identity_parts(right)
    return bool(left_vendor and right_vendor and left_vendor != right_vendor)


def _same_model_identity(left: str, right: str) -> bool:
    """Whether two model identifiers name the same vendor/model or a numeric snapshot pin."""
    _, left_leaf = _model_identity_parts(left)
    _, right_leaf = _model_identity_parts(right)
    if not left_leaf or not right_leaf:
        return False
    # A bare alias may resolve to a qualified provider id. Two explicit, different vendors cannot be
    # erased to their leaves: `z-ai/glm-5.2` and `acme/glm-5.2` name different serving authorities.
    if _explicit_vendor_mismatch(left, right):
        return False
    if right_leaf == left_leaf:
        return True
    prefix = left_leaf + "-"
    if not right_leaf.startswith(prefix):
        return False
    # The two snapshot forms observed on supported routes: GLM's MMDD pin and OpenAI's ISO date.
    # An arbitrary suffix is not a pin: ``gpt-4o-mini`` and ``llama-3-guard`` are different weights,
    # and accepting every hyphen suffix made the endpoint probe certify both as the requested model.
    suffix = right_leaf[len(prefix):]
    return bool(re.fullmatch(r"(?:\d{4}|\d{4}-\d{2}-\d{2})", suffix))


def _model_identity_verdict(requested: str, served: str) -> str:
    """One stable audit token for the per-response identity check."""
    if not served:
        return "missing"
    return "matched" if _same_model_identity(requested, served) else "substituted"


def _response_model_identity(data: dict, requested: str) -> tuple[str, str, str]:
    """Served id, audit verdict and conflict detail from one assembled provider response."""
    conflict = data.get("_model_identity_error")
    if conflict:
        identities = data.get("_model_identities")
        served = " | ".join(identities) if isinstance(identities, list) else ""
        return served, "conflicting", str(conflict)
    served = data.get("model") if isinstance(data.get("model"), str) else ""
    return served, _model_identity_verdict(requested, served), ""


def _model_identity_error(requested: str, served: str, verdict: str) -> str:
    """The terminal error for a response whose serving weights cannot be verified."""
    if verdict == "matched":
        return ""
    if verdict == "missing":
        return (f"provider response did not identify the model that answered; requested "
                f"{requested!r} cannot be verified")
    if verdict == "conflicting":
        return f"provider response named conflicting model identities: {served or 'invalid value'}"
    return f"provider served {served!r}, not the requested model {requested!r}"


def _substituted(observed: dict) -> bool:
    """Did the endpoint answer with a model other than the one it was asked for.

    **MEASURED ON THE WIRE, 2026-09-03, `https://api.z.ai/api/coding/paas/v4`:** `glm-5.2` is served
    `glm-5.3` and `glm-4.5-air` is served `glm-5.3-flash`, both HTTP 200, both naming the substitute
    in the response's own `model` field. A route that does this is invisible to every other check
    this product has: the request succeeds, the tool call comes back, and the artefacts name the
    identifier the customer typed.

    **THE RULE IS AN EXACT LEAF OR A RECOGNISED NUMERIC SNAPSHOT, not string equality, and the cost of each is
    measured rather than assumed.** Pinning a dated snapshot is a normal, honest thing for a provider
    to do — `gpt-4o` answered by `gpt-4o-2024-08-06`, `glm-5.2` answered by `glm-5.2-0929` — and
    equality would report every one of those as a substitution, which would train a reader to ignore
    the row. A broad separator prefix is the opposite mistake: it certifies `gpt-4o-mini` and
    `llama-3-guard` as the base model. Only the measured MMDD and ISO-date suffixes are accepted;
    unknown variants are refused as substitutions rather than guessed equivalent.

    Compares the LEAF after `/` only when one side is genuinely bare, because an alias map resolves
    `glm-5.2` to `z-ai/glm-5.2` on OpenRouter. Two explicit, different vendor prefixes remain distinct.
    """
    asked = observed.get("requested") or ""
    served = observed.get("model") or ""
    # An empty half is the provider naming nothing — unobserved, which is not the same as disagreeing.
    return bool(asked and served) and not _same_model_identity(asked, served)


def probe_endpoint(backend, *, model: str = "", validated_model: str = "",
                   timeout: int = 60) -> dict:
    """One tool-calling round trip. Returns a verdict, a reason, and what was observed.

    **the integration guide promises this in a sentence the product did not keep:** *"Preflight
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
        unsupported  no tool call came back, the request failed, or the served identity disagreed

    **`compatible` is not a warning.** It means the requested and served identities agree but this
    project has no measurements for that model. Missing, conflicting and substituted identities are
    unsupported: this probe may classify unfamiliar weights, but it may not silently run different or
    unverified weights than the customer configured.

    Costs one model turn — a few hundred tokens when transport succeeds. The backend can retry
    transient HTTP failures, and abandoned attempts may still be billable. Never raises: a probe that
    throws is `unsupported` with the exception as its reason, because every failure here has the same
    answer for the customer.
    """
    observed: dict = {"tool_calls": 0, "model": "", "requested": "", "substituted": False,
                      "identity_verdict": "", "error": ""}
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

    # `requested` IS THE ECHO AND `model` IS THE ANSWER, and until 2026-09-03 this dict held only the
    # echo under the name `model` inside a key called `observed`. `""` here means the provider named
    # nothing, which is a different fact from "it served what we asked" and now reads as one.
    observed["requested"] = getattr(result, "model", "") or model
    observed["model"] = getattr(result, "served_model", "") or ""
    observed["identity_verdict"] = (
        getattr(result, "identity_verdict", "")
        or _model_identity_verdict(observed["requested"], observed["model"]))
    observed["substituted"] = observed["identity_verdict"] == "substituted"
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
    identity_error = _model_identity_error(observed["requested"], observed["model"],
                                           observed["identity_verdict"])
    if identity_error:
        return {"verdict": UNSUPPORTED,
                "why": f"native tool calling cannot be accepted: {identity_error}",
                "observed": observed}

    # `validated_model` is PASSED IN rather than imported. `DEFAULT_MODEL` lives in `shard/cli.py`
    # and this module sits below it; reaching upward for it would invert the layering to save one
    # argument, and which model this project has measured is a fact the CLI already owns.
    #
    # **THE VERDICT IS ABOUT WHAT ANSWERED, NOT WHAT WAS ASKED FOR.** The request is retained to explain
    # an unverified result, but it cannot certify itself when the response names no served model.
    measured_id = observed["model"] or observed["requested"] or ""
    vendor_mismatch = _explicit_vendor_mismatch(observed["requested"], observed["model"])
    measured = (measured_id if vendor_mismatch else measured_id.split("/")[-1]) \
        or "the endpoint's default"
    if validated_model and not vendor_mismatch and _same_model_identity(validated_model, measured_id):
        return {"verdict": VALIDATED,
                "why": f"native tool calling works and {measured} is the configuration this project "
                       "has measured.", "observed": observed}
    return {"verdict": COMPATIBLE,
            "why": f"native tool calling works. {measured} is not a model this project has numbers "
                   f"for, which is a supported choice and not a warning — you supply the "
                   "inference.",
            "observed": observed}
