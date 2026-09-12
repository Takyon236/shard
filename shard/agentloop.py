
from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field

from shard.budget import BudgetExceeded, BudgetGovernor
from shard.diag import get_logger
from shard.journal import Journal
from shard.memory import fence
from shard.providermetrics import merge as _merge_provider_usage
from shard.reasoning import ensure_compute_runway, render_self_review
from shard.telemetry import _tool_metadata
from shard.tools import OBS_WINDOW_CHARS, READ_MAX_FILE_BYTES, ToolRegistry, ToolResult
from shard.toolvalidate import suggest_tool, validate_call_args

REPEAT_ADVISORY_AT = 4
REPEAT_BREAK_AT = 6

MAX_TOOLCALLS_PER_TURN = 16

COMPACT_KEEP_RECENT = 8
COMPACT_MIN_CHARS = 1500
COMPACT_READ_TOOLS = frozenset({"read_file", "grep", "list_dir", "run_bash", "code_query"})
COMPACT_NEVER_TOOLS = frozenset({"test_poc", "write_poc", "auto_fuzz", "fuzz", "sanitizer", "run_sanitizer"})
COMPACT_STUB_PREFIX = "[stale-read elided]"

MEASURE_INTERVAL = 6
MEASURE_MAX = 4

CONSTRUCT_INTERVAL = 8
CONSTRUCT_MAX = 5
CONSTRUCT_EXPLORE_TOOLS = frozenset({"read_file", "list_dir", "grep", "run_bash"})
CONSTRUCT_PROGRESS_TOOLS = frozenset({"fuzz", "use_corpus", "build_emit", "build_preset", "instrument", "batch_test"})

AUTOPUSH_MIN_INTERVAL = CONSTRUCT_INTERVAL

STALL_PROGRESS_TOOLS = CONSTRUCT_PROGRESS_TOOLS | frozenset({"test_poc", "auto_fuzz"})
STALL_OUTCOME_KEYS = ("crashed", "inner_exit", "sanitizer", "found", "n_crashes", "reached",
                      "probes_hit", "reached_sink", "build_ok", "rebuilt", "exhausted")

ENACTMENT_DENY_TOOLS = frozenset({"read_file", "grep", "list_dir"})
_BASH_READ_CMDS = frozenset({"cat", "head", "tail", "sed", "grep", "egrep", "fgrep", "rg", "ag", "less",
                             "more", "find", "ls", "tree", "strings", "od", "xxd", "hexdump", "nl", "wc",
                             "awk", "readelf", "nm", "objdump", "file", "stat", "cut", "sort", "uniq"})


def _is_read_shaped_bash(arguments) -> bool:
    cmd = str((arguments or {}).get("command", "")).strip()
    if not cmd:
        return False
    low = cmd.lower()
    if any(m in low for m in ("./poc", "seeds/", "python", "struct.pack", "gcc", "clang", "g++", " cc ",
                              "make ", "printf ", "> ./", ">./", "tee ", "dd ")):
        return False
    body = re.sub(r"^\s*cd\s+[^;&|]+[;&|]+\s*", "", cmd)
    first = re.split(r"[\s;|&<>]", body.strip(), maxsplit=1)[0].rsplit("/", 1)[-1]
    return first in _BASH_READ_CMDS
ENACTMENT_REARM_TOOLS = frozenset({"test_poc", "batch_test", "fuzz", "auto_fuzz"})
ENACTMENT_VERDICT_KEYS = ("crashed", "found", "n_crashes", "n_crashed")


def _is_enactment_measurement(result) -> bool:
    d = result.to_dict()
    if not d.get("ok"):
        return False
    data = d.get("data")
    if not isinstance(data, dict):
        return True
    for key in ENACTMENT_VERDICT_KEYS:
        if key in data:
            return True
    if "n_tested" in data:
        try:
            return int(data["n_tested"]) > 0
        except (TypeError, ValueError):
            return False
    return True


def _stall_outcome_sig(result) -> str:
    d = result.to_dict()
    data = d.get("data") if isinstance(d.get("data"), dict) else {}
    proj = {k: data.get(k) for k in STALL_OUTCOME_KEYS if k in data}
    return json.dumps({"ok": d.get("ok"), **proj}, default=str, sort_keys=True)

_CLAMP_SEARCH_STEPS = 20


def _cap_strings(node, cap: int):
    if isinstance(node, str):
        if len(node) <= cap:
            return node
        return node[:cap] + f"\n...[truncated: {len(node) - cap} more chars of this value]"
    if isinstance(node, dict):
        return {k: _cap_strings(v, cap) for k, v in node.items()}
    if isinstance(node, list):
        return [_cap_strings(v, cap) for v in node]
    return node


def clamp_observation(payload: dict, limit: int) -> str:
    full = json.dumps(payload, default=str)
    if len(full) <= limit:
        return full
    floor = json.dumps(_cap_strings(payload, 0), default=str)
    if len(floor) > limit:
        return json.dumps({"ok": payload.get("ok") if isinstance(payload, dict) else None,
                           "error": f"observation of {len(full)} chars could not be rendered within "
                                    f"{limit}; re-call the tool with a narrower scope",
                           "truncated": True}, default=str)
    best, lo, hi = floor, 0, max(len(full), limit)
    for _ in range(_CLAMP_SEARCH_STEPS):
        if lo >= hi:
            break
        mid = (lo + hi + 1) // 2
        candidate = json.dumps(_cap_strings(payload, mid), default=str)
        if len(candidate) <= limit:
            best, lo = candidate, mid
        else:
            hi = mid - 1
    return best


def _source_read_fields(result: ToolResult) -> dict | None:
    metadata = result.source_read
    if not isinstance(metadata, dict):
        return None
    path = metadata.get("path")
    bounds = [metadata.get(key) for key in ("start_line", "end_line", "total_lines")]
    partial = metadata.get("partial_line")
    if not isinstance(path, str) or not path or len(path) > 4096 or type(partial) is not bool:
        return None
    if any(type(value) is not int for value in bounds):
        return None
    start, end, total = bounds
    if not 0 <= start <= end <= total <= READ_MAX_FILE_BYTES:
        return None
    if start == 0 and (end != 0 or partial):
        return None
    return {"path": path, "start_line": start, "end_line": end,
            "total_lines": total, "partial_line": partial}


SELF_REVIEW_INTERVAL = 15

_log = get_logger(__name__)


RUN_STATUSES: tuple[str, ...] = ("done", "budget", "error", "maxsteps", "repeat", "stall")


@dataclass
class AgentResult:
    status: str
    final_text: str = ""
    steps: int = 0
    tool_calls: int = 0
    tokens: int = 0
    journal_path: str = ""
    limit_hit: str = ""


def _context_chars(messages: list) -> int:
    total = 0
    for m in messages:
        if isinstance(m, dict):
            body = m.get("content")
            if body is not None:
                total += len(body if isinstance(body, str) else str(body))
    return total


@dataclass
class LoopState:

    spent: int = 0
    n_calls: int = 0
    nudged: bool = False
    empty: int = 0
    stall_retries: int = 0
    truncated: int = 0
    camp_last: str = ""
    pb_last: str = ""
    spec_last: str = ""
    repeat_sig: str = ""
    repeat_n: int = 0
    repeat_advised: bool = False
    obs_args: dict[int, str] = field(default_factory=dict)
    steps_since_test: int = 0
    measure_nudges: int = 0
    steps_since_construct: int = 0
    construct_nudges: int = 0
    adv_last: str = ""
    sends_since_progress: int = 0
    progress_last: dict[str, str] = field(default_factory=dict)
    reads_since_progress: int = 0
    enact_denied: bool = False
    autopush_last: int = -AUTOPUSH_MIN_INTERVAL
    max_call_usd: float = 0.0
    reserved_usd: float = 0.0


@dataclass(frozen=True)
class _CarriedUsage:

    tokens: int = 0
    cost_usd: float = 0.0
    abandoned: int = 0
    unpriced: int = 0
    tokens_reported: bool = True
    cost_reported: bool = True
    provider_usage: dict | None = field(default_factory=lambda: _merge_provider_usage(()))

    @classmethod
    def from_result(cls, result) -> "_CarriedUsage":
        return cls(
            tokens=int(getattr(result, "tokens", 0) or 0),
            cost_usd=float(getattr(result, "cost_usd", 0.0) or 0.0),
            abandoned=int(getattr(result, "abandoned_attempts", 0) or 0),
            unpriced=int(getattr(result, "unpriced_attempts", 0) or 0),
            tokens_reported=getattr(result, "tokens_reported", None) is not False,
            cost_reported=getattr(result, "cost_reported", None) is not False,
            provider_usage=getattr(result, "provider_usage", None),
        )


class ToolCallingLoop:

    def __init__(self, *, backend, registry: ToolRegistry, journal: Journal, system: str,
                 model: str = "opus", max_steps: int = 40, governor: BudgetGovernor | None = None,
                 tool_names: list[str] | None = None, max_obs_chars: int = OBS_WINDOW_CHARS,
                 finish_gate=None, step_nudge=None, max_empty: int = 6, max_truncated: int = 6,
                 max_stall: int = 2, stall_backoff: float = 30.0, sleep=time.sleep,
                 timeout: int = 600, campaign=None, campaign_hook=None, recall_hook=None,
                 measure_nudge=None, specialist_hook=None, construct_nudge=None,
                 force_tool_hook=None, repeatable_nudge=None,
                 compact_read_tools: frozenset[str] | None = None,
                 compact_never_tools: frozenset[str] | None = None,
                 tool_names_resolver=None, allowed_tools=None,
                 self_review_interval: int = 0,
                 compact_keep_recent: int | None = None,
                 stall_stop_after: int = 0, stall_stop_min_pressure: float = 0.5,
                 enactment_break_after: int = 0, enactment_deny_tools: frozenset[str] | None = None,
                 enactment_rearm_tools: frozenset[str] | None = None,
                 role: str = "main") -> None:
        if not hasattr(backend, "chat"):
            raise TypeError("the backend must expose .chat — Shard requires native tool calling, and "
                            "an endpoint without it cannot run the loop")
        self.backend = backend
        self.registry = registry
        self.journal = journal
        self.role = role
        self.system = ensure_compute_runway(system)
        self.model = model
        self.max_steps = max_steps
        self.governor = governor
        self.tool_names = tool_names
        self.max_obs_chars = max_obs_chars
        self.finish_gate = finish_gate
        self.max_empty = max_empty
        self.max_truncated = max_truncated
        self.max_stall = max_stall
        self.stall_backoff = stall_backoff
        self._sleep = sleep
        self.step_nudge = step_nudge
        self.repeatable_nudge = repeatable_nudge
        self.force_tool_hook = force_tool_hook
        self.timeout = timeout
        self.campaign = campaign
        self.campaign_hook = campaign_hook
        self.recall_hook = recall_hook
        self.measure_nudge = measure_nudge
        self.construct_nudge = construct_nudge
        self.specialist_hook = specialist_hook
        self._compact_read_tools = COMPACT_READ_TOOLS if compact_read_tools is None else compact_read_tools
        self._compact_never_tools = (COMPACT_NEVER_TOOLS if compact_never_tools is None
                                     else compact_never_tools)
        self.tool_names_resolver = tool_names_resolver
        self._allowed_union = sorted(allowed_tools) if allowed_tools is not None else None
        self.self_review_interval = max(0, int(self_review_interval or 0))
        self._compact_keep_recent = (COMPACT_KEEP_RECENT if compact_keep_recent is None
                                     else max(1, int(compact_keep_recent)))
        self.stall_stop_after = max(0, int(stall_stop_after or 0))
        self.stall_stop_min_pressure = float(stall_stop_min_pressure)
        self._enact_break_after = max(0, int(enactment_break_after or 0))
        self._enact_deny = ENACTMENT_DENY_TOOLS if enactment_deny_tools is None else frozenset(enactment_deny_tools)
        self._enact_rearm = ENACTMENT_REARM_TOOLS if enactment_rearm_tools is None else frozenset(enactment_rearm_tools)

    def _meter(self, tokens: int, cost_usd: float = 0.0, *, state: LoopState | None = None) -> str:
        if not self.governor:
            return ""
        stop = ""
        exceeded: list[BudgetExceeded] = []
        invalid: list[tuple[str, ValueError]] = []
        for resource, amount in (("tokens", tokens), ("usd", cost_usd)):
            if resource == "usd" and state is not None and state.reserved_usd:
                settled = False
                try:
                    self.governor.settle("usd", state.reserved_usd, cost_usd)
                    settled = True
                except BudgetExceeded as e:
                    settled = True
                    exceeded.append(e)
                    stop = stop or e.resource
                except ValueError as e:
                    invalid.append((resource, e))
                finally:
                    if settled:
                        state.reserved_usd = 0.0
                continue
            if not amount:
                continue
            try:
                self.governor.spend(resource, amount)
            except BudgetExceeded as e:
                exceeded.append(e)
                stop = stop or e.resource
            except ValueError as e:
                invalid.append((resource, e))
        for error in exceeded:
            self._rec("budget_exceeded", detail=str(error))
        for resource, error in invalid:
            self._rec("budget_value_invalid", resource=resource, detail=str(error))
        return "invalid_usage" if invalid else stop

    def _unaffordable_next_call(self, st: LoopState) -> float:
        if self.governor is None or st.max_call_usd <= 0.0:
            return 0.0
        if self.governor.reserve("usd", st.max_call_usd):
            st.reserved_usd = st.max_call_usd
            return 0.0
        return st.max_call_usd - (self.governor.remaining("usd") - self.governor.reserved("usd"))

    def _release_call(self, st: LoopState) -> None:
        if self.governor is not None and st.reserved_usd:
            self.governor.release("usd", st.reserved_usd)
            st.reserved_usd = 0.0

    def _budget_stop(self, st: LoopState, step: int) -> AgentResult | None:
        if self.governor is None:
            return None
        self._release_call(st)
        try:
            self.governor.check()
        except BudgetExceeded as e:
            self._rec("budget_exceeded", detail=str(e))
            return self._result("budget", step - 1, st.n_calls, st.spent, str(e), limit_hit=e.resource)

        if self._unaffordable_next_call(st) <= 0.0:
            return None
        left = self.governor.remaining("usd")
        self._rec("budget_headroom", step=step, resource="usd",
                  need=round(st.max_call_usd, 6), remaining=round(left, 6))
        return self._result(
            "budget", step - 1, st.n_calls, st.spent,
            f"stopping before a call this run cannot afford: the most expensive call so far cost "
            f"${st.max_call_usd:.4f} and ${left:.4f} of the --max-spend-usd ceiling is left",
            limit_hit="usd")

    def _send_and_bill(self, st: LoopState, messages: list, tools: list,
                       step: int) -> tuple[object, str]:
        sent_at = time.monotonic()
        res, carried = self._send_turn(messages, tools, step)
        usage = self._turn_usage(res, carried)
        identity = self._identity_fields(res)
        step_tokens = usage["tokens"]
        step_usd = usage["cost_usd"]
        self._rec("llm_request", step=step, seconds=round(time.monotonic() - sent_at, 3),
                  total_tokens=step_tokens, cost_usd=step_usd,
                  provider_usage=usage["provider_usage"],
                  abandoned=usage["abandoned"], unpriced=usage["unpriced"],
                  tokens_reported=usage["tokens_reported"],
                  cost_reported=usage["cost_reported"], **identity,
                  ok=bool(getattr(res, "ok", True)),
                  finish_reason=getattr(res, "finish_reason", "") or "")
        st.spent += step_tokens
        st.max_call_usd = max(st.max_call_usd, step_usd)
        hit = self._meter(step_tokens, step_usd, state=st)
        gaps = self._usage_gaps(usage)
        for gap in gaps:
            self._rec("llm_usage_gap", step=step, resource=gap.removeprefix("unreported_"),
                      requested_model=identity["requested_model"],
                      served_model=identity["served_model"],
                      identity_verdict=identity["identity_verdict"])
        return res, self._enforced_usage_gap(gaps) or hit

    def _forced_choice(self, step: int):
        if self.force_tool_hook is None:
            return None
        try:
            return self.force_tool_hook(step)
        except Exception as e:
            self._rec("force_tool_hook_error", step=step, error=f"{type(e).__name__}: {e}")
            return None

    def _send_turn(self, messages: list, tools: list,
                   step: int) -> tuple[object, _CarriedUsage]:
        choice = self._forced_choice(step)
        if choice is None:
            return (self.backend.chat(messages, tools, model=self.model, timeout=self.timeout),
                    _CarriedUsage())
        self._rec("force_tool", step=step, tool_choice=choice)
        result = self.backend.chat(messages, tools, model=self.model, timeout=self.timeout,
                                   tool_choice=choice)
        if result.ok:
            return result, _CarriedUsage()
        self._rec("force_tool_rejected", step=step, error=(result.error or "")[:200],
                  **self._identity_fields(result))
        if not getattr(result, "forcing_retry_safe", False):
            return result, _CarriedUsage()
        replacement = self.backend.chat(messages, tools, model=self.model, timeout=self.timeout)
        return replacement, _CarriedUsage.from_result(result)

    def _turn_usage(self, result, carried: _CarriedUsage) -> dict:
        abandoned = int(getattr(result, "abandoned_attempts", 0) or 0) + carried.abandoned
        unpriced = int(getattr(result, "unpriced_attempts", 0) or 0) + carried.unpriced
        tokens_reported = getattr(result, "tokens_reported", None)
        cost_reported = getattr(result, "cost_reported", None)
        if not carried.tokens_reported:
            tokens_reported = False
        if not carried.cost_reported:
            cost_reported = False
        if abandoned:
            tokens_reported = cost_reported = False
        if unpriced:
            cost_reported = False
        return {
            "tokens": int(getattr(result, "tokens", 0) or 0) + carried.tokens,
            "cost_usd": float(getattr(result, "cost_usd", 0.0) or 0.0) + carried.cost_usd,
            "abandoned": abandoned,
            "unpriced": unpriced,
            "tokens_reported": tokens_reported,
            "cost_reported": cost_reported,
            "provider_usage": _merge_provider_usage((carried.provider_usage,
                                                     getattr(result, "provider_usage", None))),
        }

    def _identity_fields(self, result) -> dict:
        return {
            "requested_model": getattr(result, "model", "") or self.model,
            "served_model": getattr(result, "served_model", "") or "",
            "identity_verdict": getattr(result, "identity_verdict", "") or "unreported",
        }

    @staticmethod
    def _usage_gaps(usage: dict) -> tuple[str, ...]:
        gaps = []
        if usage["tokens_reported"] is False:
            gaps.append("unreported_tokens")
        if usage["cost_reported"] is False:
            gaps.append("unreported_usd")
        return tuple(gaps)

    def _enforced_usage_gap(self, gaps: tuple[str, ...]) -> str:
        if self.governor is None:
            return ""
        if self.governor.budget.tokens is not None and "unreported_tokens" in gaps:
            return "unreported_tokens"
        if self.governor.budget.usd is not None and "unreported_usd" in gaps:
            return "unreported_usd"
        return ""

    def _meter_stop_result(self, hit: str, step: int, state: LoopState) -> AgentResult:
        errors = {
            "invalid_usage": "the model endpoint returned a non-finite or negative usage value",
            "unreported_tokens": (
                "the model endpoint did not report token usage, so the finite token ceiling cannot "
                "be enforced"),
            "unreported_usd": (
                "the model endpoint did not report cost, so the finite dollar ceiling cannot be "
                "enforced"),
        }
        if hit in errors:
            return self._result("error", step, state.n_calls, state.spent, errors[hit])
        return self._result("budget", step, state.n_calls, state.spent, "run budget exhausted",
                            limit_hit=hit)

    def _rec(self, type: str, **data) -> dict:
        return self.journal.record(type, role=self.role, **data)

    def _record_source_observation(self, name: str, args: dict, result: ToolResult, obs: str) -> None:
        if name not in {"read_file", "grep"}:
            return
        if name == "read_file" and result.ok:
            fields = _source_read_fields(result)
            if fields is None:
                return
        else:
            path = args.get("path", "." if name == "grep" else None)
            if not isinstance(path, str) or not path or len(path) > 4096:
                return
            fields = {"path": path}
        self._rec("source_read" if name == "read_file" else "source_search", **fields,
                  ok=bool(result.ok), observation_complete=(obs == json.dumps(result.to_dict(), default=str)))

    def _campaign_and_push(self, st: LoopState, messages: list[dict], step: int) -> None:
        stalled = drifting = False
        camp_changed = False
        if self.campaign is not None:
            try:
                summ = self.campaign.summary()
            except Exception as e:
                self._rec("campaign_error", error=f"{type(e).__name__}: {e}")
                summ = ""
            if summ and summ != st.camp_last:
                try:
                    stalled, drifting = self.campaign.is_stalled(), self.campaign.is_drifting()
                except Exception:
                    pass
                head = ("PROGRESS STATE (your own cross-turn record — build on it; do NOT repeat a "
                        "failed hypothesis):")
                if stalled or drifting:
                    directive = ""
                    rt = getattr(self.campaign, "retask_directive", None)
                    if callable(rt):
                        try:
                            directive = rt() or ""
                        except Exception:
                            directive = ""
                    head = (directive + "\nProgress state:") if directive else (
                        "You appear STALLED or DRIFTING — repeating the same input, or your "
                        "crash keeps missing the described defect. CHANGE STRATEGY: re-localize "
                        "the EXACT described sink and reach it a different way (trace the parse "
                        "path, watch the fault dynamically) instead of refining the same bytes. "
                        "Progress state:")
                self._rec("campaign_context", step=step, stalled=stalled, drifting=drifting)
                messages.append({"role": "user", "content": fence(head + "\n" + summ)})
                st.camp_last = summ
                camp_changed = True

        if self.campaign is not None:
            push_open, want_push = camp_changed, (stalled or drifting)
        else:
            push_open = (step - st.autopush_last >= AUTOPUSH_MIN_INTERVAL
                         and (st.steps_since_construct >= CONSTRUCT_INTERVAL
                              or st.steps_since_test >= MEASURE_INTERVAL))
            want_push = push_open
            if push_open:
                st.autopush_last = step

        if push_open and want_push and self.recall_hook is not None:
            try:
                pb = self.recall_hook(self.campaign, step)
            except Exception as e:
                self._rec("recall_hook_error", error=f"{type(e).__name__}: {e}")
                pb = None
            if isinstance(pb, str) and pb.strip() and pb != st.pb_last:
                self._rec("playbook_autorecall", step=step)
                messages.append({"role": "user", "content": pb})
                st.pb_last = pb

        if push_open and self.specialist_hook is not None:
            want_spec = want_push
            if not want_spec:
                reaching = getattr(self.campaign, "is_reaching_uncrashed", None)
                if callable(reaching):
                    try:
                        want_spec = bool(reaching())
                    except Exception:
                        want_spec = False
            if want_spec:
                try:
                    sc = self.specialist_hook(self.campaign, step)
                except Exception as e:
                    self._rec("specialist_hook_error", error=f"{type(e).__name__}: {e}")
                    sc = None
                if isinstance(sc, str) and sc.strip() and sc != st.spec_last:
                    self._rec("specialist_push", step=step)
                    messages.append({"role": "user", "content": sc})
                    st.spec_last = sc

    def _cadence_nudges(self, st: LoopState, messages: list[dict], step: int) -> None:
        if self.step_nudge is not None and not st.nudged:
            try:
                nudge = self.step_nudge(step, messages)
            except Exception as e:
                self._rec("step_nudge_error", error=f"{type(e).__name__}: {e}", kind="once")
                nudge = None
            if isinstance(nudge, str) and nudge.strip():
                self._rec("step_nudge", step=step, text=nudge[:500], kind="once")
                messages.append({"role": "user", "content": nudge})
                st.nudged = True

        if self.repeatable_nudge is not None:
            try:
                rnudge = self.repeatable_nudge(step, messages)
            except Exception as e:
                self._rec("step_nudge_error", error=f"{type(e).__name__}: {e}", kind="repeatable")
                rnudge = None
            if isinstance(rnudge, str) and rnudge.strip():
                self._rec("step_nudge", step=step, text=rnudge[:500], kind="repeatable")
                messages.append({"role": "user", "content": rnudge})

        st.steps_since_test += 1
        nudged_this_step = False
        if (self.measure_nudge is not None and st.steps_since_test >= MEASURE_INTERVAL
                and st.measure_nudges < MEASURE_MAX):
            try:
                mn = self.measure_nudge(st.steps_since_test, step)
            except Exception as e:
                self._rec("measure_nudge_error", error=f"{type(e).__name__}: {e}")
                mn = None
            if isinstance(mn, str) and mn.strip():
                st.measure_nudges += 1
                self._rec("measure_nudge", step=step, since=st.steps_since_test, n=st.measure_nudges)
                messages.append({"role": "user", "content": mn})
                st.steps_since_test = 0
                nudged_this_step = True

        st.steps_since_construct += 1
        if (not nudged_this_step and self.construct_nudge is not None
                and st.steps_since_construct >= CONSTRUCT_INTERVAL and st.construct_nudges < CONSTRUCT_MAX):
            try:
                cn = self.construct_nudge(st.steps_since_construct, step)
            except Exception as e:
                self._rec("construct_nudge_error", error=f"{type(e).__name__}: {e}")
                cn = None
            if isinstance(cn, str) and cn.strip():
                st.construct_nudges += 1
                self._rec("construct_nudge", step=step, since=st.steps_since_construct,
                                    n=st.construct_nudges)
                messages.append({"role": "user", "content": cn})
                st.steps_since_construct = 0

        if (self.self_review_interval > 0 and step % self.self_review_interval == 0
                and step != self.max_steps):
            self._rec("self_review", step=step)
            messages.append({"role": "user", "content": render_self_review(step)})

    def _inject_guidance(self, st: "LoopState", messages: list, step: int,
                         full_adv_names: list[str]) -> list[str] | None:
        self._campaign_and_push(st, messages, step)
        self._cadence_nudges(st, messages, step)


        base_names: list[str] | None = full_adv_names
        if self.tool_names_resolver is not None:
            try:
                resolved = self.tool_names_resolver(step)
            except Exception as e:
                self._rec("tool_resolver_error", step=step, error=f"{type(e).__name__}: {e}")
                resolved = None
            if resolved is not None:
                base_names = list(resolved)
                adv_sig = ",".join(base_names)
                if adv_sig != st.adv_last:
                    self._rec("tools_advertised", step=step, tools=adv_sig)
                    st.adv_last = adv_sig
            else:
                base_names = None
        return base_names

    def _execute_calls(self, st: LoopState, step: int, messages: list[dict],
                       exec_calls: list) -> tuple[AgentResult | None, bool]:
        progressed = False
        for tc in exec_calls:
            st.n_calls += 1
            sig = f"{tc.name}:{json.dumps(tc.arguments, sort_keys=True)}"
            if sig == st.repeat_sig:
                st.repeat_n += 1
            else:
                st.repeat_sig, st.repeat_n, st.repeat_advised = sig, 1, False

            _tool = self.registry.get(tc.name)
            tool_metadata = _tool_metadata(_tool)
            _enforce = self._allowed_union if self.tool_names_resolver is not None else self.tool_names
            if (self._enact_break_after > 0 and st.reads_since_progress >= self._enact_break_after
                    and (tc.name in self._enact_deny
                         or (tc.name == "run_bash" and _is_read_shaped_bash(tc.arguments)))):
                self._rec("enactment_reject", key=sig, name=tc.name, reads=st.reads_since_progress)
                result = ToolResult(False, error=(
                    f"reads are DISABLED (including `cat`/`grep`/`sed` via run_bash) — you have inspected "
                    f"{st.reads_since_progress} calls without constructing or testing a candidate. Build an "
                    "input NOW: use_corpus / build_emit / emit_struct (or a run_bash that WRITES ./poc, e.g. "
                    "`python3 -c '...struct.pack...' > ./poc`), then test_poc."))
            elif _enforce is not None and tc.name not in _enforce:
                self._rec("tool_rejected", key=sig, name=tc.name)
                _hint = suggest_tool(tc.name, _enforce)
                result = ToolResult(False, error=(
                    f"tool {tc.name!r} is not available in this context — you may only call: "
                    f"{', '.join(_enforce)}." + (f" Did you mean {_hint!r}?" if _hint else "")))
            elif _tool is None:
                _hint = suggest_tool(tc.name, self.registry.names())
                self._rec("tool_unknown", key=sig, name=tc.name)
                result = ToolResult(False, error=(
                    f"unknown tool {tc.name!r}." + (f" Did you mean {_hint!r}?" if _hint else "")
                    + f" Available: {', '.join(self.registry.names())}"))
            elif (_bad := validate_call_args(_tool.args_schema, tc.arguments)) is not None:
                self._rec("tool_args_invalid", key=sig, name=tc.name, detail=_bad)
                result = ToolResult(False, error=f"{tc.name}: {_bad}")
            else:
                result = self.registry.call(tc.name, tc.arguments)
                if tc.name == "test_poc":
                    st.steps_since_test = 0
                if tc.name in CONSTRUCT_PROGRESS_TOOLS:
                    st.steps_since_construct = 0
                if tc.name in self._enact_rearm and _is_enactment_measurement(result):
                    st.reads_since_progress = 0
                else:
                    st.reads_since_progress += 1
                if self.stall_stop_after > 0 and tc.name in STALL_PROGRESS_TOOLS:
                    _psig = _stall_outcome_sig(result)
                    if st.progress_last.get(tc.name) != _psig:
                        st.progress_last[tc.name] = _psig
                        progressed = True
                if self.campaign_hook is not None:
                    try:
                        self.campaign_hook(tc.name, tc.arguments, result)
                    except Exception as e:
                        self._rec("campaign_hook_error", error=f"{type(e).__name__}: {e}")
            obs = clamp_observation(result.to_dict(), self.max_obs_chars)
            self._record_source_observation(tc.name, tc.arguments, result, obs)

            if st.repeat_n >= REPEAT_BREAK_AT:
                _log.warning("[%s] repeat-breaker STOPPING run: %s called with identical args %dx",
                             self.role, tc.name, st.repeat_n)
                self._rec("repeat_break", key=sig, n=st.repeat_n)
                messages.append({"role": "tool", "tool_call_id": tc.id, "name": tc.name, "content": obs})
                return self._result("repeat", step, st.n_calls, st.spent,
                                    f"stopped: {tc.name} called with identical args {st.repeat_n}x in a "
                                    f"row with no progress"), progressed
            if st.repeat_n >= REPEAT_ADVISORY_AT and not st.repeat_advised:
                st.repeat_advised = True
                self._rec("repeat_advisory", key=sig, n=st.repeat_n)
                obs = obs + "\n\n" + (
                    f"NOTE: you have called {tc.name} with identical arguments {st.repeat_n} times and it "
                    f"returns the SAME result each time. Change approach — different arguments, a "
                    f"different tool, or finish — or the run will be STOPPED.")

            self._rec("tool_result", key=sig, result=result.to_dict(), tool_metadata=tool_metadata)
            idx = len(messages)
            messages.append({"role": "tool", "tool_call_id": tc.id, "name": tc.name, "content": obs})
            st.obs_args[idx] = json.dumps(tc.arguments, sort_keys=True)[:200]
        return None, progressed


    def _cap_tool_calls(self, res, messages: list[dict], step: int) -> tuple[list, bool]:
        if len(res.tool_calls) <= MAX_TOOLCALLS_PER_TURN:
            return res.tool_calls, False

        sigs = [f"{tc.name}:{json.dumps(tc.arguments, sort_keys=True)}" for tc in res.tool_calls]
        seen: set[str] = set()
        kept_idx: list[int] = []
        for i, sig in enumerate(sigs):
            if sig in seen:
                continue
            seen.add(sig)
            kept_idx.append(i)
            if len(kept_idx) >= MAX_TOOLCALLS_PER_TURN:
                break
        exec_calls = [res.tool_calls[i] for i in kept_idx]
        self._rec("toolcall_cap", step=step, original=len(res.tool_calls),
                  executed=len(exec_calls), unique=len(set(sigs)))

        assistant = messages[-1]
        raw_calls = assistant.get("tool_calls") if isinstance(assistant, dict) else None
        if isinstance(raw_calls, list) and len(raw_calls) == len(res.tool_calls):
            assistant["tool_calls"] = [raw_calls[i] for i in kept_idx]
        return exec_calls, True


    def run(self, goal: str) -> AgentResult:
        st = LoopState()
        try:
            return self._run(goal, st)
        finally:
            self._release_call(st)

    def _run(self, goal: str, st: LoopState) -> AgentResult:
        tools = self.registry.openai_tools(self.tool_names)
        full_adv_names = [t["function"]["name"] for t in tools]
        messages: list = [{"role": "system", "content": self.system},
                          {"role": "user", "content": goal}]
        self._rec("loop_start", max_steps=self.max_steps,
                  self_review_interval=self.self_review_interval,
                  enactment_break_after=self._enact_break_after)
        self._rec("goal", text=goal)

        for step in range(1, self.max_steps + 1):
            stopped = self._budget_stop(st, step)
            if stopped is not None:
                return stopped

            if self.stall_stop_after > 0 and st.sends_since_progress >= self.stall_stop_after:
                pressure = self.governor.pressure("tokens") if self.governor is not None else 0.0
                if pressure >= self.stall_stop_min_pressure:
                    self._rec("stall_stop", step=step, since_progress=st.sends_since_progress,
                                        pressure=round(pressure, 4))
                    return self._result("stall", step - 1, st.n_calls, st.spent,
                                        f"stopped: {st.sends_since_progress} sends with no progress toward a "
                                        f"crash at {pressure:.0%} of the token budget")

            base_names = self._inject_guidance(st, messages, step, full_adv_names)

            deny_active = self._enact_break_after > 0 and st.reads_since_progress >= self._enact_break_after
            if deny_active != st.enact_denied:
                self._rec("enactment_break" if deny_active else "enactment_rearm",
                                    step=step, reads=st.reads_since_progress)
                st.enact_denied = deny_active
            if base_names is not None:
                names = [n for n in base_names if not (deny_active and n in self._enact_deny)]
                tools = self.registry.openai_tools(names)

            before_chars = _context_chars(messages)
            compacted = self._compact(messages, st.obs_args)
            after_chars = _context_chars(messages) if compacted else before_chars
            if compacted:
                _log.debug("[%s] step %d: compaction stubbed %d observation(s)",
                           self.role, step, compacted)
                self._rec("context_compacted", step=step, stubbed=compacted,
                          chars_before=before_chars, chars_after=after_chars)
            self._rec("context_size", step=step, messages=len(messages), chars=after_chars)

            res, hit = self._send_and_bill(st, messages, tools, step)
            if hit:
                return self._meter_stop_result(hit, step, st)
            if not res.ok:
                if res.empty_retry_safe and st.empty < self.max_empty:
                    st.empty += 1
                    self._rec("empty_retry", n=st.empty, error=(res.error or "")[:200])
                    continue
                if res.stall_retry_safe and st.stall_retries < self.max_stall:
                    st.stall_retries += 1
                    self._rec("stall_retry", n=st.stall_retries, error=(res.error or "")[:200])
                    self._sleep(self.stall_backoff * st.stall_retries)
                    continue
                self._rec("llm_error", error=res.error)
                return self._result("error", step - 1, st.n_calls, st.spent, res.error)
            st.empty = 0
            st.stall_retries = 0
            self._rec("assistant", text=(res.text or "")[:2000],
                                tool_calls=[tc.name for tc in res.tool_calls])

            if res.finish_reason == "length":
                if st.truncated < self.max_truncated:
                    st.truncated += 1
                    self._rec("truncated_turn", n=st.truncated)
                    messages.append({"role": "user", "content": (
                        "Your previous turn hit the token limit before finishing — continue and emit your "
                        "next tool call.")})
                    continue
                error = f"model hit the token limit {st.truncated + 1} consecutive times"
                self._rec("llm_error", error=error)
                return self._result("error", step, st.n_calls, st.spent, error)

            messages.append(res.raw_message or {"role": "assistant", "content": res.text})

            if not res.tool_calls:
                if self.finish_gate is not None:
                    try:
                        reason = self.finish_gate(res.text)
                    except Exception as e:
                        self._rec("finish_gate_error", error=f"{type(e).__name__}: {e}")
                        return self._result("error", step, st.n_calls, st.spent,
                                            f"finish gate failed: {type(e).__name__}: {e}")
                    if reason:
                        self._rec("finish_rejected", reason=str(reason)[:500])
                        messages.append({"role": "user", "content": str(reason)})
                        continue
                self._rec("final", text=(res.text or "")[:4000])
                return self._result("done", step, st.n_calls, st.spent, res.text or "")

            exec_calls, capped_turn = self._cap_tool_calls(res, messages, step)

            st.truncated = 0
            early, progressed = self._execute_calls(st, step, messages, exec_calls)
            if early is not None:
                return early

            if capped_turn:
                messages.append({"role": "user", "content": (
                    f"You emitted {len(res.tool_calls)} tool calls in ONE turn — only {len(exec_calls)} "
                    f"were executed; the rest were DROPPED. You appear to be repeating the same action (a "
                    f"degeneration loop). STOP: choose the SINGLE most useful next step and emit just that "
                    f"one tool call.")})

            st.sends_since_progress = 0 if progressed else st.sends_since_progress + 1

        return self._result("maxsteps", self.max_steps, st.n_calls, st.spent, "reached max steps without finishing")

    def _compact(self, messages: list, obs_args: dict[int, str]) -> int:
        tool_idxs = [i for i, m in enumerate(messages)
                     if isinstance(m, dict) and m.get("role") == "tool"]
        keep = self._compact_keep_recent
        if len(tool_idxs) <= keep:
            return 0
        n = 0
        for i in tool_idxs[:-keep]:
            m = messages[i]
            body = m.get("content", "")
            name = m.get("name", "")
            if (not isinstance(body, str) or body.startswith(COMPACT_STUB_PREFIX)
                    or name in self._compact_never_tools or name not in self._compact_read_tools
                    or len(body) <= COMPACT_MIN_CHARS):
                continue
            first_line = body.split("\n", 1)[0][:200]
            m["content"] = (f"{COMPACT_STUB_PREFIX} {name}({obs_args.get(i, '')}) first_line={first_line!r} "
                            f"bytes={len(body)} — elided to reclaim context; re-run the tool to see full.")
            n += 1
        return n

    def _result(self, status: str, steps: int, n_calls: int, tokens: int, final_text: str,
                limit_hit: str = "") -> AgentResult:
        return AgentResult(status=status, final_text=final_text, steps=steps, tool_calls=n_calls,
                           tokens=tokens, journal_path=str(self.journal.path), limit_hit=limit_hit)
