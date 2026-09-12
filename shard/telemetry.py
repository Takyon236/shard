
from __future__ import annotations

import json
from typing import Any, Iterable

from shard.journal import _MAX_JOURNAL_BYTES
from shard import providermetrics as _provider_metrics
from shard import telemetryfacts as _facts

SCHEMA = 1

CHARS_PER_TOKEN = 4

TEXT_FIELDS: tuple[str, ...] = ("text", "data", "error", "result", "goal", "final")

_UNNAMED_TOOL = "<unnamed>"


def _events(source: Any) -> list[dict]:
    if isinstance(source, (str, bytes)) or hasattr(source, "__fspath__"):
        import pathlib
        try:
            with pathlib.Path(source).open("rb") as journal:
                raw = journal.read(_MAX_JOURNAL_BYTES + 1)
        except OSError:
            return []
        if len(raw) > _MAX_JOURNAL_BYTES:
            raise ValueError("telemetry journal exceeds the byte limit")
        lines: Iterable = raw.decode("utf-8", errors="replace").split("\n")
    else:
        lines = source
    out: list[dict] = []
    for line in lines:
        if isinstance(line, dict):
            out.append(line)
            continue
        try:
            row = json.loads(line)
        except (ValueError, TypeError):
            continue
        if isinstance(row, dict):
            out.append(row)
    return out


def _tool_metadata(tool) -> dict | None:
    if tool is None:
        return None
    return {"name": tool.name, "arguments": list(tool.args_schema)}


def _tool_identity(event: dict) -> tuple[str, tuple[str, ...]]:
    metadata = event.get("tool_metadata")
    if isinstance(metadata, dict):
        name, arguments = metadata.get("name"), metadata.get("arguments")
        if (isinstance(name, str) and name and isinstance(arguments, list)
                and all(isinstance(arg, str) and arg for arg in arguments)
                and len(set(arguments)) == len(arguments)):
            return name, tuple(arguments)
    return _UNNAMED_TOOL, ()


def _safe_args(key: str, declared: tuple[str, ...]) -> dict:
    if not declared:
        return {}
    if not isinstance(key, str):
        return {"_unparsed": True}
    _, _, raw = key.partition(":")
    if not raw:
        return {}
    try:
        args = json.loads(raw)
    except ValueError:
        return {"_unparsed": True}
    if not isinstance(args, dict):
        return {"_unparsed": True}
    out = {}
    for name in declared:
        if name not in args:
            continue
        value = args[name]
        if isinstance(value, bool):
            out[name] = "bool"
        elif isinstance(value, (int, float)):
            out[name] = type(value).__name__
        else:
            out[name] = f"{type(value).__name__}[{len(str(value))}]"
    return out


def _result_shape(result: Any) -> tuple[bool, int]:
    if not isinstance(result, dict):
        return True, len(str(result or ""))
    ok = bool(result.get("ok", True))
    body = result.get("data")
    size = len(json.dumps(body, default=str)) if body is not None else 0
    size += len(str(result.get("error") or ""))
    return ok, size


def context_curve(events: Iterable[dict]) -> list[dict]:
    return _facts.context_curve(events, CHARS_PER_TOKEN, [])


def _tool_usage(events: list[dict]) -> dict[str, dict]:
    tools: dict[str, dict] = {}
    for ev in events:
        if ev.get("type") != "tool_result":
            continue
        name, declared = _tool_identity(ev)
        ok, size = _result_shape(ev.get("result"))
        row = tools.setdefault(name, {"calls": 0, "failed": 0, "bytes_returned": 0, "args": {}})
        row["calls"] += 1
        row["failed"] += 0 if ok else 1
        row["bytes_returned"] += size
        for arg, shape in _safe_args(ev.get("key", ""), declared).items():
            row["args"].setdefault(arg, shape)
    return tools


def _llm_usage(events: list[dict], gaps: list[str]) -> dict:
    reqs = [e for e in events if e.get("type") == "llm_request"]
    if not reqs:
        gaps.append("no per-request token accounting in this journal (no `llm_request` events) — "
                    "the run's total is in the report's cost line, but it cannot be attributed to a step")
        return {}
    llm = {"requests": len(reqs)}
    measurements = [_provider_metrics.validated(row.get("provider_usage")) for row in reqs]
    _provider_totals(llm, measurements, gaps)
    seconds, complete_time = _call_totals(llm, reqs, measurements, gaps)
    complete_output = False
    for field in _provider_metrics.TOKEN_FIELDS:
        complete = _split_tokens(llm, field, reqs, measurements, gaps)
        if field == "output_tokens":
            complete_output = complete
    if complete_output and "output_tokens" in llm:
        _output_rates(llm, len(reqs), seconds if complete_time else None, gaps)
    return llm


def _provider_totals(llm, measurements, gaps) -> None:
    known = [row for row in measurements if row is not None]
    merged = _provider_metrics.merge(known) if known else None
    missing = len(measurements) - len(known) if merged is not None else len(measurements)
    if merged is not None:
        llm["provider_requests"] = merged["requests"]
        llm["provider_seconds_total"] = round(merged["seconds"], 2)
    if missing:
        llm["provider_unreported_calls"] = missing
        gaps.append(f"provider request counts and timing were not reported for {missing} recorded "
                    "model call(s) — known provider totals are a floor")


def _call_totals(llm, reqs, measurements, gaps) -> tuple[float | None, bool]:
    tokens = [_provider_metrics.integer(row.get("total_tokens")) for row in reqs]
    known_tokens = [value for value in tokens if value is not None]
    if known_tokens:
        llm["total_tokens"] = sum(known_tokens)
    token_gaps = sum(value is None or _usage_missing(row, "tokens_reported", measured)
                     for row, value, measured in zip(reqs, tokens, measurements))
    cost_gaps = sum(_usage_missing(row, "cost_reported", measured)
                    for row, measured in zip(reqs, measurements))
    if token_gaps:
        llm["token_unreported_requests"] = token_gaps
        gaps.append(f"token usage was not reported for {token_gaps} recorded model call(s) — token "
                    "totals are a floor")
    if cost_gaps:
        llm["cost_unreported_requests"] = cost_gaps
        gaps.append(f"cost was not reported for {cost_gaps} recorded model call(s) — dollar totals "
                    "are a floor")
    secs = [_provider_metrics.duration(row.get("seconds")) for row in reqs]
    known_secs = [value for value in secs if value is not None]
    seconds = _provider_metrics.duration(sum(known_secs)) if known_secs else None
    complete = seconds is not None and len(known_secs) == len(reqs)
    if seconds is not None:
        llm["seconds_total"] = round(seconds, 2)
        llm["seconds_slowest"] = round(max(known_secs), 2)
    if not complete:
        gaps.append("some recorded model-call seconds are missing or invalid — known durations "
                    "are a floor and cannot establish an output rate")
    return seconds, complete


def _usage_missing(row, flag, measured) -> bool:
    return (flag in row and row[flag] is not True
            and not (row[flag] is None and measured is not None and measured["requests"] == 0))


def _split_tokens(llm, field, reqs, measurements, gaps) -> bool:
    values, reported, complete = [], 0, True
    for row, measured in zip(reqs, measurements):
        value = _provider_metrics.integer((measured if measured is not None else row).get(field))
        if value is not None:
            values.append(value)
        if measured is None:
            complete = complete and value is not None
        else:
            coverage = measured.get(field + "_reported_requests", 0)
            reported += coverage
            complete = complete and coverage == measured["requests"]
    if values:
        llm[field] = sum(values)
    if any(row is not None for row in measurements):
        llm[field + "_reported_requests"] = reported
    if not complete and (values or any(row is not None for row in measurements)):
        gaps.append(f"{field} was not reported for every provider request in the recorded calls — "
                    "known token totals are a floor")
    return complete


def _output_rates(llm, calls, seconds, gaps) -> None:
    for key, denominator in (("output_per_request", calls), ("output_per_second", seconds)):
        if denominator is None or denominator <= 0:
            continue
        try:
            rate = _provider_metrics.duration(llm["output_tokens"] / denominator)
        except OverflowError:
            rate = None
        if rate is not None:
            llm[key] = round(rate, 1)
        else:
            gaps.append("recorded output totals exceed the numeric range for rate calculation")


def _context_summary(events: list[dict], gaps: list[str]) -> dict:
    curve = _facts.context_curve(events, CHARS_PER_TOKEN, gaps)
    sized = [r for r in curve if isinstance(r.get("chars"), int)]
    compactions = [r for r in curve if r.get("event") == "compaction"]
    context: dict = {"compactions": len(compactions), "curve": curve}
    if sized:
        peak = max(sized, key=lambda r: r["chars"])
        context |= {"peak_chars": peak["chars"], "peak_est_tokens": peak["est_tokens"],
                    "peak_at_step": peak["step"],
                    "peak_messages": peak.get("messages")}
    else:
        gaps.append("no valid context-size sampling in this journal — the "
                    "compaction COUNT is known and the growth curve that would make a compaction "
                    "policy tunable is not")
    return context


def _run_summary(events: list[dict], gaps: list[str]) -> dict:
    return _facts.run_summary(events, gaps)


def _attribute_wall_clock(run: dict, llm: dict, gaps: list[str]) -> None:
    wall = _provider_metrics.duration(run.get("wall_seconds"))
    spent = _provider_metrics.duration(llm.get("provider_seconds_total"))
    if wall is None or wall <= 0:
        gaps.append("provider-request share is unavailable because the journal wall span is "
                    "missing, invalid or zero")
    elif spent is not None and not llm.get("provider_unreported_calls"):
        share = _provider_metrics.duration(spent / wall)
        if share is not None:
            run["llm_share"] = round(share, 3)
            run["llm_share_basis"] = "provider_request_seconds"
            if share > 1:
                gaps.append("summed provider-request seconds exceed the journal's own span — "
                            "requests may overlap; this ratio is not an exclusive wall-clock share")
    else:
        gaps.append("time inside provider requests is unknown or incompletely reported for this "
                    "run — recorded model-call durations also include local retry waits")


def summarise(source: Any) -> dict:
    events = _events(source)
    gaps: list[str] = []
    if not events:
        return {"schema": SCHEMA, "chars_per_token": CHARS_PER_TOKEN, "run": {},
                "gaps": ["the journal was empty or unreadable"]}

    tools = _tool_usage(events)
    if _UNNAMED_TOOL in tools:
        gaps.append(f"tool identity was not established by registry metadata for "
                    f"{tools[_UNNAMED_TOOL]['calls']} result(s) — tool and argument names were withheld")
    llm = _llm_usage(events, gaps)
    context = _context_summary(events, gaps)
    run = _run_summary(events, gaps)
    _attribute_wall_clock(run, llm, gaps)
    return {"schema": SCHEMA, "chars_per_token": CHARS_PER_TOKEN,
            "run": run, "llm": llm, "tools": tools, "context": context, "gaps": gaps}


def render_log(source: Any) -> str:
    return _render_document(summarise(source))


def _render_document(doc: dict) -> str:
    if not doc.get("run"):
        return "shard: no journal events — the run wrote nothing, or the file is unreadable.\n"

    out: list[str] = ["=" * 72, "SHARD RUN LOG", "=" * 72]
    run = doc.get("run", {})
    out.append(f"turns {run.get('model_turns', '?')}"
               + (f"/{run['max_steps']}" if "max_steps" in run else "")
               + f"   journal span {run.get('wall_seconds', '?')}s"
               + f"   status {run.get('status', '?')}"
               + f"   ({run.get('journal_events', '?')} journal events)")
    out.extend(_llm_lines(doc.get("llm", {}), run))
    out.extend(_execution_lines(run.get("execution")))

    out += ["", "TOOLS", "-" * 72]
    for name, row in sorted(doc.get("tools", {}).items(), key=lambda kv: -kv[1]["calls"]):
        failed = f"  {row['failed']} failed" if row["failed"] else ""
        out.append(f"  {name:<18} {row['calls']:>3} calls   "
                   f"{row['bytes_returned']:>9,} bytes returned{failed}")

    ctx = doc.get("context", {})
    out += ["", "CONTEXT", "-" * 72]
    if "peak_chars" in ctx:
        out.append(f"  peak {ctx['peak_chars']:,} chars (~{ctx['peak_est_tokens']:,} est tokens) "
                   f"at step {ctx['peak_at_step']}")
    out.append(f"  {ctx.get('compactions', 0)} compaction(s)")
    for row in ctx.get("curve", []):
        if row.get("event") != "compaction":
            continue
        reclaimed = row.get("reclaimed_chars")
        out.append(f"    step {row.get('step')}: stubbed {row.get('stubbed')}"
                   + (f", reclaimed {reclaimed:,} chars" if isinstance(reclaimed, int)
                      else ", amount reclaimed NOT MEASURED"))

    if doc.get("gaps"):
        out += ["", "WHAT THIS RUN COULD NOT MEASURE", "-" * 72]
        out += [f"  - {g}" for g in doc["gaps"]]

    out += ["", "=" * 72,
            "Arguments and tool output are described, never quoted: this file is safe to forward.",
            "The raw transcript contains private source and model content and is not included "
            "in these outputs.", ""]
    return "\n".join(out)


def _llm_lines(llm: dict, run: dict) -> list[str]:
    if not llm.get("requests"):
        return []
    total = llm.get("total_tokens")
    out = [f"llm   {llm['requests']} recorded model call(s)"
           + (f"   {total:,} tokens" if isinstance(total, int) else "   tokens not reported")
           + (f"   slowest call {llm['seconds_slowest']}s" if "seconds_slowest" in llm else "")]
    if "provider_requests" in llm:
        out.append(f"      {llm['provider_requests']} measured provider request(s), "
                   f"{llm['provider_seconds_total']}s inside provider requests "
                   "(transport and response handling; retry waits excluded)")
    share = run.get("llm_share")
    if isinstance(share, (int, float)):
        percentage = _provider_metrics.duration(share * 100)
        if percentage is None:
            out.append("      provider-request time / journal wall span: percentage unavailable "
                       "because the conversion exceeds the finite numeric range")
        else:
            out.append(f"      provider-request time / journal wall span: {percentage:.0f}%")
    if "output_per_request" in llm:
        rate = (f"; {llm['output_per_second']:.0f} output tok/s over recorded call time"
                if "output_per_second" in llm else "")
        out.append(f"      {llm['output_per_request']:,.0f} output tokens per recorded call{rate}")
    return out


def _execution_lines(ex: dict | None) -> list[str]:
    out: list[str] = []
    if ex:
        out.append(f"exec  armed={ex.get('armed')}  {ex.get('calls', '?')} calls "
                   f"({ex.get('entry_calls', '?')} run_entry, {ex.get('shell_calls', '?')} shell)  "
                   f"network={ex.get('network')}")
        if ex.get("armed") is not True:
            out.append("      execution tools were not armed" if ex.get("armed") is False else
                       "      whether execution tools were armed is UNKNOWN")
            return out
        refused = ex.get("refused")
        if refused is None:
            out.append("      the execution ceiling's bind signal is ABSENT from this run's journal — "
                       "whether it cut the run short is not recorded either way")
        elif refused:
            out.append(f"      CUT SHORT: the execution ceiling refused {refused} call(s). Some claim "
                       f"here was reasoned about rather than checked — treat any finding that is not "
                       f"gate-eligible as unconfirmed. Raising --max-steps raises this budget too")
        elif ex.get("spent") is True:
            out.append(f"      SPENT IN FULL: every one of the {ex.get('budget')} executions was "
                       f"used and none was refused. The model is told how many remain, so it stops "
                       f"asking rather than being denied — treat this as a ceiling that MAY have cut "
                       f"the run short. Raising --max-steps raises this budget too")
        elif ex.get("spent") is False:
            out.append("      the execution ceiling refused nothing and was not spent in full, so no "
                       "claim here was cut short by it")
        else:
            out.append("      the execution ceiling refused nothing; whether it was spent in full "
                       "is UNKNOWN, so whether it cut the run short is not established")

    return out


__all__ = ["CHARS_PER_TOKEN", "SCHEMA", "TEXT_FIELDS", "context_curve", "render_log", "summarise"]
