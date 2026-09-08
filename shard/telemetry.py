
from __future__ import annotations

import json
from typing import Any, Iterable

SCHEMA = 1

CHARS_PER_TOKEN = 4

TEXT_FIELDS: tuple[str, ...] = ("text", "data", "error", "result", "goal", "final")


def _est_tokens(chars: int) -> int:
    return int(chars) // CHARS_PER_TOKEN


def _events(source: Any) -> list[dict]:
    if isinstance(source, (list, tuple)) and (not source or isinstance(source[0], dict)):
        return [e for e in source if isinstance(e, dict)]
    if isinstance(source, (str, bytes)) or hasattr(source, "__fspath__"):
        import pathlib
        try:
            lines: Iterable[str] = pathlib.Path(source).read_text(
                encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return []
    else:
        lines = source
    out: list[dict] = []
    for line in lines:
        try:
            row = json.loads(line)
        except (ValueError, TypeError):
            continue
        if isinstance(row, dict):
            out.append(row)
    return out


def _tool_name(key: str) -> str:
    return (key or "").split(":", 1)[0] or "?"


def _safe_args(key: str) -> dict:
    _, _, raw = (key or "").partition(":")
    if not raw:
        return {}
    try:
        args = json.loads(raw)
    except ValueError:
        return {"_unparsed": True}
    if not isinstance(args, dict):
        return {"_unparsed": True}
    out = {}
    for name, value in args.items():
        if isinstance(value, bool):
            out[str(name)] = "bool"
        elif isinstance(value, (int, float)):
            out[str(name)] = type(value).__name__
        else:
            out[str(name)] = f"{type(value).__name__}[{len(str(value))}]"
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
    curve: list[dict] = []
    last_chars: int | None = None
    for ev in events:
        kind = ev.get("type")
        if kind == "context_size":
            chars = int(ev.get("chars") or 0)
            row = {"step": ev.get("step"), "messages": ev.get("messages"), "chars": chars,
                   "est_tokens": _est_tokens(chars)}
            last_chars = chars
            curve.append(row)
        elif kind == "context_compacted":
            after = ev.get("chars_after")
            before = ev.get("chars_before", last_chars)
            row = {"step": ev.get("step"), "event": "compaction",
                   "stubbed": ev.get("stubbed"),
                   "chars_before": before, "chars_after": after}
            if isinstance(before, int) and isinstance(after, int):
                row["reclaimed_chars"] = before - after
                row["reclaimed_est_tokens"] = _est_tokens(before - after)
                last_chars = after
            curve.append(row)
    return curve


def _tool_usage(events: list[dict]) -> dict[str, dict]:
    tools: dict[str, dict] = {}
    for ev in events:
        if ev.get("type") != "tool_result":
            continue
        name = _tool_name(ev.get("key", ""))
        ok, size = _result_shape(ev.get("result"))
        row = tools.setdefault(name, {"calls": 0, "failed": 0, "bytes_returned": 0, "args": {}})
        row["calls"] += 1
        row["failed"] += 0 if ok else 1
        row["bytes_returned"] += size
        for arg, shape in _safe_args(ev.get("key", "")).items():
            row["args"].setdefault(arg, shape)
    return tools


def _llm_usage(events: list[dict], gaps: list[str]) -> dict:
    reqs = [e for e in events if e.get("type") == "llm_request"]
    llm: dict = {"requests": len(reqs)} if reqs else {}
    if reqs:
        for field in ("input_tokens", "output_tokens", "cached_tokens", "total_tokens"):
            values = [int(r[field]) for r in reqs if isinstance(r.get(field), (int, float))]
            if values:
                llm[field] = sum(values)
        secs = [float(r["seconds"]) for r in reqs if isinstance(r.get("seconds"), (int, float))]
        if secs:
            llm["seconds_total"] = round(sum(secs), 2)
            llm["seconds_slowest"] = round(max(secs), 2)

        out_tokens = llm.get("output_tokens")
        if isinstance(out_tokens, int) and reqs:
            llm["output_per_request"] = round(out_tokens / len(reqs), 1)
        if isinstance(out_tokens, int) and secs and sum(secs) > 0:
            llm["output_per_second"] = round(out_tokens / sum(secs), 1)
        token_gaps = sum(r.get("tokens_reported") is False for r in reqs)
        cost_gaps = sum(r.get("cost_reported") is False for r in reqs)
        if token_gaps:
            llm["token_unreported_requests"] = token_gaps
            gaps.append(f"token usage was not reported for {token_gaps} model request(s) — token "
                        "totals are a floor")
        if cost_gaps:
            llm["cost_unreported_requests"] = cost_gaps
            gaps.append(f"cost was not reported for {cost_gaps} model request(s) — dollar totals "
                        "are a floor")
    else:
        gaps.append("no per-request token accounting in this journal (no `llm_request` events) — "
                    "the run's total is in the report's cost line, but it cannot be attributed to a step")
    return llm


def _context_summary(events: list[dict], gaps: list[str]) -> dict:
    curve = context_curve(events)
    sized = [r for r in curve if isinstance(r.get("chars"), int)]
    compactions = [r for r in curve if r.get("event") == "compaction"]
    context: dict = {"compactions": len(compactions), "curve": curve}
    if sized:
        peak = max(sized, key=lambda r: r["chars"])
        context |= {"peak_chars": peak["chars"], "peak_est_tokens": peak["est_tokens"],
                    "peak_at_step": peak["step"],
                    "peak_messages": peak.get("messages")}
    else:
        gaps.append("no context-size sampling in this journal (no `context_size` events) — the "
                    "compaction COUNT is known and the growth curve that would make a compaction "
                    "policy tunable is not")
    return context


def _run_summary(events: list[dict], gaps: list[str]) -> dict:
    stamps = [e["ts"] for e in events if isinstance(e.get("ts"), (int, float))]
    steps = [e["step"] for e in events if isinstance(e.get("step"), int)]

    run: dict = {"journal_events": len(events),
                 "model_turns": sum(1 for e in events if e.get("type") == "assistant"),
                 "last_journal_step": max(steps) if steps else 0}
    if len(stamps) > 1:
        run["wall_seconds"] = round(max(stamps) - min(stamps), 2)
    for kind, keys in (("loop_start", ("max_steps",)),
                       ("simple_proposed", ("status",)),
                       ("simple_adjudicated", ("findings", "gate_eligible")),
                       ("simple_exec", ("armed", "calls", "entry_calls", "shell_calls", "network",
                                        "budget", "refused", "exhausted", "spent"))):
        found = next((e for e in events if e.get("type") == kind), None)
        if found is None:
            continue
        bucket = {"loop_start": run, "simple_proposed": run,
                  "simple_adjudicated": run, "simple_exec": None}[kind]
        target = bucket if bucket is not None else {}
        for k in keys:
            if k in found:
                target[k] = found[k]
        if kind == "simple_proposed" and "count" in found:
            run["claims_proposed"] = found["count"]
        if kind == "simple_exec":
            run["execution"] = target

    if "execution" not in run:
        gaps.append("no `simple_exec` record — this run did not report whether the execution tools "
                    "were armed, which is not the same as their being off")
    elif "refused" not in run["execution"]:
        gaps.append("this journal predates the execution-budget bind signal — it cannot say whether "
                    "the ceiling refused a call, so `budget` and `calls` being equal does NOT mean "
                    "the run was cut short, nor that it was not")
    return run


def _attribute_wall_clock(run: dict, llm: dict, gaps: list[str]) -> None:
    wall = run.get("wall_seconds")
    spent = llm.get("seconds_total")
    if isinstance(wall, (int, float)) and isinstance(spent, (int, float)) and wall > 0:
        run["llm_share"] = round(spent / wall, 3)
        if run["llm_share"] > 1.0:
            gaps.append(f"model seconds ({spent:,.0f}) exceed the journal's own span ({wall:,.0f}) — "
                        f"one of the two is wrong, so read neither as the run's cost")
    elif isinstance(wall, (int, float)):
        gaps.append("the split between model time and local time is unknown for this run (no "
                    "per-request seconds), so a slow run cannot be attributed to the endpoint or to "
                    "this machine")


def summarise(source: Any) -> dict:
    events = _events(source)
    gaps: list[str] = []
    if not events:
        return {"schema": SCHEMA, "chars_per_token": CHARS_PER_TOKEN, "run": {},
                "gaps": ["the journal was empty or unreadable"]}

    tools = _tool_usage(events)
    llm = _llm_usage(events, gaps)
    context = _context_summary(events, gaps)
    run = _run_summary(events, gaps)
    _attribute_wall_clock(run, llm, gaps)
    return {"schema": SCHEMA, "chars_per_token": CHARS_PER_TOKEN,
            "run": run, "llm": llm, "tools": tools, "context": context, "gaps": gaps}


def render_log(source: Any) -> str:
    events = _events(source)
    doc = summarise(events)
    if not events:
        return "shard: no journal events — the run wrote nothing, or the file is unreadable.\n"

    out: list[str] = ["=" * 72, "SHARD RUN LOG", "=" * 72]
    run = doc.get("run", {})
    out.append(f"turns {run.get('model_turns', '?')}"
               + (f"/{run['max_steps']}" if "max_steps" in run else "")
               + f"   wall {run.get('wall_seconds', '?')}s"
               + f"   status {run.get('status', '?')}"
               + f"   ({run.get('journal_events', '?')} journal events)")
    llm = doc.get("llm", {})
    if llm.get("requests"):
        total = llm.get("total_tokens")
        out.append(f"llm   {llm['requests']} requests"
                   + (f"   {total:,} tokens" if isinstance(total, int) else "   tokens not reported")
                   + (f"   slowest {llm['seconds_slowest']}s" if "seconds_slowest" in llm else ""))
        share = run.get("llm_share")
        if isinstance(share, (int, float)):
            pct = share * 100
            verdict = ("waiting on the model endpoint — local speed is not this run's problem"
                       if share >= 0.9 else
                       "split between the endpoint and this machine" if share >= 0.5 else
                       "spent LOCALLY, not waiting on the model — look at this machine first")
            out.append(f"      {pct:.0f}% of the wall clock was {verdict}")
        if "output_per_request" in llm:
            rate = (f" at >={llm['output_per_second']:.0f} output tok/s"
                    if "output_per_second" in llm else "")
            out.append(f"      {llm['output_per_request']:,.0f} output tokens per request{rate}"
                       f"   (output is decoded serially; it is the half that costs wall clock)")
    ex = run.get("execution")
    if ex:
        out.append(f"exec  armed={ex.get('armed')}  {ex.get('calls', 0)} calls "
                   f"({ex.get('entry_calls', 0)} run_entry, {ex.get('shell_calls', 0)} shell)  "
                   f"network={ex.get('network')}")
        refused = ex.get("refused")
        if refused is None:
            out.append("      the execution ceiling's bind signal is ABSENT from this run's journal — "
                       "whether it cut the run short is not recorded either way")
        elif refused:
            out.append(f"      CUT SHORT: the execution ceiling refused {refused} call(s). Some claim "
                       f"here was reasoned about rather than checked — treat any finding that is not "
                       f"gate-eligible as unconfirmed. Raising --max-steps raises this budget too")
        elif ex.get("spent"):
            out.append(f"      SPENT IN FULL: every one of the {ex.get('budget')} executions was "
                       f"used and none was refused. The model is told how many remain, so it stops "
                       f"asking rather than being denied — treat this as a ceiling that MAY have cut "
                       f"the run short. Raising --max-steps raises this budget too")
        else:
            out.append("      the execution ceiling refused nothing and was not spent in full, so no "
                       "claim here was cut short by it")

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
            "Direct CLI only: retain a full transcript with "
            "shard diff --journal-path <private-path>.", ""]
    return "\n".join(out)


__all__ = ["CHARS_PER_TOKEN", "SCHEMA", "TEXT_FIELDS", "context_curve", "render_log", "summarise"]
