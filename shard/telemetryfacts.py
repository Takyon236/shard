
from __future__ import annotations

import math


_STATUSES = frozenset({"done", "error", "budget", "maxsteps", "repeat", "stall"})
_NETWORK = frozenset({"isolated", "unrestricted", "unknown", "not-armed"})
_ACTIVE = frozenset({"loop_start", "assistant", "llm_request", "context_size",
                     "context_compacted", "tool_result"})
_FIELDS = {
    "loop_start": ("max_steps",),
    "simple_proposed": ("status", "count"),
    "simple_adjudicated": ("findings", "gate_eligible"),
    "simple_exec": ("armed", "calls", "entry_calls", "shell_calls", "network", "budget",
                    "refused", "exhausted", "spent"),
}


def _gap(gaps: list[str], message: str) -> None:
    if message not in gaps:
        gaps.append(message)


def _count(value) -> bool:
    return type(value) is int and value >= 0


def _finite(value) -> bool:
    if type(value) not in (int, float):
        return False
    try:
        return math.isfinite(value)
    except OverflowError:
        return False


def _valid(field: str, value) -> bool:
    if field in ("armed", "exhausted", "spent"):
        return type(value) is bool
    if field in ("status", "network"):
        return type(value) is str and value in (_STATUSES if field == "status" else _NETWORK)
    return _count(value)


def _field(event: dict, kind: str, field: str, gaps: list[str]):
    value = event.get(field)
    if _valid(field, value):
        return value
    if (event.get("armed") is False and value is None
            and field in ("refused", "exhausted", "spent") and field in event):
        return None
    _gap(gaps, f"{kind}.{field} is missing or invalid; the measurement is unknown")
    return None


def context_curve(events, chars_per_token: int, gaps: list[str]) -> list[dict]:
    curve = []
    for event in events:
        kind = event.get("type")
        if kind == "context_size":
            row = {field: _field(event, kind, field, gaps) for field in ("step", "messages", "chars")}
            if row["chars"] is not None:
                row["est_tokens"] = row["chars"] // chars_per_token
            curve.append(row)
        elif kind == "context_compacted":
            row = {field: _field(event, kind, field, gaps)
                   for field in ("step", "stubbed", "chars_before", "chars_after")}
            row["event"] = "compaction"
            before, after = row["chars_before"], row["chars_after"]
            if before is not None and after is not None:
                row["reclaimed_chars"] = before - after
                row["reclaimed_est_tokens"] = (before - after) // chars_per_token
            curve.append(row)
    return curve


def _journal_counts(events: list[dict], gaps: list[str]) -> dict:
    run = {"journal_events": len(events),
           "model_turns": sum(event.get("type") == "assistant" for event in events)}
    known_steps = 0
    for event in events:
        if _count(event.get("step")):
            known_steps += 1
            run["last_journal_step"] = max(run.get("last_journal_step", 0), event["step"])
    if known_steps != len(events):
        _gap(gaps, "journal step counts are missing or invalid; the last known step may be incomplete")
    return run


def _journal_span(events: list[dict], run: dict, gaps: list[str]) -> None:
    if len(events) < 2 or not all(_finite(event.get("ts")) for event in events):
        _gap(gaps, "journal span is unknown because timestamps are missing or invalid")
        return
    span = max(event["ts"] for event in events) - min(event["ts"] for event in events)
    if _finite(span):
        run["wall_seconds"] = round(span, 2)
    else:
        _gap(gaps, "journal timestamp span exceeds the finite numeric range")


def _summary_records(events: list[dict]) -> tuple[dict, int]:
    records, last_activity = {}, -1
    for index, event in enumerate(events):
        kind = event.get("type")
        if type(kind) is not str:
            continue
        if kind in _ACTIVE:
            last_activity = index
        if kind not in _FIELDS:
            continue
        first, count = records.get(kind, ((index, event), 0))
        records[kind] = first, count + 1
    return records, last_activity


def _one_record(records: dict, kind: str, last_activity: int, gaps: list[str]) -> dict | None:
    entry = records.get(kind)
    if entry is None:
        _gap(gaps, f"no `{kind}` record; its run facts are unknown")
        return None
    (index, event), count = entry
    stale_limit = kind == "loop_start" and any(
        name != "loop_start" and first[0] < last_activity
        for name, (first, _) in records.items())
    if count != 1 or stale_limit or (kind != "loop_start" and index < last_activity):
        _gap(gaps, f"`{kind}` run facts are ambiguous across journal history and were withheld")
        return None
    return event


def run_summary(events: list[dict], gaps: list[str]) -> dict:
    run = _journal_counts(events, gaps)
    _journal_span(events, run, gaps)
    records, last_activity = _summary_records(events)
    for kind, fields in _FIELDS.items():
        event = _one_record(records, kind, last_activity, gaps)
        if event is None:
            continue
        values = {field: _field(event, kind, field, gaps) for field in fields}
        if kind == "simple_exec":
            run["execution"] = values
            if values["refused"] is None and values["armed"] is not False:
                _gap(gaps, "this journal cannot say whether the ceiling refused a call")
        else:
            run.update({("claims_proposed" if field == "count" else field): value
                        for field, value in values.items() if value is not None})
    return run
