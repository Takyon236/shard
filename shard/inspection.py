
from __future__ import annotations

import os


MEASUREMENT = (
    "These ranges describe source returned by read_file into the conversation, not proof that "
    "the model analysed it. Clamped observations contribute no line ranges, so counts are lower "
    "bounds. Search results, shell output and directory listings do not establish line coverage. "
    "Returned source is not a measure of security coverage or execution."
)
_COUNTERS = (
    "read_calls", "failed_reads", "empty_reads", "clamped_reads", "partial_line_reads",
    "unmeasured_reads", "search_calls", "failed_searches", "clamped_searches",
)


def _relative(path, root: str) -> str | None:
    if not isinstance(path, str) or not path or "\0" in path:
        return None
    if ".." in path.split(os.sep):
        return None
    absolute = os.path.normpath(path if os.path.isabs(path) else os.path.join(root, path))
    if absolute != root and not absolute.startswith(root.rstrip(os.sep) + os.sep):
        return None
    return os.path.relpath(absolute, root)


def _integer(value) -> bool:
    return type(value) is int and value >= 0


def _merged(spans) -> list[list[int]]:
    ordered = sorted((lo, hi) for lo, hi in spans if lo >= 1 and hi >= lo)
    merged: list[list[int]] = []
    for lo, hi in ordered:
        if merged and lo <= merged[-1][1] + 1:
            merged[-1][1] = max(merged[-1][1], hi)
        else:
            merged.append([lo, hi])
    return merged


def _guidance(spans) -> list[list[int]]:
    if not isinstance(spans, (tuple, list)):
        return []
    valid = [span for span in spans if isinstance(span, (tuple, list)) and len(span) == 2
             and all(_integer(n) for n in span)]
    return _merged(valid)


def _file(path: str, guidance) -> dict:
    return {
        "path": path, "guidance_ranges": _guidance(guidance),
        **dict.fromkeys(_COUNTERS, 0), "_ranges": [], "_totals": set(), "_source": False,
    }


def _read(row: dict, event: dict) -> None:
    row["read_calls"] += 1
    if event.get("ok") is False:
        row["failed_reads"] += 1
        return
    if event.get("ok") is not True:
        row["unmeasured_reads"] += 1
        return
    total = event.get("total_lines")
    if _integer(total):
        row["_totals"].add(total)
    if event.get("observation_complete") is False:
        row["clamped_reads"] += 1
        return
    start, end = event.get("start_line"), event.get("end_line")
    partial = event.get("partial_line")
    if (event.get("observation_complete") is not True
            or not all(_integer(n) for n in (start, end, total))
            or type(partial) is not bool):
        row["unmeasured_reads"] += 1
        return
    if start == end == 0 and not partial:
        row["empty_reads"] += 1
        return
    if not 1 <= start <= end <= total:
        row["unmeasured_reads"] += 1
        return
    row["_source"] = True
    if partial:
        row["partial_line_reads"] += 1
        end -= 1
    if end >= start:
        row["_ranges"].append((start, end))


def _search(row: dict, event: dict) -> None:
    row["search_calls"] += 1
    if event.get("ok") is False:
        row["failed_searches"] += 1
    elif event.get("observation_complete") is False:
        row["clamped_searches"] += 1


def _finish(row: dict) -> dict:
    spans = _merged(row.pop("_ranges"))
    totals = row.pop("_totals")
    total = next(iter(totals)) if len(totals) == 1 else None
    source = row.pop("_source")
    count = sum(hi - lo + 1 for lo, hi in spans)
    full = total is not None and total > 0 and spans == [[1, total]]
    return {
        **row, "status": "full" if full else "partial" if source else "no_source",
        "total_lines": total, "observed_ranges": spans, "observed_lines": count,
    }


def build(scope, events, *, repo, windows=None) -> dict:
    root = os.path.abspath(os.fspath(repo))
    hints = windows if isinstance(windows, dict) else {}
    paths = {_relative(path, root) for path in scope}
    rows = {path: _file(path, hints.get(path)) for path in sorted(paths - {None, "."})}
    outside = dict.fromkeys(
        ("unscoped_reads", "unmapped_reads", "unscoped_searches", "unmapped_searches"), 0)
    for event in events:
        if not isinstance(event, dict) or event.get("type") not in ("source_read", "source_search"):
            continue
        path = _relative(event.get("path"), root)
        kind = "reads" if event["type"] == "source_read" else "searches"
        if path not in rows:
            outside[("unmapped_" if path is None else "unscoped_") + kind] += 1
        elif kind == "reads":
            _read(rows[path], event)
        else:
            _search(rows[path], event)
    files = [_finish(row) for row in rows.values()]
    full = sum(row["status"] == "full" for row in files)
    partial = sum(row["status"] == "partial" for row in files)
    return {
        "available": True, "measurement": MEASUREMENT, "scope_files": len(files),
        "files_with_source": full + partial, "files_fully_returned": full,
        "files_partially_returned": partial, "files_without_source": len(files) - full - partial,
        "observed_lines": sum(row["observed_lines"] for row in files),
        **{key: sum(row[key] for row in files) for key in _COUNTERS}, **outside, "files": files,
    }
