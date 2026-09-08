
from __future__ import annotations

import html


MAX_ROWS = 40
_STATUS = {"full": "full source returned", "partial": "partial source returned",
           "no_source": "no source recorded"}


def summary(inspection: dict) -> str:
    return (f"{inspection['files_with_source']} of {inspection['scope_files']} scoped file(s) "
            f"returned source; {inspection['files_without_source']} with no source recorded")


def _cell(value) -> str:
    plain = "".join(c if c.isprintable() else f"\\x{ord(c):02x}" for c in str(value))
    escaped = html.escape(plain)
    for char in "|`[]*_\\":
        escaped = escaped.replace(char, f"&#{ord(char)};")
    return escaped


def _ranges(spans) -> str:
    parts = [str(start) if start == end else f"{start}–{end}" for start, end in spans[:8]]
    if len(spans) > 8:
        parts.append(f"… +{len(spans) - 8} ranges")
    return ", ".join(parts) or "none"


def _activity(row) -> str:
    details = []
    for key, label in (("failed_reads", "failed read(s)"), ("empty_reads", "empty/EOF read(s)"),
                       ("clamped_reads", "clamped read(s)"),
                       ("partial_line_reads", "partly returned line(s)"),
                       ("unmeasured_reads", "unmeasured read(s)"),
                       ("search_calls", "explicit search(es)"),
                       ("failed_searches", "failed search(es)"),
                       ("clamped_searches", "clamped search(es)")):
        if row[key]:
            details.append(f"{row[key]} {label}")
    return "; ".join(details) or "—"


def markdown(inspection: dict) -> list[str]:
    out = ["### Source inspection", "", summary(inspection) + ".", "",
           inspection["measurement"], "",
           f"Full files: **{inspection['files_fully_returned']}**. "
           f"Partial files: **{inspection['files_partially_returned']}**. "
           f"Complete source lines returned: **{inspection['observed_lines']}**.", ""]
    rows = sorted(inspection["files"], key=lambda row: (
        {"no_source": 0, "partial": 1, "full": 2}[row["status"]], row["path"]))
    if rows:
        out += ["| Scoped file | Source returned | Line ranges | Diff context ranges | Other activity |",
                "|---|---|---|---|---|"]
    for row in rows[:MAX_ROWS]:
        out.append(f"| <code>{_cell(row['path'])}</code> | {_STATUS[row['status']]} | "
                   f"{_ranges(row['observed_ranges'])} | "
                   f"{_ranges(row['guidance_ranges'])} | {_activity(row)} |")
    if len(rows) > MAX_ROWS:
        out += ["", f"{len(rows) - MAX_ROWS} further file(s) are listed in "
                "`shard-result.json` under `inspection.files`."]
    searches = inspection["unscoped_searches"] + inspection["unmapped_searches"]
    reads = inspection["unscoped_reads"] + inspection["unmapped_reads"]
    if reads or searches:
        out += ["", f"Outside the scoped-file inventory: {reads} read(s), {searches} search(es). "
                "Directory searches do not establish source inspection for each file."]
    return [*out, ""]
