"""Observed coverage — what this run actually READ and EXECUTED, stated as fact.

Every run emits the `no_coverage_statement` limit, and the sentence in it was true of every Shard
run ever made until this module existed: the run's own journal records each tool call's name,
arguments and outcome (`shard/agentloop.py` — `tool_result` events keyed `name:{args-json}`), and
no artefact read that record back to say WHICH FILES the agent opened. A customer with zero
findings could not tell *"we looked at your diff and found nothing"* from *"we never opened the
file that mattered"*, which is exactly the ambiguity the limits block exists to prevent — stated
as a caveat rather than closed as a fact.

## What this derives, and the line it does not cross

**OBSERVATIONS, NOT COVERAGE.** `read` lists the files `read_file` and `outline` opened
successfully; `searched` lists the bases `grep` ran over; the execution counts tally `run_entry`
and `run`. All four are facts the journal can prove. None of them is a statement that the attack
surface was *examined* — reading two files of a three-file diff is an observation, and
`no_coverage_statement` stays in every result document beside this block, reworded to acknowledge
it, because a no-findings run that read 12 files has still not *covered* anything in the sense a
reader hopes. `shard/telemetry.py` refuses to quote argument values for redaction reasons and is
right to; this module quotes exactly one argument per tool — the PATH, a repository file name that
the report, the SARIF and the bundles already print on every run — and refuses the rest. A grep
PATTERN is model-authored text and never appears here: a new artefact is a new injection surface,
and the pattern is not needed to state the fact.

**A SEARCH IS NOT A READ.** `grep` over a directory returns lines from files the agent never
opened, and folding its base into `read` would overstate what was examined in exactly the
direction a coverage block must not. `list_dir` is weaker still and is not derived at all.

**FAILED CALLS COUNT FOR NOTHING.** A `read_file` that errored read nothing; a `run_entry` that
returned `ok: false` demonstrated nothing. Only `ok: true` results are counted, for the same
reason `_result_shape` reads `ok` before reading anything else.

## Pure, and lexical rather than filesystem

`observed` takes journal events as dicts (the same shape `telemetry._events` accepts from a list,
and the shape `Journal.events()` yields from the file) and normalises paths LEXICALLY — `normpath`
against the repository root, with containment by prefix and no `resolve()`. The sandbox resolved
these paths against the checkout when the calls happened; re-resolving through symlinks here would
make the derivation depend on the filesystem state at REPORT time rather than at RUN time, which
is a second opinion the journal does not need and a purity a report derivation should keep.
"""


from __future__ import annotations

import json
import os


#: The tools whose `path` argument names a FILE the tool opens server-side. `outline` reads the
#: file to build its definition index — "without reading the file" is its description TO THE
#: MODEL (no body is returned); the bytes are still opened here, and a coverage block that omitted
#: them would understate what was examined.
_PATH_TOOLS = frozenset({"read_file", "outline"})

#: The tool whose `path` argument names a BASE to search under. Kept out of `read` — see the
#: module docstring.
_SEARCH_TOOL = "grep"

#: The execution tools, counted by name so the two halves of the block cannot disagree about
#: which tool is which.
_ENTRY_TOOL = "run_entry"
_SHELL_TOOL = "run"


def _repo_relative(root: str, raw: str) -> str | None:
    """A normalised repository-relative spelling of `raw`, or None when it leaves the checkout.

    LEXICAL, with no filesystem access — see the module docstring for why this is deliberately
    not `resolve()`. Containment by normalised prefix: `..` that escapes the root is dropped
    rather than clamped, the same direction `witness.resolve_entry` refuses in.
    """
    raw = (raw or "").strip()
    if not raw:
        return None
    root_abs = os.path.normpath(root)
    joined = raw if os.path.isabs(raw) else os.path.join(root_abs, raw)
    norm = os.path.normpath(joined)
    if norm != root_abs and not norm.startswith(root_abs + os.sep):
        return None
    rel = os.path.relpath(norm, root_abs)
    return None if rel in (".", "..") or rel.startswith(".." + os.sep) else rel.replace(os.sep, "/")


def observed(events, scope, root) -> dict:
    """What this run read, searched and executed, derived from journal `tool_result` events.

    `events` is an iterable of parsed journal events (dicts); `scope` the diff's scope paths;
    `root` the repository the run reviewed. Never raises: an event with a malformed key or an
    unparsable argument list is skipped, because a coverage block that took down the report would
    cost more than the one event it lost — the same trade `_events` makes on torn lines.

    Every number here is an OBSERVATION recorded by the run itself, which is what makes the block
    quotable: `read 2 of 3 changed files` has both halves measured, and neither is inferred.
    """
    read: set[str] = set()
    searched: set[str] = set()
    entry_executions = 0
    shell_executions = 0
    scope_set = set(scope or ())

    for event in events:
        if not isinstance(event, dict) or event.get("type") != "tool_result":
            continue
        key = event.get("key") or ""
        name, _, raw_args = key.partition(":")
        # The RESULT's ok is read before anything else: a call that failed did not read, search
        # or execute anything, and counting it would be the overstatement this module exists to
        # prevent rather than commit.
        result = event.get("result")
        ok = result.get("ok", True) if isinstance(result, dict) else True
        if not ok:
            continue
        if name in _PATH_TOOLS or name == _SEARCH_TOOL:
            try:
                args = json.loads(raw_args) if raw_args else {}
            except ValueError:
                continue
            if not isinstance(args, dict):
                continue
            if name in _PATH_TOOLS:
                if rel := _repo_relative(root, str(args.get("path", ""))):
                    read.add(rel)
            elif name == _SEARCH_TOOL:
                # grep's base defaults to "." in the tool's own signature, so an absent path is
                # the whole checkout — recorded as the root itself, which is the truth of what
                # was searched.
                if rel := _repo_relative(root, str(args.get("path", ".") or ".")):
                    searched.add(rel)
        elif name == _ENTRY_TOOL:
            entry_executions += 1
        elif name == _SHELL_TOOL:
            shell_executions += 1

    read_sorted = sorted(read)
    return {
        "in_scope": len(scope_set),
        "read": read_sorted,
        "read_in_scope": sorted(read & scope_set),
        "searched": sorted(searched),
        "entry_executions": entry_executions,
        "shell_executions": shell_executions,
    }


def summary_line(block: dict | None) -> str | None:
    """The one-row form for the report's header table, or None when there is nothing to say.

    The ROW carries the read fact only. Execution counts already have a row (`_observed`, built
    from `RunFacts.exec_calls`) and a second spelling of them here is the drift `report.py`'s own
    docstrings refuse; the result document carries the full block.

    None rather than a zero row: `read 0 of 3 changed files` is a real and alarming answer and
    must be SHOWN, so the empty case this returns None for is a caller that derived no block at
    all — no journal, no diff scope — which is an absence, not a measurement.
    """
    if not block:
        return None
    in_scope = block.get("in_scope", 0)
    n = len(block.get("read_in_scope") or ())
    line = f"the agent read **{n} of {in_scope}** changed file(s)"
    others = len(block.get("read") or ()) - n
    if others:
        line += f", and {others} file(s) outside the diff"
    line += (" — an observation, not a claim that the attack surface was examined"
             if not n else " — the files it did not read were not examined by reading")
    return line


__all__ = ["observed", "summary_line"]
