
from __future__ import annotations

from shard.report import (
    COMPLETED_STATUSES,
    TRANSPORT_ERROR_ADVICE,
    cap,
    finding_names,
    is_numbered,
    report_label,
)

SCHEMA = 1

OBSERVED_IN_RESULT = 2000

LIMIT_STATEMENTS: dict[str, str] = {
    "run_incomplete":
        "this run stopped before completing its audit. The findings below are what it reached, and "
        "the absence of others is not a clean result",
    "stopped_by_ceiling":
        "a spending ceiling stopped this run. Every count in this document is a floor",
    "transport_error":
        "the model endpoint failed in a way that ended the run. This is a fact about the endpoint, "
        "not a result about the code",
    "location_is_entry_point":
        "alerts are anchored on the entry point that reproduces them, not on the line at fault. "
        "Shard resolves a reproduction, not a source location, and does not guess a line",
    "no_coverage_statement":
        "Shard reports what it found. It does not report what it covered, so a result with no "
        "findings is not a statement that the attack surface was examined",
    "findings_dropped":
        "findings ranked below the reporting cap are not in this document",
    "target_walk_truncated":
        "the walk of the repository hit its file ceiling, so every repository count here is a floor",
    "levers_unavailable":
        "tools this run could have used did not register on the machine it ran on. It had less "
        "leverage than a run with them",
    "executions_refused":
        "the execution budget refused commands this run tried to make. It investigated less than it "
        "attempted to",
    "executions_spent":
        "this run used every execution its ceiling allowed and was never refused one. The agent is "
        "told how many remain, so it stops asking rather than being denied — whether it finished "
        "checking or ran out is not established here, and any finding in this document that is not "
        "gate-eligible is unconfirmed",
    "no_execution":
        "this run executed nothing in the checkout, so no claim here was formed by running the code",
    "witness_refused":
        "at least one candidate was never adjudicated — the entry point could not be run. That is "
        "not the same as a candidate that ran and did not demonstrate",
    "gate_not_evaluated":
        "the gate could not be evaluated on this run, so the exit code is not a verdict",
    "gate_on_claimed_location":
        "at least one finding was counted as new on the agent's claim that this change introduced it, "
        "not on a measured location and not on a re-run against the base revision. The defect is "
        "demonstrated; which change introduced it is not established",
    "scope_degraded":
        "the set of changed files could not be resolved, so what was reviewed is not what changed",
    "no_baseline":
        "no state repository is configured, so nothing accumulates between runs and no finding here "
        "can be called new",
}


def build(findings, *, status: str, mode: str, target: str = "", run=None,
          gate_reasons=(), scope_reasons=(), artefacts=None,
          bundle_names: dict[int, str] | None = None, previously_dropped: int = 0) -> dict:
    if type(previously_dropped) is not int or previously_dropped < 0:
        raise ValueError("previously_dropped must be a nonnegative integer")
    ordered, dropped = cap(findings)
    dropped += previously_dropped
    named = [(f, (bundle_names or {}).get(id(f), name))
             for f, name in zip(ordered, finding_names(ordered))]
    reproduced = [f for f in ordered if f.gate_eligible]
    hypotheses = [f for f in ordered if not f.gate_eligible]
    ident = getattr(run, "report_id", "") or ""
    return {
        "schema": SCHEMA,
        "tool": "Shard",
        "mode": mode,
        "target": target,
        "report_id": ident,
        "numbered": is_numbered(ident),
        "label": report_label(ident, target, quoted=False),
        "status": status,
        "complete": status in COMPLETED_STATUSES,
        "verdict": {
            "reproduced": len(reproduced),
            "hypotheses": len(hypotheses),
            "dropped": dropped,
        },
        "gate": _gate(run, reproduced, gate_reasons, scope_reasons),
        "repository": _repository(run),
        "inspection": getattr(run, "inspection", None),
        "library": getattr(run, "library", None),
        "run": _run(run),
        "limits": limits(ordered, status=status, run=run,
                         gate_reasons=gate_reasons, scope_reasons=scope_reasons, dropped=dropped),
        "reproduced": [_finding(f, name) for f, name in named if f.gate_eligible],
        "hypotheses": [_finding(f, name) for f, name in named if not f.gate_eligible],
        "artefacts": dict(artefacts or {}),
    }


def _weakness(f) -> dict | None:
    state = f.crash
    if not state.parsed:
        return None
    return {
        "class": state.crash_type,
        "access": state.access or None,
        "sanitizer": state.sanitizer,
        "crash_state": list(state.frames),
        "cwe": [f"CWE-{n}" for n in state.cwe_ids],
        "severity": state.severity or None,
        "severity_score": state.security_severity or None,
        "signature": state.signature,
    }


def _finding(f, name: str) -> dict:
    reproduced = bool(f.gate_eligible)
    observed = f.evidence or ""
    return {
        "id": name,
        "rule": f.rule_id,
        "rule_title": f.rule_title or f.title,
        "title": f.title,
        "message": f.message,
        "level": f.level,
        "gate_eligible": reproduced,
        "location": {
            "path": f.location,
            "line": f.line,
            "is_entry_point": bool(f.location_is_harness),
            "measured": bool(f.location_measured),
        },
        "attribution": {"verdict": f.attribution, "reason": f.attribution_reason},
        **({"callers": {"note": f.caller_note, "sites": list(f.caller_rows)}} if f.caller_note else {}),
        "weakness": _weakness(f),
        "reproduction": {
            "replays": f.replays,
            "crashes": f.crash_count,
            "sanitizer": f.sanitizer,
            "command": f.reproduce_command,
            "bundle": f"bundles/{name}",
            "container_digest": f.container_digest,
        } if reproduced else None,
        "observed": observed[:OBSERVED_IN_RESULT],
        "observed_truncated": len(observed) > OBSERVED_IN_RESULT,
        "doubts": list(f.doubts),
        "witness_refused": f.witness_refused,
    }


def _gate(run, reproduced, gate_reasons, scope_reasons) -> dict:
    return {
        "fail_on": getattr(run, "fail_on", "") or "",
        "eligible": len(reproduced),
        "reasons": [str(r) for r in gate_reasons],
        "scope_reasons": [str(r) for r in scope_reasons],
    }


def _repository(run) -> dict:
    return {
        "files": getattr(run, "target_files", None),
        "bytes": getattr(run, "target_bytes", None),
        "languages": list(getattr(run, "target_languages", ()) or ()),
        "truncated": bool(getattr(run, "target_truncated", False)),
    }


def _run(run) -> dict:
    kind = getattr(run, "error_kind", "") or ""
    return {
        "base_ref": getattr(run, "base_ref", "") or "",
        "files_reviewed": getattr(run, "files_reviewed", None),
        "witness_entry": getattr(run, "witness_entry", "") or "",
        "scan": getattr(run, "scan", "") or "",
        "exec_calls": getattr(run, "exec_calls", None),
        "executions_spent": getattr(run, "executions_spent", None),
        "exec_refused": getattr(run, "exec_refused", None),
        "usd": getattr(run, "usd", None),
        "tokens": getattr(run, "tokens", None),
        "seconds": getattr(run, "seconds", None),
        "limit_hit": getattr(run, "limit_hit", "") or "",
        "error_kind": kind,
        "error_advice": TRANSPORT_ERROR_ADVICE.get(kind, ""),
        "unavailable_levers": list(getattr(run, "unavailable_levers", ()) or ()),
        "stateful": getattr(run, "stateful", None),
    }


def limits(findings, *, status: str, run=None, gate_reasons=(), scope_reasons=(),
           dropped: int = 0) -> list[dict]:
    codes: list[str] = []
    if status not in COMPLETED_STATUSES:
        codes.append("run_incomplete")
    if getattr(run, "limit_hit", ""):
        codes.append("stopped_by_ceiling")
    if getattr(run, "error_kind", ""):
        codes.append("transport_error")
    codes.extend(getattr(r, "code", "gate_not_evaluated") for r in gate_reasons)
    if scope_reasons:
        codes.append("scope_degraded")
    if any(f.witness_refused for f in findings):
        codes.append("witness_refused")
    if any(f.location_is_harness for f in findings):
        codes.append("location_is_entry_point")
    refused = getattr(run, "exec_refused", None)
    if refused:
        codes.append("executions_refused")
    elif getattr(run, "executions_spent", None):
        codes.append("executions_spent")
    if getattr(run, "exec_calls", None) == 0:
        codes.append("no_execution")
    if getattr(run, "unavailable_levers", ()) and getattr(run, "levers_image_bound", None):
        codes.append("levers_unavailable")
    if getattr(run, "target_truncated", False):
        codes.append("target_walk_truncated")
    if getattr(run, "stateful", None) is False:
        codes.append("no_baseline")
    if dropped:
        codes.append("findings_dropped")
    codes.append("no_coverage_statement")
    return [{"code": c, "statement": LIMIT_STATEMENTS[c]} for c in dict.fromkeys(codes)]
