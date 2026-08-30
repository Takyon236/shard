"""The machine-readable scan result — one versioned document, for the tool on the other side.

## The defect this module exists to end

**The markdown is the only artefact that carries the whole result, and it is the one a machine
cannot read.** Measured against the shipping tree on 2026-08-26, a consumer wanting the result of a
scan had five places to look and no complete one among them:

    shard-report.md            the whole story, in prose
    shard.sarif                GitHub's shape. No run facts, no attribution, no replay count,
                               no doubts, no bundle path, no cost, no reason the run stopped
    bundles/<fp>/metadata.json one finding each, no run context, no index
    shard-telemetry.json       the RUN — seconds, turns, tools. Never the findings
    --json on stdout           not written to disk, unversioned, and DIFFERENT KEYS on
                               `diff` and `deep`

That is this repository's most-recorded defect class — one fact spelled several ways, with the
maintained spelling being whichever the reader happened to open — at the product's outermost
boundary, where the reader is somebody else's software.

## What is different here

**The honesty is in the data, not in the prose.** Every caveat the markdown states in a sentence
has a code in `limits`: an unfinished run, a ceiling that bound, a walk that truncated, a lever
that could not fire, an alert anchored on the entry point rather than the fault. `docs/
ADOPTION-GAPS-2026-08-26.md` B5 names the consequence of leaving them in prose — *"make sure
whatever consumes that output does not read '0 findings' as green. The tool is careful here;
dashboards usually are not."* A dashboard cannot read careful. It can read a code.

`no_coverage_statement` is in that list on EVERY run, including a clean one. Shard reports what it
found and does not report what it looked at (gap A2), and a document that says so in a field is a
document a downstream agent cannot over-read.

**Two arrays, not one list with a flag.** `reproduced` and `hypotheses` are separate because the
product's whole claim is that they are different kinds of thing, and a consumer looping over a flat
list with a boolean it forgot to check rebuilds the false-positive triage queue this product exists
to eliminate. The shape refuses the mistake rather than documenting against it.

**Three fields say the same thing about a finding, and they cannot disagree.** `gate_eligible`,
`level`, and whether `reproduction` is null are all derived from `Finding.gate_eligible` here, in
one expression each, so whichever a consumer reads it gets the same answer.
the maintainers' suite asserts the agreement per finding rather than trusting this paragraph.

## The classification, added 2026-08-28

`weakness` carries the CWE ids, the severity band and the crash state — the SAME values
`report._rule_properties` puts in the SARIF, read from the SAME `Finding.crash` property, so the
document a dashboard parses and the alert a security team triages cannot disagree about the
weakness. Two spellings of one fact is this repository's most-recorded defect class, and the fix
each time was one derivation rather than two.

It is **null when the observed output was not a sanitiser report** — a free-tier `output_marker`
finding, a target with no sanitiser compiled in — because `shard/crashstate.py` abstains rather
than defaulting. A consumer must read null as "this run did not establish a class", never as
"unclassified means low".

## What this is NOT

Not a coverage report. the design notes A2 is open and `limits` reports it on
every run rather than papering over it.

**And `weakness` is not a re-ranking of the finding.** The severity describes the WEAKNESS CLASS and
is ClusterFuzz's band for that class, unchanged; how much to trust the alert is a different axis and
lives in `gate_eligible`. The earlier version of this paragraph said a CWE mapping did not belong
here at all — that was right while the alternative was inventing one, and wrong once the mapping
became a measured lookup that the SARIF already carries. Withholding it from the machine-readable
artefact would have meant the only complete document was, again, the one a machine cannot read.
"""

from __future__ import annotations

from shard.report import (
    COMPLETED_STATUSES,
    TRANSPORT_ERROR_ADVICE,
    cap,
    is_numbered,
    rank,
    report_label,
)

#: The document's shape. Bumped when a consumer would MISREAD an older file, not on every addition —
#: a new optional key is not a breaking change and a renamed one is.
#:
#: The wording, the key name and the policy are `shard.telemetry.SCHEMA`'s, deliberately and verbatim.
#: Two version conventions in two artefacts of one run is the drift this module was written to end,
#: and it would be a poor place to start a second one.
SCHEMA = 1

#: How much observed output the DOCUMENT carries. Above the SARIF's 300 and the markdown's 1,200,
#: because this file is parsed rather than skimmed, and below the 4,000 the capture allows, because a
#: result document is forwarded and a crash tail is the part of it least worth forwarding twice. The
#: bundle holds all of it; `reproduction.bundle` names where.
OBSERVED_IN_RESULT = 2000

#: **WHAT THIS RUN DOES NOT ESTABLISH**, keyed by code, in the channel a machine reads.
#:
#: KEYED, NOT DERIVED, and for `TRANSPORT_ERROR_ADVICE`'s reason one file over: the CODES are decided
#: by run facts that other modules own, and the SENTENCES are decided here, because this module owns
#: what a consumer reads. the maintainers' suite pins that every code emitted has a statement and
#: every statement has a code, so a limit cannot be detected and then rendered as nothing.
#:
#: A statement is written to be quotable on its own. It lands in somebody else's dashboard, next to
#: none of the context this file has.
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
    "no_execution":
        "this run executed nothing in the checkout, so no claim here was formed by running the code",
    "witness_refused":
        "at least one candidate was never adjudicated — the entry point could not be run. That is "
        "not the same as a candidate that ran and did not demonstrate",
    "gate_not_evaluated":
        "the gate could not be evaluated on this run, so the exit code is not a verdict",
    "scope_degraded":
        "the set of changed files could not be resolved, so what was reviewed is not what changed",
    "no_baseline":
        "no state repository is configured, so nothing accumulates between runs and no finding here "
        "can be called new",
}


def build(findings, *, status: str, mode: str, target: str = "", run=None,
          gate_reasons=(), scope_reasons=(), artefacts=None) -> dict:
    """The whole result of one scan, as one document.

    `findings` is the full set and is CAPPED here, by the same `report.cap` the SARIF uses, so the two
    machine-readable artefacts of a run describe the same set. What the cap removed is reported as a
    count and as a `findings_dropped` limit, never absorbed.

    `run` is a `report.RunFacts` or None. Nothing here invents a value it was not given: an unknown
    field is `null`, which is a different answer from `0` and is the rule every field of `RunFacts`
    already follows.
    """
    kept, dropped = cap(findings)
    ordered = rank(kept)
    reproduced = [f for f in ordered if f.gate_eligible]
    hypotheses = [f for f in ordered if not f.gate_eligible]
    ident = getattr(run, "report_id", "") or ""
    return {
        "schema": SCHEMA,
        "tool": "Shard",
        "mode": mode,
        "target": target,
        # The run's own number, and whether it HAS one. `is_numbered` because `"000000"` is the
        # reserved value for a run that came from no numbered CI, and a consumer keying on the string
        # would file every local run under one identity.
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
        "run": _run(run),
        "limits": limits(ordered, status=status, run=run,
                         gate_reasons=gate_reasons, scope_reasons=scope_reasons, dropped=dropped),
        "reproduced": [_finding(f) for f in reproduced],
        "hypotheses": [_finding(f) for f in hypotheses],
        "artefacts": dict(artefacts or {}),
    }


def _weakness(f) -> dict | None:
    """The finding's defect class, or **null** when the observed output was not a sanitiser report.

    Null rather than an empty object, and rather than a zeroed one. An empty object reads as "we
    looked and there is no weakness"; a zeroed severity reads as "harmless". Both are claims this
    run did not make, and the second is trap 7 of `RunFacts` — a zero you cannot distinguish from an
    unknown is a lie with a number on it.

    `severity_score` is the string GitHub's SARIF field carries and is emitted as a string here too,
    so a consumer diffing the two artefacts sees the same token rather than `5.5` against `"5.5"`.
    """
    state = f.crash
    if not state.parsed:
        return None
    return {
        "class": state.crash_type,
        "access": state.access or None,
        "sanitizer": state.sanitizer,
        # The top application frames, sanitiser and fuzzing-engine frames removed. NOT a claim that
        # the defect is IN the first frame — it is where the fault was detected, which is the same
        # distinction `location.is_entry_point` already draws one field up.
        "crash_state": list(state.frames),
        "cwe": [f"CWE-{n}" for n in state.cwe_ids],
        "severity": state.severity or None,
        "severity_score": state.security_severity or None,
        # The cross-run identity, named so a consumer knows what to key its own history on. This is
        # the value in the SARIF's `partialFingerprints`, and it is deliberately NOT `id` above:
        # `id` names this run's bundle directory and must stay unique within a run.
        "signature": state.signature,
    }


def _finding(f) -> dict:
    """One finding. `reproduction` is null when there is none, which is the only thing that gates."""
    reproduced = bool(f.gate_eligible)
    observed = f.evidence or ""
    return {
        "id": f.fingerprint,
        "rule": f.rule_id,
        "rule_title": f.rule_title or f.title,
        "title": f.title,
        "message": f.message,
        # Derived from `f.gate_eligible` in one expression each, so a consumer reading any of the
        # three gets the same answer. `f.level` is `report.Finding`'s own property and is the SARIF's.
        "level": f.level,
        "gate_eligible": reproduced,
        "location": {
            "path": f.location,
            "line": f.line,
            # NOT "the defect is here". See `LIMIT_STATEMENTS["location_is_entry_point"]`.
            "is_entry_point": bool(f.location_is_harness),
            "measured": bool(f.location_measured),
        },
        "attribution": {"verdict": f.attribution, "reason": f.attribution_reason},
        "weakness": _weakness(f),
        "reproduction": {
            "replays": f.replays,
            "crashes": f.crash_count,
            "sanitizer": f.sanitizer,
            "command": f.reproduce_command,
            "bundle": f"bundles/{f.fingerprint}",
            "container_digest": f.container_digest,
        } if reproduced else None,
        "observed": observed[:OBSERVED_IN_RESULT],
        "observed_truncated": len(observed) > OBSERVED_IN_RESULT,
        "doubts": list(f.doubts),
        "witness_refused": f.witness_refused,
    }


def _gate(run, reproduced, gate_reasons, scope_reasons) -> dict:
    """What may fail a build, and what stopped that question being answerable."""
    return {
        "fail_on": getattr(run, "fail_on", "") or "",
        # The count of findings that MAY gate. Whether one DID is the exit code's answer, and it is
        # `shard.gate`'s to give — this document reports the input to that rule, never a second copy
        # of the rule itself.
        "eligible": len(reproduced),
        "reasons": [str(r) for r in gate_reasons],
        "scope_reasons": [str(r) for r in scope_reasons],
    }


def _repository(run) -> dict:
    """What the repository IS, from the walk that decided the harness. `truncated` rides beside the
    counts because it is what makes them floors."""
    return {
        "files": getattr(run, "target_files", None),
        "bytes": getattr(run, "target_bytes", None),
        "languages": list(getattr(run, "target_languages", ()) or ()),
        "truncated": bool(getattr(run, "target_truncated", False)),
    }


def _run(run) -> dict:
    """What the run DID. Every field is `RunFacts`', unrenamed, so the document and the report header
    cannot come to disagree about a number they read from the same record."""
    kind = getattr(run, "error_kind", "") or ""
    return {
        "base_ref": getattr(run, "base_ref", "") or "",
        "files_reviewed": getattr(run, "files_reviewed", None),
        "witness_entry": getattr(run, "witness_entry", "") or "",
        "scan": getattr(run, "scan", "") or "",
        "exec_calls": getattr(run, "exec_calls", None),
        "exec_refused": getattr(run, "exec_refused", None),
        "usd": getattr(run, "usd", None),
        "tokens": getattr(run, "tokens", None),
        "seconds": getattr(run, "seconds", None),
        # WHICH ceiling bound, not merely that one did: `status: budget` covers tokens, wall clock and
        # dollars, and the customer's next action differs by which.
        "limit_hit": getattr(run, "limit_hit", "") or "",
        "error_kind": kind,
        # The advice travels WITH the classification, for the reason `TRANSPORT_ERROR_ADVICE` exists:
        # a kind a consumer cannot act on is half a defect report.
        "error_advice": TRANSPORT_ERROR_ADVICE.get(kind, ""),
        "unavailable_levers": list(getattr(run, "unavailable_levers", ()) or ()),
        # `None` where the mode never established it, which is a different answer from `False`.
        "stateful": getattr(run, "stateful", None),
    }


def limits(findings, *, status: str, run=None, gate_reasons=(), scope_reasons=(),
           dropped: int = 0) -> list[dict]:
    """What this run does not establish, as `[{code, statement}]`, ordered most-limiting first.

    Public because it is the block a consumer is most likely to want on its own, and because a run
    that emitted no document at all still has limits worth naming.

    `no_coverage_statement` is unconditional. It is true of every Shard run ever made and the one
    caveat a clean report is most likely to be read against.
    """
    codes: list[str] = []
    if status not in COMPLETED_STATUSES:
        codes.append("run_incomplete")
    if getattr(run, "limit_hit", ""):
        codes.append("stopped_by_ceiling")
    if getattr(run, "error_kind", ""):
        codes.append("transport_error")
    if gate_reasons:
        codes.append("gate_not_evaluated")
    if scope_reasons:
        codes.append("scope_degraded")
    if any(f.witness_refused for f in findings):
        codes.append("witness_refused")
    if any(f.location_is_harness for f in findings):
        codes.append("location_is_entry_point")
    refused = getattr(run, "exec_refused", None)
    if refused:
        codes.append("executions_refused")
    if getattr(run, "exec_calls", None) is None and run is not None:
        codes.append("no_execution")
    # A lever that did not register is only a LOSS when the workdir could have used it. The two facts
    # answer different questions and rendering the first alone told runs that lost nothing that they
    # had lost four things — see `RunFacts.levers_image_bound`.
    if getattr(run, "unavailable_levers", ()) and getattr(run, "levers_image_bound", None):
        codes.append("levers_unavailable")
    if getattr(run, "target_truncated", False):
        codes.append("target_walk_truncated")
    if getattr(run, "stateful", None) is False:
        codes.append("no_baseline")
    if dropped:
        codes.append("findings_dropped")
    codes.append("no_coverage_statement")
    return [{"code": c, "statement": LIMIT_STATEMENTS[c]} for c in codes]
