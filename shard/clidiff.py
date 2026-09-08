
from __future__ import annotations

import contextlib
import json
import pathlib
import tempfile

from shard.budget import BudgetGovernor
from shard.cliemit import _emit
from shard.climeter import _budget
from shard.climeter import _max_steps
from shard.climeter import _scan_payload
from shard.climeter import _spend
from shard.cliprint import _cost_line
from shard.gate import EXIT_CONFIG, ConfigError, exit_code, is_new_finding
from shard.journal import Journal
from shard.target import profile_repo


@contextlib.contextmanager
def _diff_journal(args):
    supplied = getattr(args, "journal_path", None)
    if supplied:
        path = pathlib.Path(supplied)
        if args.out_dir and path.resolve().is_relative_to(pathlib.Path(args.out_dir).resolve()):
            raise ConfigError(
                "--journal-path must be outside --out-dir: the raw transcript contains model "
                "reasoning and source returned by tools")
        owner = contextlib.nullcontext()
    else:
        owner = tempfile.TemporaryDirectory(prefix="shard-journal-")

    with owner as private:
        path = path if supplied else pathlib.Path(private) / "shard_journal.jsonl"
        journal = Journal(path)
        try:
            yield journal
        finally:
            journal.close()


class GateReason(str):

    def __new__(cls, code: str, text: str) -> "GateReason":
        reason = super().__new__(cls, text)
        reason.code = code
        return reason


def _gate_reasons(findings, *, fail_on: str, scope_reasons: list[str], changed,
                  introduced) -> list[GateReason]:
    from shard.witness import UNATTRIBUTED

    diff_unread = bool(scope_reasons) and not changed

    gate_reasons: list[GateReason] = []
    if diff_unread:
        gate_reasons.append(GateReason(
            "gate_not_evaluated",
            "fail-on new could NOT be evaluated: the diff was not read, so no finding can be "
            "attributed to this change and the gate did not fire. This is a degraded run, not a "
            "clean one — see scope_reasons for why git could not answer"
            if fail_on == "new" else
            f"the diff was not read, so this run reviewed no changed code and fail-on "
            f"{fail_on} had nothing to judge. This is a degraded run, not a clean one — see "
            f"scope_reasons for why git could not answer"))

    refused = [f for f in findings if getattr(f, "witness_refused", "")]
    if refused:
        why = sorted({f.witness_refused.split(".")[0].strip() for f in refused})
        gate_reasons.append(GateReason(
            "witness_refused",
            f"{len(refused)} of {len(findings)} finding(s) proposed a witness that was NEVER "
            f"ADJUDICATED, so this run judged less than it looks: {'; '.join(why[:3])}. The "
            f"gate-eligible count is a FLOOR — those findings were not refuted, they were not tried"))

    claimed = sum(1 for f in findings
                  if is_new_finding(f, introduced)
                  and f.attribution == UNATTRIBUTED and not f.location_measured)
    if fail_on == "new" and claimed and not diff_unread:
        gate_reasons.append(GateReason(
            "gate_on_claimed_location",
            f"{claimed} finding(s) were counted as new on the agent's claim rather than on a measured "
            f"location: the demonstration produced no source location — a successful exploit is often "
            f"SILENT, exiting 0 with no stack — and the base revision could not be re-run to check the "
            f"claim causally. They are demonstrated defects; what rests on the agent's word is that "
            f"THIS change introduced them"))
    return gate_reasons


def _delivered_verdict(findings, written: dict, introduced, gate_new: int, status: str) -> dict:
    delivery = written.get("delivery") or {}
    if not delivery:
        return {"failed": False, "findings": findings, "new": gate_new, "status": status,
                "state_findings": findings}

    from shard.report import cap, finding_names

    kept, _dropped = cap(findings)
    names = set(delivery.get("delivered") or ())
    delivered = [f for f, name in zip(kept, finding_names(kept)) if name in names]
    delivered_new = sum(1 for f in delivered if is_new_finding(f, introduced))
    failed = bool(delivery.get("failed_required"))
    return {"failed": failed, "findings": delivered, "new": delivered_new,
            "status": "error" if failed else status,
            "state_findings": [f for f in findings if not f.gate_eligible] + delivered}


def _delivery_exit(delivery: dict, payload: dict, fail_on: str) -> int:
    if delivery["failed"]:
        return EXIT_CONFIG
    return exit_code(bool(payload["gate_eligible"]), fail_on, new=bool(delivery["new"]),
                     status=str(payload.get("status") or "error"))


def _counterfactual_base(args, repo: pathlib.Path,
                         scope_reasons: list[str]) -> pathlib.Path | None:
    if args.fail_on != "new" or not args.witness_entry:
        return None

    from shard.diffscope import base_tree

    base_dir = pathlib.Path(tempfile.mkdtemp(prefix="shard-base-")) / "tree"
    return base_tree(repo, args.base_ref, base_dir, reasons=scope_reasons)


def _cmd_diff(args, journal: Journal | None = None) -> int:
    if journal is None:
        with _diff_journal(args) as owned:
            return _cmd_diff(args, owned)

    from shard.cli import _backend, _existing_dir
    from shard.diffscope import (HUNK_RADIUS, hunk_windows, introduced_line_index, load_diff,
                                 scope_paths, summarise)
    from shard.simple import run_simple
    from shard.state import survey_note
    from shard.witness import offered_expectations

    repo = _existing_dir(args.repo, "repo")
    state, state_reasons = _open_state(args)
    survey, survey_payload = _load_or_build_survey(state, repo, args)

    scope_reasons: list[str] = []
    changed = load_diff(repo, args.base_ref, reasons=scope_reasons)
    scope = scope_paths(changed)

    backend = _backend(args)
    diff_budget = _budget(args)
    governor = BudgetGovernor(diff_budget)
    radius = HUNK_RADIUS if args.hunk_radius is None else args.hunk_radius
    windows = hunk_windows(changed, radius=radius) if radius else {}
    base_repo = _counterfactual_base(args, repo, scope_reasons)

    run = run_simple(repo=repo, backend=backend, journal=journal, scope=scope,
                     witness_entry=args.witness_entry, model=args.model, max_steps=_max_steps(args),
                     governor=governor,
                     survey_note="" if getattr(args, "no_survey", False) else survey_note(survey),
                     windows=windows,
                     base_repo=base_repo,
                     secret_env_names=(args.api_key_env or "OPENROUTER_API_KEY",),
                     execution=not getattr(args, "no_execution", False))
    findings = run.findings

    introduced = introduced_line_index(changed)

    gate_new = sum(1 for f in findings if is_new_finding(f, introduced))

    gate_reasons = _gate_reasons(findings, fail_on=args.fail_on, scope_reasons=scope_reasons,
                                 changed=changed, introduced=introduced)

    spend = _spend(backend, governor)
    scan_facts = _scan_payload(args, diff_budget)
    facts = _diff_run_facts(args, run, spend=spend, scan_facts=scan_facts,
                            changed=changed, tokens=governor.spent("tokens"))
    written = _emit(findings, args.out_dir, status=run.status, target=args.slug or str(repo),
                    mode="diff", gate_reasons=gate_reasons, scope_reasons=scope_reasons, run=facts,
                    journal_path=journal.path)
    delivery = _delivered_verdict(findings, written, introduced, gate_new, run.status)
    outcome = _write_state(state, args, scope=scope, findings=delivery["state_findings"],
                           survey_payload=survey_payload, prior_reasons=state_reasons,
                           status=delivery["status"])

    payload = {
        "mode": "diff",
        "scan": scan_facts,
        "status": delivery["status"],
        "limit_hit": getattr(run, "limit_hit", "") or "",
        "scope": summarise(changed),
        "examined": list(scope),
        "inspection": facts.inspection,
        "findings": len(findings),
        "gate_eligible": sum(1 for f in delivery["findings"] if f.gate_eligible),
        "gate_new": delivery["new"],
        "gate_reasons": gate_reasons,
        "artefacts": written,
        "state": {"attempted": outcome.attempted, "ok": outcome.ok, "reasons": outcome.reasons},
        "tokens": governor.spent("tokens"),
        "cost": spend,
        "scope_reasons": scope_reasons,
        "hunk_radius": radius,
        "windows": {p: [list(s) for s in spans] for p, spans in sorted(windows.items())},
        "offered_expectations": list(offered_expectations()),
    }
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"scope        {payload['scope']}")
        if facts.inspection is not None:
            from shard.inspectionview import summary

            print(f"inspection   {summary(facts.inspection)}")
        for reason in scope_reasons:
            print(f"scope        {reason}")
        print(f"status       {payload['status']}")
        print(f"findings     {payload['findings']} "
              f"({payload['gate_eligible']} with a demonstration, the rest informational)")
        if payload["gate_eligible"]:
            print(f"new          {payload['gate_new']} of {payload['gate_eligible']} demonstrated "
                  f"finding(s) sit on a line this change introduced")
        for reason in gate_reasons:
            print(f"gate         {reason}")
        print(f"cost         {_cost_line(payload['tokens'], payload['cost'])}")
        for reason in outcome.reasons:
            print(f"state        {reason}")
    return _delivery_exit(delivery, payload, args.fail_on)


def _open_state(args):
    from shard.state import StateUnavailable, open_state

    if not args.state_repo:
        return None, ["no state repository configured; nothing will accumulate between runs"]
    try:
        return open_state(args.state_repo, args.slug or ""), []
    except StateUnavailable as e:
        return None, [str(e)]


def _load_or_build_survey(state, repo, args):
    from shard.cli import _applicable_kind_names
    from shard.state import load_survey
    from shard.survey import assess, survey_repo, to_payload

    if state is not None:
        survey, _reason = load_survey(state)
        if survey:
            return survey, None

    profile = profile_repo(repo)
    kinds, deep_available = _applicable_kind_names(profile)
    scan = survey_repo(repo)
    payload = to_payload(scan, assess(scan, harness_kinds=tuple(kinds),
                                      witness_entry=args.witness_entry,
                                      deep_available=deep_available,
                                      languages=set(profile.languages)))
    return payload, payload


def _write_state(state, args, *, scope, findings, survey_payload, prior_reasons, status):
    from shard.state import StateOutcome, append_run, build_run_record, commit_and_push, save_survey

    outcome = StateOutcome(reasons=list(prior_reasons))
    if state is None:
        return outcome
    outcome.attempted = True

    if survey_payload is not None:
        reason = save_survey(state, survey_payload)
        outcome.survey_written = not reason
        if reason:
            outcome.reasons.append(reason)

    record = build_run_record(run_id=args.run_id, mode="diff", status=status, scope=scope,
                              findings=findings, survey_seen=survey_payload is None)
    reason = append_run(state, record)
    outcome.run_written = not reason
    if reason:
        outcome.reasons.append(reason)

    reason = commit_and_push(state, f"shard: {args.slug} run {args.run_id}")
    if reason:
        outcome.reasons.append(reason)
    return outcome


def _diff_run_facts(args, run, *, spend: dict, scan_facts: dict, changed, tokens):
    from shard.report import RunFacts, _report_id

    return RunFacts(
        base_ref=args.base_ref, files_reviewed=len(changed),
        inspection=getattr(run, "inspection", None),
        report_id=_report_id(),
        scan=scan_facts["kind"] if scan_facts["declared"] else "",
        scan_why=scan_facts["why"] if scan_facts["declared"] else "",
        limit_hit=getattr(run, "limit_hit", "") or "",
        executions_spent=getattr(run, "executions_spent", None),
        error_kind=getattr(run, "error_kind", "") or "",
        step_flag="--max-steps",
        stateful=bool(args.state_repo),
        exec_refused=getattr(run, "exec_refused", None),
        exec_calls=getattr(run, "exec_calls", None),
        witness_entry=args.witness_entry or "", fail_on=args.fail_on,
        usd=spend["usd"], tokens=tokens, seconds=spend["seconds"])
