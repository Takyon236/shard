"""The pull request as an entry point — `shard diff`, the free tier and the v1 shipping artefact.

Split out of `shard/cli.py` on 2026-08-30, after `cliargs`, `cliemit`, `climeter` and `cliprint` had
taken the surface, the artefact writer, the ceilings and the rendering. What was left in the
dispatcher was six subcommand bodies, and `_cmd_diff` was the largest of them at 248 lines with its
own supporting cast: the gate's caveats, the run facts the report needs, and the state repository.

**The seam is the TARGET, not the size.** `diff` reviews a change; `preflight` and `survey` describe
a repository; the paid three need a capability the free image does not carry. Those are three
different questions about three different things, and only the first needs a base ref, a diff, a hunk
window and somewhere to record what the run learned.


This is the FREE tier's own command, and the maintainers' suite asks the SOURCE by AST so
a nested import cannot hide. The paid subcommands live in a module this build does not carry, which is the one
declared exception; this module is not on that list and must never join it.

## Why the shared helpers are imported inside the function bodies

`shard/cli.py` imports this module at module scope, to build its handler table. So a module-scope
`from shard.cli import _backend` here would be a cycle. The three names this module borrows —
`_backend`, `_existing_dir`, `_applicable_kind_names` — are therefore imported where they are used,
which is also how every command in this package has always reached `shard.simple`,
`shard.diffscope` and `shard.witness`.

The alternative was a shared module holding those four. It was rejected: it would have been named for
its position in the import graph rather than for a job, which is the definition of the junk drawer
the maintainers' notes' "a module names one job" rule exists to prevent.
"""

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
    """The raw transcript for one diff run, with ownership deciding its lifetime.

    An explicit path is the operator's retained diagnostic and is closed but never removed here. The
    default is a mode-0700 temporary directory owned by this invocation; telemetry and the redacted run
    log consume it before this context exits, then ``TemporaryDirectory`` removes the raw source-bearing
    transcript on success or error. The Action exposes no explicit path, so it can take only that owned
    branch.
    """
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
    """A caveat sentence, carrying the LIMIT CODE it maps to in `resultdoc.LIMIT_STATEMENTS`.

    A `str` everywhere it was already read — `report.build_markdown` interpolates it, `--json`
    serialises it, `resultdoc._gate` calls `str()` on it — so no consumer changed. What it adds is the
    one thing a sentence cannot carry: WHICH arm produced it.

    **Measured 2026-09-02.** `resultdoc.limits` mapped the PRESENCE of any reason onto
    `gate_not_evaluated`, whose statement is "the gate could not be evaluated on this run, so the exit
    code is not a verdict". Arms 2 and 3 fire on runs whose gate ran and gated, and arm 3 requires
    `is_new_finding`, which requires `gate_eligible` — so it can fire ONLY on a run that exits 1. The
    sentence telling a dashboard to discount the exit code was emitted only ever on builds Shard had
    correctly failed. A `str` subclass rather than a parallel list of codes because two lists that must
    stay in step is this repository's most-recorded defect class; here the code and the sentence are
    one object, constructed together, and cannot drift.
    """

    def __new__(cls, code: str, text: str) -> "GateReason":
        reason = super().__new__(cls, text)
        reason.code = code
        return reason


def _gate_reasons(findings, *, fail_on: str, scope_reasons: list[str], changed,
                  introduced) -> list[GateReason]:
    """Why the gate did what it did, in the customer's words. Three arms, each a way a run can be
    LESS conclusive than its exit code suggests.

    Separated from `_cmd_diff` because it is the only part of that function that is an ARGUMENT rather
    than a step: the surrounding pipeline reads a diff, runs a scan and writes files, while this
    decides what the customer is owed as an explanation. Each arm exists because a real run once said
    nothing and should have — the measurement is recorded per arm below, which is why none of the
    three may be dropped as noise later.

    Every arm is ADDITIVE and none of them suppresses the gate. A caveat that could switch a gate off
    is the exact defect the first arm was written for.
    """
    from shard.witness import UNATTRIBUTED

    # ONE PREDICATE, computed once and used by both arms below, because two spellings of "the diff was
    # not read" is how this drifted in the first place. It reads the OUTCOME — did any changed file
    # come back — rather than the presence of a reason, so a caveat can never disable the gate again.
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

    # **A WITNESS THAT NEVER GOT A VERDICT, ANNOUNCED AT THE RUN LEVEL — 2026-08-18.**
    #
    # `Witness.refusal` means nothing was adjudicated: the entry point was killed, its runtime is
    # absent from the image, it changed during the run, the payload could not be staged. Every one of
    # those reached the finding's prose and NOTHING ELSE, so a run whose witnesses were all refused
    # rendered as a report full of hypotheses and exited 0 — indistinguishable, at the level a customer
    # actually reads, from a run that looked and found nothing.
    #
    # Measured 2026-08-18: two REAL exploits on the canary — command injection and a pickle RCE — were
    # lost to `rc=137` under host memory pressure, and the run reported `status: done`, `exit 0`.
    #
    # This is a `gate_reason` and not a status change, deliberately. The run DID complete; what it did
    # not do is judge every witness it was given, and the honest word for the resulting number is a
    # FLOOR. Changing the status would say the review was cut short, which is a different untrue thing.
    refused = [f for f in findings if getattr(f, "witness_refused", "")]
    if refused:
        why = sorted({f.witness_refused.split(".")[0].strip() for f in refused})
        gate_reasons.append(GateReason(
            "witness_refused",
            f"{len(refused)} of {len(findings)} finding(s) proposed a witness that was NEVER "
            f"ADJUDICATED, so this run judged less than it looks: {'; '.join(why[:3])}. The "
            f"gate-eligible count is a FLOOR — those findings were not refuted, they were not tried"))

    # THE OTHER WAY `new` SILENTLY DOES NOT FIRE, and it needs no broken diff to happen.
    #
    # `gate_new` requires `location_measured` — a location the DEMONSTRATION itself produced — and two
    # classes of genuinely new demonstrated defect do not have one. Measured
    # (an internal audit item 7), every row a demonstrated finding:
    #
    #     finding                                        none  reproduced  new
    #     introduced defect, location measured             0        1       1
    #     introduced defect, exploit was SILENT            0        1       0   <- no stack, no location
    #     defect on a pure DELETION seam                   0        1       0   <- W9 §P2b.5, 6317e54
    #     pre-existing defect                              0        1       0
    #
    # A silent successful exploit is the NORMAL case for the managed languages (W9 §P2b.5: real command
    # injection and real path traversal exit 0 with no traceback), so `new` is weakest exactly where
    # this product demonstrates most reliably. Whether that should CHANGE is a product decision and is
    # the audit's item 7; it is not patched here. What is in our gift is refusing to be silent about
    # it — a customer who selected `new` and got a green check is entitled to know the gate had
    # findings it could not evaluate rather than findings it cleared.
    #
    # Only the UNLOCATED ones. A demonstrated finding WITH a measured location that is not on an
    # introduced line was evaluated and correctly found not-new, which is the feature working; saying
    # so on every run would be the noise that gets a real announcement skipped.
    #
    # SUPERSEDED IN ITS CONCLUSION BY THE OWNER DECISION ABOVE, KEPT IN ITS PURPOSE. This arm was
    # written to say "the gate had findings it could not evaluate", when an unmeasured location meant
    # no gate at all. Those findings gate now, and the reason to say something did not go away — it
    # inverted. A gate that fired on the AGENT'S CLAIM, because the counterfactual that would have
    # checked the claim could not run, should say so rather than presenting the same green tick as one
    # that measured everything.
    #
    # `not scope_reasons` because the arm above already speaks for a run with no diff, and two
    # sentences about the same failure is how the second one stops being read.
    # THROUGH `is_new_finding`, not a second spelling of it. The three conditions that follow narrow
    # the gate's own answer to the subset it reached on the agent's claim; re-deriving the gate rule
    # here made this a TRANSCRIPTION, and `is_new_finding`'s own docstring records what a transcription
    # of this rule already cost once ("the bench was measured against a MUTATED `_cmd_diff` and did not
    # notice"). Going through the function also makes `claimed <= gate_new` structural rather than a
    # coincidence of two expressions agreeing — a fourth `attribution` value, or a reorder inside
    # `is_new_finding`, would otherwise leave the gate firing while the sentence that says why is silent.
    claimed = sum(1 for f in findings
                  if is_new_finding(f, introduced)
                  and f.attribution == UNATTRIBUTED and not f.location_measured)
    # `diff_unread` rather than `scope_reasons`, for the reason given above: a diverged base is a
    # caveat on a diff that exists, and suppressing this arm there would hide a real claimed-line
    # warning on exactly the runs most likely to need it.
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
    """The gate inputs after reproduction bundles have actually reached disk."""
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
    """A missing required bundle is run-integrity failure, even when no finding gate was requested."""
    if delivery["failed"]:
        return EXIT_CONFIG
    return exit_code(bool(payload["gate_eligible"]), fail_on, new=bool(delivery["new"]),
                     status=str(payload.get("status") or "error"))


def _counterfactual_base(args, repo: pathlib.Path,
                         scope_reasons: list[str]) -> pathlib.Path | None:
    """Materialise the base tree only for a gate with a witness to replay there.

    This is a separate acquisition phase rather than another branch in ``_cmd_diff``: the main
    pipeline hunts in the current checkout, while this tree exists solely to answer the later causal
    attribution question. Keeping the condition beside the acquisition also makes the cost boundary
    visible — report-only and reproduced gates must not archive a second checkout.
    """
    if args.fail_on != "new" or not args.witness_entry:
        return None

    from shard.diffscope import base_tree

    base_dir = pathlib.Path(tempfile.mkdtemp(prefix="shard-base-")) / "tree"
    return base_tree(repo, args.base_ref, base_dir, reasons=scope_reasons)


def _cmd_diff(args, journal: Journal | None = None) -> int:
    """The pull request as an entry point: read the survey, scope to the diff, hunt, write back.

    The design notes. This is the FREE tier and the v1 shipping artefact, so nothing
    in this command may import the separate package — the mode split is enforced by that absence and measured
    by the maintainers' suite.

    The order is load-state → scope → hunt → EMIT → write-state, and the emit comes before the write
    deliberately: the SARIF, the report and the bundles are the deliverable, and a state repository
    that is unreachable must cost the customer a bookkeeping line, never a finding or a build.
    """
    # The DEFAULT is never the working directory OR `out_dir`. The latter is explicitly
    # customer-forwardable, while this file holds model reasoning and source returned by tools. The
    # Action used to put both in one directory, so the documented `upload-artifact: path: shard-out/`
    # exfiltrated the transcript even though every public output path correctly named only its redacted
    # derivatives. A direct CLI operator may retain it elsewhere only by passing `--journal-path`.
    if journal is None:
        with _diff_journal(args) as owned:
            return _cmd_diff(args, owned)

    # From the dispatcher, INSIDE the body: `shard/cli.py` imports this module at module scope to
    # build its handler table, so a module-scope import back would be a cycle. See the module
    # docstring for why a shared module holding these was rejected rather than written.
    from shard.cli import _backend, _existing_dir
    from shard.diffscope import (HUNK_RADIUS, hunk_windows, introduced_line_index, load_diff,
                                 scope_paths, summarise)
    from shard.simple import run_simple
    from shard.state import survey_note
    from shard.witness import offered_expectations

    repo = _existing_dir(args.repo, "repo")
    state, state_reasons = _open_state(args)
    survey, survey_payload = _load_or_build_survey(state, repo, args)

    # `scope_reasons` carries the difference between "this pull request changed nothing" and "git could
    # not tell us what it changed", which collapsed into one empty tuple until 2026-08-08. On a runner
    # the second is a real state — a container action is root and the checkout is not — and it produced
    # a clean report for a pull request nothing had read. See `diffscope.safe_directory_argv`.
    scope_reasons: list[str] = []
    changed = load_diff(repo, args.base_ref, reasons=scope_reasons)
    scope = scope_paths(changed)

    # Both held rather than built inline, because the run's cost is read off them AFTER the hunt. The
    # free tier is the tier with the ceilings in `action.yml` and it was the tier with no meter:
    # the ≈$0.29 of the first real diff run was obtainable only from OpenRouter's billing API, never
    # from the product. The design notes.
    backend = _backend(args)
    diff_budget = _budget(args)
    governor = BudgetGovernor(diff_budget)
    # WHERE in each file the change is, not only which files. The design notes: the line numbers
    # were parsed all along and stopped at `scope_paths`, so a one-line change in a 7,980-line file was
    # priced as a full-file audit. `--hunk-radius 0` restores the old behaviour exactly, which is what
    # makes the two comparable on the same commit.
    # DEFAULT ON, at `HUNK_RADIUS`, and the numbers that earned it are in the design notes.
    # On §7's own measured shape — one line changed in a 6,895-line xmlparse.c — it cut 795,519 tokens
    # to 476,601 and $0.0977 to $0.0564 at an identical step count. On the risk §7 raised against it —
    # a defect 69 lines OUTSIDE the window — it was found and gated 3 times out of 3, anchored on the
    # right line, because the window narrows attention and not capability. `--hunk-radius 0` restores
    # file scope exactly.
    radius = HUNK_RADIUS if args.hunk_radius is None else args.hunk_radius
    windows = hunk_windows(changed, radius=radius) if radius else {}
    # THE FOURTH CEILING, and the one that actually bound the first real diff review this product ever
    # made. `DEFAULT_MAX_STEPS` was a module constant that `_cmd_diff` never passed, so no flag and no
    # action input could reach it: three ceilings were offered — dollars, minutes, tokens — and the run
    # stopped on a fourth that was a literal. The design notes, "Found by the FIRST DOGFOOD RUN".
    #
    # The DEFAULT IS UNCHANGED at 40. A default is a claim, and no measurement has chosen a different
    # number — one run of one diff says 40 was not enough for that diff, which is not a rate.
    # THE BASE REVISION, extracted ONLY when a gate will read the answer.
    #
    # `fail-on: new` asks "did this change introduce it". Until 2026-08-12 that was approximated by
    # "does the finding sit on a line the diff added", which cannot answer for a silent exploit (no
    # location at all) or for a defect a DELETION introduced (no line to sit on) — the two rows the
    # owner ruled must gate. With a reproducing input in hand the question is answerable directly, by
    # re-running that input against the code as it was: `witness.attribute`.
    #
    # Under `reproduced` and `none` nothing reads it, so nothing is extracted and no entry point is
    # executed a second time. `base_reasons` joins `scope_reasons` because a base we could not obtain
    # is the same class of fact as a diff we could not read: the run answered less than it looks.
    base_repo = _counterfactual_base(args, repo, scope_reasons)

    run = run_simple(repo=repo, backend=backend, journal=journal, scope=scope,
                     witness_entry=args.witness_entry, model=args.model, max_steps=_max_steps(args),
                     governor=governor,
                     # THE SECOND CONTROL ARM. `survey_note` is the ONLY route by which accumulated
                     # understanding reaches the model (`simple._system` joins exactly four clauses,
                     # and this is one of them), so blanking it here ablates the whole mechanism
                     # without touching the survey that was built or the state that gets written.
                     # `getattr` for the reason the execution arm gives below.
                     survey_note="" if getattr(args, "no_survey", False) else survey_note(survey),
                     windows=windows,
                     base_repo=base_repo,
                     secret_env_names=(args.api_key_env or "OPENROUTER_API_KEY",),
                     # THE CONTROL ARM. `getattr` because this entry point is reached by callers that
                     # build their own namespace (the action, and the tests), and an ablation flag
                     # must never be the reason a shipping path raises. Absent => the shipping
                     # configuration, which is execution ON.
                     execution=not getattr(args, "no_execution", False))
    findings = run.findings

    # EMIT FIRST. Everything below this line is bookkeeping.
    #
    # The SLUG names the target when we have one. `str(repo)` is a path INSIDE OUR CONTAINER: on a
    # runner the report's first line read `/github/workspace`, which is true of the mount and says
    # nothing about the customer's repository. The action already resolves `--slug` from
    # `GITHUB_REPOSITORY`, so on the path this matters the better name is in hand.
    # What `fail-on: new` reads: demonstrated findings sitting on a line THIS change introduced.
    # `f.gate_eligible` is the first conjunct of the narrowing and it is here as well as in
    # `exit_code`, so `gate_new` in the payload can never exceed `gate_eligible` — a count that
    # included a hypothesis would be the payload contradicting the one guarantee the product makes.
    #
    # **THE CAUSAL ANSWER WINS WHERE IT EXISTS, and the line test is the fallback.** Owner decision,
    # 2026-08-12, on an internal audit item 7: `new` must gate on a demonstrated defect
    # whose exploit was SILENT (no location) and on one a DELETION introduced (no line). Neither is
    # answerable from text, and both are answerable by re-running the reproducing input against the
    # code as it was — `witness.attribute`, whose verdict is on `Finding.attribution`.
    #
    #     attribution == INTRODUCED    gates, whatever the location says   <- rows 2 and 3
    #     attribution == INHERITED     never gates, whatever the location says
    #     attribution == UNATTRIBUTED  fall back to the line test below
    #
    # `INHERITED` overriding an added-line match is a TIGHTENING that came free: a pre-existing defect
    # can sit on a line this change added — code moves — and the line test called that new.
    #
    # **THE FALLBACK IS WIDER THAN IT WAS, and this is the part with a cost.** It no longer requires
    # `location_measured`, so an agent-CLAIMED line on an introduced line now gates. That is the owner's
    # row 2 in the case where the counterfactual could not run, and it hands the agent a choice it did
    # not have: it must still DEMONSTRATE a real defect, and it must name a file and line this pull
    # request actually introduced, but within that it decides. The claim is checked rather than trusted
    # whenever a base revision is available, which is why `base_tree` is attempted on every `new` run.
    introduced = introduced_line_index(changed)

    gate_new = sum(1 for f in findings if is_new_finding(f, introduced))

    # `new` is evaluable only from a diff that was READ. That it does not gate then is structural —
    # `git_diff` returns "" whenever it appends a reason, so `introduced` is empty and `gate_new` is
    # 0 — but structure is SILENT, and silence here is the exact shape of the recorded defect where an
    # ownership refusal made diff mode report a clean scan of a pull request it never read. This arm
    # is the announcement: the reason lands in the payload, which action mode echoes verbatim into
    # the log, and in the printed report below.
    #
    # **AND IT IS ANNOUNCED FOR EVERY `--fail-on` VALUE, not just `new`.** The narrow version was the
    # third defect landing on the same input, and again on customers who followed the documentation
    # (an internal audit Finding 5): the integration guide §4 advises `fetch-depth: 2`
    # while `action.yml` and `README.md` advise `base_ref: <pull_request.base.sha>`, and when the base
    # has moved that SHA is outside the shallow window. Measured — `fatal: bad object`,
    # `scope_paths: ()`, `summarise: 'no changed files in scope'`, exit 0.
    #
    # Under `--fail-on reproduced` that was a PASSING CHECK with a paragraph in a file nobody's CI
    # reads, because this arm was gated on `new`. An unread diff is a degraded run whatever the gate is
    # set to: `reproduced` reviewed no code so it found nothing to reproduce, and `none` is report-only
    # on a report with nothing in it. The sentence differs per value because what could not be
    # evaluated differs; the announcement does not.
    # **THE INVARIANT THE PARAGRAPH ABOVE RESTS ON IS FALSE, AND HAS BEEN SINCE `_note_divergence`.**
    #
    # It says *"`git_diff` returns "" whenever it appends a reason"*. That was true of every reason
    # then and is not true of the divergence note, which appends a caveat and returns a REAL DIFF —
    # its own docstring is explicit: *"Announced, never fatal. A diverged base still produces an honest
    # diff, so this is a caveat on a result rather than a refusal."*
    #
    # So one caveat disabled the gate and printed a sentence that was simply untrue. Measured
    # 2026-08-18 against `mistralai/mistral-common` #285, in the configuration `action.yml`
    # RECOMMENDS — `github.event.pull_request.base.sha` with a full fetch:
    #
    #     scope   4 file(s) changed, 221 line(s) added        <- the diff was read
    #     scope   '693adfb43bcb' is not an ancestor of HEAD    <- a caveat, never fatal
    #     gate    fail-on new could NOT be evaluated: the diff was not read
    #
    # GitHub's `base.sha` is the base branch tip at the last sync, so it is routinely NOT an ancestor
    # of the head; three-dot then diffs from the merge base, which is the CORRECT causal answer to
    # "what did this change add" and is exactly what `fail-on: new` wants. The gate was evaluable and
    # was switched off anyway.
    #
    gate_reasons = _gate_reasons(findings, fail_on=args.fail_on, scope_reasons=scope_reasons,
                                 changed=changed, introduced=introduced)

    # THE HEADER'S FACTS, gathered where they are known. Until 2026-08-13 the report was handed
    # findings and a status only, so a clean run and one cut off at its step ceiling rendered almost
    # identically — measured the same day on two real runs, `findings 0` at `maxsteps` beside
    # `findings 0` at `done`. Telling them apart meant reading a workflow log, and the artefact is what
    # people keep. `_spend` already answers the cost question for the payload; it is the same call.
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
        "scan": scan_facts,          # computed above for the header; one reading, one number
        # The RUN's own status, not a literal. It was `"done"` on every diff run ever made, including
        # the ones that were not. The design notes.
        "status": delivery["status"],
        "limit_hit": getattr(run, "limit_hit", "") or "",
        "scope": summarise(changed),
        "examined": list(scope),
        "inspection": facts.inspection,
        "findings": len(findings),
        "gate_eligible": sum(1 for f in delivery["findings"] if f.gate_eligible),
        # The `fail-on: new` view of the same findings: how many demonstrated ones sit on a line this
        # change introduced (`diffscope.introduced_line_index` — added lines plus deletion seams).
        # Always reported, whatever `--fail-on` says, so a report-only customer can see what the gate
        # WOULD have done before opting in.
        "gate_new": delivery["new"],
        "gate_reasons": gate_reasons,
        "artefacts": written,
        "state": {"attempted": outcome.attempted, "ok": outcome.ok, "reasons": outcome.reasons},
        "tokens": governor.spent("tokens"),
        "cost": spend,
        "scope_reasons": scope_reasons,
        # What was actually named to the agent, so a run's cost can be read against its
        # scope rather than against an assumption about it.
        "hunk_radius": radius,
        "windows": {p: [list(s) for s in spans] for p, spans in sorted(windows.items())},
        # **WHICH ROUTES THE RUN COULD EVEN OFFER.** The design notes' cheaper sibling, and
        # an internal audit. Two levers decide this set —
        # `DIFFERENTIAL_NONZERO_EXIT` and `UNHANDLED_EXCEPTION`, both off — so two runs of the same
        # code against the same diff can offer different routes and neither artefact said which.
        #
        # That is not hypothetical bookkeeping: resolving the P1.3 discrepancy needed forensics on raw
        # `output.txt` precisely because a measurement did not state its own configuration, and it is
        # the same defect the run STATUS fixed one layer up. A finding says how it was witnessed —
        # `rule_id` is `shard/simple-<expectation>` — and until now nothing said what it could have
        # been witnessed BY.
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
    # `status=` because a run that ERRORED must not pass a gate the customer asked for. Read off the
    # payload rather than off `run`, so the exit code and the artefact cannot disagree about the run.
    return _delivery_exit(delivery, payload, args.fail_on)


def _open_state(args):
    """Open the state repository, or report why not. NEVER fatal — see `shard/state.py`."""
    from shard.state import StateUnavailable, open_state

    if not args.state_repo:
        # The honest degradation: no state repository means nothing accumulates, which keeps the free
        # tier installable in one step and costs us nothing.
        return None, ["no state repository configured; nothing will accumulate between runs"]
    try:
        return open_state(args.state_repo, args.slug or ""), []
    except StateUnavailable as e:
        return None, [str(e)]


def _load_or_build_survey(state, repo, args):
    """The recorded survey, or a fresh one on first contact.

    Returns `(survey, payload_to_write)`. `payload_to_write` is None when the survey was already
    recorded, so a pull-request run does not rewrite an unchanged file on every push.
    """
    # From the dispatcher, INSIDE the body: `shard/cli.py` imports this module at module scope to
    # build its handler table, so a module-scope import back would be a cycle. See the module
    # docstring for why a shared module holding these was rejected rather than written.
    from shard.cli import _applicable_kind_names
    from shard.state import load_survey
    from shard.survey import assess, survey_repo, to_payload

    if state is not None:
        survey, _reason = load_survey(state)
        if survey:
            return survey, None

    # First contact, or no state at all. The initial scan happens HERE rather than being a separate
    # thing a customer has to remember to run — the design notes requires it on the
    # free tier, and a survey nobody triggered is a survey that never exists.
    profile = profile_repo(repo)
    kinds, deep_available = _applicable_kind_names(profile)
    scan = survey_repo(repo)
    payload = to_payload(scan, assess(scan, harness_kinds=tuple(kinds),
                                      witness_entry=args.witness_entry,
                                      deep_available=deep_available,
                                      languages=set(profile.languages)))
    return payload, payload


def _write_state(state, args, *, scope, findings, survey_payload, prior_reasons, status):
    """Record what this run learned. Every failure is a reason, never an exit code.

    `status` is the RUN's own, for the same reason the payload's is. `SimpleRun`'s docstring records
    that a hardcoded `"done"` made a run whose model refused, whose budget ran out or whose backend
    died **indistinguishable from a clean review** — and that fix reached the payload and the report
    while this call site, the accumulating history a customer keeps, kept the literal. The state
    repository is the one artefact that outlives the run, so a run that stopped early claiming it
    finished is the version of this defect that compounds.
    """
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
    """Everything the report needs to say what this diff run WAS, as one `report.RunFacts`.

    UNANNOTATED RETURN, deliberately. `shard.report` is imported inside the body, the way every other
    consumer in this module imports it, and a `-> "RunFacts"` annotation on a name that has no
    module-scope binding is an undefined reference — caught by ruff, and correctly. The type is in the
    first line of this docstring instead, which is where a reader looks anyway.

    **THE SEAM the maintainers' suite NAMES.** `_cmd_diff` sat one point under the oversized
    threshold with this assembly inline, and the ratchet's own note says the honest way across the line
    is this extraction and nothing else — never a variable folded away to move three points. It is a
    real seam and not a cosmetic one: every field here answers *what happened*, while the rest of
    `_cmd_diff` decides *what to do about it*.

    Each field below is a defect this artefact once had. A diff run reported `status: done` whatever
    really happened; a `budget` stop could not say which of three ceilings; an execution ceiling that
    changed a finding said nothing at all; and every transport failure — a revoked key included —
    arrived as the single word `error`.
    """
    from shard.report import RunFacts, _report_id

    return RunFacts(
        base_ref=args.base_ref, files_reviewed=len(changed),
        inspection=getattr(run, "inspection", None),
        # THE RUN'S OWN NUMBER, from the CI environment. `report.report_id` is pure and takes the env,
        # so this is the one line that reads it — see its docstring for why `GITHUB_RUN_NUMBER` beats a
        # counter we would have to store somewhere.
        report_id=_report_id(),
        # ONLY WHEN A PROFILE IS ACTUALLY IN FORCE. `_scan_payload` answers `unset` for the machine
        # channel, which is a fact about the flag; passing that string here printed a report row reading
        # "no scan profile applies to this mode", and that sentence is false — `--scan followup` applies
        # here and works. `RunFacts.scan` says an unknown omits its row, and this is the field that
        # ignored its own rule.
        scan=scan_facts["kind"] if scan_facts["declared"] else "",
        scan_why=scan_facts["why"] if scan_facts["declared"] else "",
        limit_hit=getattr(run, "limit_hit", "") or "",
        # **AND WHETHER THE EXECUTION CEILING WAS SPENT, which no field carried.** `limit_hit` above
        # names the ceiling that ENDED the loop; this names one that may have shortened it without
        # ending it. Measured 2026-09-03: 24 of 24 executions used, `refused: 0`, `status: done`, and
        # the report said `complete run` while the agent's own last turn opened "I have no tool budget
        # left" at model turn 20 of an allowed 40. The model is handed `executions_left` on every tool
        # result, so it stops asking rather than being refused — the ceiling binds in silence.
        executions_spent=getattr(run, "executions_spent", None),
        # AND WHY, WHEN THE STOP WAS NOT A CEILING. The field above splits `budget` into three
        # resources because the customer's next action differs by which; this splits `error` the same
        # way, and the difference matters more — a revoked key, a spent balance and a mistyped model
        # name are all fixable in a minute, and a provider outage is not. All four reported the same
        # bare word until 2026-08-22.
        error_kind=getattr(run, "error_kind", "") or "",
        step_flag="--max-steps",
        # WHETHER ANYTHING ACCUMULATES BETWEEN RUNS. The declared flag, not the opened repository:
        # `no_baseline` in the result document is the question "is a state repository configured",
        # and a configured one that failed to open is a different fact with its own reasons already
        # travelling through `_write_state`.
        stateful=bool(args.state_repo),
        # WHETHER THE EXECUTION CEILING CUT THE RUN SHORT, which no artefact could say until
        # 2026-08-21. `spend` refused the agent and told only the agent, so a run that could not finish
        # verifying wrote the same report as one that finished — and on the first paying engagement
        # that silence let a candidate the agent could not clear ship as a finding
        # (a measured run).
        #
        # `getattr` because this field is newer than the record: an older `SimpleRun` yields `None`,
        # which is the honest unknown and omits the row. A bare attribute access would be an
        # AttributeError; a default of `0` would be a claim that nothing was refused, which is the
        # thing we cannot know.
        exec_refused=getattr(run, "exec_refused", None),
        # WHAT THE AGENT RAN, beside what the ceiling denied. Same `getattr` reason as the line above,
        # and the same honest-unknown default: `None` omits the row, and a default of `0` would assert
        # a read-only review of a run we cannot see into.
        exec_calls=getattr(run, "exec_calls", None),
        witness_entry=args.witness_entry or "", fail_on=args.fail_on,
        usd=spend["usd"], tokens=tokens, seconds=spend["seconds"])
