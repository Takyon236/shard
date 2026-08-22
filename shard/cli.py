"""The entry point — the single external consumer surface, and what closes C4.

the integration guide flagged the problem this resolves: the GitHub Action was going to become
a SECOND external consumer alongside the predecessor project's `scripts/the benchmark/cloud_sweep.py`, leaving the package
with two entry points and the maintainers' notes's first-listed trap live in both. The benchmark driver and the
product now run the same path, which is the only arrangement in which a green benchmark is evidence
about the product rather than about itself.

    python -m shard preflight --repo .           what this repository is, and what we could do with it
    python -m shard deep --repo . --workdir ...  acquire a workdir, run the solver, report


the separate package is imported inside the deep subcommand's function body and nowhere else. That is not a
startup optimisation. the design notes, "Protecting the harness": the free image ships simple mode and
must contain nothing of that capability, and if the two share an import closure the free tier gives
the jewel away with no later protection recovering it. the maintainers' suite asserts this file's
closure directly, so a convenient top-level `from the separate package import ...` fails the suite rather than
shipping.

`preflight` is therefore fully available in the free image, which is correct — it is the onboarding and
pricing instrument (the integration guideb) on every tier.

## The exit-code contract, which is the "does not break the build" promise

**Report-only is the default and it is not a suggestion.** A tool that breaks the build on the day it is
installed does not survive the week. `--fail-on` opts into gating, and one rule overrides it in every
configuration: **the check never fails on an unreproduced finding.** That is the anti-slop guarantee
expressed as behaviour rather than as marketing, and it is enforceable only because the oracle exists.

| code | meaning |
|---|---|
| 0 | the run completed. Findings may exist; nothing gated |
| 1 | a REPRODUCED finding exists and `--fail-on reproduced` asked for the gate — or `--fail-on new`
|   | did, and THIS change introduced the demonstrated defect |
| 2 | the run could not be configured or the target could not be acquired |

2 is deliberately distinct from 1. A customer whose repository cannot be acquired has a setup problem,
and reporting it as a security finding would be a false positive of the most annoying kind.
"""


import argparse
import json
import os
import pathlib
import sys
import tempfile

from shard.budget import SCAN_PROFILES, Budget, BudgetGovernor
from shard.journal import Journal

#: **THE OPTIONAL CAPABILITY PACKAGE, named ONCE.** `""` in a build that does not carry it.
#:
#: `preflight` asks two questions it may not be able to answer: what this runner can do, and which
#: harness kinds apply. Both answers live in a package the free artefact excludes, so both sites used
#:
#: One name, in one place, that the build can empty. `_optional_probe` reads it and returns None when
#: it is blank, so the free artefact's preflight answers exactly as it did — *this build cannot say* —
#: without the artefact stating what the missing thing is called.
_PROBE_PACKAGE = ""


def _optional_probe(module: str):
    """A submodule of `_PROBE_PACKAGE`, or None when this build does not carry it.

    Returning None rather than raising is the contract both callers already had: a preflight that
    crashed on an optional field would take down the one command a customer runs before spending
    anything.
    """
    if not _PROBE_PACKAGE:
        return None
    try:
        import importlib

        return importlib.import_module(f"{_PROBE_PACKAGE}.{module}")
    except ImportError:                                         # pragma: no cover - absent-build path
        return None
# MODULE SCOPE, not inside `_emit`, and the maintainers' suite is why. Its reachability probe
# executes each free entry point and asks which `shard.*` modules were imported; a module in
# `FREE_MODULES` that no command reaches is dead weight in the artefact, which is how `instrument`
# and `retry` came to sit in the free image. A function-scoped import inside `_emit` is reached
# only by a run that completes far enough to write artefacts — which the probe's keyless
# `diff --repo .` never does — so the module shipped and scored unreachable. Importing it here is
# the truthful arrangement rather than a weaker probe: it is dependency-free, it is part of the
# free CLI, and every command now genuinely loads it.
from shard.telemetry import render_log as _render_log, summarise as _telemetry
from shard.target import (cargo_fuzz_targets, demonstrability, entry_template, estimate_diff_cost,
                          free_tier_verdict, probe_runtimes, profile_repo, validate_workdir)

# THE GATE — the contract with CI, which is not the CLI's to own. `shard/gate.py` holds the exit codes,
# the `fail-on` vocabulary and the two rules that decide a build, so that `action.py` can read what a 1
# means without importing the entry point. That reach-back was this repository's only import cycle. The
# names are re-exported here because every caller — the tests, the bench, a maintenance script — has
# always read them off `shard.cli`, and the contract moving is not a reason to break them.
from shard.gate import (DEEP_FAIL_ON_CHOICES, EXIT_CONFIG, EXIT_GATED, EXIT_OK, FAIL_ON_CHOICES,
                        exit_code, is_new_finding)

#: The default model, stated once. A LITERAL rather than an import of `SolvePlan.model`, because
#:
#: GLM-5.2 by decision: open weights the customer controls (the maintainers' notes), and the frontier alias this
#: used to name refuses the solver's opening prompt outright — see the design notes, "Found by the
#: FIRST REAL RUN".
DEFAULT_MODEL = "glm-5.2"


#: Set to re-raise instead of reporting. Development and CI-of-Shard want the traceback; a CUSTOMER's
#: pull request must never be broken by one. Named rather than inferred, so turning it on is deliberate.
DEBUG_ENV = "SHARD_DEBUG"


def main(argv: list[str] | None = None) -> int:
    """Every exit from this function is one of the three documented codes.

    **The broad `except` is load-bearing and it is not lazy error handling.** `__main__.py` does
    `sys.exit(main())`, so an exception escaping here makes Python print a traceback and exit 1 — and
    `EXIT_GATED` IS 1. An internal error would therefore be indistinguishable from "a reproduced
    finding gated your build", and it would break the build even under the DEFAULT `--fail-on none`,
    which is the one promise the exit-code contract exists to keep.

    It reports as EXIT_CONFIG because that is what an internal failure is from the customer's side: a
    problem with the tool, never a security finding about their code.

    The thing a broad `except` normally costs is a hidden corpse — the design notes records a
    fail-safe that made a DEAD arm indistinguishable from a quiet one. Two things stop that here: the
    exception TYPE and message are printed rather than swallowed, and `SHARD_DEBUG` re-raises, so
    Shard's own suite and any developer see the traceback in full.
    """
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        return args.handler(args)
    except _ConfigError as e:
        print(f"shard: {e}", file=sys.stderr)
        return EXIT_CONFIG
    except Exception as e:                                   # noqa: BLE001 - see the docstring
        if os.environ.get(DEBUG_ENV):
            raise
        print(f"shard: internal error, no finding is implied: {type(e).__name__}: {e}",
              file=sys.stderr)
        return EXIT_CONFIG


class _ConfigError(Exception):
    """A problem with the invocation or the target — never a security finding. Exits 2."""


# --- preflight ---------------------------------------------------------------------------------------

def _cmd_preflight(args) -> int:
    """Profile a repository and state what can be done with it. No inference, so it is nearly free.

    Imports nothing from the separate package at module scope; the dictionary lookup below is the one place it
    is needed, and it degrades to "that capability not in this build" when the module is absent — which
    is exactly what happens inside the free image, and is the right answer there rather than a crash.
    """
    repo = _existing_dir(args.repo, "repo")
    profile = profile_repo(repo)
    kinds, deep_available = _applicable_kind_names(profile)

    # THE TEMPLATE, AND NOTHING ELSE, so the output redirects: `--entry-template > .shard/entry.sh`.
    # PRINTED RATHER THAN WRITTEN, deliberately. Preflight is the command a customer runs to decide
    # whether to adopt this product at all; one that edits their checkout is not one they can run to
    # find out. Committing it themselves is also what makes it theirs, which is the half of the
    # soundness argument a generated file would quietly spend.
    if args.entry_template:
        print(entry_template(profile.primary_language), end="")
        return EXIT_OK

    payload = {
        "repo": str(repo),
        "files": profile.files,
        "source_bytes": profile.source_bytes,
        "languages": profile.languages,
        "build_systems": list(profile.build_systems),
        "fuzz_harnesses": list(profile.fuzz_harnesses),
        "oss_fuzz": profile.oss_fuzz,
        "prepared_harness": profile.prepared_harness,
        "truncated": profile.truncated,
        "memory_unsafe": profile.memory_unsafe,
        "deep_capability_in_this_build": deep_available,
        "applicable_harness_kinds": kinds,
        "deep": _mode_verdict(profile, kinds, deep_available),
        # THE MACHINE, answered where a customer asks BEFORE paying for a run rather than only in the
        #
        # `None` in the free image rather than an invented answer: the probe lives behind the mode
        # split, and a preflight that guessed would be asserting something it did not measure.
        "machine": _machine_payload() if deep_available else None,
        # THE SAME QUESTION FOR THE FREE TIER, which had no answer at all. `machine` above is deep-only
        "runtimes": probe_runtimes(profile.languages),
        # **WHAT IT WILL COST THE CUSTOMER, and what tier they are on.**
        # the integration guideb designates preflight the pricing instrument — *"preflight
        # becomes the pricing instrument"* — and it profiled the repository and said nothing about
        # money, which is the half the commercial model was built on
        # (an internal audit). COGS ≈ 0 is true and irrelevant to the buyer: they
        # supply the inference on every tier, so their bill IS the price.
        "cost": estimate_diff_cost(profile),
        "free_tier": free_tier_verdict(profile, visibility=args.visibility),
        # **CAN ANYTHING THIS REPOSITORY PRODUCES ACTUALLY FAIL A BUILD.** The precondition under the
        # product's central claim, and the one fact this instrument did not report. A customer could
        # be told every runtime is present and what a run costs, and still get nothing that gates —
        # which is exactly what the first paying engagement got: 24 findings, `gate_eligible = 0` on
        # all 13 chunks, because the target declared no entry point
        # (a measured run). Printed beside the cost for the same reason the cost
        # is printed at all: a fact a human never sees is not a fact they have.
        "demonstrable": demonstrability(repo, declared=getattr(args, "witness_entry", "") or ""),
    }
    if args.probe_endpoint:
        # **§6c'S OWN SENTENCE: "preflight refuses rather than producing a bad run."** Opt-in because
        # it costs one real request and preflight is otherwise free — a profiling command that quietly
        # spends money is worse than one that has to be asked. an internal audit.
        from shard.llm import probe_endpoint

        payload["endpoint"] = probe_endpoint(_backend(args), model=args.model,
                                             validated_model=DEFAULT_MODEL)
    if args.workdir is not None:
        payload["workdir"] = _report_payload(validate_workdir(args.workdir))

    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        _print_preflight(payload, profile)
    return EXIT_OK


def _cmd_survey(args) -> int:
    """What this codebase is, and what we might look for in it.

    NOT `preflight`, and the distinction is the owner's (the design notes). Preflight
    answers "can we run here and what will it cost". This answers "what is here and what could we
    prove", and it is available on the FREE tier — it is what makes a first interaction useful on a
    repository where nothing is yet provable.
    """
    from shard.survey import assess, summarise, survey_repo, to_payload

    repo = _existing_dir(args.repo, "repo")
    profile = profile_repo(repo)
    kinds, deep_available = _applicable_kind_names(profile)

    scan = survey_repo(repo)
    # The capability facts are RESOLVED here and passed IN. `shard/survey.py` is simple-safe and must
    # not import the harness dictionary; this is the same seam `_mode_verdict` uses.
    assessment = assess(scan, harness_kinds=tuple(kinds), witness_entry=args.witness_entry,
                        deep_available=deep_available, languages=set(profile.languages))

    payload = to_payload(scan, assessment)
    # THE SLUG WHEN WE HAVE ONE, exactly as `_cmd_diff` names its target. `str(repo)` inside the
    # action is `/github/workspace`, a path in OUR container: true of the mount, and unattributable.
    # Measured 2026-08-13 on a real scan of urllib3 — the artefact this writes said
    # `"repo": "/github/workspace"` and could not say what it had surveyed.
    #
    # The KEY keeps its name deliberately. `shard-survey.json` is a file a customer may already parse,
    # and renaming a field to improve a value is a breaking change for a cosmetic gain; nothing in this
    # tree reads it, so the value is free to get better while the schema does not move.
    payload["repo"] = args.slug or str(repo)
    payload["languages"] = profile.languages
    payload["applicable_harness_kinds"] = kinds

    # ONE RENDERING OF THE SUMMARY, used by the artefact and by stdout alike. A second phrasing for the
    # file would be a copy of every number in it.
    summary = summarise(scan, assessment)

    if args.out_dir:
        from shard.report import _report_id, build_survey_markdown

        out = pathlib.Path(args.out_dir)
        out.mkdir(parents=True, exist_ok=True)
        (out / "shard-survey.json").write_text(json.dumps(payload, indent=2, sort_keys=True),
                                               encoding="utf-8")
        # **THE HUMAN ARTEFACT, STILL OPEN row 19.** Survey is the mode a customer meets first and it
        # wrote JSON and nothing else; the summary below reached a step log that GitHub deletes with
        # the runner. `shard-report.md` and not `shard-survey.md` deliberately — `action.yml` declares
        # ONE `report-path` output, and a workflow that uploads or comments it should not have to
        # branch on the mode to find the file.
        report = out / "shard-report.md"
        report.write_text(build_survey_markdown(summary, target=args.slug or str(repo),
                                                truncated=scan.truncated,
                                                report_ident=_report_id(),
                                                witness_entry=args.witness_entry or ""),
                          encoding="utf-8")
        payload["written"] = str(out / "shard-survey.json")
        payload["artefacts"] = {"survey": str(out / "shard-survey.json"), "report": str(report)}

    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"repository   {args.slug or repo}")
        print(summary)
    return EXIT_OK


def _gate_reasons(findings, *, fail_on: str, scope_reasons: list[str], changed, introduced) -> list[str]:
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

    gate_reasons: list[str] = []
    if diff_unread:
        gate_reasons.append(
            "fail-on new could NOT be evaluated: the diff was not read, so no finding can be "
            "attributed to this change and the gate did not fire. This is a degraded run, not a "
            "clean one — see scope_reasons for why git could not answer"
            if fail_on == "new" else
            f"the diff was not read, so this run reviewed no changed code and fail-on "
            f"{fail_on} had nothing to judge. This is a degraded run, not a clean one — see "
            f"scope_reasons for why git could not answer")

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
        gate_reasons.append(
            f"{len(refused)} of {len(findings)} finding(s) proposed a witness that was NEVER "
            f"ADJUDICATED, so this run judged less than it looks: {'; '.join(why[:3])}. The "
            f"gate-eligible count is a FLOOR — those findings were not refuted, they were not tried")

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
        gate_reasons.append(
            f"{claimed} finding(s) were counted as new on the agent's claim rather than on a measured "
            f"location: the demonstration produced no source location — a successful exploit is often "
            f"SILENT, exiting 0 with no stack — and the base revision could not be re-run to check the "
            f"claim causally. They are demonstrated defects; what rests on the agent's word is that "
            f"THIS change introduced them")
    return gate_reasons


def _cmd_diff(args) -> int:
    """The pull request as an entry point: read the survey, scope to the diff, hunt, write back.

    the design notes This is the FREE tier and the v1 shipping artefact, so nothing
    in this function may import the separate package — the mode split is enforced by that absence and measured
    by the maintainers' suite.

    The order is load-state → scope → hunt → EMIT → write-state, and the emit comes before the write
    deliberately: the SARIF, the report and the bundles are the deliverable, and a state repository
    that is unreachable must cost the customer a bookkeeping line, never a finding or a build.
    """
    from shard.diffscope import (HUNK_RADIUS, base_tree, hunk_windows, introduced_line_index,
                                 load_diff, scope_paths, summarise)
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

    # NEVER the working directory. On a runner the CWD is the customer's checkout, and
    # the design notes is explicit that we do not write there — a stray
    # `shard_journal.jsonl` dirties their working tree for every later step in their own workflow.
    # `out_dir` is where our artefacts already go; without one, scratch.
    journal = Journal(_scratch_dir(args.out_dir) / "shard_journal.jsonl")
    # Both held rather than built inline, because the run's cost is read off them AFTER the hunt. The
    # free tier is the tier with the ceilings in `action.yml` and it was the tier with no meter:
    # the ≈$0.29 of the first real diff run was obtainable only from OpenRouter's billing API, never
    # from the product. the design notes
    backend = _backend(args)
    diff_budget = _budget(args)
    governor = BudgetGovernor(diff_budget)
    # WHERE in each file the change is, not only which files. the design notes: the line numbers
    # were parsed all along and stopped at `scope_paths`, so a one-line change in a 7,980-line file was
    # priced as a full-file audit. `--hunk-radius 0` restores the old behaviour exactly, which is what
    # makes the two comparable on the same commit.
    # DEFAULT ON, at `HUNK_RADIUS`, and the numbers that earned it are in the design notes
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
    # stopped on a fourth that was a literal. the design notes, "Found by the FIRST DOGFOOD RUN".
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
    base_repo = None
    if args.fail_on == "new" and args.witness_entry:
        base_dir = pathlib.Path(tempfile.mkdtemp(prefix="shard-base-")) / "tree"
        base_repo = base_tree(repo, args.base_ref, base_dir, reasons=scope_reasons)

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
    # (an internal audit Finding 5): `CI-INTEGRATION.md` §4 advises `fetch-depth: 2`
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
                    gate_reasons=gate_reasons, scope_reasons=scope_reasons, run=facts,
                    journal_path=journal.path)
    outcome = _write_state(state, args, scope=scope, findings=findings,
                           survey_payload=survey_payload, prior_reasons=state_reasons,
                           status=run.status)

    payload = {
        "mode": "diff",
        "scan": scan_facts,          # computed above for the header; one reading, one number
        # The RUN's own status, not a literal. It was `"done"` on every diff run ever made, including
        # the ones that were not. the design notes
        "status": run.status,
        "limit_hit": getattr(run, "limit_hit", "") or "",
        "scope": summarise(changed),
        "examined": list(scope),
        "findings": len(findings),
        "gate_eligible": sum(1 for f in findings if f.gate_eligible),
        # The `fail-on: new` view of the same findings: how many demonstrated ones sit on a line this
        # change introduced (`diffscope.introduced_line_index` — added lines plus deletion seams).
        # Always reported, whatever `--fail-on` says, so a report-only customer can see what the gate
        # WOULD have done before opting in.
        "gate_new": gate_new,
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
        # **WHICH ROUTES THE RUN COULD EVEN OFFER.** the design notes's cheaper sibling, and
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
        for reason in scope_reasons:
            print(f"scope        {reason}")
        print(f"status       {run.status}")
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
    return exit_code(bool(payload["gate_eligible"]), args.fail_on, new=bool(gate_new),
                      status=str(payload.get("status") or "error"))


def _scratch_dir(out_dir: str | None) -> pathlib.Path:
    """Somewhere we may write. `out_dir` when the caller named one, otherwise a temp directory.

    The one thing this must never return is the current working directory: on a CI runner that IS the
    repository under review, and the decision that we never write there is what makes the state-repo
    design coherent in the first place.
    """
    if out_dir:
        path = pathlib.Path(out_dir)
        path.mkdir(parents=True, exist_ok=True)
        return path
    return pathlib.Path(tempfile.mkdtemp(prefix="shard-run-"))


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


def _machine_payload() -> dict | None:
    """The machine probe, or None when this build has no that capability to probe for.

    A function rather than an inline import because preflight runs in the FREE image too, where
    the separate package does not exist. `deep_available` is already computed by the caller and this is only
    reached when it is true — the try/except is the belt for a half-built tree, and it returns None
    rather than raising, because a preflight that crashed on an optional field would take down the one
    command a customer runs before spending anything.
    """
    machine = _optional_probe("machine")
    if machine is None:
        return None
    return machine.payload(machine.probe())


def _mode_verdict(profile, kinds: list[str], deep_available: bool) -> dict:
    """that capability's verdict for this repository, in the vocabulary the integration guideb fixed.

    `unsupported` and `degraded` are different answers and conflating them would be the free-target
    audit's §2 again: a repository we decline is not the same as one we can analyse with less leverage,
    and the customer's next action differs.
    """
    if not deep_available:
        return {"available": False, "verdict": "unsupported",
                "reason": "this build does not carry that capability"}
    if not kinds:
        # ONE STEP AWAY, not a refusal. A repository that ships cargo-fuzz targets is the BEST possible
        cargo = cargo_fuzz_targets(profile)
        if cargo:
            example = cargo[0].name
            n = len(cargo)
            return {
                "available": True, "verdict": "unsupported",
                # A friendlier HEADLINE than the bare verdict word, printed in its place. The machine
                # verdict stays `unsupported` — the checkout cannot be adjudicated AS IS — but the
                # customer sees how close it is. §6b fixes the three verdict words; this adds a headline,
                # it does not invent a fourth verdict.
                "headline": (f"one step away — {n} cargo-fuzz target{'s' if n != 1 else ''} found, "
                             f"and Shard can use them directly"),
                "reason": (f"build one and no test_poc.sh is needed:\n"
                           f"    cargo +nightly fuzz build {example}\n"
                           f"or, the manual route, add a test_poc.sh and declare it at "
                           f".shard/test_poc.sh"),
                "cargo_fuzz_targets": [t.name for t in cargo],
            }
        # NAME THE CODE WE ARE REFUSING TO LOOK AT. The cargo-fuzz branch above exists because listing
        # a capability and declining in the same breath is the worst answer available; this is the same
        # rule for the case where the missing piece is genuinely the CUSTOMER's to supply. Measured on
        # NousResearch/hermes-agent 2026-08-21: 7,131 files, `c=3` in a tally, and one real hand-written
        # C tokeniser — `native/fts5_cjk/fts5_cjk.c`, a UTF-8 decoder, exactly what this mode is for. A
        if profile.native_sources:
            shown = ", ".join(profile.native_sources[:3])
            more = len(profile.native_sources) - 3
            return {
                "available": True, "verdict": "unsupported",
                "reason": (f"no harness kind applies, so no workdir can be produced that the oracle "
                           f"could adjudicate.\n"
                           f"deep mode is aimed at memory-unsafe code, and this repository has some: "
                           f"{shown}{f', and {more} more' if more > 0 else ''}\n"
                           f"it needs an entry point that takes ONE argument, an input file, and "
                           f"exercises that code. Declare it at .shard/test_poc.sh\n"
                           f"start from: shard preflight --repo . --entry-template > .shard/entry.sh"),
                "native_sources": list(profile.native_sources),
            }
        return {"available": True, "verdict": "unsupported",
                "reason": ("no harness kind applies, so no workdir can be produced that the oracle "
                           "could adjudicate. Add a test_poc.sh and declare it at .shard/test_poc.sh")}
    if not profile.memory_unsafe:
        return {"available": True, "verdict": "degraded",
                "reason": ("no memory-unsafe source detected; deep mode's sanitiser, fuzz and crash "
                           "classification levers are aimed at C, C++, assembly and Zig"),
                "harness_kinds": kinds}
    return {"available": True, "verdict": "supported", "harness_kinds": kinds}


# --- deep --------------------------------------------------------------------------------------------











def _explicit_harness_fields(args) -> dict:
    """The caller's explicit harness setup, keyed by the KIND's own field names.

    **This exists because a second harness kind made the old form unreachable.** `--harness` and
    `--corpus` are `prepared`'s field names, and they were passed as a literal `{"harness": ...,
    "corpus": ...}` proposal whatever `--harness-kind` said. `cargo_fuzz` takes a `target`, so
    `--harness-kind cargo_fuzz` could only ever answer *"requires 'target'"* — the kind shipped
    green, fully tested, and drivable ONLY through model discovery. That is the maintainers' notes's standing
    trap verbatim: six mechanisms found built, tested and unreachable in production, one of them
    exactly the feature a task needed.

    `--harness` and `--corpus` keep their exact meaning, because the benchmark sweep driver — which
    produced every benchmark number this product quotes, and which lives in another repository —
    drives them, so a change to what they mean breaks a caller that cannot be seen from here. They
    simply stop being the only names a caller can say.

    Empty when the caller supplied nothing, which is what selects discovery. `--corpus` alone does
    NOT count: a corpus with no harness names no entry point, and treating it as an explicit setup
    would turn a mistyped flag into a refusal instead of the discovery it asked for.
    """
    fields = {}
    if args.harness:
        fields["harness"] = args.harness
    for item in getattr(args, "harness_field", None) or ():
        key, sep, value = item.partition("=")
        if not sep or not key.strip():
            raise _ConfigError(
                f"--harness-field expects KEY=VALUE, got {item!r}. The keys are the harness kind's "
                f"own setup fields — `shard preflight` names them per kind")
        fields[key.strip()] = value
    if fields and args.corpus:
        fields["corpus"] = args.corpus
    return fields




def _cmd_action(args) -> int:
    """The GitHub Action, which had no entry point at all until 2026-08-08.

    A subcommand rather than a second console script, because this module's opening line is that there
    is ONE external consumer surface — the integration guide, and the maintainers' notes's first-listed
    trap is what a second entry point costs. The action is now a caller of the same argv the benchmark
    driver and a developer at a terminal use, which is the only arrangement in which testing one says
    anything about the others.

    `shard/action.py` holds the mapping and the reasoning. It takes no flags: its interface is the
    environment GitHub sets, and a flag here would be a way to invoke it that no runner ever will.
    """
    from shard.action import ActionInputError, run

    try:
        return run()
    except ActionInputError as e:
        raise _ConfigError(str(e)) from e


# --- fix ---------------------------------------------------------------------------------------------



def _print_fix(payload: dict) -> None:
    """The human rendering. The patch itself prints only for a VERIFIED fix with nowhere else to go."""
    print(f"proposed     a patch for {payload['path']} ({len(payload['patch'].splitlines())} line(s))")
    print(f"verdict      {payload['verdict']}"
          + (f" — {payload['evidence']}" if payload["evidence"] else ""))
    for name in payload["controls_broken"]:
        print(f"             broke {name}")
    spend = payload["cost"]
    if spend["usd"] is not None:
        print(f"cost         ${spend['usd']:.2f} on {spend['requests']} request(s)")
    if payload["artefacts"].get("patch"):
        print(f"patch        {payload['artefacts']['patch']}")
    elif payload["fixed"]:
        print(payload["patch"], end="" if payload["patch"].endswith("\n") else "\n")














def _write_artefact(what: str, failed: list, write) -> bool:
    """Write ONE artefact. A failure costs that file and nothing else.

    **The run is over by the time this is called, and every token has been paid for.** `_emit` used to
    write the SARIF, the report and every bundle as one uninterrupted sequence, so the first exception
    escaped to `cli.main`'s broad `except`, which reports `EXIT_CONFIG` — a finished, adjudicated,
    gate-eligible run delivered a zero-byte report, no bundles, no alerts and exit 2. Measured cause: a
    single unpaired surrogate in a finding, which `write_text(encoding="utf-8")` cannot encode. That one
    is closed at the source by `report.Finding.__post_init__`; this closes the SHAPE, which is that any
    failure at all — a full disk, a read-only mount, a name the filesystem refuses — takes the whole
    deliverable rather than one file of it.

    Broad, and for `main`'s own reason rather than in spite of it: what a broad `except` normally costs
    is a hidden corpse, and nothing is hidden here. The type and message go to stderr and the name goes
    into the payload's `failed` list, so the customer is told which artefact is missing and why.

    **No `SHARD_DEBUG` re-raise, deliberately**, unlike `main`. Re-raising under the flag would restore
    exactly this defect for every developer and for Shard's own suite — the run-losing path would be the
    one under test, and the surviving path the one nobody exercises.
    """
    try:
        write()
        return True
    except Exception as e:                                   # noqa: BLE001 - see the docstring
        print(f"shard: could not write {what}: {type(e).__name__}: {e}. The run itself is unaffected "
              f"and the other artefacts were written.", file=sys.stderr)
        failed.append(what)
        return False


def _emit(findings: list, out_dir: str | None, *, status: str, target: str,
          gate_reasons=(), scope_reasons=(), run=None, journal_path=None) -> dict:
    """Write the artefacts. Returns what was written, for the JSON payload and the action outputs.

    `out_dir` is optional: a local run that only wants the verdict on stdout should not litter the
    working tree. In CI the action always passes one.

    **Each write is INDEPENDENT — see `_write_artefact`.** A key is present only when its file was
    written, so `written["sarif"]` is a claim that the SARIF exists rather than a path we intended to
    use; `written["failed"]` names anything that did not survive.
    """
    from shard.report import build_markdown, cap, write_bundle, write_sarif

    if out_dir is None:
        return {}
    out = pathlib.Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    # ONE CAP, READ BY BOTH WRITERS. `write_sarif` returns the same number, and taking it from there
    # made the report's drop count depend on the SARIF write having succeeded — so the artefact that
    # states what was omitted could only state it while the other artefact was fine. `cap` is pure.
    kept, dropped = cap(findings)

    written: dict = {}
    failed: list[str] = []
    sarif = out / "shard.sarif"
    # The status reaches the SARIF, not only the markdown. the design notes: the report was the
    # only honest artefact, and it is the one a CI consumer does not read.
    if _write_artefact("shard.sarif", failed,
                       lambda: write_sarif(findings, sarif, status=status)):
        written["sarif"] = str(sarif)
    report = out / "shard-report.md"
    if _write_artefact("shard-report.md", failed,
                       lambda: report.write_text(
                           build_markdown(findings, status=status, dropped=dropped, target=target,
                                          gate_reasons=gate_reasons, scope_reasons=scope_reasons,
                                          run=run),
                           encoding="utf-8")):
        written["report"] = str(report)

    # THE RUN'S OWN TELEMETRY. Everything above describes the CODE — what was found, whether it gates.
    # These two describe the RUN: where the seconds and the tokens went, how the context grew, which
    # tools fired and which failed. A customer debugging a slow or expensive review had no file to
    # open, and `shard_journal.jsonl` is not that file — it carries the model's reasoning prose and the
    # body of every tool result, i.e. excerpts of their own source, so it is not something they can
    # forward. `shard/telemetry.py` redacts in ONE place and documents what it drops.
    #
    # DERIVED FROM THE JOURNAL, so there is one recorder and these cannot disagree with it about what
    # happened. Written LAST because the journal is complete only once adjudication has recorded its
    # own events, which it has by the time `_emit` is reached.
    #
    # Each write is independent, like every artefact above it: telemetry that cannot be produced costs
    # the telemetry and never the report. A missing journal is not an error — a run invoked without
    # `--out-dir` journals to scratch and may not have one to hand — so the keys are simply absent and
    # `action.outputs_for` renders them empty, which is the same shape `bundle-path` already has.
    if journal_path is not None and pathlib.Path(journal_path).is_file():
        telemetry = out / "shard-telemetry.json"
        if _write_artefact("shard-telemetry.json", failed,
                           lambda: telemetry.write_text(
                               json.dumps(_telemetry(journal_path), indent=2, default=str),
                               encoding="utf-8")):
            written["telemetry"] = str(telemetry)
        runlog = out / "shard-run.log"
        if _write_artefact("shard-run.log", failed,
                           lambda: runlog.write_text(_render_log(journal_path), encoding="utf-8")):
            written["log"] = str(runlog)

    # One fingerprint can legitimately cover TWO demonstrations: identity names the defect site, and the
    # measured canary run demonstrated the same parse_command injection through `output_marker` and
    # `nonzero_exit` in a single run. Code scanning collapsing them into one alert is correct; a second
    # bundle silently overwriting the first would discard a paid demonstration, so a repeat gets a
    # numbered directory instead. The suffix keeps the fingerprint's path-safe character set.
    bundles, seen = [], {}
    for f in kept:
        # **A BUNDLE FOR A REFUSED WITNESS TOO, SINCE 2026-08-18, AND TWO DOCSTRINGS ALREADY SAID SO.**
        #
        # `report.write_bundle`: *"Written for a finding whether or not it reproduced, because a
        # hypothesis with a candidate input is still the fastest thing to hand a reviewer;
        # metadata.json states which it is."* `simple._to_finding`: *"Carried whenever a witness ran,
        # since a candidate input for a refuted claim is still the fastest thing to hand a reviewer."*
        # Both were true of the code that PRODUCES the payload, and this loop threw it away — so the
        # only artefact that could diagnose a refused witness was the one thing not written.
        #
        # Measured 2026-08-18: three demonstrations died on `rc=137` and their payloads could not be
        # recovered to test, because the journal records counts and no bundle existed. The whole
        # diagnosis had to be reconstructed from prose.
        #
        # A finding with NO payload is still skipped — there is nothing to put in the directory — and
        # `metadata.json` already carries `reproduced`, so a candidate input cannot be read as a
        # reproduction by anything that opens one. `kept` is the capped set, so this is bounded.
        if not f.gate_eligible and not f.poc_path:
            continue
        nth = seen[f.fingerprint] = seen.get(f.fingerprint, 0) + 1
        name = f.fingerprint if nth == 1 else f"{f.fingerprint}-{nth}"
        dest = out / "bundles" / name
        if _write_artefact(f"bundles/{name}", failed, lambda f=f, dest=dest: write_bundle(f, dest)):
            bundles.append(str(dest))
    written["bundles"] = bundles
    written["dropped"] = dropped
    if failed:
        # NAMED IN THE PAYLOAD, not only on a step log GitHub deletes with the runner. `action.py`
        # reads `artefacts["sarif"]` and treats an absent one as *"survey mode emits no SARIF; nothing
        # to say about it"* — true there and a false statement about a diff run, which is the
        # fail-safe-hiding-a-corpse shape `main`'s docstring records. Present only when something did
        # fail, for the reason the report's `levers` row is: a key that says "nothing wrong" on every
        # run is a key nobody reads on the run where something was.
        written["failed"] = failed
    return written


# --- shared ------------------------------------------------------------------------------------------

def _applicable_kind_names(profile) -> tuple[list[str], bool]:
    """Applicable harness kinds, and whether that capability is in this build at all.

    The ImportError arm is the FREE IMAGE, where the separate package is excluded at packaging time. It is a
    normal state there, not a failure, so preflight still answers — it simply answers that the separate capability is
    unavailable.
    """
    harness = _optional_probe("harness")
    if harness is None:
        return [], False
    return [k.name for k in harness.applicable(profile)], True


def _backend(args):
    """Build the customer's endpoint. We operate none, on any tier — see the design notes."""
    from shard.llm import OpenRouterBackend

    endpoint = args.model_endpoint
    if endpoint in ("bedrock", "vertex"):
        raise _ConfigError(
            f"the {endpoint} adapter is not built yet (workstream W3). Point --model-endpoint at an "
            f"OpenAI-compatible base URL — self-hosted vLLM is the guaranteed EU-residency path")
    api_key = os.environ.get(args.api_key_env or "OPENROUTER_API_KEY", "")
    if not api_key:
        raise _ConfigError(
            f"no API key in ${args.api_key_env or 'OPENROUTER_API_KEY'}. The customer supplies "
            f"inference on every tier; we operate no endpoint")
    return OpenRouterBackend(api_key=api_key, base_url=endpoint or None)


def _max_steps(args) -> int:
    """The hunt's step ceiling, defaulting to the measured one.

    `0` IS REFUSED, and that is the whole reason this is a function rather than an argparse default.
    The other three ceilings read `0` as *unmetered*, so a customer copying that convention here would
    write `max_steps: 0` meaning "no limit" — and `agentloop` runs `for step in range(1, max_steps + 1)`,
    so zero steps is not unbounded, it is NO REVIEW AT ALL. That run completes, reports no findings and
    exits 0: the green-check-that-reviewed-nothing this repository has now recorded three times, offered
    as a configuration option. A negative is refused for the same reason.

    There is deliberately no "unmetered" spelling. An unbounded ReAct loop on a customer's runner is the
    thing the ceilings exist to prevent, and `--max-spend-usd` is the ceiling for "let it run".

    **AN UNSET FLAG TAKES THE SCAN PROFILE'S FLOOR, the same precedence `_budget` gives `--max-tokens`
    and `_max_findings` gives `--max-findings`.** Until 2026-08-21 `--scan initial` raised the token
    ceiling to 6,000,000 and left this at 40, so the profile moved the ceiling that was not binding and
    left the one that was. a measured run is the measurement: the first real
    customer audit had to pass `--max-steps 200` by hand for a 300-file chunk, and a ceiling the
    operator must know to raise is not a profile — it is a trap with a default.

    The floor is taken with `max()` against the mode's own default, never as a replacement, so naming a
    scan can only ever RAISE the step count. A profile carrying `min_steps=0` — `followup` does — is
    inert by construction rather than by a check that could be dropped.
    """
    if args.max_steps is None:
        from shard.simple import DEFAULT_MAX_STEPS
        profile = _scan_profile(args)
        return max(DEFAULT_MAX_STEPS, profile.min_steps if profile is not None else 0)
    if args.max_steps < 1:
        raise _ConfigError(
            f"--max-steps must be at least 1, not {args.max_steps}. Unlike the dollar, minute and "
            f"token ceilings, 0 does NOT mean unmetered here: it means the hunt takes no turns at "
            f"all, and a run that reviewed nothing reports no findings and exits 0. To let a run go "
            f"long, raise --max-spend-usd")
    return args.max_steps










#: How far below the caller's measured default a DEEP run's explicit token ceiling may be set — HALF of
#: it. A run may be given less headroom than the measurement had (`SolvePlan.token_cap`, 8,000,000,
#: *"raised from 2M so 200 steps is reachable"*), but not so much less that it cannot reach the behaviour
#: the measurement describes. Expressed as a FRACTION of that default rather than a fixed 4,000,000, so
#: the refusal's "less than half of" is true by construction and the floor tracks the default instead of
#: being a second literal that has to be kept in sync with it.
DEEP_TOKEN_FLOOR_FRACTION = 0.5


def _refuse_a_token_ceiling_below_the_floor(asked: float, default_tokens: float | None) -> None:
    """A deep run may not be handed a ceiling it cannot finish inside. Raises `_ConfigError`.

    **This exists because it was got wrong by hand, on a real run, by someone who had just spent the day
    reading this file.** `--max-tokens 2000000` was passed to a live deep run on 2026-08-19 — exactly the
    value `SolvePlan.token_cap`'s own comment records having been RAISED FROM, for the stated reason that
    200 steps were not reachable below it. Nothing objected. The number is pinned as the measured
    configuration by the maintainers' suite, and nothing stopped a CALLER from undercutting it.
    `action.yml` exposes `max_tokens` as a customer input with no floor and no warning, so the same
    mistake is one YAML line away for anybody installing the product.

    **REFUSED, NOT RAISED, and the direction matters.** Silently lifting a ceiling to 4M would spend more
    of the customer's money than they authorised — on their own inference endpoint — which is a worse
    failure than declining to start. `budget.py` already argues that a ceiling is *"mandatory rather than
    advisory"*; a ceiling the product quietly overrides is neither.

    THREE THINGS IT DELIBERATELY DOES NOT TOUCH:

    * **Diff mode.** `_cmd_diff` calls `_budget` with no `default_tokens`, so `default_tokens is None`
      is exactly "this mode has no measured deep ceiling to defend". a real repository's diff run finished on
      402,300 tokens; a 4M floor there would be a floor above the ceiling.
    * **`--scan followup`, whose profile is 400,000 tokens.** That is a MEASURED, named configuration
      for an incremental scan and the whole point of declaring one is that it *"genuinely overrides
      downward"*. So the floor is checked against the EXPLICIT flag, never against the resolved value —
      checking the resolved value would refuse the one downward override the product supports.
    * **`0`.** It is falsy, so it never reaches here; it means "no explicit ceiling" and falls through to
      the profile or the plan's own 8,000,000.
    """
    if default_tokens is None:
        return
    floor = default_tokens * DEEP_TOKEN_FLOOR_FRACTION
    if asked >= floor:
        return
    raise _ConfigError(
        f"--max-tokens {asked:,.0f} is below the {floor:,.0f} floor a deep run needs. The "
        f"measured configuration is {default_tokens:,.0f} — raised from 2,000,000 precisely because "
        f"200 steps were not reachable below it — so a run given less than half of that stops at the "
        f"ceiling rather than at an answer, having spent everything it was given. Omit --max-tokens to "
        f"take the measured ceiling, or pass at least {floor:,.0f}. For a deliberately cheap "
        f"incremental run use --scan followup, which is a measured profile rather than a guess.")


def _budget(args, *, default_tokens: float | None = None) -> Budget:
    """`max-spend-usd`, `max-minutes` and `max-tokens`, which is `budget.py` becoming user-facing.

    A per-run ceiling is mandatory rather than advisory: the measured 16x spread across tasks means that
    without one, a weekly deep sweep on a large repository can consume a month of a team's inference
    budget without anybody having agreed to it.

    `default_tokens` is what an UNSET `--max-tokens` means, and it exists because the previous answer
    was `None` — unmetered. `Solve.__init__` falls back to `Budget(tokens=plan.token_cap)` only when no
    governor is supplied and `_cmd_deep` always supplies one, so the 8,000,000 that
    the maintainers' suite pins as the measured configuration governed sub-agent loops and nothing
    else. `shard deep` with no flags was completely unmetered on tokens (the design notes). The
    caller passes the ceiling it can defend: deep passes `SolvePlan.token_cap`, which is a measured
    number, and simple mode passes nothing, because no measurement of a diff-scoped run supports one and
    a ceiling invented here would be a number nobody had ever checked against a real run.
    """
    profile = _scan_profile(args)
    if args.max_tokens:
        _refuse_a_token_ceiling_below_the_floor(args.max_tokens, default_tokens)
        tokens: float | None = args.max_tokens
    elif profile is None:
        tokens = default_tokens
    elif profile.name == "initial":
        # A FLOOR, not a replacement. "Initial" says *at least* this much, so a mode that already
        # defends a higher measured ceiling keeps it — `SolvePlan.token_cap` is 8,000,000 because 200
        # steps had to be reachable, and the maintainers' suite pins it as the measured
        # configuration. Taking the max means naming a first scan can never REDUCE its coverage, which
        # would be the opposite of what the profile is for.
        tokens = max(profile.max_tokens, default_tokens or 0.0)
    else:
        # A follow-up genuinely overrides downward: that is the entire point of declaring one.
        tokens = profile.max_tokens
    return Budget(
        tokens=tokens,
        usd=args.max_spend_usd if args.max_spend_usd else None,
        wall_seconds=args.max_minutes * 60 if args.max_minutes else None,
    )


def _scan_profile(args):
    """The `--scan` profile in force, or None when the caller has no such flag.

    An EXPLICIT `--max-tokens` always wins over the profile — a customer who names a number gets that
    number. The profile only decides what an unset flag means, which until 2026-08-17 was one ceiling
    for both a first scan and a re-check. See `budget.ScanProfile`.
    """
    return SCAN_PROFILES.get(getattr(args, "scan", "") or "")


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
        # WHICH CEILING STOPPED IT, ON THE FREE TIER TOO. `AgentResult.limit_hit` has carried the
        limit_hit=getattr(run, "limit_hit", "") or "",
        # AND WHY, WHEN THE STOP WAS NOT A CEILING. The field above splits `budget` into three
        # resources because the customer's next action differs by which; this splits `error` the same
        # way, and the difference matters more — a revoked key, a spent balance and a mistyped model
        # name are all fixable in a minute, and a provider outage is not. All four reported the same
        # bare word until 2026-08-22.
        error_kind=getattr(run, "error_kind", "") or "",
        step_flag="--max-steps",
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
        witness_entry=args.witness_entry or "", fail_on=args.fail_on,
        usd=spend["usd"], tokens=tokens, seconds=spend["seconds"])


def _scan_payload(args, budget) -> dict:
    """What scan this was and what it was allowed to spend — for the payload and the report.

    Reported rather than implied, because `status: budget` means two different things: on a follow-up
    it is an ordinary stop against a deliberately small ceiling, and on an initial scan it means the
    baseline is INCOMPLETE and every count from it is a floor. A reader cannot tell those apart from
    the status alone, and the whole point of naming the two scans is that they are not the same claim.
    """
    profile = _scan_profile(args)
    return {
        # WHETHER A PROFILE IS IN FORCE AT ALL, as a boolean, because `kind` cannot say it: `"unset"` is
        # a legitimate answer here and reads as a profile name to anything that treats this field as
        # one. The report used to render it as a row and told every diff customer "no scan profile
        # applies to this mode", which is not true — both profiles are offered on diff mode and are
        # opt-in rather than imposed.
        "declared": profile is not None,
        "kind": profile.name if profile else "unset",
        "why": profile.summary if profile else "no profile declared, so this mode's own default ceiling "
                                              "applies — `--scan initial` or `--scan followup` names one",
        "max_tokens": budget.tokens,
        "ceiling_source": "--max-tokens" if args.max_tokens else
                          ("--scan " + profile.name if profile else "mode default"),
    }


def _spend(backend, governor) -> dict:
    """What the run cost, and against which ceilings — the half of a budget that faces the customer.

    Both halves of the design notes and §8: a ceiling nobody can reconcile against a reported
    number is as decorative as a ceiling nothing debits. `deep` reported steps and tokens and never a
    dollar figure; `diff` reported no cost of ANY kind, so the ≈$0.29 of the first real run had to be
    read off OpenRouter's billing API afterwards.

    `usd` is None, never 0.0, when no response this run carried a price. "This run was free" and "this
    endpoint does not price its responses" are different facts, and printing them as the same $0.00 is
    the exact defect class this function was written to close. A backend with no `usage_summary` at all
    (the engine client, a test double) reports None for the same reason.
    """
    usage = getattr(backend, "usage_summary", None)
    usage = usage() if callable(usage) else {}
    priced = int(usage.get("priced_requests", 0) or 0)
    return {
        "usd": round(float(usage.get("cost_usd", 0.0) or 0.0), 6) if priced else None,
        "usd_ceiling": governor.budget.usd,
        "tokens_ceiling": governor.budget.tokens,
        "requests": int(usage.get("llm_requests", 0) or 0),
        "priced_requests": priced,
        # **HOW LONG IT TOOK, which this product measured and never reported.** `--max-minutes` is a
        # ceiling, so `budget.py` has tracked `wall_seconds` from the first run — and nothing surfaced
        # it, in any mode, in the payload or the report. That is this function's own opening argument
        # ("a ceiling nobody can reconcile against a reported number is as decorative as a ceiling
        # nothing debits") applied to the one resource it forgot.
        #
        # It is not a secondary number for a CI product: wall-clock is what BLOCKS a customer's
        # pipeline, and it is the first thing anybody asks before putting a gate on a pull request.
        # Both `deep-proof.yml` and every manual run so far computed it OUTSIDE the product with
        # `date +%s`, which is the tell — an artefact everyone reconstructs by hand is one the product
        # should have written.
        "seconds": round(governor.spent("wall_seconds"), 1),
        "seconds_ceiling": governor.budget.wall_seconds,
    }


def _cost_line(tokens: float, cost: dict) -> str:
    """`tokens of ceiling, $spent of ceiling` — one line, and every number in it is one we hold."""
    # THE SAME TRI-STATE THE DOLLAR HALF HAS HAD, and it was missing here. "0 tokens" is a measurement;
    # an endpoint that omits `usage` gives us no measurement at all, and printing 0 asserts one. Worse,
    # `--max-tokens` cannot bind against a count that never arrives, so the line stating the ceiling was
    # exactly the line a customer would have used to notice it was inert.
    if not tokens and cost["requests"]:
        parts = ["token count not reported by this endpoint"
                 + (f" (ceiling {cost['tokens_ceiling']:,.0f} could not be enforced)"
                    if cost["tokens_ceiling"] else "")]
    else:
        parts = [f"{tokens:,.0f} tokens" + (f" of {cost['tokens_ceiling']:,.0f}"
                                            if cost["tokens_ceiling"] else " (no token ceiling)")]
    if cost["usd"] is None:
        parts.append("cost not reported by this endpoint" if cost["requests"]
                     else "no inference")
    else:
        parts.append(f"${cost['usd']:.2f}" + (f" of ${cost['usd_ceiling']:.2f}"
                                              if cost["usd_ceiling"] else " (no spend ceiling)"))
        if cost["priced_requests"] < cost["requests"]:
            # Partial pricing is stated rather than smoothed over: the figure above is a FLOOR, and a
            # customer reconciling it against a bill needs to know which way it is wrong.
            parts.append(f"priced on {cost['priced_requests']} of {cost['requests']} requests — a floor")
    return ", ".join(parts)


def _report_payload(report) -> dict:
    return {"verdict": report.verdict, "harness": report.harness, "exit_marker": report.exit_marker,
            "corpus": report.corpus, "repo_tree": report.repo_tree,
            # Tri-state, and it reaches the payload as one. `null` means the control replay was never
            # run — which is always the answer from `preflight`, since deciding it needs a subprocess.
            "control_crashed": report.control_crashed,
            "reasons": list(report.reasons)}


def _existing_dir(value, label: str) -> pathlib.Path:
    path = pathlib.Path(value)
    if not path.is_dir():
        raise _ConfigError(f"--{label} {str(path)!r} is not a directory")
    return path


def _print_preflight(payload: dict, profile) -> None:
    deep = payload["deep"]
    print(f"repository   {payload['repo']}")
    print(f"source       {payload['files']} files, {payload['source_bytes'] / 1024:.0f} KiB"
          + ("  (TRUNCATED — counts are a floor)" if payload["truncated"] else ""))
    print(f"languages    {', '.join(f'{k}={v}' for k, v in profile.languages.items()) or 'none'}")
    print(f"build        {', '.join(payload['build_systems']) or 'none detected'}")
    print(f"fuzz         {', '.join(payload['fuzz_harnesses']) or 'no harnesses found'}"
          + ("  (OSS-Fuzz integration present)" if payload["oss_fuzz"] else ""))
    # **A BUILD WITH NO SUCH CAPABILITY DOES NOT REPORT ON ONE.** Found by running the shipped image
    # against a real repository on 2026-08-23, which is the only way it could have been found: this is
    # a runtime string, so neither the packaging gates nor the prose redaction can see it. Preflight
    # printed
    #
    #
    # to every customer of an artefact built to contain no trace of that capability — naming it, twice,
    # in the one command people run before they spend anything. `available` is False exactly when the
    # probe found nothing to ask, so the row simply does not exist in that build. Where the capability
    # IS present the row is unchanged, including the honest `unsupported` verdicts.
    if deep.get("available"):
        # The HEADLINE stands in for the bare verdict word when there is one — a buildable cargo-fuzz
        # repository reads "one step away", not "unsupported", though the machine verdict stays
        # unsupported.
        print(f"deep mode    {deep.get('headline') or deep['verdict']}")
        if deep.get("reason"):
            # Per-line indent so a multi-line reason (the cargo-fuzz build command sits on its own
            # line) stays aligned under the column rather than wrapping back to the margin.
            for line in deep["reason"].split("\n"):
                print(f"             {line}")
    if deep.get("harness_kinds"):
        print(f"             harness kinds: {', '.join(deep['harness_kinds'])}")
    # THE BOX, beside the verdict about the REPOSITORY. Printed rather than left in the JSON for the
    # reason §6b gives about the cost band: a number a human never sees is not one, and this is the
    # command a customer runs to check the claim they are being sold on.
    mach = payload.get("machine")
    if mach:
        mem = f", {mach['memory_gb']} GiB" if mach.get("memory_gb") is not None else ""
        limit = " (container limit)" if mach.get("cpus_are_a_container_limit") else ""
        print(f"this runner  {mach['cpus']} cpu{limit}{mem}, docker "
              f"{'yes' if mach['docker'] else 'NO'}")
        if mach.get("note"):
            print(f"             {mach['note']}")
    # CAN THIS BOX EXECUTE THE CUSTOMER'S LANGUAGE AT ALL — the free tier's half of the line above, and
    # it printed nothing until 2026-08-17. A demonstration is the product; a language whose runtime is
    # absent cannot produce one, and the witness only discovered that after a review had been paid for.
    # Printed for the same reason as the cost band: a fact a human never sees is not a fact they have.
    runtimes = payload.get("runtimes") or {}
    if runtimes.get("absent"):
        print(f"runtimes     MISSING for {', '.join(runtimes['absent'])} — nothing written in "
              f"{'them' if len(runtimes['absent']) > 1 else 'it'} can be executed here")
        print(f"             {runtimes['note']}")
    elif runtimes.get("probed"):
        found = ", ".join(f"{r['command']}" for r in runtimes["probed"] if r["present"])
        print(f"runtimes     present for every detected language ({found})")
    if runtimes.get("unknown"):
        # Named rather than counted as fine. `_mode_verdict`'s rule: answer `unknown`, do not guess.
        print(f"             not looked up for: {', '.join(runtimes['unknown'])}")

    # CAN ANYTHING HERE FAIL A BUILD — printed ABOVE the money, because it decides what the money buys.
    # A customer reading "your cost $0.02–$0.51" and "runtimes present" reasonably concludes the
    # product will work; without an entry point every finding it returns is informational. That is not
    # a hypothetical: it is what the first paying engagement received, 24 findings and `gate_eligible`
    # 0 on all 13 chunks (a measured run).
    dem = payload["demonstrable"]
    if dem["can_gate"]:
        print(f"can gate     YES — `{dem['entry']}` is runnable, so a reproduced finding fails the build")
        # FOUND BY CONVENTION IS NOT THE SAME AS CONFIGURED. The file exists; nothing reads it unless
        # the workflow names it, so a customer who stops here still gets an informational-only run.
        if dem["source"] == "convention":
            print("             it is NOT read by default — declare it as `witness_entry` in the workflow")
    else:
        print("can gate     NO — every finding will be INFORMATIONAL and none can fail the build")
        print(f"             {dem['why']}")
        # THE BLANK PAGE IS THE BARRIER, not the concept. Naming the limit and leaving the customer to
        # guess the contract is half a fix; the contract has two non-obvious parts (one argument, and
        # an empty payload must be quiet) and both are what people get wrong.
        if dem["source"] == "none":
            print("             start from: shard preflight --repo . --entry-template > .shard/entry.sh")

    # THE MONEY, in the shell output and not only in the JSON. the integration guideb makes this
    # the pricing instrument, and a number a human never sees is not one.
    cost = payload["cost"]
    print(f"your cost    ${cost['usd_low']:.2f}–${cost['usd_high']:.2f} a pull-request run, on YOUR "
          f"inference bill")
    print(f"             ${cost['per_month_at_100_runs']['low']:.0f}–"
          f"${cost['per_month_at_100_runs']['high']:.0f}/month at 100 runs. "
          f"This repository resembles {cost['resembles']}")
    print(f"             band is wide on purpose: {cost['basis']}")
    print(f"             what drives it: {cost['driver']}")
    free = payload["free_tier"]
    print(f"free tier    {free['verdict']} — {free['why']}")
    for need in free["needs"]:
        print(f"             needs {need}")

    if "workdir" in payload:
        w = payload["workdir"]
        print(f"workdir      {w['verdict']}")
        for reason in w["reasons"]:
            print(f"             {reason}")




def _endpoint_args(parser) -> None:
    """The three flags that name WHOSE endpoint this is. One declaration, three subcommands.

    `--model-endpoint` falling through to `None` is the sovereignty breach this repository leads with
    (`shard/llm.py` `ENDPOINT` is a hardwired openrouter.ai URL), so the flags that select an endpoint
    are the last place to tolerate three near-copies drifting apart.
    """
    parser.add_argument("--model-endpoint", default=None,
                        help="an OpenAI-compatible base URL for self-hosted vLLM or Ollama")
    parser.add_argument("--model", default=DEFAULT_MODEL, help="model identifier")
    parser.add_argument("--api-key-env", default=None,
                        help="environment variable holding the endpoint's key")


def _budget_args(parser, *, scan_default: str) -> None:
    """The three per-run ceilings. Same argument as `_endpoint_args`, and the same drift happened.

    `0` MEANS UNMETERED on all three, and `_budget` (below) depends on that reading — so the sentence
    saying so is not decoration. Before this was one declaration, `deep` carried it and `diff` did not,
    which meant the free tier, the v1 shipping artefact, documented its spend ceiling less well than
    the separate build did.

    `--max-steps` is deliberately NOT here: it is diff-mode only, and `0` on it is refused rather than
    unmetered (`_max_steps`). A flag whose zero means the opposite of these three does not belong in
    the helper that promises they agree.
    """
    parser.add_argument(
        "--max-spend-usd", type=float, default=0.0,
        help="hard ceiling on inference spend, debited from the price the endpoint reports on every "
             "response. 0 means unmetered. The run stops BEFORE a model call it cannot afford at the "
             "highest price it has already paid this run, so the ceiling holds rather than being "
             "crossed by the call that trips it. Two cases still cross it by at most one call and "
             "neither is knowable in advance: the FIRST call of a run has no observed price behind "
             "it, and a call can be priced above every call before it — no endpoint we support "
             "accepts a spend cap as a request parameter, so a call's real cost arrives with its "
             "response")
    parser.add_argument("--max-minutes", type=float, default=0.0, help="0 means unmetered")
    parser.add_argument("--max-tokens", type=float, default=0.0, help="0 means unmetered")
    parser.add_argument(
        "--scan", choices=sorted(SCAN_PROFILES), default=scan_default,
        help="which kind of scan this is, and therefore what unset ceilings mean. THIS SETS A "
             "BUDGET, NOT A SCOPE: in diff mode the run reviews exactly the diff whichever you pick. "
             "'initial' is a first look at a target, sized for COVERAGE, because a first scan that "
             "stops early reports a floor rather than a result. 'followup' is every run after that: "
             "the baseline exists, so the run pays for the change rather than for the tree. An "
             "explicit --max-tokens or --max-steps always wins over both")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="shard",
        description="Security analysis with a reproducing input attached. Runs in your CI, on your "
                    "model endpoint.")
    sub = parser.add_subparsers(dest="command", required=True)

    pre = sub.add_parser("preflight", help="profile a repository; no inference, nearly free")
    pre.add_argument("--repo", default=".", help="path to the checkout")
    pre.add_argument("--workdir", default=None,
                     help="also validate an already-materialised workdir against the contract")
    # SUPPLIED, NOT GUESSED. A checkout does not know whether its origin is public, and the free
    # tier is public + simple — so half the rule is unavailable locally. `free_tier_verdict` answers
    # "unknown" without it, deliberately: a pricing instrument that resolves ambiguity in our own
    # favour is the kind of thing a customer finds out about later.
    pre.add_argument("--visibility", default="", choices=["", "public", "private"],
                     help="public or private. Half of the free-tier rule, and a checkout cannot "
                          "know it; omitted means the verdict is 'unknown' rather than a guess.")
    # THE ENDPOINT PROBE, opt-in. §6c promises preflight refuses a bad endpoint rather than
    # producing a bad run, and it costs ONE request — so it is a flag rather than a default, because
    # a profiling command that quietly spends money is worse than one that has to be asked.
    pre.add_argument("--entry-template", action="store_true",
                     help="print a ready-to-commit .shard/entry.sh for this repository's primary "
                          "language and exit. Redirect it: --entry-template > .shard/entry.sh. It is "
                          "a fixed skeleton, not generated from your code")
    pre.add_argument("--witness-entry", default="",
                     help="the repo-relative entry point your workflow declares, if it is not at a "
                          "conventional path. Preflight checks whether it exists and is runnable, "
                          "because without one NOTHING a run reports can fail a build")
    pre.add_argument("--probe-endpoint", action="store_true",
                     help="spend one request confirming the endpoint supports native tool calling. "
                          "Without it a scan on an incapable endpoint finds nothing and looks clean.")
    _endpoint_args(pre)
    pre.add_argument("--json", action="store_true")
    pre.set_defaults(handler=_cmd_preflight)

    dif = sub.add_parser("diff", help="review a pull request; the free tier and the v1 artefact")
    dif.add_argument("--repo", default=".", help="path to the checkout")
    dif.add_argument("--base-ref", default="HEAD~1", help="what this pull request is measured against")
    dif.add_argument("--witness-entry", default=None,
                     help="repo-relative runnable entry point the customer declared. Without one, "
                          "nothing this run reports can gate the build")
    dif.add_argument("--state-repo", default=None,
                     help="path to the checked-out DEDICATED state repository. Optional: without it "
                          "nothing accumulates between runs")
    dif.add_argument("--slug", default=None, help="<owner>/<name> of the repository under review")
    dif.add_argument("--run-id", default="run", help="identifier for this run's record")
    _endpoint_args(dif)
    # Diff mode defaults to NO profile, which keeps its unset `--max-tokens` meaning what it has
    # always meant: unmetered. `test_the_free_tier_has_no_invented_token_ceiling` records why —
    # no measurement of a diff-scoped run supports a ceiling, and one invented here would be a
    # number nobody checked, quoted to a customer as a safety property. Both profiles are still
    # offered here; on this mode they are opt-in rather than imposed.
    _budget_args(dif, scan_default=None)
    dif.add_argument("--fail-on", choices=FAIL_ON_CHOICES, default="none",
                     help="none reports only. reproduced gates on a finding carrying a DEMONSTRATION. "
                          "new gates only when a demonstrated finding sits on a line this change "
                          "introduced — derived from the diff in hand, nothing stored. A hypothesis "
                          "NEVER gates")
    dif.add_argument("--max-steps", type=int, default=None,
                     help="how many turns the hunt may take. Omit for the measured default, "
                          "simple.DEFAULT_MAX_STEPS — or the higher floor a --scan profile sets, "
                          "which since 2026-08-21 is what `--scan initial` does. This is the FOURTH "
                          "ceiling and until 2026-08-11 "
                          "it was the only one nobody could set: the first real diff this product "
                          "reviewed — 3 files, 71 added lines — used all 40 steps, spent $0.28 of a "
                          "$0.30 allowance and stopped at `maxsteps` with nothing to show. Dollars, "
                          "minutes and tokens were all configurable and none of them was the "
                          "constraint")
    dif.add_argument("--hunk-radius", type=int, default=None,
                     help="lines of context either side of a changed line to name as the change's "
                          "neighbourhood. 0 scopes to whole files, which is what every run before "
                          "2026-08-08 did. Omit for the measured "
                          "default, diffscope.HUNK_RADIUS")
    dif.add_argument("--out-dir", default=None)
    # ABLATION ARM ONLY — the maintainers' notes arm A, and the same shape the separate package uses for
    # `contract_endpoint`. It reproduces the pre-2026-08-19 toolset (four tools, nothing executable) so
    # that a maintenance script --compare-execution` has a control. Not a customer knob: `README.md`
    # does not document it, and if arm A says execution does not pay, the capability goes and this
    # flag goes with it rather than becoming a permanent option.
    dif.add_argument("--no-execution", action="store_true",
                     help=argparse.SUPPRESS)
    # ABLATION ARM ONLY, same contract as `--no-execution` one line above. It blanks the survey note
    # that `shard/state.py` feeds into the SYSTEM message, so a maintenance script --compare-survey`
    # has a control for the one accumulation mechanism this product already ships.
    #
    # **IT BLANKS THE NOTE AND NOTHING ELSE, and that is the whole design.** The survey is still built
    # and still written to the state repository in both arms, because the arms have to differ in what
    # the MODEL was told and never in what the harness did — the confound `simple._CAPABILITY_OFF`'s
    # first draft shipped, inverted. Skipping the build would also skip the state write, which is a
    # second variable and would make any difference between the arms unattributable.
    dif.add_argument("--no-survey", action="store_true",
                     help=argparse.SUPPRESS)
    dif.add_argument("--json", action="store_true")
    dif.set_defaults(handler=_cmd_diff)

    surv = sub.add_parser("survey", help="what this codebase is and what we might look for; free tier")
    surv.add_argument("--repo", default=".", help="path to the checkout")
    surv.add_argument("--witness-entry", default=None,
                      help="repo-relative runnable entry point the customer declared. Without one, "
                           "every candidate stays a hypothesis")
    surv.add_argument("--out-dir", default=None, help="write shard-survey.json here")
    surv.add_argument("--slug", default=None, help="<owner>/<name> of the repository under review")
    surv.add_argument("--json", action="store_true")
    surv.set_defaults(handler=_cmd_survey)

    # `default=None` MEANS UNSET, so the scan profile can answer — see `_max_findings`. It was `1`, and
    # a literal default is indistinguishable from a customer typing 1, which is what let an `initial`
    # scan stop at the first reproduction while its own summary promised coverage. `0` is still refused
    # rather than reused as the sentinel: 0 reads as "report none", and that refusal is a safety
    # decision this must not quietly undo.
    # the library. the library design. Underscores in the ACTION's input names, hyphens here —
    # `action.yml` records why: eleven of fourteen inputs were inert on a real runner because hyphens do
    # not survive the `INPUT_<name>` transform, and argparse maps `--library-mirror` to
    # `args.library_mirror` on this side regardless.

    act = sub.add_parser("action", help="run from a GitHub Action's INPUT_* environment")
    act.set_defaults(handler=_cmd_action)

    # MIRROR — at the END of the parser block so that cherry-picks of other builders' edits to the

    return parser




__all__ = ["DEEP_FAIL_ON_CHOICES", "EXIT_CONFIG", "EXIT_GATED", "EXIT_OK", "FAIL_ON_CHOICES", "main"]


# `python -m shard.cli` — AND IT USED TO SCAN NOTHING AND EXIT 0.
#
# a measured run.1 logged this as an environment trap that cost time. It is worse
# than a trap. `python -m shard.cli diff --repo . --base-ref main` is a plausible thing to write in a
# pipeline — it names the module the documentation talks about — and with no `__main__` guard Python
# imported this file, defined `main`, called nothing, and exited **0**. For a security gate, exit 0 with
# no output is not a silent no-op: it is a PASS. A build goes green having reviewed nothing, and the one
# promise `main`'s docstring makes about exit codes is kept by a process that never ran.
#
# Delegating to the same `main` rather than refusing: two spellings that both work cannot drift, whereas
# a refusal is a second contract to keep. `python -m shard` stays the documented form and
# `shard/__main__.py` stays the tested one — this is three lines with no imports of its own, so
# the maintainers' suite's import-closure measurement is unchanged.
if __name__ == "__main__":                                   # pragma: no cover - process entry point
    sys.exit(main())
