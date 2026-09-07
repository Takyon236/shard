"""The entry point — the single external consumer surface, and what closes C4.

The integration guide flagged the problem this resolves: the GitHub Action was going to become
a SECOND external consumer alongside the predecessor project's maintenance tooling, leaving the package
with two entry points and the maintainers' notes' first-listed trap live in both. The benchmark driver and the
product now run the same path, which is the only arrangement in which a green benchmark is evidence
about the product rather than about itself.

    python -m shard preflight --repo .           what this repository is, and what we could do with it
    python -m shard diff --repo . --base-ref …   review a pull request and report what it demonstrates

Which commands `--help` offers depends on the build. `build_parser` walks the handler table below, so
the parser is derived from what this artefact actually carries rather than declared beside it.

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
import hashlib
import json
import os
import pathlib
import sys


#: **THE OPTIONAL CAPABILITY PACKAGE, named ONCE.** `""` in a build that does not carry it.
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
from shard.clidiff import _cmd_diff
from shard.cliprint import _print_preflight
from shard.target import (cargo_fuzz_targets, demonstrability, entry_template, estimate_diff_cost,
                          free_tier_verdict, probe_runtimes, profile_repo, validate_workdir)

# THE GATE — the contract with CI, which is not the CLI's to own. `shard/gate.py` holds the exit codes,
# the `fail-on` vocabulary and the two rules that decide a build, so that `action.py` can read what a 1
# means without importing the entry point. That reach-back was this repository's only import cycle. The
# names are re-exported here because every caller — the tests, the bench, a maintenance script — has
# always read them off `shard.cli`, and the contract moving is not a reason to break them.
from shard.gate import (DEEP_FAIL_ON_CHOICES, EXIT_CONFIG, EXIT_GATED, EXIT_OK, FAIL_ON_CHOICES,
                        ConfigError)

# THE COMMAND-LINE SURFACE, which is not the dispatcher's to own. `shard/cliargs.py` holds every flag,
# every help string and the default model, so this file holds the control flow and nothing else. Same
# arrangement as `shard/gate.py` one block above, for the same reason: the names are re-exported here
# because every caller — five test modules, the action's argv builder — has always read `DEFAULT_MODEL`
# off `shard.cli`, and the declaration moving is not a reason to break them.
#
# MODULE SCOPE, and the maintainers' suite's reachability probe is why: a module reached only from
# inside a function body scores unreachable and ships as dead weight in the free artefact. That is the
# same argument the `telemetry` and `resultdoc` imports above make, and it cost two modules to learn.
from shard.cliargs import DEFAULT_MODEL, build_parser


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
    except ConfigError as e:
        print(f"shard: {e}", file=sys.stderr)
        return EXIT_CONFIG
    except Exception as e:                                   # noqa: BLE001 - see the docstring
        if os.environ.get(DEBUG_ENV):
            raise
        print(f"shard: internal error, no finding is implied: {type(e).__name__}: {e}",
              file=sys.stderr)
        return EXIT_CONFIG


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
        # `None` in the free image rather than an invented answer: the probe lives behind the mode
        # split, and a preflight that guessed would be asserting something it did not measure.
        "machine": _machine_payload() if deep_available else None,
        "runtimes": probe_runtimes(profile.languages),
        # **WHAT IT WILL COST THE CUSTOMER, and what tier they are on.**
        # The integration guide designates preflight the pricing instrument — *"preflight
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
        # spends money is worse than one that has to be asked. An internal audit.
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
    payload["mode"] = "survey"
    payload["status"] = "done"
    payload["findings"] = 0
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
        from shard.artefactfs import atomic_write, trusted_directory
        from shard.report import _report_id, build_survey_markdown

        out = pathlib.Path(args.out_dir)
        survey_bytes = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
        # **THE HUMAN ARTEFACT, STILL OPEN row 19.** Survey is the mode a customer meets first and it
        # wrote JSON and nothing else; the summary below reached a step log that GitHub deletes with
        # the runner. `shard-report.md` and not `shard-survey.md` deliberately — `action.yml` declares
        # ONE `report-path` output, and a workflow that uploads or comments it should not have to
        # branch on the mode to find the file.
        report = out / "shard-report.md"
        # `assessment.ranked` AND NOT `payload["candidates"]`, though both are to hand. The payload is
        # capped at its own limit for a consumer that parses it; the report takes its own, smaller cap
        # off the full ranking, so the two artefacts stay independently correct rather than one being
        # a truncation of the other's truncation.
        # `files_read_in_part` TRAVELS WITH `truncated`, and the two are different ceilings. The trust
        # row read `truncated` alone, so a scan that stopped part-way through ten files printed
        # `trust | complete scan` eight lines above its own blind spot saying every count was a floor
        # for them. Measured on `facebook/zstd` and `libgit2`, both 2026-09-02. See `_survey_trust`.
        report_bytes = build_survey_markdown(
            summary, target=args.slug or str(repo), truncated=scan.truncated,
            partial_files=scan.files_read_in_part, report_ident=_report_id(),
            ranked=assessment.ranked, witness_entry=args.witness_entry or "",
        ).encode("utf-8")
        with trusted_directory(out, create=True) as (_trusted_out, out_fd):
            atomic_write(out_fd, "shard-survey.json", survey_bytes)
            atomic_write(out_fd, report.name, report_bytes)
        payload["written"] = str(out / "shard-survey.json")
        payload["artefacts"] = {
            "survey": str(out / "shard-survey.json"),
            "report": str(report),
            "sha256": {
                "survey": hashlib.sha256(survey_bytes).hexdigest(),
                "report": hashlib.sha256(report_bytes).hexdigest(),
            },
        }

    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"repository   {args.slug or repo}")
        print(summary)
    return EXIT_OK


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
    """That capability's verdict for this repository, in the vocabulary the integration guide fixed.

    `unsupported` and `degraded` are different answers and conflating them would be the free-target
    audit's §2 again: a repository we decline is not the same as one we can analyse with less leverage,
    and the customer's next action differs.
    """
    if not deep_available:
        return {"available": False, "verdict": "unsupported",
                "reason": "this build does not carry that capability"}
    if not kinds:
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
                           f"start from: mkdir -p .shard && shard preflight --repo . "
                           f"--entry-template > .shard/test_poc.sh"),
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


def _cmd_action(args) -> int:
    """The GitHub Action, which had no entry point at all until 2026-08-08.

    A subcommand rather than a second console script, because this module's opening line is that there
    is ONE external consumer surface — the integration guide, and the maintainers' notes' first-listed
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
        raise ConfigError(str(e)) from e


# --- fix ---------------------------------------------------------------------------------------------


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
        raise ConfigError(
            f"the {endpoint} adapter is not built yet (workstream W3). Point --model-endpoint at an "
            f"OpenAI-compatible base URL — self-hosted vLLM is the guaranteed EU-residency path")
    api_key = os.environ.get(args.api_key_env or "OPENROUTER_API_KEY", "")
    if not api_key:
        raise ConfigError(
            f"no API key in ${args.api_key_env or 'OPENROUTER_API_KEY'}. The customer supplies "
            f"inference on every tier; we operate no endpoint")
    return OpenRouterBackend(api_key=api_key, base_url=endpoint or None)


def _report_payload(report) -> dict:
    return {"verdict": report.verdict, "harness": report.harness, "exit_marker": report.exit_marker,
            "corpus": report.corpus, "repo_tree": report.repo_tree,
            # Tri-state, and it reaches the payload as one. `null` means the control replay was never
            # run — which is always the answer from `preflight`, since deciding it needs a subprocess.
            "control_crashed": report.control_crashed,
            # THE TWO FACTS `verdict` NOW TURNS ON for a customer's own harness: can a fault reach us
            # AS a fault, statically and then as measured. A payload carrying the verdict and not what
            # decided it leaves a customer reading `degraded` with no field to check it against.
            # `exec_tail` is null iff there is no harness; `marker_printed` is null when nobody ran
            # one, which is always the answer from preflight.
            "exec_tail": report.exec_tail, "marker_printed": report.marker_printed,
            "reasons": list(report.reasons)}


def _existing_dir(value, label: str) -> pathlib.Path:
    path = pathlib.Path(value)
    if not path.is_dir():
        raise ConfigError(f"--{label} {str(path)!r} is not a directory")
    return path


_HANDLERS = {
    "preflight": _cmd_preflight,
    "diff": _cmd_diff,
    "survey": _cmd_survey,
    "action": _cmd_action,
}


def _build_parser() -> argparse.ArgumentParser:
    """The declared surface, wired to this module's handlers.

    Kept as a name on `shard.cli` because five test modules reach it there — `test_action`,
    `test_scan_profiles`, `test_mirror`, `test_memory_reaches_the_solver`, `test_enactment_breaker` —
    and the declaration moving to `shard/cliargs.py` is not a reason to break them. The `shard.gate`
    re-export block at the top of this file is the same decision for the same reason.
    """
    return build_parser(_HANDLERS)


__all__ = ["DEEP_FAIL_ON_CHOICES", "EXIT_CONFIG", "EXIT_GATED", "EXIT_OK", "FAIL_ON_CHOICES", "main"]


# `python -m shard.cli` — AND IT USED TO SCAN NOTHING AND EXIT 0.
#
# A measured run.1 logged this as an environment trap that cost time. It is worse
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
