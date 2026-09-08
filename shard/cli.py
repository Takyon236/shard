


import argparse
import hashlib
import json
import os
import pathlib
import sys


_PROBE_PACKAGE = ""


def _optional_probe(module: str):
    if not _PROBE_PACKAGE:
        return None
    try:
        import importlib

        return importlib.import_module(f"{_PROBE_PACKAGE}.{module}")
    except ImportError:
        return None
from shard.clidiff import _cmd_diff
from shard.cliprint import _print_preflight
from shard.target import (cargo_fuzz_targets, demonstrability, entry_template, estimate_diff_cost,
                          free_tier_verdict, probe_runtimes, profile_repo, validate_workdir)

from shard.gate import (DEEP_FAIL_ON_CHOICES, EXIT_CONFIG, EXIT_GATED, EXIT_OK, FAIL_ON_CHOICES,
                        ConfigError)

from shard.cliargs import DEFAULT_MODEL, build_parser


DEBUG_ENV = "SHARD_DEBUG"


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        return args.handler(args)
    except ConfigError as e:
        print(f"shard: {e}", file=sys.stderr)
        return EXIT_CONFIG
    except Exception as e:
        if os.environ.get(DEBUG_ENV):
            raise
        print(f"shard: internal error, no finding is implied: {type(e).__name__}: {e}",
              file=sys.stderr)
        return EXIT_CONFIG



def _cmd_preflight(args) -> int:
    repo = _existing_dir(args.repo, "repo")
    profile = profile_repo(repo)
    kinds, deep_available = _applicable_kind_names(profile)

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
        "machine": _machine_payload() if deep_available else None,
        "runtimes": probe_runtimes(profile.languages),
        "cost": estimate_diff_cost(profile),
        "free_tier": free_tier_verdict(profile, visibility=args.visibility),
        "demonstrable": demonstrability(repo, declared=getattr(args, "witness_entry", "") or ""),
    }
    if args.probe_endpoint:
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
    from shard.survey import assess, summarise, survey_repo, to_payload

    repo = _existing_dir(args.repo, "repo")
    profile = profile_repo(repo)
    kinds, deep_available = _applicable_kind_names(profile)

    scan = survey_repo(repo)
    assessment = assess(scan, harness_kinds=tuple(kinds), witness_entry=args.witness_entry,
                        deep_available=deep_available, languages=set(profile.languages))

    payload = to_payload(scan, assessment)
    payload["mode"] = "survey"
    payload["status"] = "done"
    payload["findings"] = 0
    payload["repo"] = args.slug or str(repo)
    payload["languages"] = profile.languages
    payload["applicable_harness_kinds"] = kinds

    summary = summarise(scan, assessment)

    if args.out_dir:
        from shard.artefactfs import atomic_write, trusted_directory
        from shard.report import _report_id, build_survey_markdown

        out = pathlib.Path(args.out_dir)
        survey_bytes = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
        report = out / "shard-report.md"
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
    machine = _optional_probe("machine")
    if machine is None:
        return None
    return machine.payload(machine.probe())


def _mode_verdict(profile, kinds: list[str], deep_available: bool) -> dict:
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




def _cmd_action(args) -> int:
    from shard.action import ActionInputError, run

    try:
        return run()
    except ActionInputError as e:
        raise ConfigError(str(e)) from e





def _applicable_kind_names(profile) -> tuple[list[str], bool]:
    harness = _optional_probe("harness")
    if harness is None:
        return [], False
    return [k.name for k in harness.applicable(profile)], True


def _backend(args):
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
            "control_crashed": report.control_crashed,
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
    return build_parser(_HANDLERS)


__all__ = ["DEEP_FAIL_ON_CHOICES", "EXIT_CONFIG", "EXIT_GATED", "EXIT_OK", "FAIL_ON_CHOICES", "main"]


if __name__ == "__main__":
    sys.exit(main())
