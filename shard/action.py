"""The GitHub Action's entry point — the layer that was documented and never ran.

`action.yml` declared fourteen inputs and five outputs and its `runs:` block was two lines:
`using: docker`, `image: Dockerfile`. A Docker container action with no `args:` runs the image's `CMD`,
which was `["--help"]`. **So the shipped action printed the argparse help, exited 0 — a passing check —
and ignored every input.** Nothing read an `INPUT_*` variable anywhere in the package. Every measured
number this project has ever produced came through `python -m shard` invoked by hand.

That is the maintainers' notes's standing process rule at the layer that IS the product: correct code that never
executed. the design notes, "Found by wiring the budget".

## Why this is Python and not a shell entrypoint

A fixed `args:` block cannot do the job: the three modes take different flags (`--base-ref` is diff's,
`--harness` is deep's, `survey` takes neither), so one static argument list is wrong for two modes out
of three. And `args:` cannot write `$GITHUB_OUTPUT`, which is where the five declared outputs have to
end up. That leaves a shell script or this. It is this because the maintainers' notes's quality bar asks for a
deterministic test with no LLM call for everything that ships, and `argv_for` is a pure function from a
dict to a list of strings — the maintainers' suite proves every input reaches a flag, which is the guard
the backlog asked for in the same commit as the fix.

## The environment is the interface

GitHub passes each input as `INPUT_<NAME>`, upper-cased with SPACES replaced by underscores and
NOTHING ELSE — a hyphen passes through unchanged (actions/toolkit `core.getInput`; github/docs#32671).
This module believed `-` → `_` until 2026-08-11, so every hyphenated input — eleven of fourteen,
including the spend ceiling and the witness entry point — was inert on a real runner, and the test
that should have caught it derived the variable names with the code's own rule. The declared names
are underscore-spelled now, and `_input` reads the hyphenated spelling too, because a hand-written
`with:` block may use either. Three more come from the
runner's own environment rather than from an input, because asking a customer to type what GitHub
already knows is a way of being wrong later:

    GITHUB_WORKSPACE  → --repo       the checkout, which is where a container action's work happens
    GITHUB_REPOSITORY → --slug       <owner>/<name>, when the customer did not override it
    GITHUB_RUN_ID     → --run-id     so a state repository's records are the run they came from
    RUNNER_TEMP       → --workdir    the separate capability only, and it must be OUTSIDE the checkout

## What the outputs are read off

The `--json` payload, in-process. Not a re-derivation from the SARIF on disk: `gate_eligible` has
exactly one definition and a second one computed from a file would be free to drift from it — the
defect class this repository has now recorded five times. The payload is echoed to the log verbatim,
so nothing is swallowed to obtain it.

**A run that failed writes no outputs at all.** Writing `findings=0` for a run that never completed is
the shape the design notes is about: an errored run indistinguishable from a clean one, in the
one place a workflow reads to decide what happened.

## Simple-safe

Imports `shard.cli` and nothing from the separate package. the separate capability reaches the solver the same way it always
does — through the lazy import inside `_cmd_deep` — so this module ships in the free image with the
mode split intact. the maintainers' suite measures it.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import pathlib
import re

# THE CONTRACT, not the entry point. This module is a CALLER of the CLI and used to import `shard.cli`
# just to learn what a 1 means — from inside a function body, because importing the entry point at
# module scope to read two integers is the wrong shape and a previous session left a comment saying so
# rather than a fix. `shard/gate.py` is the contract on its own, it pulls in nothing, and reading it
# here at module scope is now honest.
from shard.gate import EXIT_GATED, EXIT_OK

#: The three modes `action.yml` offers, and they are the subcommand names on purpose: a mapping
#: table between two vocabularies is a thing that drifts, and there is nothing to gain from one here.
MODES = ('survey', 'diff')

#: Every input this module reads. Held here rather than inferred from the parser because
#: the maintainers' suite asserts this set against `action.yml` itself — an input added to the
#: product surface without being wired to a flag is then a failing test rather than a support call.
# Narrowed at build time to the inputs this artefact can act on.
INPUTS = (
    'mode', 'model_endpoint', 'model', 'api_key_env', 'max_spend_usd', 'max_minutes', 'max_tokens', 'scan', 'max_steps', 'hunk_radius', 'witness_entry', 'base_ref', 'state_repo', 'slug', 'fail_on', 'out_dir', 'github_token',
)

#: Inputs this module acts on ITSELF instead of forwarding. Held as a set rather than as a check
#: inside the identity test, so that adding a second one is a one-line change in the place a reader
#: looks, and so the test's exclusion list cannot drift from the reason for it.
NOT_A_FLAG = frozenset({"github_token", "id_token"})

#: Declared on the product surface and read by NOTHING — stated here rather than silently dropped,
#: because an input that quietly does nothing is exactly what this module exists to fix. The value is
#: the reason, and it is quoted in `action.yml` beside the input itself.
#:
#: **EMPTY SINCE 2026-08-13, and the mechanism stays.** `scope_file` was the only entry and it is off
#: the manifest — an internal audit. Being honest about an inert input was the
#: right call while it was declared, and it was still a security product shipping a security control
#: that never executes, which is a review liability the honesty does not remove. The module behind it
#: is unchanged and `SECURITY.md` still describes it; the input comes back in the commit that WIRES it.
#:
#: Kept rather than deleted because the guard is the point: the maintainers' suite asserts the
#: manifest equals `INPUTS | NOT_WIRED`, so an input added to the product surface and to neither is a
#: failing test. An empty dict keeps that closed and costs nothing, exactly as `WITNESSABLE_KINDS` is
#: an empty frozenset rather than an absent one.
NOT_WIRED: dict[str, str] = {}

#: The five outputs, and which payload key each is read off per mode. `deep` and `diff` count the
#: gate-eligible half under different names because they are different claims — a reproduction and a
#: demonstration — and the action flattens them for the workflow that consumes it.
_GATE_KEY = {"diff": "gate_eligible", "deep": "reproduced"}

DEFAULT_OUT_DIR = "shard-out"


class ActionInputError(Exception):
    """An input GitHub passed that this action cannot act on. Reported as a configuration error."""


def _input(env, name: str) -> str:
    """One `INPUT_*` variable, stripped. Absent and empty are the same thing here: GitHub sets every
    declared input, so an optional one the customer left alone arrives as an empty string, not as a
    missing variable.

    TWO spellings are read, because GitHub's transformation is upper-case and spaces-to-underscores
    ONLY — it does not touch hyphens — and it sets an `INPUT_*` variable for EVERY key in a workflow's
    `with:` block, declared or not. So `witness_entry` arrives as `INPUT_WITNESS_ENTRY` from the
    declaration, and a hand-written `with: {witness-entry: x}` arrives as `INPUT_WITNESS-ENTRY`
    BESIDE it — with the underscore variable still carrying the declaration's default. The first
    NON-EMPTY value wins and the hyphenated one is consulted first: when both are set, the hyphenated
    one is the customer's explicit choice and the underscore one is our default. An empty value never
    shadows a set one."""
    upper = name.upper()
    for key in ("INPUT_" + upper.replace("_", "-"), "INPUT_" + upper):
        value = (env.get(key) or "").strip()
        if value:
            return value
    return ""


def _opt(argv: list[str], flag: str, value: str) -> None:
    """Append `--flag value`, or nothing at all when the value is empty.

    Passing an empty string through would mostly work — the CLI treats `""` as falsy in every place
    that matters — but it makes the argv a customer sees in a failing log claim they configured
    something they did not.
    """
    if value:
        argv += [flag, value]


def _ceilings(env, argv: list[str]) -> None:
    """The three budget ceilings, which now fire (the design notes) and therefore have to
    arrive. They are numbers, and `0` is meaningful for all three — so the empty-string test above is
    the right one and a falsy test would silently drop a deliberate `0`."""
    for flag, name in (("--max-spend-usd", "max_spend_usd"), ("--max-minutes", "max_minutes"),
                       ("--max-tokens", "max_tokens")):
        _opt(argv, flag, _input(env, name))


def workdir_for(env) -> str:
    """that capability's workdir. `RUNNER_TEMP` on a runner, and it is chosen because it is OUTSIDE the
    checkout — `--workdir` says it must be, and a path under `GITHUB_WORKSPACE` would put a
    materialised target inside the repository we promise never to write to."""
    root = env.get("RUNNER_TEMP") or "/tmp"
    return str(pathlib.Path(root) / "shard-workdir")


def argv_for(env) -> list[str]:
    """The `python -m shard ...` command line this action's inputs describe. Pure, so it is testable.

    `--json` is always appended: the outputs are read off the payload it prints, and the payload is
    echoed to the log so the customer still sees everything the run said.
    """
    mode = _input(env, "mode") or "diff"
    if mode not in MODES:
        raise ActionInputError(f"mode must be one of {list(MODES)}, not {mode!r}")

    argv = [mode, "--repo", env.get("GITHUB_WORKSPACE") or ".",
            "--out-dir", _input(env, "out_dir") or DEFAULT_OUT_DIR]

    # THE TARGET NAMES ITSELF, IN EVERY MODE, and it is hoisted above the survey's early return
    # because that return is exactly how it came to be missing. `--repo` is `/github/workspace`, a
    # path inside OUR container that is true of the mount and says nothing about the repository under
    # review — so an artefact carrying it cannot be attributed to anything. Measured 2026-08-13 on a
    # real scan of urllib3 (the maintainers' notes, the SCAN block): the survey payload said
    # `"repo": "/github/workspace"`, and the diff report — which DID have a slug — named
    # `the development tree`, because the workflow scanning somebody else's code is not that code.
    #
    # `GITHUB_REPOSITORY` stays the default, and the input still overrides it: that is right for the
    # arrangement this was written for, a customer scanning their own repository, and an internal CI workflow
    # is the one that must say otherwise. Both halves are now reachable from every mode.
    _opt(argv, "--slug", _input(env, "slug") or (env.get("GITHUB_REPOSITORY") or ""))

    if mode == "survey":
        # No model, no endpoint, no ceilings: the survey makes no inference call at all, and offering
        # it a spend ceiling would be a knob with nothing behind it.
        _opt(argv, "--witness-entry", _input(env, "witness_entry"))
        return argv + ["--json"]

    _opt(argv, "--model", _input(env, "model"))
    _opt(argv, "--model-endpoint", _input(env, "model_endpoint"))
    _opt(argv, "--api-key-env", _input(env, "api_key_env"))
    _ceilings(env, argv)
    # BESIDE THE CEILINGS because that is where the CLI declares it (`_budget_args`): the profile names
    # what an UNSET --max-tokens means, and on deep it also answers --max-findings. Both metered modes
    # take it — deep defaults to `initial` in its own parser, diff to no profile — and `_opt` drops an
    # empty value, so leaving the input alone keeps each mode's own default. Until 2026-08-20 nothing
    # emitted this flag, so the `scan: followup` configuration `max_tokens`' description advises was
    # silently ignored and a deep run from CI was locked to the initial profile.
    _opt(argv, "--scan", _input(env, "scan"))
    _opt(argv, "--fail-on", _input(env, "fail_on"))

    if mode == "diff":
        _opt(argv, "--max-steps", _input(env, "max_steps"))
        _opt(argv, "--hunk-radius", _input(env, "hunk_radius"))
        _opt(argv, "--base-ref", _input(env, "base_ref"))
        _opt(argv, "--witness-entry", _input(env, "witness_entry"))
        _opt(argv, "--state-repo", _input(env, "state_repo"))
        # The runner already knows this one too, and nobody has to type what GitHub is holding. The
        # slug that used to sit beside it is above, applied to every mode.
        _opt(argv, "--run-id", env.get("GITHUB_RUN_ID") or "")
    else:
        argv += ["--workdir", workdir_for(env)]
        _opt(argv, "--harness", _input(env, "harness"))
        # Unset stays unset: `_opt` drops an empty value, so the flag is absent and the solver runs
        # with no memory, which is the measured configuration. The path is the CUSTOMER's — we operate
        # no storage (the design notes, "no control plane") — and it is theirs to persist between
        # scans with `actions/cache`.
        _opt(argv, "--memory-file", _input(env, "memory_file"))
        _opt(argv, "--library", _input(env, "library"))
        _opt(argv, "--library-mirror", _input(env, "library_mirror"))

    return argv + ["--json"]


def outputs_for(mode: str, payload: dict) -> dict[str, str]:
    """The five declared outputs, off the run's own payload.

    `survey` emits no findings by construction — it is a scan, not a hunt — so its counts are 0 and
    `sarif-path` and `bundle-path` are empty. That is the honest answer rather than a missing key a
    workflow would read as the string "null".

    **`report-path` is NOT empty for survey since 2026-08-13** (the maintainers' notes row 19). It
    points at the same `shard-report.md` diff mode writes, so a workflow that uploads or comments the
    report does not branch on the mode — which is the whole reason the survey artefact took that name.
    """
    artefacts = payload.get("artefacts") or {}
    bundles = artefacts.get("bundles") or []
    return {
        # WHETHER THE RUN FINISHED, and it is an output rather than a detail: an errored run writes
        # `findings: 0` and exits 0, which is byte-for-byte what a completed audit that found nothing
        # writes. the design notes The exit code stays 0 — installing Shard does not break a
        # build — so a workflow that wants to react needs somewhere to read it, and until now there was
        # nowhere. `survey` reports no status of its own; it either produced a scan or it failed.
        "status": str(payload.get("status", "done")),
        "findings": str(payload.get("findings", 0)),
        "gate-eligible": str(payload.get(_GATE_KEY.get(mode, ""), 0)),
        "sarif-path": str(artefacts.get("sarif", "")),
        "report-path": str(artefacts.get("report", "")),
        # The DIRECTORY the bundles were written into, not the list: `bundle-path` is singular on the
        # product surface, and a multi-line output value is a thing every consumer has to special-case.
        "bundle-path": str(pathlib.Path(bundles[0]).parent) if bundles else "",
        # THE RUN'S OWN TELEMETRY. Everything above describes the CODE; these describe the RUN — where
        # the seconds and tokens went, how the context grew, which tools failed. EMPTY when the run
        "telemetry-path": str(artefacts.get("telemetry", "")),
        "log-path": str(artefacts.get("log", "")),
    }


def render_outputs(outputs: dict[str, str]) -> str:
    """`$GITHUB_OUTPUT` lines. Single-line values only — every one of the five is a count or a path, and
    a value carrying a newline would be a malformed file rather than a wrong value, so it is refused."""
    lines = []
    for name, value in outputs.items():
        if "\n" in value or "\r" in value:
            raise ActionInputError(f"output {name!r} is not single-line: {value!r}")
        lines.append(f"{name}={value}")
    return "\n".join(lines) + "\n"


def run(env=None, *, invoke=None, echo=print, opener=None) -> int:
    """Read the environment, run the CLI, write the outputs, deliver them. Returns the CLI's exit code.

    `invoke` is injected by the tests for the same reason `run_simple` takes a `loop_factory`: the
    mapping and the reporting are the things worth testing, and they must be testable without a run.
    `opener` is the same seam for the code-scanning upload — the maintainers' notes requires every test to be
    deterministic with no network, and a delivery step reached only through `urllib` at module scope
    would be untestable exactly where being wrong is most expensive.
    """
    # `main` ONLY, and this is the one edge back to the entry point that is meant to be here: `shard
    # action` re-enters `main` with an argv built from the environment, so `cli._cmd_action` imports
    # this module and this module calls back — deliberate re-entry, not a lookup. The exit codes used
    # to travel this way too and no longer do; they come from `shard.gate` at module scope above. The
    from shard.cli import main

    env = os.environ if env is None else env
    invoke = invoke or main
    argv = argv_for(env)

    # ---- THE RUN NAMES ITSELF, FROM ITS OWN ARGUMENTS ------------------------------------------------
    #
    # **A step's LABEL cannot come from in here, and that is a platform fact rather than a choice.**
    # GitHub resolves `name:` before this container starts, so a `uses:` step without one renders as
    # `Run ./` — and an internal CI workflow showed FOUR steps labelled `Run ./` in one job and THREE
    # labelled `Run ./vendor/shard` in another, each asserting something different. Run 32079827043's
    # own step list is the evidence.
    #
    # What the container can do is refuse to be anonymous in the channels it owns. This heading is
    # DERIVED from `argv` — the arguments this invocation actually received — so it cannot drift from
    # what ran and nobody has to remember to write it. `::group::` makes it the collapsible title around
    # this run's output, so several invocations in one job read as several named sections however their
    # steps happen to be labelled.
    echo(f"::group::{describe(argv, env)}")
    try:
        return _run(argv, env, invoke=invoke, echo=echo, opener=opener)
    finally:
        # In a `finally` so the heading closes on a raise too. An unclosed `::group::` swallows every
        # later line in the job into a collapsed block, which would make a crash HARDER to read than
        # no grouping at all.
        echo("::endgroup::")


def describe(argv: list[str], env=None) -> str:
    """What this invocation IS, in one line, derived from the arguments it was given.

    Leads with `[Shard-report][NNNNNN] <slug>` when the run has a number, from `report.report_label` —
    the SAME declaration the markdown heading uses, so the log and the artefact cannot disagree about
    which report this is. Two spellings of one identifier is how the channels drifted before.

    **Derived and never authored.** A hand-written label is a second description of the same run, and it
    drifts the first time a flag moves — the copies-drift rule this module already follows for `INPUTS`.

    The mode comes first because it is what a reader looks for, then only the facts that distinguish two
    invocations of the SAME mode against the SAME target: what the change was measured against, and
    which ceilings were imposed. an internal CI workflow's metered job runs `diff` three times over one
    pinned target and the three differ in nothing else.

    A revision is truncated for the same reason `report._short` truncates one: a 40-character SHA in a
    heading pushes out the thing that identifies the run.
    """
    labels = {"--base-ref": "against", "--max-spend-usd": "max $", "--max-tokens": "max tokens",
              "--max-minutes": "max minutes", "--max-steps": "max steps", "--fail-on": "fail-on",
              "--scan": "scan", "--witness-entry": "witness", "--api-key-env": "key from",
              "--model-endpoint": "endpoint"}
    parts = []
    for flag, label in labels.items():
        if flag not in argv:
            continue
        at = argv.index(flag) + 1
        value = argv[at] if at < len(argv) else ""
        if not value:
            continue
        # **`0` MEANS UNMETERED on every ceiling flag** — `_budget_args`' own help text says so, and its
        # docstring calls that reading load-bearing. Printing `max tokens 0` in a heading therefore
        # states the opposite of the truth: it reads as a ceiling of zero. Observed on run 32082545211,
        # where all three headings carried `max tokens 0 · max minutes 60` from untouched defaults.
        # A ceiling nobody set is not a fact about the run.
        if flag.startswith("--max-") and value in ("0", "0.0", "0.00"):
            continue
        parts.append(f"{label} {value[:12] if flag == '--base-ref' else value}".strip())
    from shard.report import is_numbered, report_id, report_label

    body = f"shard {argv[0] if argv else '?'}" + (" · " + " · ".join(parts) if parts else "")
    ident = report_id(env if env is not None else {})
    if not is_numbered(ident):
        # An unnumbered run says nothing rather than printing a zero that looks like a real id in a log.
        return body
    # `--slug` is deliberately NOT in the table above: it leads the line as part of the label, and
    # printing it twice is the noise this heading exists to remove.
    slug = argv[argv.index("--slug") + 1] if "--slug" in argv else ""
    return f"{report_label(ident, slug, quoted=False)} — {body}"


def _run(argv, env, *, invoke, echo, opener) -> int:
    """The body of `run`, split out so the heading above wraps every exit from it, raises included."""
    if (_input(env, "mode") or "diff") == "deep" and _input(env, "max_steps"):
        echo("shard: deep mode IGNORED max_steps — the solver's step budget is part of its measured "
             "configuration. To bound a deep run use max_spend_usd, max_minutes, max_tokens, or "
             "`scan: followup`.")

    # The payload is captured rather than parsed off disk, then echoed VERBATIM. Capturing to obtain a
    # number and then swallowing the output would be the hidden-corpse failure the design notes
    # records, on the one surface where the customer's only view of the run is the log.
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        code = invoke(argv)
    captured = buffer.getvalue()
    if captured:
        echo(captured.rstrip("\n"))

    # `EXIT_GATED` is a COMPLETED run: `gate.exit_code` returns it only when a reproduction exists and
    # `--fail-on reproduced` asked for the gate, and it is the run somebody actually has to go and look
    # at — so its outputs are the last ones that may be dropped. Anything else is `EXIT_CONFIG`, and a
    # run that did not complete writes NO outputs: `findings=0` from a run that never happened is
    # the design notes — an errored run indistinguishable from a clean one — written into the
    # one place a workflow reads to decide what to do next.
    if code not in (EXIT_OK, EXIT_GATED):
        echo("shard: the run did not complete; no outputs were written")
        return code

    try:
        payload = json.loads(captured)
    except (ValueError, TypeError):
        echo("shard: the run produced no machine-readable payload; no outputs were written")
        return code

    # AN ARTEFACT THAT DID NOT SURVIVE IS SAID OUT LOUD, and this line exists because the fix that made
    # it possible is what made it silent. `_emit` used to write the artefacts as one sequence, so a
    # single unencodable character cost the WHOLE finished run — zero-byte report, exit 2, every token
    # already paid. Writing each artefact independently fixed that, and left a quieter failure in its
    # place: a missing `sarif`/`report` key sends the delivery steps below down their "survey mode emits
    # no SARIF" and "not a pull request" branches, which are the same branches a perfectly healthy run
    # takes. The reason lived only in the payload and on stderr.
    #
    # `::error::` rather than a plain line: this is the degraded-run-as-clean shape the whole product is
    # built against, and a workflow that lost its alerts should not have to read a JSON payload to find
    # out. The exit status is deliberately NOT changed — installing Shard does not break a build, and
    # one lost artefact is not a reason to fail somebody's pull request.
    failed = (payload.get("artefacts") or {}).get("failed") or {}
    if failed:
        echo(f"::error::shard: {len(failed)} artefact(s) could not be written and are MISSING from this "
             f"run: {', '.join(sorted(failed))}. The findings themselves are unaffected — what is "
             f"missing is where they were written to.")

    outputs = outputs_for(_input(env, "mode") or "diff", payload)
    path = env.get("GITHUB_OUTPUT")
    if path:
        # The write is guarded because by this point the ANALYSIS IS DONE and the customer has already
        # paid for it. Unguarded, an unwritable $GITHUB_OUTPUT — a read-only mount, a permissions quirk
        # on a self-hosted runner — raised `PermissionError` out of `run`, which `cli.py` reports as
        # "shard: internal error" with exit 2, discarding a completed review and its findings over a
        # log file. Measured 2026-08-10 in the shipped image. `code` is still returned, so the gate
        # decision the customer asked for survives the failure to announce it.
        try:
            with open(path, "a", encoding="utf-8") as handle:
                handle.write(render_outputs(outputs))
        except OSError as e:
            echo(f"shard: $GITHUB_OUTPUT could not be written ({e.__class__.__name__}: {e}); the "
                 f"findings and the exit status are unaffected, but a later step reading these "
                 f"outputs will see nothing")
    else:
        # Not an error: `docker run` of this image by hand is a supported way to see what the action
        # does, and there is no output file there.
        echo("shard: no $GITHUB_OUTPUT; outputs were computed and not written")

    write_step_summary(env, payload, echo=echo)
    upload_sarif(env, payload, opener=opener, echo=echo)
    comment_on_pull_request(env, payload, opener=opener, echo=echo)
    return code


#: The needle that makes the comment an UPSERT. An HTML comment, so it is invisible in the rendered
#: page and survives an edit that keeps the body. Changing it orphans every comment already posted,
#: which is the same rule `SARIF_CATEGORY` carries and for the same reason.
COMMENT_MARKER = "<!-- shard:report -->"


def comment_on_pull_request(env, payload: dict, *, opener=None, echo=print) -> bool:
    """Post the report as a pull-request comment, editing our own rather than adding one.

    **an internal audit, item 3.** `action.yml`'s own output description says
    `report-path` is *"the short markdown report, for a pull-request comment"* — describing a consumer
    that existed on neither side.

    **UPSERT BY MARKER, and the reason is a measured property of this product rather than tidiness.**
    A pull request is pushed to repeatedly and this action runs on every push. Appending would leave a
    column of near-identical reports, the newest at the bottom, and a reviewer reading the top one
    would be reading the OLDEST verdict — a stale finding presented as current, which is the same
    false-confidence failure the fixed header was built to end.

    Needs `permissions: {pull-requests: write}`. Absent token, absent permission and "this is not a
    pull request" are three different facts and are reported as three different lines: a customer
    whose comment never appears has to be able to tell which one happened.

    Never raises, for the reason `upload_sarif` states.
    """
    token = _input(env, "github_token")
    report = ((payload.get("artefacts") or {}).get("report") or "").strip()
    repo = (env.get("GITHUB_REPOSITORY") or "").strip()
    slug = _input(env, "slug")
    number = _pull_request_number(env)

    if not report or number is None:
        return False                       # not a pull request, or nothing written: both are normal
    if not token:
        echo("shard: no github_token, so no pull-request comment was posted. Pass "
             "`github_token: ${{ secrets.GITHUB_TOKEN }}` with `permissions: "
             "{pull-requests: write}` — see README.md.")
        return False
    if not repo or (slug and slug != repo):
        echo(f"shard: the review was of {slug or 'another repository'!r} and this pull request "
             f"belongs to {repo or 'nothing this run can name'!r}, so no comment was posted.")
        return False

    try:
        import urllib.request

        api = (env.get("GITHUB_API_URL") or "https://api.github.com").rstrip("/")
        issues = f"{api}/repos/{repo}/issues"
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
                   "X-GitHub-Api-Version": "2022-11-28", "Content-Type": "application/json"}
        send = opener or urllib.request.urlopen

        # OURS ONLY. The list is filtered on the marker, so a comment somebody else wrote — a human
        # quoting our report, another tool — is never edited by us. `?per_page=100` rather than
        # paging: a pull request with more than 100 comments is one where a fresh comment at the
        # bottom is the right answer anyway.
        with send(urllib.request.Request(f"{issues}/{number}/comments?per_page=100",
                                         headers=headers), timeout=60) as response:
            existing = json.loads(response.read().decode())
        mine = [c for c in existing if COMMENT_MARKER in (c.get("body") or "")]

        body = json.dumps({"body": f"{COMMENT_MARKER}\n{pathlib.Path(report).read_text('utf-8')}"})
        if mine:
            url, verb = f"{issues}/comments/{mine[-1]['id']}", "PATCH"
        else:
            url, verb = f"{issues}/{number}/comments", "POST"
        with send(urllib.request.Request(url, data=body.encode(), method=verb, headers=headers),
                  timeout=60) as response:
            status = getattr(response, "status", 0)
    except Exception as e:                                              # noqa: BLE001
        echo(f"shard: the pull-request comment failed ({e.__class__.__name__}: {e}); the findings, "
             f"the artefacts and the exit status are unaffected.")
        return False

    if status not in (200, 201):
        echo(f"shard: the pull-request comment was refused ({status}); "
             f"`permissions: {{pull-requests: write}}` is the usual cause.")
        return False
    echo(f"shard: report {'updated on' if mine else 'posted to'} {repo}#{number}.")
    return True


def _pull_request_number(env) -> int | None:
    """The pull request this run is about, or None.

    `GITHUB_REF` is `refs/pull/<n>/merge` on a `pull_request` event and that is the cheapest reliable
    source — it needs no event payload file, which a container action may not be able to read. A
    `workflow_dispatch` or a push has no number and gets None, which is not an error: most runs are
    not pull requests.
    """
    found = re.match(r"^refs/pull/(\d+)/", env.get("GITHUB_REF") or "")
    return int(found.group(1)) if found else None


#: What code scanning is told produced the results. A fixed string, because the API keys alert
#: identity on it: changing it later republishes every finding as new.
SARIF_CATEGORY = "shard"


def upload_sarif(env, payload: dict, *, opener=None, echo=print) -> bool:
    """POST the SARIF to code scanning. Returns whether it was accepted.

    **an internal audit, and the integration guide's whole argument.** That
    section banks 13–19 weeks of avoided scope on one table — *findings storage → code scanning
    alerts; user interface → the Security tab; enforcement → check run status* — and every row of it
    was unwired. The argument for building no control plane is sound and the integration it depends on
    was never made, so the product had neither a control plane nor GitHub's.

    Uploaded from INSIDE the run rather than by a second workflow step, because the free tier's stated
    design constraint is that installing Shard is one step. `github/codeql-action/upload-sarif` stays
    documented in `README.md` for customers who prefer it; both are supported and they are the same
    API.

    **AN ABSENT TOKEN IS A STATED SKIP, NEVER A SILENT ONE.** A customer who forgot the permission
    would otherwise get a green check, no alerts, and nothing to read — which is the degraded-run
    shape this product refuses everywhere else.

    **IT REFUSES TO UPLOAD SOMEBODY ELSE'S SCAN.** `GITHUB_REPOSITORY` is the repository whose token
    we hold; `slug` is the repository that was REVIEWED, and an internal CI workflow is a
    live arrangement where they differ. Publishing a third-party review into our own Security tab
    would attribute a stranger's defects to us against a `commit_sha` that does not exist here — the
    same false-attribution defect the report itself had on run `31675518894`, one layer out.

    Never raises: the analysis is finished and paid for by the time this runs.
    """
    token = _input(env, "github_token")
    sarif = ((payload.get("artefacts") or {}).get("sarif") or "").strip()
    repo = (env.get("GITHUB_REPOSITORY") or "").strip()
    sha = (env.get("GITHUB_SHA") or "").strip()
    ref = (env.get("GITHUB_REF") or "").strip()
    slug = _input(env, "slug")

    if not sarif:
        return False                       # survey mode emits no SARIF; nothing to say about it
    if not token:
        echo("shard: no github_token, so the SARIF was NOT uploaded to code scanning and this run "
             "produced no alerts. Pass `github_token: ${{ secrets.GITHUB_TOKEN }}` with "
             "`permissions: {security-events: write}` — see README.md.")
        return False
    if not (repo and sha and ref):
        echo("shard: GITHUB_REPOSITORY, GITHUB_SHA or GITHUB_REF is unset, so there is nothing to "
             "attach a code-scanning upload to; the SARIF is still in the artefacts.")
        return False
    if slug and slug != repo:
        echo(f"shard: the review was of {slug!r} and this token belongs to {repo!r}, so the SARIF "
             f"was NOT uploaded — alerts would attribute another repository's findings to this one, "
             f"against a commit that does not exist here.")
        return False

    try:
        import base64
        import gzip
        import urllib.request

        body = json.dumps({
            "commit_sha": sha,
            "ref": ref,
            "sarif": base64.b64encode(gzip.compress(pathlib.Path(sarif).read_bytes())).decode(),
            # Named so a second security tool's alerts and ours never collide, and so re-running
            # Shard REPLACES its own previous results rather than duplicating them.
            "tool_name": SARIF_CATEGORY,
            "checkout_uri": pathlib.Path(env.get("GITHUB_WORKSPACE") or ".").as_uri(),
        }).encode()
        api = (env.get("GITHUB_API_URL") or "https://api.github.com").rstrip("/")
        request = urllib.request.Request(f"{api}/repos/{repo}/code-scanning/sarifs", data=body,
                                         method="POST", headers={
                                             "Authorization": f"Bearer {token}",
                                             "Accept": "application/vnd.github+json",
                                             "X-GitHub-Api-Version": "2022-11-28",
                                             "Content-Type": "application/json"})
        with (opener or urllib.request.urlopen)(request, timeout=60) as response:
            status = getattr(response, "status", 0)
    except Exception as e:                                              # noqa: BLE001
        # BROAD ON PURPOSE, and the breadth is the point rather than laziness. Every failure here —
        # HTTPError 403 from a missing permission, URLError from a proxy, a gzip failure on a
        # truncated file — has the same correct response: say so and keep the findings. A narrower
        # clause would let one unanticipated class discard a completed review over a delivery step.
        echo(f"shard: the SARIF upload failed ({e.__class__.__name__}: {e}); the findings, the "
             f"artefacts and the exit status are unaffected, but this run produced no alerts.")
        return False

    if status not in (200, 202):
        echo(f"shard: code scanning answered {status} rather than 202; no alerts were created.")
        return False
    echo(f"shard: SARIF uploaded to {repo} code scanning for {sha}.")
    return True


def write_step_summary(env, payload: dict, *, echo=print) -> bool:
    """Put the report in the Actions UI. Returns whether anything was written.

    **an internal audit, and it is the cheapest row in that document.** The product
    wrote a correct SARIF, a markdown report and reproduction bundles into a directory on a runner that
    is destroyed when the job ends, and **nothing consumed any of them**. Measured the same day on run
    `31687294640`, which gated a build on a real target: the only way anybody saw the finding was
    `gh run download`. `$GITHUB_STEP_SUMMARY` needs no token, no permission and no network — it is a
    file GitHub renders on the job page — so it is the one delivery surface that cannot be blocked by
    a missing `github_token`, and it is what makes a DEGRADED run noticeable, which the audit calls the
    hardest state for a customer to spot.

    The report is emitted VERBATIM. It already opens with the fixed header — verdict, trust, reviewed,
    gate, witness, cost — and a second rendering here would be a copy that drifts from the artefact
    the customer keeps.

    Never raises. The analysis is finished and paid for by the time this runs, so an unwritable
    summary file must cost a log line and never a finding — the rule `$GITHUB_OUTPUT` above already
    follows, for the defect measured in the shipped image on 2026-08-10.
    """
    path = env.get("GITHUB_STEP_SUMMARY")
    if not path:
        return False
    report = ((payload.get("artefacts") or {}).get("report") or "").strip()
    if not report:
        # A run with no `out_dir` writes no report. Saying so beats an empty summary, which reads as a
        # run that produced nothing rather than one that was asked to write nothing.
        echo("shard: no report artefact, so nothing was written to $GITHUB_STEP_SUMMARY")
        return False
    try:
        text = pathlib.Path(report).read_text(encoding="utf-8")
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(text if text.endswith("\n") else text + "\n")
    except OSError as e:
        echo(f"shard: $GITHUB_STEP_SUMMARY could not be written ({e.__class__.__name__}: {e}); the "
             f"findings and the exit status are unaffected, but this run will not be legible in the "
             f"Actions UI")
        return False
    return True


__all__ = ["COMMENT_MARKER", "INPUTS", "MODES", "NOT_A_FLAG", "NOT_WIRED", "SARIF_CATEGORY",
           "ActionInputError", "argv_for", "comment_on_pull_request", "outputs_for", "render_outputs",
           "run", "upload_sarif", "workdir_for", "write_step_summary"]
