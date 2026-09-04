"""Writing the run's artefacts — the deliverable, one file at a time.

Split out of `shard/cli.py` on 2026-08-28, after `shard/cliargs.py`. The maintainers' backlog item 2: that file
held seven subcommands, the parser, the ceilings, the terminal rendering and this behind one name.
The seam is real rather than a line count — everything here runs AFTER the run is over and every
token has been paid for, and it decides nothing. `cli.py` decides; this writes down what was decided.

## The one rule, and it is why `_write_artefact` exists at all

**A key in the returned dict is a claim that the file is there.** Each write is independent, so a
failure costs that artefact and nothing else. `_emit` used to write the SARIF, the report and every
bundle as one uninterrupted sequence, so the first exception escaped to `cli.main`'s broad `except` —
which reports `EXIT_CONFIG` — and a finished, adjudicated, gate-eligible run delivered a zero-byte
report, no bundles, no alerts and exit 2, on one unpaired surrogate in a finding.

## Where the imports are, and why two of them are at module scope

The maintainers' suite's reachability probe executes each free entry point and asks which
`shard.*` modules were imported; a module in `FREE_MODULES` that no command reaches is dead weight in
the artefact. `telemetry` and `resultdoc` shipped exactly that way while their imports sat inside
`_emit`'s body, which the probe's `diff --repo .` never reaches. `shard.report` stays function-scoped
as it always was — `resultdoc` already pulls it in at module scope, so the closure is identical
either way and the smaller diff is the one that cannot be wrong.

## The names keep their underscores

`_emit` and `_write_artefact` are imported into `shard/cli.py` under exactly these names, so every
existing reader still works verbatim: the maintainers' suite calls `cli._emit`,
the maintainers' suite parses `shard/cli.py` for `_emit` CALL SITES, and the design notes names
`cli._emit` in three places. The call sites did not move; only the definition did. It is also how
this package already reads across modules — `shard/report.py` exports `_findings` and `_report_id`
the same way.
"""

from __future__ import annotations

import json
import pathlib
import sys

# MODULE SCOPE, not inside `_emit`, and the maintainers' suite is why. See the module docstring:
# its reachability probe scored both of these unreachable when the imports sat in the function body,
# so both shipped in the free image as dead weight. Both are dependency-free.
from shard.telemetry import render_log as _render_log, summarise as _telemetry
from shard.resultdoc import build as _build_result


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


def _emit(findings: list, out_dir: str | None, *, status: str, target: str, mode: str,
          gate_reasons=(), scope_reasons=(), run=None, journal_path=None) -> dict:
    """Write the artefacts. Returns what was written, for the JSON payload and the action outputs.

    `out_dir` is optional: a local run that only wants the verdict on stdout should not litter the
    working tree. In CI the action always passes one.

    **Each write is INDEPENDENT — see `_write_artefact`.** A key is present only when its file was
    written, so `written["sarif"]` is a claim that the SARIF exists rather than a path we intended to
    use; `written["failed"]` names anything that did not survive.
    """
    from shard.report import build_markdown, cap, finding_names, write_bundle, write_sarif

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
    # The status reaches the SARIF, not only the markdown. The design notes: the report was the
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

    # **THE WHOLE RESULT, FOR THE TOOL ON THE OTHER SIDE.** Written LAST of the three finding
    # artefacts because it names the other two: `artefacts` in the document is what actually survived,
    # so a consumer following a path from it is following a path to a file that exists. That is
    # `_write_artefact`'s rule — a key is a claim the file is there — applied one level out.
    #
    # It is not a fourth spelling of the report. `shard/resultdoc.py` records what it replaces: five
    # partial views of one result, the only complete one being the markdown, which is the one a
    # machine cannot read.
    result = out / "shard-result.json"
    if _write_artefact("shard-result.json", failed,
                       lambda: result.write_text(
                           json.dumps(_build_result(findings, status=status, mode=mode, target=target,
                                                   run=run, gate_reasons=gate_reasons,
                                                   scope_reasons=scope_reasons,
                                                   artefacts=dict(written)),
                                      indent=2, sort_keys=True),
                           encoding="utf-8")):
        written["result"] = str(result)

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
    # numbered directory instead.
    #
    # THE NAME IS NOT COMPUTED HERE ANY MORE, and the reason is what the second spelling cost.
    # `resultdoc._finding` re-derived `bundles/<fingerprint>` unconditionally, so the canonical result
    # document pointed both findings of a repeated fingerprint at the FIRST one's input and named the
    # `-2` directory nowhere. `report.finding_names` is the one derivation; both read it, over the same
    # capped list, so they cannot disagree about which directory holds which input.
    bundles = []
    for f, name in zip(kept, finding_names(kept)):
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
