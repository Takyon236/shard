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
the maintainers' suite parses `shard/cli.py` for `_emit` CALL SITES. The call sites did not move; only
the definition did. It is also how this package already reads across modules — `shard/report.py`
exports `_findings` and `_report_id` the same way.
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import stat
import sys
import tempfile
from dataclasses import replace

# MODULE SCOPE, not inside `_emit`, and the maintainers' suite is why. See the module docstring:
# its reachability probe scored both of these unreachable when the imports sat in the function body,
# so both shipped in the free image as dead weight. Both are dependency-free.
from shard.telemetry import render_log as _render_log, summarise as _telemetry
from shard.resultdoc import build as _build_result
from shard.artefactfs import (atomic_write as _atomic_write,
                              child_directory as _child_directory,
                              private_directory as _private_directory,
                              remove_tree as _remove_tree)
from shard.artefactfs import trusted_directory as _trusted_directory


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _publish_bytes(parent_fd: int, filename: str, data: bytes,
                   integrity: dict[str, str], role: str, *, mode: int = 0o644) -> None:
    """Publish one file and bind its in-memory bytes into the stdout authority."""
    _atomic_write(parent_fd, filename, data, mode=mode)
    integrity[role] = _sha256(data)


def _write_artefact(what: str, failed: list, write, *, details: list | None = None,
                    required: bool = False, finding: str = "") -> bool:
    """Write one artefact; a required bundle failure also withdraws its gate verdict.

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
        effect = ("The finding cannot gate and this run reports a delivery failure."
                  if required else "The run itself is unaffected and the other artefacts were written.")
        print(f"shard: could not write {what}: {type(e).__name__}: {e}. {effect}", file=sys.stderr)
        failed.append(what)
        if details is not None:
            details.append({"artefact": what, "required": required, "finding": finding,
                            "error": type(e).__name__, "message": str(e)})
        return False


def _generated_bytes(name: str, write) -> bytes:
    """Run one existing path-based renderer in a new private directory and return its bytes."""
    with tempfile.TemporaryDirectory(prefix="shard-emit-") as scratch:
        staged = pathlib.Path(scratch) / name
        write(staged)
        return staged.read_bytes()


def _replace_bundle_directory(parent_fd: int, source_name: str,
                              source_fd: int, dest_name: str) -> None:
    """Publish a held private bundle only while its parent entry names the same inode."""
    held = os.fstat(source_fd)
    if not stat.S_ISDIR(held.st_mode):
        raise OSError("the staged bundle is not a directory")
    source = os.stat(source_name, dir_fd=parent_fd, follow_symlinks=False)
    if (held.st_dev, held.st_ino) != (source.st_dev, source.st_ino):
        raise OSError("the private bundle directory was replaced before publication")
    _remove_tree(parent_fd, dest_name, missing_ok=True)
    os.rename(source_name, dest_name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
    public = os.stat(dest_name, dir_fd=parent_fd, follow_symlinks=False)
    if (held.st_dev, held.st_ino) != (public.st_dev, public.st_ino):
        raise OSError("the published bundle directory changed before it was claimed")


def _publish_bundle(finding, name: str, bundles_fd: int) -> dict[str, bytes]:
    """Stage, validate and publish one bundle without resolving its public path."""
    from shard.report import _write_bundle_fd

    stage_name = ""
    published = False
    files = {}
    try:
        with _private_directory(bundles_fd, f".shard-{name}") as (stage_name, stage_fd):
            files = _write_bundle_fd(finding, stage_fd, require_input=finding.gate_eligible)
            _replace_bundle_directory(bundles_fd, stage_name, stage_fd, name)
        published = True
    finally:
        if not published:
            try:
                if stage_name:
                    _remove_tree(bundles_fd, stage_name, missing_ok=True)
            finally:
                # `replace_directory` may have consumed the private name before its final identity
                # check. A failed required bundle leaves no stale public directory for a later claim.
                _remove_tree(bundles_fd, name, missing_ok=True)
    return files


def _bundle_delivery(kept: list, bundles_fd: int, public_out: pathlib.Path,
                     failed: list[str],
                     failed_details: list[dict], integrity: dict[str, str]
                     ) -> tuple[list, dict[int, str], list[str], list[dict]]:
    """Write and verify bundles, then withdraw any verdict whose required input did not survive."""
    from shard.report import finding_names

    names: dict[int, str] = {}
    bundles: list[str] = []
    required_failed: set[int] = set()
    for finding, name in zip(kept, finding_names(kept)):
        if not finding.gate_eligible and not finding.poc_path:
            continue
        public_dest = public_out / "bundles" / name

        published: dict[str, bytes] = {}

        def write_one(finding=finding, name=name, published=published):
            published.update(_publish_bundle(finding, name, bundles_fd))

        if _write_artefact(f"bundles/{name}", failed, write_one, details=failed_details,
                           required=finding.gate_eligible, finding=name):
            bundles.append(str(public_dest))
            names[id(finding)] = name
            integrity.update({f"bundles/{name}/{filename}": _sha256(data)
                              for filename, data in published.items()})
        elif finding.gate_eligible:
            required_failed.add(id(finding))

    note = "the reproduction bundle could not be delivered; this claim cannot gate"
    deliverable = [replace(finding, gate_eligible=False, poc_path=None, reproduce_command="",
                           doubts=tuple(finding.doubts) + (note,))
                   if id(finding) in required_failed else finding for finding in kept]
    required_failures = [row for row in failed_details if row["required"]]
    return deliverable, names, bundles, required_failures


def _deliver_bundles(kept: list, out: pathlib.Path, out_fd: int, failed: list[str],
                     failed_details: list[dict], integrity: dict[str, str]):
    """Bind the bundle parent to the output root and account for a parent-level refusal."""
    if not any(finding.gate_eligible or finding.poc_path for finding in kept):
        return kept, {}, [], []
    try:
        with _child_directory(out_fd, "bundles", create=True) as bundles_fd:
            return _bundle_delivery(kept, bundles_fd, out, failed, failed_details, integrity)
    except Exception as e:                                      # noqa: BLE001 - per-bundle account
        from shard.report import finding_names

        required_ids: set[int] = set()
        for finding, name in zip(kept, finding_names(kept)):
            if not finding.gate_eligible and not finding.poc_path:
                continue
            row = {"artefact": f"bundles/{name}", "required": finding.gate_eligible,
                   "finding": name, "error": type(e).__name__, "message": str(e)}
            failed.append(row["artefact"])
            failed_details.append(row)
            if finding.gate_eligible:
                required_ids.add(id(finding))
        note = "the reproduction bundle directory was unavailable; this claim cannot gate"
        deliverable = [replace(finding, gate_eligible=False, poc_path=None,
                               reproduce_command="", doubts=tuple(finding.doubts) + (note,))
                       if id(finding) in required_ids else finding for finding in kept]
        required = [row for row in failed_details if row["required"]]
        return deliverable, {}, [], required


def _emit(findings: list, out_dir: str | None, *, status: str, target: str, mode: str,
          gate_reasons=(), scope_reasons=(), run=None, journal_path=None) -> dict:
    """Write the artefacts. Returns what was written, for the JSON payload and the action outputs.

    `out_dir` is optional: a local run that only wants the verdict on stdout should not litter the
    working tree. In CI the action always passes one.

    **Each write is INDEPENDENT — see `_write_artefact`.** A key is present only when its file was
    written, so `written["sarif"]` is a claim that the SARIF exists rather than a path we intended to
    use; `written["failed"]` names anything that did not survive.
    """
    if out_dir is None:
        return {}
    public_out = pathlib.Path(out_dir)
    with _trusted_directory(out_dir, create=True) as (_trusted_out, out_fd):
        return _emit_open(findings, public_out, out_fd, status=status, target=target, mode=mode,
                          gate_reasons=gate_reasons, scope_reasons=scope_reasons, run=run,
                          journal_path=journal_path)


def _emit_open(findings: list, out: pathlib.Path, out_fd: int, *, status: str, target: str,
               mode: str, gate_reasons=(), scope_reasons=(), run=None, journal_path=None) -> dict:
    """Write a run below one descriptor-bound output root."""
    from shard.report import build_markdown, cap, write_sarif

    # ONE CAP, READ BY BOTH WRITERS. `write_sarif` returns the same number, and taking it from there
    # made the report's drop count depend on the SARIF write having succeeded — so the artefact that
    # states what was omitted could only state it while the other artefact was fine. `cap` is pure.
    kept, dropped = cap(findings)

    written: dict = {}
    failed: list[str] = []
    failed_details: list[dict] = []
    integrity: dict[str, str] = {}

    # A reproduction is a delivered input, not only an adjudicator's boolean. Bundles are attempted
    # before every artefact that can call a finding reproduced.
    deliverable, bundle_names, bundles, required_failures = _deliver_bundles(
        kept, out, out_fd, failed, failed_details, integrity)
    delivered = [bundle_names[id(f)] for f in kept if f.gate_eligible and id(f) in bundle_names]
    written["bundles"] = bundles
    written["bundle_map"] = {name: str(out / "bundles" / name)
                             for name in bundle_names.values()}
    written["delivery"] = {
        "ok": not required_failures,
        "delivered_reproductions": len(delivered),
        "delivered": delivered,
        "failed_required": required_failures,
    }
    # Paths are mutable names inside a checkout shared with the code Shard just executed. The stdout
    # payload is the Action's separate authority, so every consumer can reject bytes changed through a
    # pre-opened descriptor after atomic rename. This map is populated only after its write succeeds.
    written["sha256"] = integrity
    effective_status = "error" if required_failures else status

    sarif = out / "shard.sarif"
    if _write_artefact("shard.sarif", failed,
                       lambda: _publish_bytes(
                           out_fd, sarif.name,
                           _generated_bytes(sarif.name, lambda path: write_sarif(
                               deliverable, path, status=effective_status)),
                           integrity, "sarif"),
                       details=failed_details):
        written["sarif"] = str(sarif)
    report = out / "shard-report.md"
    if _write_artefact("shard-report.md", failed,
                       lambda: _publish_bytes(
                           out_fd, report.name,
                           build_markdown(deliverable, status=effective_status, dropped=dropped,
                                          target=target, gate_reasons=gate_reasons,
                                          scope_reasons=scope_reasons, run=run,
                                          bundle_names=bundle_names).encode(),
                           integrity, "report"),
                       details=failed_details):
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
                           lambda: _publish_bytes(
                               out_fd, telemetry.name,
                               json.dumps(_telemetry(journal_path), indent=2,
                                          default=str).encode(), integrity, "telemetry"),
                           details=failed_details):
            written["telemetry"] = str(telemetry)
        runlog = out / "shard-run.log"
        if _write_artefact("shard-run.log", failed,
                           lambda: _publish_bytes(
                               out_fd, runlog.name, _render_log(journal_path).encode(),
                               integrity, "log"),
                           details=failed_details):
            written["log"] = str(runlog)

    # The canonical result is the LAST writer because it names everything else. It receives the map
    # from successful bundle writes, so a non-null reproduction path is an observed directory.
    if failed_details:
        written["failed_artefacts"] = failed_details
    written["dropped"] = dropped
    result = out / "shard-result.json"
    snapshot = dict(written)
    snapshot["sha256"] = dict(integrity)
    if _write_artefact("shard-result.json", failed,
                       lambda: _publish_bytes(
                           out_fd, result.name,
                           json.dumps(_build_result(
                               deliverable, status=effective_status, mode=mode, target=target,
                               run=run, gate_reasons=gate_reasons, scope_reasons=scope_reasons,
                               artefacts=snapshot, bundle_names=bundle_names),
                               indent=2, sort_keys=True).encode(), integrity, "result"),
                       details=failed_details):
        written["result"] = str(result)
    if failed:
        # NAMED IN THE PAYLOAD, not only on a step log GitHub deletes with the runner. `action.py`
        # reads `artefacts["sarif"]` and treats an absent one as *"survey mode emits no SARIF; nothing
        # to say about it"* — true there and a false statement about a diff run, which is the
        # fail-safe-hiding-a-corpse shape `main`'s docstring records. Present only when something did
        # fail, for the reason the report's `levers` row is: a key that says "nothing wrong" on every
        # run is a key nobody reads on the run where something was.
        written["failed"] = failed
        written["failed_artefacts"] = failed_details
    return written
