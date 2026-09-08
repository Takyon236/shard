
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import stat
import sys
import tempfile
from dataclasses import replace

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
    _atomic_write(parent_fd, filename, data, mode=mode)
    integrity[role] = _sha256(data)


def _write_artefact(what: str, failed: list, write, *, details: list | None = None,
                    required: bool = False, finding: str = "") -> bool:
    try:
        write()
        return True
    except Exception as e:
        effect = ("The finding cannot gate and this run reports a delivery failure."
                  if required else "The run itself is unaffected and the other artefacts were written.")
        print(f"shard: could not write {what}: {type(e).__name__}: {e}. {effect}", file=sys.stderr)
        failed.append(what)
        if details is not None:
            details.append({"artefact": what, "required": required, "finding": finding,
                            "error": type(e).__name__, "message": str(e)})
        return False


def _generated_bytes(name: str, write) -> bytes:
    with tempfile.TemporaryDirectory(prefix="shard-emit-") as scratch:
        staged = pathlib.Path(scratch) / name
        write(staged)
        return staged.read_bytes()


def _replace_bundle_directory(parent_fd: int, source_name: str,
                              source_fd: int, dest_name: str) -> None:
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
                _remove_tree(bundles_fd, name, missing_ok=True)
    return files


def _bundle_delivery(kept: list, bundles_fd: int, public_out: pathlib.Path,
                     failed: list[str],
                     failed_details: list[dict], integrity: dict[str, str]
                     ) -> tuple[list, dict[int, str], list[str], list[dict]]:
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
    if not any(finding.gate_eligible or finding.poc_path for finding in kept):
        return kept, {}, [], []
    try:
        with _child_directory(out_fd, "bundles", create=True) as bundles_fd:
            return _bundle_delivery(kept, bundles_fd, out, failed, failed_details, integrity)
    except Exception as e:
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
    if out_dir is None:
        return {}
    public_out = pathlib.Path(out_dir)
    with _trusted_directory(out_dir, create=True) as (_trusted_out, out_fd):
        return _emit_open(findings, public_out, out_fd, status=status, target=target, mode=mode,
                          gate_reasons=gate_reasons, scope_reasons=scope_reasons, run=run,
                          journal_path=journal_path)


def _emit_open(findings: list, out: pathlib.Path, out_fd: int, *, status: str, target: str,
               mode: str, gate_reasons=(), scope_reasons=(), run=None, journal_path=None) -> dict:
    from shard.report import build_markdown, cap, write_sarif

    kept, dropped = cap(findings)

    written: dict = {}
    failed: list[str] = []
    failed_details: list[dict] = []
    integrity: dict[str, str] = {}

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
        written["failed"] = failed
        written["failed_artefacts"] = failed_details
    return written
