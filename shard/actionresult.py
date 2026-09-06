"""Validate a CLI result before the GitHub Action publishes any part of it.

The CLI payload is the Action's authority for outputs, uploads, summaries and comments. Defaults are
therefore forbidden here: applying them before proving this is a complete result turns ``{}`` into a
clean run. This module names one boundary and imports only the standard library so it ships on the
free tier with the Action that calls it.
"""

from __future__ import annotations

import errno
import os
import pathlib
import unicodedata

from shard.artefactfs import (child_directory as _child_directory,
                              read_file as _read_file,
                              trusted_directory as _trusted_directory)
from shard.actionintegrity import captured_error as _integrity_error
from shard.actionintegrity import shape_error as _integrity_shape_error


_REQUIRED_FILES = {
    "survey": {"survey": "shard-survey.json", "report": "shard-report.md"},
    "diff": {"sarif": "shard.sarif", "report": "shard-report.md", "result": "shard-result.json"},
    "deep": {"sarif": "shard.sarif", "report": "shard-report.md", "result": "shard-result.json"},
}
_OPTIONAL_FILES = {"telemetry": "shard-telemetry.json", "log": "shard-run.log"}
_FILE_ARTEFACTS = tuple({**_REQUIRED_FILES["diff"], **_REQUIRED_FILES["survey"],
                         **_OPTIONAL_FILES})
_MODE_STATUSES = {
    "survey": frozenset({"done"}),
    # `stall` exists in agentloop's experimental vocabulary but every shipping construction leaves
    # its breaker at zero. The Action must accept what this build can emit, not every dormant word.
    "diff": frozenset({"done", "budget", "error", "maxsteps", "repeat"}),
    "deep": frozenset({"done", "audited", "budget", "error", "maxsteps", "repeat"}),
}
_BUNDLE_FILES = frozenset({"metadata.json", "input", "output.txt", "reproduce.sh"})


def _control_text_error(value, label: str = "payload") -> str:
    """Reject control characters anywhere in the producer-controlled JSON tree."""
    if isinstance(value, str):
        if any(unicodedata.category(character) == "Cc" for character in value):
            return f"{label} contains control text"
        return ""
    if isinstance(value, list):
        for index, item in enumerate(value):
            error = _control_text_error(item, f"{label}[{index}]")
            if error:
                return error
    elif isinstance(value, dict):
        for key, item in value.items():
            error = _control_text_error(key, f"{label} key")
            if error:
                return error
            error = _control_text_error(item, f"{label}.{key}")
            if error:
                return error
    return ""


def _failure_error(artefacts: dict) -> tuple[str, set[str]]:
    """Validate the emitter's paired failure account; return its names when complete."""
    failed = artefacts.get("failed", [])
    details = artefacts.get("failed_artefacts", [])
    if not isinstance(failed, list) or not all(isinstance(name, str) and name for name in failed):
        return "artefacts.failed is not an array of non-empty artefact names", set()
    if len(failed) != len(set(failed)):
        return "artefacts.failed repeats an artefact name", set()
    if not isinstance(details, list):
        return "artefacts.failed_artefacts is not an array", set()
    for row in details:
        if not isinstance(row, dict):
            return "artefacts.failed_artefacts contains a non-object failure", set()
        if not isinstance(row.get("artefact"), str) or not row["artefact"]:
            return "artefacts.failed_artefacts contains an unnamed failure", set()
        if not isinstance(row.get("required"), bool):
            return "artefacts.failed_artefacts contains a failure without a boolean required field", set()
        if not isinstance(row.get("finding"), str):
            return "artefacts.failed_artefacts contains a failure with an invalid finding", set()
        if not isinstance(row.get("error"), str) or not row["error"]:
            return "artefacts.failed_artefacts contains a failure without an error type", set()
        if not isinstance(row.get("message"), str):
            return "artefacts.failed_artefacts contains a failure with an invalid message", set()
    detail_names = [row["artefact"] for row in details]
    if len(detail_names) != len(set(detail_names)):
        return "artefacts.failed_artefacts repeats an artefact name", set()
    if set(failed) != set(detail_names):
        return "artefacts.failed and artefacts.failed_artefacts disagree", set()
    return "", set(failed)


def _required_file_error(mode: str, artefacts: dict, failed: set[str]) -> str:
    for key, emitted_name in _REQUIRED_FILES.get(mode, {}).items():
        value = artefacts.get(key)
        if isinstance(value, str) and value:
            if emitted_name in failed:
                return f"artefacts.{key} is present but {emitted_name} is recorded as failed"
            continue
        if emitted_name not in failed:
            return f"the {mode} payload neither names nor accounts for {emitted_name}"
    return ""


def _count_error(mode: str, payload: dict) -> str:
    keys = ["findings"] + (["gate_eligible", "gate_new"] if mode == "diff"
                            else (["reproduced"] if mode == "deep" else []))
    for key in keys:
        value = payload[key]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            return f"{key} is not a non-negative integer"
    if mode == "survey" and payload["findings"] != 0:
        return "survey mode cannot report findings"
    if mode in ("diff", "deep"):
        eligible = payload["gate_eligible" if mode == "diff" else "reproduced"]
        if eligible > payload["findings"]:
            return "the gate-eligible count is larger than the finding count"
        if mode == "diff" and payload["gate_new"] > eligible:
            return "the new gate count is larger than the gate-eligible count"
    return ""


def _deep_error(payload: dict) -> str:
    if not isinstance(payload["solved"], bool):
        return "deep solved is not a boolean"
    if payload["solved"] is not bool(payload["reproduced"]):
        return "deep solved disagrees with the reproduced count"
    if not isinstance(payload["workdir"], dict):
        return "deep workdir is not an object"
    if not isinstance(payload["harness_kind"], str) or not payload["harness_kind"]:
        return "deep harness_kind is not a non-empty string"
    return ""


def _survey_error(payload: dict, artefacts: dict) -> str:
    if not isinstance(payload["repo"], str) or not payload["repo"]:
        return "survey repo is not a non-empty string"
    if not isinstance(payload["candidates"], list) or not isinstance(payload["blind_spots"], list):
        return "survey candidates and blind_spots must be arrays"
    if not all(isinstance(artefacts.get(key), str) and artefacts[key]
               for key in ("survey", "report")):
        return "the survey payload does not name both written artefacts"
    return ""


def _delivery_shape_error(artefacts: dict) -> str:
    bundles = artefacts.get("bundles")
    if not isinstance(bundles, list) or not all(isinstance(path, str) and path for path in bundles):
        return "artefacts.bundles is not an array of non-empty paths"
    delivery = artefacts.get("delivery")
    if not isinstance(delivery, dict) or not isinstance(delivery.get("failed_required"), list):
        return "artefacts.delivery does not describe required bundle delivery"
    delivered = delivery.get("delivered")
    if not isinstance(delivered, list) or not all(isinstance(name, str) and name for name in delivered):
        return "artefacts.delivery.delivered is not an array of bundle names"
    for row in delivery["failed_required"]:
        if not isinstance(row, dict) or row.get("required") is not True:
            return "artefacts.delivery.failed_required contains an invalid failure"
        finding = row.get("finding")
        artefact = row.get("artefact")
        if (not isinstance(finding, str) or not finding or finding in (".", "..")
                or "/" in finding or "\\" in finding
                or artefact != f"bundles/{finding}"):
            return "artefacts.delivery.failed_required does not identify a reproduction bundle"
    if not isinstance(delivery.get("ok"), bool):
        return "artefacts.delivery.ok is not a boolean"
    return ""


def _delivery_consistency_error(mode: str, payload: dict, artefacts: dict) -> str:
    bundles = artefacts["bundles"]
    delivery = artefacts["delivery"]
    delivered = delivery["delivered"]
    expected = payload["gate_eligible" if mode == "diff" else "reproduced"]
    delivered_count = delivery.get("delivered_reproductions")
    if (isinstance(delivered_count, bool) or not isinstance(delivered_count, int)
            or delivered_count != expected or len(delivered) != expected):
        return "the delivered reproduction count disagrees with the payload"
    if len(delivered) != len(set(delivered)):
        return "artefacts.delivery.delivered repeats a bundle name"
    if not set(delivered).issubset({pathlib.Path(path).name for path in bundles}):
        return "a delivered reproduction does not name a written bundle path"
    failed = delivery["failed_required"]
    failed_names = {row["finding"] for row in failed}
    written_names = {pathlib.Path(path).name for path in bundles}
    if len(delivered) + len(failed_names) > payload["findings"]:
        return "bundle delivery attempts exceed the finding count"
    if failed_names & (set(delivered) | written_names):
        return "a reproduction is recorded as both delivered and failed"
    if delivery["ok"] != (not failed):
        return "artefacts.delivery.ok disagrees with required failures"
    if failed and payload["status"] != "error":
        return "required bundle delivery failed but status is not error"
    return ""


def payload_error(mode: str, payload) -> str:
    """Return why stdout is not a complete result for ``mode``, or an empty string."""
    if not isinstance(payload, dict):
        return "the payload is not a JSON object"
    if mode not in _MODE_STATUSES:
        return f"mode is not one of {sorted(_MODE_STATUSES)}"
    control_error = _control_text_error(payload)
    if control_error:
        return control_error
    common = {"mode", "status", "findings", "artefacts"}
    per_mode = {
        "survey": {"repo", "candidates", "blind_spots"},
        "diff": {"gate_eligible", "gate_new"},
        "deep": {"reproduced", "solved", "workdir", "harness_kind"},
    }
    missing = sorted((common | per_mode[mode]) - payload.keys())
    if missing:
        return f"the {mode} payload is missing required field(s): {', '.join(missing)}"
    if payload["mode"] != mode:
        return f"the payload identifies mode {payload['mode']!r}, but {mode!r} ran"
    if (not isinstance(payload["status"], str)
            or payload["status"] not in _MODE_STATUSES[mode]):
        return f"status is not one {mode} mode can emit"
    count_error = _count_error(mode, payload)
    if count_error:
        return count_error
    artefacts = payload["artefacts"]
    if not isinstance(artefacts, dict):
        return "artefacts is not an object"
    failure_error, failed = _failure_error(artefacts)
    if failure_error:
        return failure_error
    boundary_error = _required_file_error(mode, artefacts, failed) or _integrity_shape_error(artefacts)
    if boundary_error:
        return boundary_error
    if mode == "survey":
        return _survey_error(payload, artefacts)
    delivery_error = (_deep_error(payload) if mode == "deep" else "") \
        or _delivery_shape_error(artefacts) \
        or _delivery_consistency_error(mode, payload, artefacts)
    if delivery_error:
        return delivery_error
    required_failures = artefacts["delivery"]["failed_required"]
    if any(row not in artefacts.get("failed_artefacts", []) for row in required_failures):
        return "artefacts.delivery.failed_required is not recorded in failed_artefacts"
    return ""


def _absolute(path) -> pathlib.Path:
    """A lexical absolute path: normalise dots without following a symlink."""
    return pathlib.Path(os.path.abspath(os.fspath(path)))


def _relative_claim(path: str, root: pathlib.Path, *, label: str) -> tuple[str, pathlib.PurePath | None]:
    """Turn one lexical claim into a confined name; filesystem resolution happens only by dirfd."""
    if not isinstance(path, str) or not path:
        return f"{label} is not a non-empty path", None
    raw = pathlib.Path(path)
    if ".." in raw.parts:
        return f"{label} uses parent traversal", None
    candidate = _absolute(raw)
    try:
        relative = candidate.relative_to(root)
    except ValueError:
        return f"{label} is outside --out-dir", None
    if not relative.parts:
        return f"{label} names --out-dir itself", None
    return "", pathlib.PurePath(*relative.parts)


def _filesystem_error(label: str, error: OSError) -> str:
    if error.errno == errno.ENOENT:
        return f"{label} does not exist ({type(error).__name__}: {error})"
    if error.errno in (errno.ELOOP, errno.ENOTDIR):
        return f"{label} is or traverses a symlink or non-directory"
    if error.errno in (errno.EINVAL, errno.EISDIR):
        return f"{label} is not a regular file"
    if error.errno == errno.EMLINK:
        return f"{label} has more than one hard link"
    if error.errno == errno.ESTALE:
        return f"{label} changed while it was being validated"
    return f"{label} changed or could not be bound ({type(error).__name__}: {error})"


def _bound_read(parent_fd: int, relative, label: str) -> tuple[str, bytes | None]:
    try:
        return "", _read_file(parent_fd, relative)
    except OSError as error:
        return _filesystem_error(label, error), None
    except ValueError as error:
        return f"{label} is not a confined file ({error})", None


def _file_error(artefacts: dict, mode: str, root: pathlib.Path, root_fd: int,
                captured: dict[str, bytes]) -> str:
    """Bind every single-file role to its fixed name and descriptor-read its bytes."""
    allowed = dict(_REQUIRED_FILES[mode])
    if mode in ("diff", "deep"):
        allowed.update(_OPTIONAL_FILES)
    claims: list[tuple[str, pathlib.PurePath]] = []
    for key in _FILE_ARTEFACTS:
        if key not in artefacts:
            continue
        if key not in allowed:
            return f"artefacts.{key} is not a file role {mode} mode emits"
        error, relative = _relative_claim(artefacts[key], root, label=f"artefacts.{key}")
        if error:
            return error
        assert relative is not None
        claims.append((key, relative))
    relatives = [relative for _key, relative in claims]
    if len(relatives) != len(set(relatives)):
        return "different artefact roles name the same file"
    for key, relative in claims:
        expected = pathlib.PurePath(allowed[key])
        if relative != expected:
            return f"artefacts.{key} does not use its fixed immediate name {allowed[key]!r}"
        error, data = _bound_read(root_fd, relative, f"artefacts.{key}")
        if error:
            return error
        assert data is not None
        captured[key] = data
    return ""


def _bundle_map_error(artefacts: dict, root: pathlib.Path,
                      by_name: dict[str, pathlib.PurePath]) -> str:
    """Prove the optional name map is a second spelling of the descriptor-opened directories."""
    bundle_map = artefacts.get("bundle_map")
    if bundle_map is None:
        return ""
    if not isinstance(bundle_map, dict) or not all(
            isinstance(name, str) and name and isinstance(path, str) and path
            for name, path in bundle_map.items()):
        return "artefacts.bundle_map is not a name-to-path object"
    if set(bundle_map) != set(by_name):
        return "artefacts.bundle_map disagrees with artefacts.bundles"
    for name, claimed in bundle_map.items():
        error, relative = _relative_claim(claimed, root,
                                          label=f"artefacts.bundle_map[{name!r}]")
        if error:
            return error
        if relative != by_name[name]:
            return f"artefacts.bundle_map[{name!r}] names a different bundle path"
    return ""


def _directory_identity(status: os.stat_result) -> tuple:
    return (status.st_dev, status.st_ino, status.st_size, status.st_mtime_ns,
            status.st_ctime_ns, status.st_nlink)


def _read_bundle(bundle_fd: int, name: str, delivered: bool,
                 captured: dict[str, bytes]) -> str:
    before = os.fstat(bundle_fd)
    entries = sorted(os.listdir(bundle_fd))
    if any(entry not in _BUNDLE_FILES for entry in entries):
        return f"bundle {name!r} contains a file outside the bundle contract"
    if "metadata.json" not in entries:
        return f"bundle {name!r}/metadata.json does not exist"
    if delivered and "input" not in entries:
        return f"delivered bundle {name!r}/input does not exist"
    for entry in entries:
        error, data = _bound_read(bundle_fd, entry, f"bundle {name!r}/{entry}")
        if error:
            return error
        assert data is not None
        captured[f"bundles/{name}/{entry}"] = data
    if entries != sorted(os.listdir(bundle_fd)) or _directory_identity(before) != _directory_identity(
            os.fstat(bundle_fd)):
        return f"bundle {name!r} changed while it was being validated"
    return ""


def _bundle_error(mode: str, artefacts: dict, root: pathlib.Path, root_fd: int,
                  captured: dict[str, bytes]) -> str:
    """Open every claimed bundle below the held root and capture every published child file."""
    claims: list[tuple[str, pathlib.PurePath]] = []
    for index, claimed in enumerate(artefacts.get("bundles", [])):
        label = f"artefacts.bundles[{index}]"
        error, relative = _relative_claim(claimed, root, label=label)
        if error:
            if error.endswith("names --out-dir itself"):
                return f"{label} is not an immediate child of --out-dir/bundles"
            return error
        assert relative is not None
        if len(relative.parts) != 2 or relative.parts[0] != "bundles":
            return f"{label} is not an immediate child of --out-dir/bundles"
        name = relative.parts[1]
        if name in ("", ".", ".."):
            return f"{label} has an invalid bundle name"
        claims.append((name, relative))
    by_name = dict(claims)
    if len(by_name) != len(claims):
        return "artefacts.bundles repeats a bundle name"
    map_error = _bundle_map_error(artefacts, root, by_name)
    if map_error:
        return map_error
    if not claims:
        return ""
    delivered = set(artefacts.get("delivery", {}).get("delivered", [])) \
        if mode in ("diff", "deep") else set()
    try:
        with _child_directory(root_fd, "bundles") as bundles_fd:
            for name, _relative in claims:
                with _child_directory(bundles_fd, name) as bundle_fd:
                    error = _read_bundle(bundle_fd, name, name in delivered, captured)
                    if error:
                        return error
    except OSError as error:
        return _filesystem_error("a claimed bundle directory", error)
    except ValueError as error:
        return f"a claimed bundle name is invalid ({error})"
    return ""


def validated_artefacts(mode: str, payload: dict,
                        out_dir: str) -> tuple[str, dict[str, bytes]]:
    """Validate every filesystem claim and bind delivery to bytes read from held descriptors."""
    control_error = _control_text_error(payload)
    if control_error:
        return control_error, {}
    artefacts = payload["artefacts"]
    captured: dict[str, bytes] = {}
    try:
        # This is deliberately the FIRST filesystem operation. Every later name is resolved below
        # this held descriptor, so renaming the public root and installing a same-named directory
        # cannot move a single read to the replacement.
        with _trusted_directory(out_dir) as (root, root_fd):
            file_error = _file_error(artefacts, mode, root, root_fd, captured)
            if file_error:
                return file_error, {}
            bundle_error = _bundle_error(mode, artefacts, root, root_fd, captured)
            if bundle_error:
                return bundle_error, {}
            integrity_error = _integrity_error(artefacts, captured)
            if integrity_error:
                return integrity_error, {}
    except OSError as error:
        return _filesystem_error("--out-dir", error), {}
    except ValueError as error:
        return f"--out-dir is not a trusted directory ({error})", {}
    return "", captured


def artefact_error(mode: str, payload: dict, out_dir: str) -> str:
    """Return why the payload's filesystem claims are not confined, surviving artefacts."""
    error, _captured = validated_artefacts(mode, payload, out_dir)
    return error


__all__ = ["artefact_error", "payload_error"]
