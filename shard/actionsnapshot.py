
from __future__ import annotations

import pathlib

from shard.actionresult import (_OPTIONAL_FILES, _REQUIRED_FILES, _control_text_error,
                                validated_artefacts)
from shard.artefactfs import (atomic_write as _atomic_write,
                              child_directory as _child_directory,
                              private_directory as _private_directory,
                              trusted_directory as _trusted_directory)


def _publish(payload: dict, captured: dict[str, bytes],
             destination_root: str) -> tuple[str, dict, dict[str, bytes]]:
    if _control_text_error(destination_root, "RUNNER_TEMP"):
        return "RUNNER_TEMP contains control text", {}, {}
    source = payload["artefacts"]
    try:
        with _trusted_directory(destination_root) as (public_root, parent_fd):
            with _private_directory(parent_fd, "shard-action") as (name, snapshot_fd):
                snapshot = public_root / name
                published = dict(source)
                handoff: dict[str, bytes] = {}
                roles = dict(_REQUIRED_FILES[payload["mode"]])
                if payload["mode"] in ("diff", "deep"):
                    roles.update(_OPTIONAL_FILES)
                for key, filename in roles.items():
                    if key in source:
                        _atomic_write(snapshot_fd, filename, captured[key])
                        published[key] = str(snapshot / filename)
                        handoff[f"{name}/{filename}"] = captured[key]

                bundles: list[str] = []
                if source.get("bundles"):
                    with _child_directory(snapshot_fd, "bundles", create=True) as bundles_fd:
                        for claimed in source["bundles"]:
                            bundle_name = pathlib.PurePath(claimed).name
                            with _child_directory(bundles_fd, bundle_name, create=True) as bundle_fd:
                                prefix = f"bundles/{bundle_name}/"
                                for captured_name, data in captured.items():
                                    if captured_name.startswith(prefix):
                                        filename = captured_name[len(prefix):]
                                        mode = 0o755 if filename == "reproduce.sh" else 0o644
                                        _atomic_write(bundle_fd, filename, data, mode=mode)
                                        handoff[f"{name}/{captured_name}"] = data
                            bundles.append(str(snapshot / "bundles" / bundle_name))
                published["bundles"] = bundles
                if "bundle_map" in source:
                    published["bundle_map"] = {
                        pathlib.PurePath(path).name: str(
                            snapshot / "bundles" / pathlib.PurePath(path).name)
                        for path in source["bundles"]
                    }
                return "", published, handoff
    except (KeyError, OSError, ValueError) as error:
        return (f"validated artefacts could not be published ({type(error).__name__}: {error})",
                {}, {})


def ingest_artefacts(mode: str, payload: dict, out_dir: str,
                     destination_root: str) -> tuple[str, dict[str, bytes], dict, dict[str, bytes]]:
    error, captured = validated_artefacts(mode, payload, out_dir)
    if error:
        return error, {}, payload, {}
    error, published, handoff = _publish(payload, captured, destination_root)
    if error:
        return error, {}, payload, {}
    result = dict(payload)
    result["artefacts"] = published
    return "", captured, result, handoff


__all__ = ["ingest_artefacts"]
