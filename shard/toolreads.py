"""Descriptor-confined traversal and isolated regex evaluation for model-facing read tools.

The tool registry types stay in :mod:`shard.tools`; this leaf holds the filesystem walk and regex
worker so the shared registry module does not become another monolith.  It is free-tier code and uses
only the standard library plus :mod:`shard.artefactfs`.
"""

from __future__ import annotations

import json
import os
import pathlib
import stat
import struct
import subprocess
import sys
from dataclasses import dataclass
from typing import Callable

from shard.artefactfs import (read_file_prefix, relative_directory, trusted_directory)


ReadRef = tuple[pathlib.Path, pathlib.Path, pathlib.Path]
Selector = Callable[[str], tuple[pathlib.Path, pathlib.Path, pathlib.Path] | None]


@dataclass
class WalkState:
    entries: int = 0
    files: int = 0
    unscanned: int = 0
    vcs_skipped: int = 0
    links_skipped: int = 0
    depth_skipped: int = 0
    truncated: bool = False


@dataclass(frozen=True)
class _WalkPolicy:
    selector: Selector | None
    max_files: int
    max_entries: int
    max_depth: int
    vcs_dirs: frozenset[str]


@dataclass(frozen=True)
class ReadBatch:
    payload: bytes
    unreadable: int
    partial_files: int
    byte_skipped: int


@dataclass(frozen=True)
class RegexResult:
    hits: list[str]
    capped: bool


def selected_path(roots: tuple[pathlib.Path, ...], immutable: bool, path: str
                  ) -> tuple[pathlib.Path, pathlib.Path, pathlib.Path] | None:
    """Select a captured root without resolving a path in a hostile-writable tree."""
    supplied = pathlib.Path(path)
    display = supplied if supplied.is_absolute() else roots[0] / supplied
    try:
        candidate = display.resolve() if immutable else pathlib.Path(os.path.abspath(display))
    except (OSError, RuntimeError):
        return None
    for root in sorted(set(roots), key=lambda item: len(item.parts), reverse=True):
        try:
            return root, candidate.relative_to(root), display
        except ValueError:
            continue
    return None


def _record_ref(refs: list[ReadRef], state: WalkState, root: pathlib.Path,
                target: pathlib.Path, display: pathlib.Path, max_files: int) -> None:
    state.files += 1
    if len(refs) < max_files:
        refs.append((root, target, display))
    else:
        state.unscanned += 1


def _record_link(selector: Selector, refs: list[ReadRef], state: WalkState,
                 display: pathlib.Path, max_files: int) -> None:
    try:
        selected = selector(str(display))
        if selected is None:
            raise ValueError("link target is outside the captured roots")
        root, relative, _shown = selected
        info = (root / relative).stat()
    except (OSError, ValueError):
        state.links_skipped += 1
        return
    if stat.S_ISREG(info.st_mode):
        _record_ref(refs, state, root, relative, display, max_files)


def _walk_entry(directory_fd: int, root: pathlib.Path, relative: pathlib.Path,
                display: pathlib.Path, name: str, refs: list[ReadRef], state: WalkState, depth: int,
                policy: _WalkPolicy) -> None:
    try:
        info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except OSError:
        return
    target = relative / name
    shown = display / name
    if stat.S_ISREG(info.st_mode):
        _record_ref(refs, state, root, target, shown, policy.max_files)
        return
    if stat.S_ISLNK(info.st_mode):
        if policy.selector is None:
            state.links_skipped += 1
        else:
            _record_link(policy.selector, refs, state, shown, policy.max_files)
        return
    if not stat.S_ISDIR(info.st_mode):
        return
    if name in policy.vcs_dirs:
        state.vcs_skipped += 1
        return
    if depth >= policy.max_depth:
        state.depth_skipped += 1
        return
    try:
        with relative_directory(directory_fd, name) as child_fd:
            _walk_refs(child_fd, root, target, shown, refs, state, depth + 1, policy)
    except OSError:
        return


def _walk_refs(directory_fd: int, root: pathlib.Path, relative: pathlib.Path,
               display: pathlib.Path, refs: list[ReadRef], state: WalkState, depth: int,
               policy: _WalkPolicy) -> None:
    names = []
    with os.scandir(directory_fd) as entries:
        for entry in entries:
            if state.entries >= policy.max_entries:
                state.truncated = True
                break
            state.entries += 1
            names.append(entry.name)
    for name in sorted(names):
        _walk_entry(directory_fd, root, relative, display, name, refs, state, depth, policy)


def grep_refs(root: pathlib.Path, relative: pathlib.Path, display: pathlib.Path, *,
              selector: Selector | None, max_files: int, max_entries: int, max_depth: int,
              vcs_dirs: frozenset[str]) -> tuple[list[ReadRef], WalkState] | None:
    """Collect a bounded set of regular-file references beneath one captured root."""
    refs: list[ReadRef] = []
    state = WalkState()
    policy = _WalkPolicy(selector, max_files, max_entries, max_depth, vcs_dirs)
    with trusted_directory(root) as (_root, root_fd):
        try:
            with relative_directory(root_fd, relative) as directory_fd:
                _walk_refs(directory_fd, root, relative, display, refs, state, 0, policy)
                return refs, state
        except OSError:
            pass
        try:
            read_file_prefix(root_fd, relative, max_bytes=0)
        except FileNotFoundError:
            return refs, state
        except OSError:
            return None
    _record_ref(refs, state, root, relative, display, max_files)
    return refs, state


def capture_refs(refs: list[ReadRef], *, max_file_bytes: int,
                 max_total_bytes: int) -> ReadBatch:
    """Capture bounded stable bytes and frame them for the isolated regex worker."""
    payload = bytearray()
    unreadable = partial_files = byte_skipped = total = 0
    for index, (root, target, shown) in enumerate(refs):
        try:
            with trusted_directory(root) as (_root, root_fd):
                raw = read_file_prefix(root_fd, target, max_bytes=max_file_bytes + 1)
        except (OSError, ValueError):
            unreadable += 1
            continue
        if len(raw) > max_file_bytes:
            partial_files += 1
            raw = raw[:max_file_bytes]
        if total + len(raw) > max_total_bytes:
            byte_skipped = len(refs) - index
            break
        encoded_path = os.fsencode(shown)
        payload.extend(struct.pack("!II", len(encoded_path), len(raw)))
        payload.extend(encoded_path)
        payload.extend(raw)
        total += len(raw)
    return ReadBatch(bytes(payload), unreadable, partial_files, byte_skipped)


_REGEX_WORKER = r"""
import json, os, re, resource, struct, sys
cap = 256 * 1024 * 1024
hard = resource.getrlimit(resource.RLIMIT_AS)[1]
resource.setrlimit(resource.RLIMIT_AS, (min(cap, hard) if hard >= 0 else cap, hard))
data = memoryview(sys.stdin.buffer.read())
pattern_size, limit = struct.unpack_from("!II", data, 0)
cursor = 8
pattern = bytes(data[cursor:cursor + pattern_size]).decode("utf-8", "replace")
cursor += pattern_size
try:
    regex = re.compile(pattern)
except re.error as exc:
    print(json.dumps({"error": str(exc)}))
    raise SystemExit(0)
hits = []
capped = False
while cursor < len(data):
    path_size, content_size = struct.unpack_from("!II", data, cursor)
    cursor += 8
    path = os.fsdecode(bytes(data[cursor:cursor + path_size]))
    cursor += path_size
    text = bytes(data[cursor:cursor + content_size]).decode("utf-8", "replace")
    cursor += content_size
    for line_number, line in enumerate(text.splitlines(), 1):
        if regex.search(line):
            hits.append(f"{path}:{line_number}: {line.strip()[:200]}")
            if len(hits) >= limit:
                capped = True
                break
    if capped:
        break
print(json.dumps({"hits": hits, "capped": capped}, separators=(",", ":")))
"""


def regex_hits(pattern: str, batch: ReadBatch, *, max_matches: int,
               timeout: float, max_pattern_bytes: int) -> RegexResult:
    """Evaluate a bounded regex in a memory-capped child, safe from any caller thread."""
    encoded = pattern.encode("utf-8")
    if len(encoded) > max_pattern_bytes:
        raise ValueError(f"grep pattern exceeds its {max_pattern_bytes}-byte ceiling")
    header = struct.pack("!II", len(encoded), max_matches)
    try:
        process = subprocess.run(
            [sys.executable, "-I", "-c", _REGEX_WORKER], input=header + encoded + batch.payload,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False,
            cwd="/", env={},
        )
    except subprocess.TimeoutExpired as exc:
        raise TimeoutError from exc
    if process.returncode != 0:
        raise OSError(f"isolated regex worker exited {process.returncode}")
    try:
        result = json.loads(process.stdout)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise OSError("isolated regex worker returned malformed output") from exc
    if "error" in result:
        raise ValueError(f"invalid grep pattern: {result['error']}")
    return RegexResult(list(result["hits"]), bool(result["capped"]))


def directory_entries(root: pathlib.Path, relative: pathlib.Path, *, max_entries: int
                      ) -> tuple[list[tuple[str, int]], bool]:
    """List a held directory without following an entry and stop before fan-out allocation."""
    names: list[tuple[str, int]] = []
    truncated = False
    with trusted_directory(root) as (_root, root_fd):
        with relative_directory(root_fd, relative) as directory_fd:
            with os.scandir(directory_fd) as entries:
                for entry in entries:
                    if len(names) >= max_entries:
                        truncated = True
                        break
                    info = os.stat(entry.name, dir_fd=directory_fd, follow_symlinks=False)
                    names.append((entry.name, info.st_mode))
    return names, truncated


def immutable_directory_link(selector: Selector, path: pathlib.Path) -> bool:
    """Classify a captured in-tree directory link without reopening the link itself."""
    selected = selector(str(path))
    if selected is None:
        return False
    root, relative, _shown = selected
    try:
        with trusted_directory(root) as (_root, root_fd):
            with relative_directory(root_fd, relative):
                return True
    except (OSError, ValueError):
        return False
