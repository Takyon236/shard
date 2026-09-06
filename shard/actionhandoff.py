"""Authenticate Action files across the untrusted-container-to-runner boundary.

The process that reviews a repository cannot make a path immutable: repository code has the same uid
inside the container and can keep a writable descriptor to a temporary file across its atomic rename.
The launcher therefore sends a one-run key over stdin before repository code starts.  The Action binds
the bytes it captured, and the exact GitHub command-file bytes it intended, into a keyed manifest.  A
second read-only container checks that manifest after the reviewing container and all its descendants
have exited.  Only then may the launcher relay a path to another workflow step.

The key is deliberately never an environment variable or argv value.  Linux exposes a process's
initial environment through ``/proc/<pid>/environ`` even after ``unsetenv``; popping an environment
secret would look erased to Python while leaving it readable to a same-uid descendant.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import pathlib
import stat
import sys

from shard.artefactfs import atomic_write as _atomic_write
from shard.artefactfs import read_file as _read_file
from shard.artefactfs import trusted_directory as _trusted_directory


_HANDOFF_ENV = "SHARD_ACTION_HANDOFF"
_MANIFEST = ".shard-handoff.json"
_MANIFEST_LIMIT = 4 * 1024 * 1024
_RELAYS = frozenset({"output", "summary"})


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical(body: dict) -> bytes:
    return json.dumps(body, ensure_ascii=True, separators=(",", ":"),
                      sort_keys=True).encode("ascii")


def _valid_digest(value) -> bool:
    return (isinstance(value, str) and len(value) == 64 and value == value.lower()
            and all(character in "0123456789abcdef" for character in value))


def _relative_name(value, *, one_component: bool = False) -> pathlib.PurePosixPath | None:
    if not isinstance(value, str) or not value or "\\" in value:
        return None
    path = pathlib.PurePosixPath(value)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        return None
    if one_component and len(path.parts) != 1:
        return None
    return path


def read_launch_key(stream=None) -> bytearray:
    """Consume the one key line, including EOF, before any repository-controlled process starts."""
    source = sys.stdin.buffer if stream is None else stream
    line = source.readline(66)
    trailing = source.read(1)
    if (len(line) != 65 or not line.endswith(b"\n") or trailing
            or any(character not in b"0123456789abcdef" for character in line[:-1])):
        raise ValueError("the Action handoff key was absent or malformed")
    return bytearray.fromhex(line[:-1].decode("ascii"))


def _make_nondumpable() -> None:
    """Keep later same-uid target processes out of the Action parent's memory."""
    import ctypes

    libc = ctypes.CDLL(None, use_errno=True)
    # PR_SET_DUMPABLE=4, SUID_DUMP_DISABLE=0.  The Action is Linux-only; silently omitting this on a
    # different libc would turn the stdin boundary into a key stored in readable parent memory.
    if libc.prctl(4, 0, 0, 0, 0) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


class ActionHandoff:
    """One in-memory authority for snapshot and command-file bytes."""

    def __init__(self, key: bytearray, publication_root: str, relays=()):
        if len(key) != 32:
            raise ValueError("the Action handoff key is not 256 bits")
        if not isinstance(publication_root, str) or not publication_root:
            raise ValueError("SHARD_ACTION_SNAPSHOT_ROOT is absent")
        names = frozenset(relays)
        if not names.issubset(_RELAYS):
            raise ValueError("the Action handoff names an unknown command file")
        self._key = key
        self._publication_root = publication_root
        self._files: dict[str, bytes] = {}
        self._snapshot = ""
        self._relays = {name: bytearray() for name in names}
        self._sealed = False

    @classmethod
    def begin(cls, env, *, stream=None):
        """Return an authenticated session only when the composite launcher requested one."""
        marker = env.pop(_HANDOFF_ENV, "")
        if not marker:
            return None
        if marker != "1":
            raise ValueError("SHARD_ACTION_HANDOFF has an invalid value")
        if env is os.environ:
            _make_nondumpable()
        key = read_launch_key(stream)
        relays = []
        if env.get("GITHUB_OUTPUT"):
            relays.append("output")
        if env.get("GITHUB_STEP_SUMMARY"):
            relays.append("summary")
        return cls(key, env.get("SHARD_ACTION_SNAPSHOT_ROOT", ""), relays)

    def bind_snapshot(self, files: dict[str, bytes]) -> None:
        """Bind the names and original bytes republished by ``actionsnapshot`` exactly once."""
        if self._files or self._snapshot:
            raise ValueError("the Action handoff snapshot was bound twice")
        snapshots = set()
        for name, data in files.items():
            relative = _relative_name(name)
            if relative is None or len(relative.parts) < 2 or not isinstance(data, bytes):
                raise ValueError("the Action handoff received an invalid snapshot file")
            snapshots.add(relative.parts[0])
        if len(snapshots) > 1:
            raise ValueError("the Action handoff spans more than one snapshot")
        self._snapshot = next(iter(snapshots), "")
        self._files = dict(files)

    def append_relay(self, name: str, data: bytes) -> None:
        """Record bytes only after the Action successfully appended them to a command file."""
        if name not in self._relays or not isinstance(data, bytes):
            raise ValueError("the Action handoff received an unknown relay append")
        self._relays[name].extend(data)

    def seal(self) -> str:
        """Write the keyed manifest; return a controlled error and erase the key on failure."""
        if self._sealed:
            return "the Action handoff was sealed twice"
        self._sealed = True
        try:
            files = {name: {"bytes": len(data), "sha256": _digest(data)}
                     for name, data in self._files.items()}
            relays = {name: {"bytes": len(data), "sha256": _digest(data)}
                      for name, data in self._relays.items()}
            body = {"files": files, "relays": relays, "snapshot": self._snapshot, "version": 1}
            envelope = {"body": body,
                        "mac": hmac.new(self._key, _canonical(body), hashlib.sha256).hexdigest()}
            data = _canonical(envelope) + b"\n"
            with _trusted_directory(self._publication_root) as (_root, root_fd):
                _atomic_write(root_fd, _MANIFEST, data, mode=0o600)
            return ""
        except (OSError, TypeError, ValueError) as error:
            return f"the Action handoff could not be sealed ({type(error).__name__}: {error})"
        finally:
            self.discard()

    def discard(self) -> None:
        """Erase the mutable key buffer when a run raises before it can be sealed."""
        for index in range(len(self._key)):
            self._key[index] = 0


def _entry_error(entries, label: str) -> str:
    if not isinstance(entries, dict):
        return f"the handoff {label} table is not an object"
    for name, record in entries.items():
        if _relative_name(name, one_component=(label == "relay")) is None:
            return f"the handoff {label} table contains an unsafe name"
        if (not isinstance(record, dict) or set(record) != {"bytes", "sha256"}
                or isinstance(record.get("bytes"), bool)
                or not isinstance(record.get("bytes"), int) or record["bytes"] < 0
                or not _valid_digest(record.get("sha256"))):
            return f"the handoff {label} table contains an invalid byte record"
    return ""


def _body_error(body: dict) -> str:
    if not isinstance(body, dict) or set(body) != {"files", "relays", "snapshot", "version"}:
        return "the Action handoff manifest has an invalid body"
    if isinstance(body["version"], bool) or not isinstance(body["version"], int) \
            or body["version"] != 1:
        return "the Action handoff manifest version is unsupported"
    if not isinstance(body["snapshot"], str):
        return "the Action handoff snapshot name is unsafe"
    snapshot = _relative_name(body["snapshot"], one_component=True) if body["snapshot"] else None
    if body["snapshot"] and snapshot is None:
        return "the Action handoff snapshot name is unsafe"
    for label, entries in (("file", body["files"]), ("relay", body["relays"])):
        error = _entry_error(entries, label)
        if error:
            return error
    if not set(body["relays"]).issubset(_RELAYS):
        return "the Action handoff names an unknown relay"
    roots = {pathlib.PurePosixPath(name).parts[0] for name in body["files"]}
    if roots != ({body["snapshot"]} if body["snapshot"] else set()):
        return "the Action handoff file table disagrees with its snapshot"
    if any(len(pathlib.PurePosixPath(name).parts) < 2 for name in body["files"]):
        return "the Action handoff file table names its snapshot as a file"
    return ""


def _manifest(root_fd: int, key: bytearray) -> tuple[str, dict]:
    try:
        raw = _read_file(root_fd, _MANIFEST, max_bytes=_MANIFEST_LIMIT)
        envelope = json.loads(raw)
    except (OSError, UnicodeError, ValueError) as error:
        return f"the Action handoff manifest is unreadable ({type(error).__name__}: {error})", {}
    if not isinstance(envelope, dict) or set(envelope) != {"body", "mac"}:
        return "the Action handoff manifest has an invalid envelope", {}
    body, claimed = envelope["body"], envelope["mac"]
    if not _valid_digest(claimed):
        return "the Action handoff manifest has an invalid authenticator", {}
    if not isinstance(body, dict):
        return "the Action handoff manifest has an invalid body", {}
    actual = hmac.new(key, _canonical(body), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(actual, claimed):
        return "the Action handoff manifest authenticator does not match", {}
    invalid = _body_error(body)
    if invalid:
        return invalid, {}
    return "", body


def _walk_tree(parent_fd: int, prefix: pathlib.PurePosixPath | None = None
               ) -> tuple[str, set[str], set[str]]:
    files: set[str] = set()
    directories: set[str] = set()
    try:
        names = os.listdir(parent_fd)
    except OSError as error:
        return (f"a handoff directory could not be listed ({type(error).__name__}: {error})",
                set(), set())
    for name in names:
        relative = pathlib.PurePosixPath(name) if prefix is None else prefix / name
        try:
            info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
                child_fd = os.open(name, flags, dir_fd=parent_fd)
                try:
                    error, children, descendants = _walk_tree(child_fd, relative)
                finally:
                    os.close(child_fd)
                if error:
                    return error, set(), set()
                directories.add(relative.as_posix())
                directories.update(descendants)
                files.update(children)
            elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                files.add(relative.as_posix())
            else:
                return (f"the Action handoff contains a non-regular or multiply-linked entry: {relative}",
                        set(), set())
        except OSError as error:
            return (f"a handoff entry could not be bound ({type(error).__name__}: {error})",
                    set(), set())
    return "", files, directories


def _verify_records(root_fd: int, records: dict, actual_names: set[str],
                    actual_directories: set[str], label: str,
                    capture: str = "") -> tuple[str, bytes]:
    expected_names = set(records)
    expected_directories = {
        parent.as_posix()
        for name in expected_names
        for parent in pathlib.PurePosixPath(name).parents
        if parent != pathlib.PurePosixPath(".")
    }
    if actual_names != expected_names or actual_directories != expected_directories:
        missing = sorted(expected_names - actual_names)
        extra = sorted(actual_names - expected_names)
        missing_directories = sorted(expected_directories - actual_directories)
        extra_directories = sorted(actual_directories - expected_directories)
        detail = []
        if missing:
            detail.append(f"missing {', '.join(missing)}")
        if extra:
            detail.append(f"unexpected {', '.join(extra)}")
        if missing_directories:
            detail.append(f"missing directories {', '.join(missing_directories)}")
        if extra_directories:
            detail.append(f"unexpected directories {', '.join(extra_directories)}")
        return (f"the Action handoff {label} tree disagrees with its manifest "
                f"({'; '.join(detail)})", b"")
    if capture and capture not in records:
        return f"the Action handoff did not authenticate the requested {capture} relay", b""
    captured = b""
    for name, record in records.items():
        try:
            data = _read_file(root_fd, pathlib.PurePosixPath(name), max_bytes=record["bytes"])
        except (OSError, ValueError) as error:
            return (f"the Action handoff {label} file {name!r} is unreadable "
                    f"({type(error).__name__}: {error})", b"")
        if len(data) != record["bytes"] or not hmac.compare_digest(_digest(data), record["sha256"]):
            return (f"the Action handoff {label} file {name!r} does not match its authenticated bytes",
                    b"")
        if name == capture:
            captured = data
    return "", captured


def _verified_bytes(publication_root: str, relay_root: str, key: bytearray,
                    emit: str = "") -> tuple[str, bytes]:
    """Verify both trees and return one relay from the descriptor that was actually checked."""
    try:
        if emit and emit not in _RELAYS:
            return "the Action handoff was asked to emit an unknown relay", b""
        with _trusted_directory(publication_root) as (_publication, publication_fd):
            error, body = _manifest(publication_fd, key)
            if error:
                return error, b""
            error, published, publication_directories = _walk_tree(publication_fd)
            if error:
                return error, b""
            published.discard(_MANIFEST)
            error, _unused = _verify_records(publication_fd, body["files"], published,
                                             publication_directories, "publication")
            if error:
                return error, b""
        with _trusted_directory(relay_root) as (_relay, relay_fd):
            error, relays, relay_directories = _walk_tree(relay_fd)
            if error:
                return error, b""
            return _verify_records(relay_fd, body["relays"], relays,
                                   relay_directories, "relay", capture=emit)
    except (OSError, ValueError) as error:
        return f"the Action handoff roots could not be bound ({type(error).__name__}: {error})", b""
    finally:
        for index in range(len(key)):
            key[index] = 0


def verify(publication_root: str, relay_root: str, key: bytearray) -> str:
    """Verify exact publication and relay trees after the untrusted container has exited."""
    error, _unused = _verified_bytes(publication_root, relay_root, key)
    return error


def main(argv=None) -> int:
    """Read the key from stdin and verify the two read-only mounts used by ``action.yml``."""
    args = sys.argv[1:] if argv is None else argv
    if len(args) not in (2, 4) or (len(args) == 4 and args[2] != "--emit"):
        print("shard: action handoff verifier requires publication and relay roots", file=sys.stderr)
        return 2
    emit = args[3] if len(args) == 4 else ""
    try:
        key = read_launch_key()
    except (OSError, ValueError) as error:
        print(f"shard: Action handoff key rejected ({type(error).__name__}: {error})", file=sys.stderr)
        return 2
    error, data = _verified_bytes(args[0], args[1], key, emit=emit)
    if error:
        print(f"shard: {error}", file=sys.stderr)
        return 2
    try:
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()
    except OSError as error:
        print(f"shard: authenticated relay could not be emitted ({type(error).__name__}: {error})",
              file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["ActionHandoff", "main", "read_launch_key", "verify"]
