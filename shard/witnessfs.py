
from __future__ import annotations

import hashlib
import os
import pathlib
import shutil
import stat
import tempfile
from dataclasses import dataclass


class SnapshotError(RuntimeError):
    pass


@dataclass(frozen=True)
class _Entry:
    path: str
    kind: str
    mode: int
    value: str


_STRUCTURAL_ROOTS = frozenset({".git"})


class SourceSnapshot:

    def __init__(self, original: pathlib.Path, root: pathlib.Path, source: pathlib.Path,
                 trial: pathlib.Path, manifest: tuple[_Entry, ...]):
        self.original = original
        self.root = root
        self.source = source
        self.trial = trial
        self.manifest = manifest

    @classmethod
    def capture(cls, repo) -> SourceSnapshot:
        try:
            original = pathlib.Path(repo).resolve(strict=True)
            if not original.is_dir():
                raise SnapshotError(f"source root is not a directory: {original}")
            root = pathlib.Path(tempfile.mkdtemp(prefix="shard-witness-source-"))
            name = _safe_name(original.name)
            source = root / "source" / name
            trial = root / "trial" / name
            source.parent.mkdir(parents=True)
            _copy_tree(original, source, original)
            manifest = _manifest(source, source)
            snap = cls(original, root, source, trial, manifest)
            snap.verify_source()
            snap.verify_original()
            return snap
        except SnapshotError:
            if "root" in locals():
                _discard_tree(root)
            raise
        except (OSError, shutil.Error) as e:
            if "root" in locals():
                _discard_tree(root)
            raise SnapshotError(f"could not capture the source snapshot: {e}") from e

    def verify_source(self) -> None:
        try:
            got = _manifest(self.source, self.source)
        except OSError as e:
            raise SnapshotError(f"could not verify the source snapshot: {e}") from e
        if got != self.manifest:
            raise SnapshotError(_difference(self.manifest, got, "source snapshot"))

    def verify_original(self) -> None:
        changed = _expected_difference(self.original, self.manifest, "reviewed checkout")
        if changed:
            raise SnapshotError(f"reviewed source changed after the pristine snapshot: {changed}")

    def materialize(self) -> pathlib.Path:
        self.verify_source()
        try:
            _remove_tree(self.trial.parent)
        except FileNotFoundError:
            pass
        except OSError as e:
            raise SnapshotError(f"could not clear the previous witness trial: {e}") from e
        try:
            self.trial.parent.mkdir(parents=True)
            _copy_tree(self.source, self.trial, self.source)
            got = _manifest(self.trial, self.trial)
        except (OSError, shutil.Error) as e:
            raise SnapshotError(f"could not materialise a pristine witness trial: {e}") from e
        if got != self.manifest:
            raise SnapshotError(_difference(self.manifest, got, "materialised witness trial"))
        return self.trial

    def materialize_input(self, data: bytes) -> pathlib.Path:
        parent = self.root / "input"
        try:
            _remove_tree(parent)
        except FileNotFoundError:
            pass
        except OSError as e:
            raise SnapshotError(f"could not clear the previous witness input: {e}") from e
        try:
            parent.mkdir(mode=0o700)
            staged = parent / "candidate"
            staged.write_bytes(data)
            staged.chmod(0o600)
        except OSError as e:
            raise SnapshotError(f"could not stage a fresh witness input: {e}") from e
        return staged

    def verify_trial(self) -> None:
        changed = _expected_difference(self.trial, self.manifest, "witness trial")
        if changed:
            raise SnapshotError(f"witness execution changed pristine source: {changed}")

    def close(self) -> None:
        _discard_tree(self.root)


class SnapshotSet:

    def __init__(self, source: SourceSnapshot | None, base: SourceSnapshot | None, *,
                 own_source: bool, own_base: bool, failure: str = ""):
        self.source = source
        self.base = base
        self.own_source = own_source
        self.own_base = own_base
        self.failure = failure

    @classmethod
    def prepare(cls, repo, *, needed: bool, base_repo=None,
                source: SourceSnapshot | None = None,
                base: SourceSnapshot | None = None) -> SnapshotSet:
        own_source = needed and source is None
        own_base = needed and base_repo is not None and base is None
        pair = cls(source, base, own_source=own_source, own_base=own_base)
        try:
            if own_source:
                pair.source = SourceSnapshot.capture(repo)
            if own_base:
                pair.base = SourceSnapshot.capture(base_repo)
        except SnapshotError as e:
            pair.failure = str(e)
            pair.close()
        return pair

    def close(self) -> None:
        if self.own_source and self.source is not None:
            self.source.close()
            self.source = None
        if self.own_base and self.base is not None:
            self.base.close()
            self.base = None

    def repository(self, fallback):
        return self.source.source if self.source is not None else fallback

    def refusal(self, prefix: str) -> str:
        return prefix + self.failure if self.failure else ""


def original_paths(text: str, snapshot: SourceSnapshot) -> str:
    return text.replace(str(snapshot.trial), str(snapshot.original))


def _safe_name(name: str) -> str:
    clean = "".join(c if c.isalnum() or c in "-_." else "_" for c in name)
    return clean or "repo"


def _remove_tree(path: pathlib.Path) -> None:
    def retry(function, name, _error):
        os.chmod(name, 0o700, follow_symlinks=False)
        function(name)

    shutil.rmtree(path, onerror=retry)


def _discard_tree(path: pathlib.Path) -> None:
    try:
        _remove_tree(path)
    except Exception:
        pass


def _excluded(relative: pathlib.PurePath, *, is_dir: bool) -> bool:
    parts = relative.parts
    return any(part in _STRUCTURAL_ROOTS for part in parts)


def _copy_tree(source: pathlib.Path, destination: pathlib.Path, boundary: pathlib.Path) -> None:
    destination.mkdir(mode=0o700, parents=False)
    for item in os.scandir(source):
        src = pathlib.Path(item.path)
        rel = src.relative_to(boundary)
        status = item.stat(follow_symlinks=False)
        is_dir = stat.S_ISDIR(status.st_mode)
        if _excluded(rel, is_dir=is_dir):
            continue
        dst = destination / item.name
        if stat.S_ISLNK(status.st_mode):
            target = os.readlink(src)
            try:
                resolved = (src.parent / target).resolve()
            except (OSError, RuntimeError) as e:
                raise SnapshotError(f"source snapshot cannot resolve symlink {rel}: {e}") from e
            if pathlib.Path(target).is_absolute() or not _inside(resolved, boundary):
                raise SnapshotError(f"source snapshot refuses an escaping symlink: {rel}")
            dst.symlink_to(target)
        elif is_dir:
            _copy_tree(src, dst, boundary)
        elif stat.S_ISREG(status.st_mode):
            _require_single_link(status, rel)
            shutil.copy2(src, dst, follow_symlinks=False)
        else:
            raise SnapshotError(f"source snapshot refuses a non-file entry: {rel}")
        try:
            after = src.lstat()
        except OSError as e:
            raise SnapshotError(f"source snapshot entry changed while it was copied: {rel}: {e}") from e
        if ((after.st_dev, after.st_ino, stat.S_IFMT(after.st_mode))
                != (status.st_dev, status.st_ino, stat.S_IFMT(status.st_mode))):
            raise SnapshotError(f"source snapshot entry changed while it was copied: {rel}")
        if stat.S_ISREG(after.st_mode):
            _require_single_link(after, rel)
    shutil.copystat(source, destination, follow_symlinks=False)


def _manifest(root: pathlib.Path, boundary: pathlib.Path) -> tuple[_Entry, ...]:
    entries: list[_Entry] = []
    for item in sorted(os.scandir(root), key=lambda x: x.name):
        path = pathlib.Path(item.path)
        rel = path.relative_to(boundary)
        if _excluded(rel, is_dir=item.is_dir(follow_symlinks=False)):
            continue
        mode = stat.S_IMODE(item.stat(follow_symlinks=False).st_mode)
        if item.is_symlink():
            entries.append(_Entry(rel.as_posix(), "link", mode, os.readlink(path)))
        elif item.is_dir(follow_symlinks=False):
            entries.append(_Entry(rel.as_posix(), "dir", mode, ""))
            entries.extend(_manifest(path, boundary))
        elif item.is_file(follow_symlinks=False):
            _require_single_link(item.stat(follow_symlinks=False), rel)
            entries.append(_Entry(rel.as_posix(), "file", mode, _digest(path)))
        else:
            entries.append(_Entry(rel.as_posix(), "special", mode, ""))
    return tuple(entries)


def _digest(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _require_single_link(status: os.stat_result, relative: pathlib.PurePath) -> None:
    if status.st_nlink != 1:
        raise SnapshotError(
            f"source snapshot refuses a regular file with more than one hard link: {relative}"
        )


def _expected_difference(root: pathlib.Path, manifest: tuple[_Entry, ...], label: str) -> str:
    try:
        for expected in manifest:
            if _entry_at(root, expected.path) != expected:
                return expected.path
    except OSError as e:
        raise SnapshotError(f"could not verify the {label}: {e}") from e
    return ""


def _entry_at(root: pathlib.Path, relative: str) -> _Entry | None:
    path = root.joinpath(*pathlib.PurePosixPath(relative).parts)
    try:
        status = path.lstat()
    except FileNotFoundError:
        return None
    mode = stat.S_IMODE(status.st_mode)
    if stat.S_ISLNK(status.st_mode):
        return _Entry(relative, "link", mode, os.readlink(path))
    if stat.S_ISDIR(status.st_mode):
        return _Entry(relative, "dir", mode, "")
    if stat.S_ISREG(status.st_mode):
        return _Entry(relative, "file", mode, _digest(path))
    return _Entry(relative, "special", mode, "")


def _inside(path: pathlib.Path, root: pathlib.Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _difference(want: tuple[_Entry, ...], got: tuple[_Entry, ...], label: str) -> str:
    expected = {e.path: e for e in want}
    actual = {e.path: e for e in got}
    path = next((p for p in sorted(set(expected) | set(actual))
                 if expected.get(p) != actual.get(p)), "unknown entry")
    return f"{label} does not match its manifest: {path}"


__all__ = ["SnapshotError", "SnapshotSet", "SourceSnapshot", "original_paths"]
