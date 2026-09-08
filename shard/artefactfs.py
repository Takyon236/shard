
from __future__ import annotations

import contextlib
import errno
import os
import pathlib
import secrets
import stat
import tempfile


def _directory_flags() -> int:
    required = ("O_DIRECTORY", "O_NOFOLLOW")
    if any(not hasattr(os, name) for name in required):
        raise OSError(errno.ENOTSUP, "descriptor-bound artefact directories are unavailable")
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


@contextlib.contextmanager
def trusted_directory(path, *, create: bool = False):
    absolute = pathlib.Path(os.path.abspath(os.fspath(path)))
    flags = _directory_flags()
    current = os.open(absolute.anchor, flags)
    try:
        for part in absolute.parts[1:]:
            if create:
                try:
                    os.mkdir(part, dir_fd=current)
                except FileExistsError:
                    pass
            child = os.open(part, flags, dir_fd=current)
            os.close(current)
            current = child
        yield absolute, current
    finally:
        os.close(current)


@contextlib.contextmanager
def child_directory(parent_fd: int, name: str, *, create: bool = False):
    if pathlib.PurePath(name).name != name or name in ("", ".", ".."):
        raise ValueError("an artefact directory name must be one basename")
    if create:
        try:
            os.mkdir(name, dir_fd=parent_fd)
        except FileExistsError:
            pass
    fd = os.open(name, _directory_flags(), dir_fd=parent_fd)
    try:
        yield fd
    finally:
        os.close(fd)


@contextlib.contextmanager
def relative_directory(parent_fd: int, relative, *, create: bool = False):
    path = pathlib.PurePath(os.fspath(relative))
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise ValueError("an artefact directory must be a confined relative path")
    current = os.dup(parent_fd)
    try:
        for part in path.parts:
            if create:
                try:
                    os.mkdir(part, dir_fd=current)
                except FileExistsError:
                    pass
            child = os.open(part, _directory_flags(), dir_fd=current)
            os.close(current)
            current = child
        yield current
    finally:
        os.close(current)


@contextlib.contextmanager
def private_directory(parent_fd: int, prefix: str):
    if pathlib.PurePath(prefix).name != prefix or prefix in ("", ".", ".."):
        raise ValueError("an artefact directory prefix must be one basename")
    for _attempt in range(100):
        name = f"{prefix}-{secrets.token_hex(12)}"
        try:
            os.mkdir(name, 0o700, dir_fd=parent_fd)
        except FileExistsError:
            continue
        fd = os.open(name, _directory_flags(), dir_fd=parent_fd)
        try:
            yield name, fd
        finally:
            os.close(fd)
        return
    raise OSError(errno.EEXIST, "could not allocate a private artefact directory")


def atomic_write(parent_fd: int, name: str, data: bytes, *, mode: int = 0o644) -> None:
    if pathlib.PurePath(name).name != name or name in ("", ".", ".."):
        raise ValueError("an artefact file name must be one basename")
    temporary = f".shard-{name}-{secrets.token_hex(12)}.tmp"
    flags = (os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
             | getattr(os, "O_CLOEXEC", 0))
    fd = os.open(temporary, flags, mode, dir_fd=parent_fd)
    published = False
    try:
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written == 0:
                raise OSError(errno.EIO, "artefact write made no progress")
            view = view[written:]
        os.fsync(fd)
        os.close(fd)
        fd = -1
        os.replace(temporary, name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        published = True
    finally:
        if fd >= 0:
            os.close(fd)
        if not published:
            try:
                os.unlink(temporary, dir_fd=parent_fd)
            except FileNotFoundError:
                pass


def append_file(parent_fd: int, name: str, data: bytes, *, mode: int = 0o644) -> None:
    if pathlib.PurePath(name).name != name or name in ("", ".", ".."):
        raise ValueError("an artefact file name must be one basename")
    flags = (os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW
             | getattr(os, "O_CLOEXEC", 0))
    fd = os.open(name, flags, mode, dir_fd=parent_fd)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise OSError(errno.EINVAL, "artefact is not a regular file")
        if info.st_nlink != 1:
            raise OSError(errno.EMLINK, "artefact has more than one hard link")
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written == 0:
                raise OSError(errno.EIO, "artefact append made no progress")
            view = view[written:]
    finally:
        os.close(fd)


def read_file(parent_fd: int, relative, *, max_bytes: int | None = None) -> bytes:
    raw = os.fspath(relative)
    path = pathlib.PurePath(raw)
    if path.is_absolute() or not path.parts or any(part in ("", ".", "..") for part in path.parts):
        raise ValueError("an artefact file must be a confined relative path")

    directory = os.dup(parent_fd)
    fd = -1
    try:
        for part in path.parts[:-1]:
            child = os.open(part, _directory_flags(), dir_fd=directory)
            os.close(directory)
            directory = child
        flags = (os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW
                 | getattr(os, "O_CLOEXEC", 0))
        fd = os.open(path.parts[-1], flags, dir_fd=directory)
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise OSError(errno.EINVAL, "artefact is not a regular file")
        if before.st_nlink != 1:
            raise OSError(errno.EMLINK, "artefact has more than one hard link")
        if max_bytes is not None and before.st_size > max_bytes:
            raise OSError(errno.EFBIG, "artefact exceeds its byte ceiling")
        chunks: list[bytes] = []
        total = 0
        while chunk := os.read(fd, 1024 * 1024):
            total += len(chunk)
            if max_bytes is not None and total > max_bytes:
                raise OSError(errno.EFBIG, "artefact grew beyond its byte ceiling")
            chunks.append(chunk)
        after = os.fstat(fd)

        def identity(row):
            return (row.st_dev, row.st_ino, row.st_size, row.st_mtime_ns,
                    row.st_ctime_ns, row.st_nlink)
        if identity(before) != identity(after):
            raise OSError(errno.ESTALE, "artefact changed while it was being validated")
        return b"".join(chunks)
    finally:
        if fd >= 0:
            os.close(fd)
        os.close(directory)


def read_file_prefix(parent_fd: int, relative, *, max_bytes: int) -> bytes:
    if max_bytes < 0:
        raise ValueError("an artefact prefix ceiling must not be negative")
    raw = os.fspath(relative)
    path = pathlib.PurePath(raw)
    if path.is_absolute() or not path.parts or any(part in ("", ".", "..") for part in path.parts):
        raise ValueError("an artefact file must be a confined relative path")
    directory = os.dup(parent_fd)
    fd = -1
    try:
        for part in path.parts[:-1]:
            child = os.open(part, _directory_flags(), dir_fd=directory)
            os.close(directory)
            directory = child
        flags = (os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW
                 | getattr(os, "O_CLOEXEC", 0))
        fd = os.open(path.parts[-1], flags, dir_fd=directory)
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise OSError(errno.EINVAL, "artefact is not a regular file")
        if before.st_nlink != 1:
            raise OSError(errno.EMLINK, "artefact has more than one hard link")
        chunks: list[bytes] = []
        remaining = max_bytes
        while remaining:
            chunk = os.read(fd, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        after = os.fstat(fd)
        def identity(row):
            return (row.st_dev, row.st_ino, row.st_size, row.st_mtime_ns,
                    row.st_ctime_ns, row.st_nlink)
        if identity(before) != identity(after):
            raise OSError(errno.ESTALE, "artefact changed while it was being validated")
        return data
    finally:
        if fd >= 0:
            os.close(fd)
        os.close(directory)


def remove_file(parent_fd: int, name: str, *, missing_ok: bool = False) -> None:
    if pathlib.PurePath(name).name != name or name in ("", ".", ".."):
        raise ValueError("an artefact file name must be one basename")
    try:
        info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        if missing_ok:
            return
        raise
    if stat.S_ISDIR(info.st_mode):
        raise OSError(errno.EISDIR, "artefact is a directory")
    os.unlink(name, dir_fd=parent_fd)


def _same_inode(left, right) -> bool:
    return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)


def _remove_directory_contents(directory_fd: int) -> None:
    with os.scandir(directory_fd) as entries:
        names = [entry.name for entry in entries]
    for name in names:
        try:
            info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            continue
        if not stat.S_ISDIR(info.st_mode):
            os.unlink(name, dir_fd=directory_fd)
            continue
        child = os.open(name, _directory_flags(), dir_fd=directory_fd)
        try:
            held = os.fstat(child)
            if not _same_inode(info, held):
                raise OSError(errno.ESTALE, "artefact directory changed before cleanup")
            _remove_directory_contents(child)
            current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if not _same_inode(held, current):
                raise OSError(errno.ESTALE, "artefact directory changed during cleanup")
        finally:
            os.close(child)
        os.rmdir(name, dir_fd=directory_fd)


def remove_tree(parent_fd: int, name: str, *, missing_ok: bool = False) -> None:
    if pathlib.PurePath(name).name != name or name in ("", ".", ".."):
        raise ValueError("an artefact tree name must be one basename")
    try:
        info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        if missing_ok:
            return
        raise
    if not stat.S_ISDIR(info.st_mode):
        os.unlink(name, dir_fd=parent_fd)
        return
    child = os.open(name, _directory_flags(), dir_fd=parent_fd)
    try:
        held = os.fstat(child)
        if not _same_inode(info, held):
            raise OSError(errno.ESTALE, "artefact tree changed before cleanup")
        _remove_directory_contents(child)
        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if not _same_inode(held, current):
            raise OSError(errno.ESTALE, "artefact tree changed during cleanup")
    finally:
        os.close(child)
    os.rmdir(name, dir_fd=parent_fd)


def _confined_relative(root, target) -> pathlib.PurePath:
    base = pathlib.Path(os.path.abspath(os.fspath(root)))
    candidate = pathlib.Path(os.fspath(target))
    if not candidate.is_absolute():
        candidate = base / candidate
    try:
        relative = pathlib.Path(os.path.abspath(candidate)).relative_to(base)
    except ValueError as exc:
        raise ValueError("an artefact path must stay below its trusted root") from exc
    if not relative.parts:
        raise ValueError("an artefact path must name a file below its trusted root")
    return pathlib.PurePath(*relative.parts)


@contextlib.contextmanager
def _rooted_parent(root, target, *, create: bool = False):
    relative = _confined_relative(root, target)
    with trusted_directory(root) as (_root, root_fd):
        if len(relative.parts) == 1:
            yield root_fd, relative.name
            return
        with relative_directory(root_fd, pathlib.PurePath(*relative.parts[:-1]),
                                create=create) as parent_fd:
            yield parent_fd, relative.name


def rooted_read(root, target, *, max_bytes: int | None = None) -> bytes:
    with _rooted_parent(root, target) as (parent_fd, name):
        return read_file(parent_fd, name, max_bytes=max_bytes)


def rooted_read_prefix(root, target, *, max_bytes: int) -> bytes:
    with _rooted_parent(root, target) as (parent_fd, name):
        return read_file_prefix(parent_fd, name, max_bytes=max_bytes)


def rooted_write(root, target, data: bytes, *, create_parents: bool = False,
                 mode: int = 0o644) -> None:
    with _rooted_parent(root, target, create=create_parents) as (parent_fd, name):
        atomic_write(parent_fd, name, data, mode=mode)


def rooted_append(root, target, data: bytes, *, create_parents: bool = False,
                  mode: int = 0o644) -> None:
    with _rooted_parent(root, target, create=create_parents) as (parent_fd, name):
        append_file(parent_fd, name, data, mode=mode)


def rooted_remove(root, target, *, missing_ok: bool = False) -> None:
    with _rooted_parent(root, target) as (parent_fd, name):
        remove_file(parent_fd, name, missing_ok=missing_ok)


def rooted_files(root, directory, *, max_files: int | None = None,
                 max_bytes: int | None = None,
                 max_total_bytes: int | None = None,
                 max_entries: int | None = None) -> list[tuple[str, bytes]]:
    relative = _confined_relative(root, pathlib.Path(directory) / ".placeholder").parent
    with trusted_directory(root) as (_root, root_fd):
        with relative_directory(root_fd, relative) as directory_fd:
            rows = []
            total = 0
            names = []
            with os.scandir(directory_fd) as entries:
                for entry in entries:
                    if max_entries is not None and len(names) >= max_entries:
                        raise OSError(errno.E2BIG, "artefact directory exceeds its entry ceiling")
                    names.append(entry.name)
            for name in sorted(names):
                if max_files is not None and len(rows) >= max_files:
                    break
                try:
                    data = read_file(directory_fd, name, max_bytes=max_bytes)
                except (OSError, ValueError):
                    continue
                if max_total_bytes is not None and total + len(data) > max_total_bytes:
                    break
                rows.append((name, data))
                total += len(data)
            return rows


def _walk_regular_files(directory_fd: int, prefix: pathlib.PurePath,
                        found: list[pathlib.PurePath], budget: list[int], depth: int) -> None:
    if depth < 0:
        raise OSError(errno.ELOOP, "artefact tree exceeds its depth ceiling")
    names = []
    with os.scandir(directory_fd) as entries:
        for entry in entries:
            budget[0] -= 1
            if budget[0] < 0:
                raise OSError(errno.E2BIG, "artefact tree exceeds its entry ceiling")
            names.append(entry.name)
    for name in sorted(names):
        try:
            info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            continue
        relative = prefix / name
        if stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
            found.append(relative)
        elif stat.S_ISDIR(info.st_mode):
            try:
                child_fd = os.open(name, _directory_flags(), dir_fd=directory_fd)
            except OSError:
                continue
            try:
                _walk_regular_files(child_fd, relative, found, budget, depth - 1)
            finally:
                os.close(child_fd)


def rooted_file_names(root, directory=".", *, max_entries: int, max_depth: int = 64
                      ) -> list[pathlib.PurePath]:
    if max_entries < 1 or max_depth < 0:
        raise ValueError("artefact walk ceilings must be positive")
    budget = [max_entries]
    with trusted_directory(root) as (_root, root_fd):
        relative = pathlib.PurePath(os.fspath(directory))
        if relative.parts:
            with relative_directory(root_fd, relative) as directory_fd:
                found: list[pathlib.PurePath] = []
                _walk_regular_files(directory_fd, relative, found, budget, max_depth)
                return found
        found = []
        _walk_regular_files(root_fd, pathlib.PurePath(), found, budget, max_depth)
        return found


@contextlib.contextmanager
def materialized_file(root, target, *, name: str = "input", max_bytes: int | None = None):
    data = rooted_read(root, target, max_bytes=max_bytes)
    with tempfile.TemporaryDirectory(prefix="shard-artefact-") as temporary:
        with trusted_directory(temporary) as (_path, directory_fd):
            atomic_write(directory_fd, name, data, mode=0o400)
        yield pathlib.Path(temporary) / name


__all__ = [
    "append_file", "atomic_write", "child_directory", "materialized_file", "private_directory", "read_file",
    "read_file_prefix", "relative_directory", "remove_file", "remove_tree", "rooted_append",
    "rooted_file_names",
    "rooted_files", "rooted_read", "rooted_read_prefix", "rooted_remove", "rooted_write",
    "trusted_directory",
]
