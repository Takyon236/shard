
from __future__ import annotations

import pathlib
import re
import struct
from typing import NamedTuple

__all__ = ["IgnoreIndex"]

ALWAYS_PRUNE = frozenset({".claude", ".git", ".hg", ".svn"})


_INDEX_VERSIONS = frozenset({2, 3})

_INDEX_ENTRY_CAP = 500_000

_INDEX_FIXED = 62


class _GitIndex(NamedTuple):

    files: frozenset[str]
    dirs: frozenset[str]
    basis: str
    refusal: str


def _read_git_index(root: pathlib.Path) -> _GitIndex:
    def no(why: str) -> _GitIndex:
        return _GitIndex(frozenset(), frozenset(), "", why)

    try:
        blob = (root / ".git" / "index").read_bytes()
    except OSError:
        return no("no .git/index is present, so nothing here knows what git tracks")
    if len(blob) < 12 or blob[:4] != b"DIRC":
        return no(".git/index is not in the format this walk reads")
    version, count = struct.unpack(">II", blob[4:12])
    if version not in _INDEX_VERSIONS:
        return no(f".git/index is version {version}, which this walk does not read — versions "
                  f"{'/'.join(str(v) for v in sorted(_INDEX_VERSIONS))} only")
    if count > _INDEX_ENTRY_CAP:
        return no(f".git/index lists {count:,} paths, above the {_INDEX_ENTRY_CAP:,} this walk will "
                  f"hold in memory")

    files: set[str] = set()
    dirs: set[str] = set()
    off, size = 12, len(blob)
    for _ in range(count):
        if off + _INDEX_FIXED > size:
            return no(".git/index ends mid-entry, so no part of it is trusted")
        flags = struct.unpack(">H", blob[off + 60:off + 62])[0]
        at = off + _INDEX_FIXED
        if version >= 3 and flags & 0x4000:
            at += 2
        length = flags & 0x0FFF
        if length < 0x0FFF:
            end = at + length
        else:
            end = blob.find(b"\x00", at)
        if end == -1 or end > size:
            return no(".git/index holds a path this walk could not read to its end")
        name = blob[at:end].decode("utf-8", errors="replace")
        if not name:
            return no(".git/index holds an empty path, so it is not being read correctly")
        files.add(name)
        parts = name.split("/")
        for depth in range(1, len(parts)):
            dirs.add("/".join(parts[:depth]))
        used = end - off
        off += (used // 8 + 1) * 8
    return _GitIndex(frozenset(files), frozenset(dirs),
                     f"git index ({len(files):,} tracked path(s))", "")


class _Rule:

    __slots__ = ("regex", "negated", "dir_only")

    def __init__(self, regex: re.Pattern[str], negated: bool, dir_only: bool) -> None:
        self.regex = regex
        self.negated = negated
        self.dir_only = dir_only


def _translate(pattern: str) -> str:
    out: list[str] = []
    i, n = 0, len(pattern)
    while i < n:
        c = pattern[i]
        if c == "*":
            if pattern.startswith("**", i):
                i += 2
                if pattern.startswith("/", i):
                    out.append("(?:.*/)?")
                    i += 1
                else:
                    out.append(".*")
            else:
                out.append("[^/]*")
                i += 1
        elif c == "?":
            out.append("[^/]")
            i += 1
        elif c == "[":
            close = pattern.find("]", i + 1)
            if close == -1:
                out.append(re.escape(c))
                i += 1
            else:
                body = pattern[i + 1:close]
                body = body.replace("\\", "\\\\")
                if body.startswith("!"):
                    body = "^" + body[1:]
                out.append(f"[{body}]")
                i = close + 1
        else:
            out.append(re.escape(c))
            i += 1
    return "".join(out)


def _compile(line: str) -> _Rule | None:
    if not line or line.startswith("#"):
        return None
    stripped = re.sub(r"(?<!\\)\s+$", "", line)
    if not stripped:
        return None

    negated = stripped.startswith("!")
    if negated:
        stripped = stripped[1:]
    if stripped.startswith("\\"):
        stripped = stripped[1:]
    if not stripped:
        return None

    dir_only = stripped.endswith("/")
    if dir_only:
        stripped = stripped[:-1]
    if not stripped:
        return None

    anchored = "/" in stripped
    if stripped.startswith("/"):
        stripped = stripped[1:]
    if not stripped:
        return None

    body = _translate(stripped)
    expr = f"^{body}$" if anchored else f"^(?:.*/)?{body}$"
    try:
        return _Rule(re.compile(expr), negated, dir_only)
    except re.error:
        return None


class IgnoreIndex:

    def __init__(self, root) -> None:
        self._root = pathlib.Path(root)
        self._rules: dict[str, tuple[_Rule, ...]] = {}
        git = _read_git_index(self._root)
        self._tracked, self._tracked_dirs = git.files, git.dirs
        self.tracked_basis = git.basis
        self.tracked_refusal = git.refusal
        self.rescued = 0

    def load(self, rel_dir: str = "") -> None:
        key = rel_dir.strip("/")
        if key in self._rules:
            return
        path = (self._root / key / ".gitignore") if key else (self._root / ".gitignore")
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            self._rules[key] = ()
            return
        self._rules[key] = tuple(r for r in (_compile(ln) for ln in text.splitlines()) if r)

    def ignored(self, rel_path: str, *, is_dir: bool) -> bool:
        rel = rel_path.strip("/")
        if not rel:
            return False
        parts = rel.split("/")
        if any(p in ALWAYS_PRUNE for p in parts):
            return True

        decision = False
        for depth in range(len(parts)):
            key = "/".join(parts[:depth])
            rules = self._rules.get(key)
            if not rules:
                continue
            subject = "/".join(parts[depth:])
            for rule in rules:
                if rule.dir_only and not is_dir:
                    continue
                if rule.regex.match(subject):
                    decision = not rule.negated
        if decision and self._is_tracked(rel, is_dir=is_dir):
            self.rescued += 1
            return False
        return decision

    def _is_tracked(self, rel: str, *, is_dir: bool) -> bool:
        if not self.tracked_basis:
            return False
        return rel in self._tracked_dirs if is_dir else rel in self._tracked
