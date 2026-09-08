
from __future__ import annotations

import pathlib
import re
import subprocess
from dataclasses import dataclass

_DIFF_HEADER = "diff --git "

_HEADER = re.compile(
    r'^diff --git (?P<a>"a/(?:[^"\\]|\\.)*"|a/.+?) (?P<b>"b/(?:[^"\\]|\\.)*"|b/.+)$')

_C_ESCAPES = {"a": 7, "b": 8, "f": 12, "n": 10, "r": 13, "t": 9, "v": 11, '"': 34, "\\": 92}
_OCTAL = "01234567"

_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(?P<start>\d+)(?:,(?P<count>\d+))? @@")

_DEV_NULL = "/dev/null"

_PROMPT_UNSAFE = re.compile("[\x00-\x1f\x7f-\x9f\u2028\u2029\u200e\u200f\u202a-\u202e"
                            "\u2066-\u2069\ufeff]")

MAX_PROMPT_FIELD_CHARS = 200


def prompt_safe(value, *, limit: int = MAX_PROMPT_FIELD_CHARS) -> str:
    text = value if isinstance(value, str) else str(value)
    if len(text) > limit:
        text = text[:limit] + "…"
    return _PROMPT_UNSAFE.sub(lambda m: _ESCAPES.get(m.group(), f"\\x{ord(m.group()):02x}")
                              if ord(m.group()) < 0x100 else f"\\u{ord(m.group()):04x}", text)


_ESCAPES = {"\n": "\\n", "\r": "\\r", "\t": "\\t"}


@dataclass(frozen=True)
class ChangedFile:

    path: str
    added: tuple[int, ...] = ()
    deleted: bool = False

    @property
    def added_only_removals(self) -> bool:
        return not self.deleted and not self.added


def _plus_path(value: str) -> str:
    if value.startswith('"'):
        return _header_path(value[:value.rindex('"') + 1])
    return _header_path(value.split("\t", 1)[0])


def _header_path(token: str) -> str:
    if not token.startswith('"'):
        return token[2:]
    inner = token[3:-1]
    out = bytearray()
    i = 0
    while i < len(inner):
        char = inner[i]
        if char != "\\":
            out += char.encode("utf-8", "replace")
            i += 1
        elif i + 1 >= len(inner):
            break
        elif inner[i + 1] in _C_ESCAPES:
            out.append(_C_ESCAPES[inner[i + 1]])
            i += 2
        elif inner[i + 1] in _OCTAL:
            digits = ""
            i += 1
            while i < len(inner) and inner[i] in _OCTAL and len(digits) < 3:
                digits += inner[i]
                i += 1
            out.append(int(digits, 8) & 0xFF)
        else:
            out += inner[i + 1].encode("utf-8", "replace")
            i += 2
    return out.decode("utf-8", "replace")


def parse_diff(text: str, *, reasons=None) -> tuple[ChangedFile, ...]:
    files: list[ChangedFile] = []
    path: str | None = None
    deleted = False
    added: list[int] = []
    line_no = 0
    in_hunk = False

    def flush() -> None:
        if path is not None:
            files.append(ChangedFile(path=path, added=tuple(added), deleted=deleted))

    for raw in _lines(text):
        if raw.startswith(_DIFF_HEADER):
            flush()
            path, deleted, added, in_hunk = None, False, [], False
            header = _HEADER.match(raw)
            if header:
                path = _header_path(header.group("b"))
            else:
                _note(reasons, f"a diff header could not be read, so that file was NOT examined and "
                               f"nothing in it can gate: {raw[:160]}")
            continue
        if path is None:
            continue

        if not in_hunk and raw.startswith(("+++ ", "--- ")):
            if raw.startswith("+++ "):
                value = raw[4:]
                deleted = value.strip() == _DEV_NULL
                if not deleted:
                    path = _plus_path(value)
            continue

        hunk = _HUNK.match(raw)
        if hunk:
            line_no, in_hunk = int(hunk.group("start")), True
            continue
        if not in_hunk:
            continue

        if raw.startswith("+"):
            added.append(line_no)
            line_no += 1
        elif raw.startswith("-") or raw.startswith("\\"):
            continue
        else:
            line_no += 1

    flush()
    return tuple(files)


def _lines(text: str) -> list[str]:
    return [line[:-1] if line.endswith("\r") else line for line in text.split("\n")]


def safe_directory_argv(repo) -> list[str]:
    return ["git", "-c", f"safe.directory={pathlib.Path(repo).resolve()}"]


def _note(reasons, text: str) -> None:
    if reasons is not None:
        reasons.append(text)


def git_diff(repo, base_ref: str = "HEAD~1", *, runner=subprocess.run, reasons=None) -> str:
    try:
        proc = runner([*safe_directory_argv(repo), "-c", "core.quotePath=false",
                       "-C", str(repo), "diff", "--unified=0", "--no-color", "--no-ext-diff",
                       "--src-prefix=a/", "--dst-prefix=b/", f"{base_ref}...HEAD", "--"],
                      capture_output=True, text=True, errors="replace", timeout=120)
    except (OSError, subprocess.SubprocessError) as e:
        _note(reasons, f"the diff could not be read ({type(e).__name__}: {e}); nothing was examined")
        return ""
    if proc.returncode != 0:
        _note(reasons, f"git could not resolve {base_ref!r}: "
                       f"{(proc.stderr or '').strip()[:200] or f'exit {proc.returncode}'}")
        return ""
    if reasons is not None:
        _note_divergence(repo, base_ref, runner=runner, reasons=reasons)
    return proc.stdout


def _note_divergence(repo, base_ref: str, *, runner, reasons) -> None:
    try:
        proc = runner([*safe_directory_argv(repo), "-C", str(repo), "merge-base", "--is-ancestor",
                       base_ref, "HEAD"], capture_output=True, text=True, errors="replace", timeout=60)
    except (OSError, subprocess.SubprocessError):
        return
    if proc.returncode != 0:
        _note(reasons, f"{base_ref!r} is not an ancestor of HEAD, so the review covers what HEAD adds "
                       f"since the two diverged (their merge base) rather than everything that differs "
                       f"between them")


HUNK_RADIUS = 40


def hunk_windows(files, *, radius: int = HUNK_RADIUS) -> dict[str, tuple[tuple[int, int], ...]]:
    out: dict[str, tuple[tuple[int, int], ...]] = {}
    for f in files:
        if f.deleted or not f.added:
            continue
        spans: list[list[int]] = []
        for line in sorted(f.added):
            lo, hi = max(1, line - radius), line + radius
            if spans and lo <= spans[-1][1] + 1:
                spans[-1][1] = max(spans[-1][1], hi)
            else:
                spans.append([lo, hi])
        out[f.path] = tuple((lo, hi) for lo, hi in spans)
    return out


def scope_paths(files, *, exclude_deleted: bool = True) -> tuple[str, ...]:
    return tuple(sorted(f.path for f in files if not (exclude_deleted and f.deleted)))


def added_line_index(files) -> dict[str, frozenset[int]]:
    return {f.path: frozenset(f.added) for f in files}


def introduced_line_index(files) -> dict[str, frozenset[int]]:
    return added_line_index(files)


def is_in_diff(index: dict[str, frozenset[int]], path: str, line: int) -> bool:
    return line in index.get(path, frozenset())


def summarise(files) -> str:
    if not files:
        return "no changed files in scope"
    added = sum(len(f.added) for f in files)
    removed = sum(1 for f in files if f.deleted)
    parts = [f"{len(files)} file(s) changed", f"{added} line(s) added"]
    if removed:
        parts.append(f"{removed} deleted")
    return ", ".join(parts)


def load_diff(repo, base_ref: str = "HEAD~1", *, runner=subprocess.run,
              reasons=None) -> tuple[ChangedFile, ...]:
    return parse_diff(git_diff(repo, base_ref, runner=runner, reasons=reasons), reasons=reasons)


def base_tree(repo, base_ref: str, dest, *, runner=subprocess.run, reasons=None) -> pathlib.Path | None:
    dest = pathlib.Path(dest)
    try:
        dest.mkdir(parents=True, exist_ok=True)
        tar = dest.parent / f"{dest.name}.tar"
        proc = runner([*safe_directory_argv(repo), "-C", str(repo), "archive", "--format=tar",
                       "-o", str(tar), base_ref],
                      capture_output=True, text=True, errors="replace", timeout=300)
    except (OSError, subprocess.SubprocessError) as e:
        _note(reasons, f"the base revision could not be extracted ({type(e).__name__}: {e}), so no "
                       f"finding could be attributed to this change by re-running it")
        return None
    if proc.returncode != 0:
        _note(reasons, f"git could not archive {base_ref!r}: "
                       f"{(proc.stderr or '').strip()[:200] or f'exit {proc.returncode}'}")
        return None
    try:
        import tarfile
        with tarfile.open(tar) as archive:
            archive.extractall(dest, filter="data")
        tar.unlink(missing_ok=True)
    except (OSError, tarfile.TarError, ValueError) as e:
        _note(reasons, f"the base revision could not be unpacked ({type(e).__name__}: {e})")
        return None
    return dest


def resolve(repo, path: str) -> pathlib.Path:
    return pathlib.Path(repo) / path


__all__ = [
    "HUNK_RADIUS", "MAX_PROMPT_FIELD_CHARS", "ChangedFile", "added_line_index", "git_diff",
    "hunk_windows", "introduced_line_index", "is_in_diff", "load_diff", "parse_diff", "prompt_safe",
    "resolve", "safe_directory_argv", "scope_paths", "summarise",
]
