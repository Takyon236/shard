
from __future__ import annotations

import errno
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from shard.artefactfs import read_file, trusted_directory
from shard.toolreads import (capture_refs, directory_entries, grep_refs,
                             immutable_directory_link, regex_hits, selected_path)



_UNSET_ROOT = Path("/nonexistent/shard-toolcontext-unset")


@dataclass
class ToolContext:

    engine_root: Path = _UNSET_ROOT
    audit_root: Path = _UNSET_ROOT
    shard_root: Path = Path(__file__).resolve().parent.parent
    secret_env_names: tuple[str, ...] = ()
    weggli: Path | None = None
    immutable_read_roots: bool = False
    _captured_read_roots: tuple[Path, ...] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        self._captured_read_roots = tuple(
            Path(root).resolve() for root in (self.engine_root, self.shard_root, self.audit_root)
        )


@dataclass
class ToolResult:
    ok: bool
    data: Any = None
    error: str = ""
    source_read: dict | None = field(default=None, compare=False, repr=False)

    def to_dict(self) -> dict:
        return {"ok": self.ok, "data": self.data, "error": self.error}


@dataclass
class Tool:
    name: str
    kind: str
    description: str
    fn: Callable[..., ToolResult]
    args_schema: dict = field(default_factory=dict)
    priority: int = 0


_JSON_TYPES = {"str": "string", "int": "integer", "float": "number", "bool": "boolean", "list": "array"}


def _param_schema(spec: str) -> tuple[dict, bool]:
    optional = spec.endswith("?")
    atom = spec[:-1] if optional else spec
    schema: dict = {"type": _JSON_TYPES.get(atom, "string")}
    if schema["type"] == "array":
        schema["items"] = {"type": "string"}
    return schema, optional


def tool_to_openai(tool: Tool) -> dict:
    props: dict = {}
    required: list[str] = []
    for name, spec in tool.args_schema.items():
        schema, optional = _param_schema(str(spec))
        props[name] = schema
        if not optional:
            required.append(name)
    return {"type": "function", "function": {
        "name": tool.name, "description": tool.description,
        "parameters": {"type": "object", "properties": props, "required": required},
    }}


class ToolRegistry:
    def __init__(self, ctx: ToolContext) -> None:
        self.ctx = ctx
        self._tools: dict[str, Tool] = {}

    def register(self, tool: Tool) -> None:
        self._tools[tool.name] = tool

    def get(self, name: str) -> Tool | None:
        return self._tools.get(name)

    def names(self) -> list[str]:
        return sorted(self._tools)

    def spec(self) -> str:
        return "\n".join(
            f"- {t.name}({', '.join(t.args_schema) or ''}) [{t.kind}] — {t.description}"
            for t in (self._tools[n] for n in self.names())
        )

    def openai_tools(self, only: list[str] | None = None) -> list[dict]:
        names = [n for n in (only if only is not None else self.names()) if n in self._tools]
        names.sort(key=lambda n: (-self._tools[n].priority, n))
        return [tool_to_openai(self._tools[n]) for n in names]

    def call(self, name: str, args: dict) -> ToolResult:
        tool = self._tools.get(name)
        if tool is None:
            return ToolResult(False, error=f"unknown tool: {name}")
        try:
            return tool.fn(self.ctx, **(args or {}))
        except TypeError as e:
            return ToolResult(False, error=f"bad args for {name}: {e}")
        except Exception as e:
            return ToolResult(False, error=f"{type(e).__name__}: {e}")


def _is_within(p: Path, root: Path) -> bool:
    try:
        p.resolve().relative_to(root)
        return True
    except ValueError:
        return False


def _read_allowed_roots(ctx: ToolContext) -> tuple[Path, ...]:
    return ctx._captured_read_roots


def _selected_read_path(ctx: ToolContext, path: str) -> tuple[Path, Path, Path] | None:
    return selected_path(_read_allowed_roots(ctx), ctx.immutable_read_roots, path)


_IDX_MAX_ENTRIES = 24
_IDX_MAX_CHARS = 900
_IDX_SIG_CHARS = 76
_IDX_CALLABLE = re.compile(r"^[A-Za-z_][A-Za-z0-9_ \t*&:<>,\[\]]*\([^;]*$")
_IDX_TYPE = re.compile(r"^(?:typedef\s+)?(?:struct|union|enum|class|namespace)\s+[A-Za-z_]\w*")
_IDX_DEFINE = re.compile(r"^#\s*define\s+[A-Za-z_]\w*\(")
_IDX_PY = re.compile(r"^[ \t]{0,4}(?:async\s+)?(?:def|class)\s+[A-Za-z_]\w*")


_IDX_BY_SUFFIX: "dict[str, tuple]" = {
    **{s: (_IDX_CALLABLE, _IDX_TYPE, _IDX_DEFINE)
       for s in (".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".hxx", ".inc")},
    **{s: (_IDX_PY,) for s in (".py", ".pyi")},
}


def _file_index(lines: "list[str]", suffix: str = "") -> str:
    pats = _IDX_BY_SUFFIX.get(suffix.lower())
    if not pats:
        return ""
    hits: list[str] = []
    total = 0
    for i, line in enumerate(lines):
        if not line or (line[0] in " \t" and pats is not _IDX_BY_SUFFIX[".py"]):
            continue
        if not any(p.match(line) for p in pats):
            continue
        total += 1
        if len(hits) < _IDX_MAX_ENTRIES:
            hits.append(f"{i}:{line.strip()[:_IDX_SIG_CHARS]}")
    if len(hits) < 2:
        return ""
    shown = f" ({len(hits)} of {total})" if total > len(hits) else ""
    body = " | ".join(hits)
    if len(body) > _IDX_MAX_CHARS:
        body = body[:_IDX_MAX_CHARS].rsplit(" | ", 1)[0]
    return (f"\n...[index{shown}, HEURISTIC — line:definition; re-call read_file with that offset= to "
            f"jump. Verify before relying on it]\n{body}")


MIN_READ_BYTES = 0


OBS_WINDOW_CHARS = 12000

READ_MAX_LINES = 400

READ_MAX_FILE_BYTES = 16 * 1024 * 1024


def _read_source(ctx: ToolContext, path: str) -> tuple[bytes, Path, Path] | ToolResult:
    selected = _selected_read_path(ctx, path)
    display = Path(path) if Path(path).is_absolute() else _read_allowed_roots(ctx)[0] / path
    if selected is None:
        return ToolResult(False, error=f"refused: read outside allowed roots ({display})")
    root, relative, shown = selected
    try:
        with trusted_directory(root) as (_root, root_fd):
            return read_file(root_fd, relative, max_bytes=READ_MAX_FILE_BYTES), shown, root / relative
    except OSError as exc:
        if exc.errno == errno.EFBIG:
            return ToolResult(False, error=(f"file exceeds the {READ_MAX_FILE_BYTES}-byte read ceiling: "
                                            f"{shown}"))
        return ToolResult(False, error=f"not a regular single-link file: {shown}")


def _read_file(ctx: ToolContext, path: str, offset: int = 0, max_bytes: int = OBS_WINDOW_CHARS,
               max_lines: int = READ_MAX_LINES) -> ToolResult:
    source = _read_source(ctx, path)
    if isinstance(source, ToolResult):
        return source
    raw, p, selected = source
    lines = raw.decode("utf-8", errors="replace").splitlines()
    n = len(lines)
    start = max(0, int(offset))
    cap = max(1, int(max_lines))
    if start >= n:
        result = ToolResult(True, "" if n == 0 else f"[offset {start} past end of file ({n} lines)]",
                            source_read={"path": str(p), "start_line": 0, "end_line": 0,
                                         "total_lines": n, "partial_line": False})
    else:
        result = _read_window(lines, p, start, cap, max_bytes)
    result.source_read["path"] = str(selected)
    return result


def _read_window(lines: list[str], p: Path, start: int, cap: int, max_bytes: int) -> ToolResult:
    n = len(lines)
    max_bytes = max(int(max_bytes), MIN_READ_BYTES)
    full_budget = max(256, (int(max_bytes) * 85) // 100)
    window_chars = sum(len(ln) + 1 for ln in lines[start:start + cap])
    partial = (start + cap) < n or start > 0 or window_chars > full_budget
    index_txt = _file_index(lines, p.suffix) if partial else ""
    content_cap = max(256, full_budget - len(index_txt))
    out: list[str] = []
    used = 0
    i = start
    partial_line = False
    while i < n and (i - start) < cap:
        line = lines[i]
        if not out and len(line) > content_cap:
            out.append(line[:content_cap] + f"\n...[line {i} truncated to {content_cap} chars of {len(line)}]")
            partial_line = True
            i += 1
            break
        if out and used + len(line) + 1 > content_cap:
            break
        out.append(line)
        used += len(line) + 1
        i += 1
    chunk = "\n".join(out)
    if i < n:
        chunk += f"\n...[truncated: {n - i} more lines; re-call read_file with offset={i}]"
    return ToolResult(True, chunk + index_txt,
                      source_read={"path": str(p), "start_line": start + 1, "end_line": i,
                                   "total_lines": n, "partial_line": partial_line})


_GREP_MAX_FILES = 5000
_GREP_MAX_ENTRIES = _GREP_MAX_FILES
_GREP_MAX_DEPTH = 64
_GREP_MAX_FILE_BYTES = 262_144
_GREP_MAX_TOTAL_BYTES = READ_MAX_FILE_BYTES
_GREP_MAX_PATTERN_BYTES = OBS_WINDOW_CHARS
_GREP_MAX_RETAINED_MATCHES = _GREP_MAX_FILES
_GREP_WALL_SECONDS = 60.0
_LIST_MAX_ENTRIES = _GREP_MAX_ENTRIES

_VCS_DIRS: frozenset[str] = frozenset({".git", ".hg", ".svn"})


def _grep_notes(state, batch, result, match_limit: int) -> list[str]:
    notes: list[str] = []
    if result.capped:
        notes.append(f"...[stopped at max_matches={match_limit}; more matches may exist — "
                     f"narrow `path`; at most {_GREP_MAX_RETAINED_MATCHES} matches are retained]")
    if state.unscanned:
        notes.append(f"...[truncated: scanned {_GREP_MAX_FILES} of {state.files} files; "
                     f"{state.unscanned} not searched — an empty/short result is NOT proof of absence; "
                     "narrow `path`]")
    if state.truncated or state.depth_skipped:
        notes.append(f"...[truncated at {_GREP_MAX_ENTRIES} filesystem entries / "
                     f"depth {_GREP_MAX_DEPTH}; narrow `path`]")
    if state.vcs_skipped:
        notes.append(f"...[skipped {state.vcs_skipped} VCS metadata director(ies) "
                     f"({', '.join(sorted(_VCS_DIRS))}); pass an explicit path to search within one]")
    if state.links_skipped:
        notes.append(f"...[skipped {state.links_skipped} untrusted symlink file(s) resolving outside "
                     "the allowed roots or authored after the source snapshot]")
    if batch.partial_files:
        notes.append(f"...[searched only the first {_GREP_MAX_FILE_BYTES} bytes of "
                     f"{batch.partial_files} oversized file(s)]")
    if batch.byte_skipped:
        notes.append(f"...[truncated after {_GREP_MAX_TOTAL_BYTES} source bytes; "
                     f"{batch.byte_skipped} file(s) not searched; narrow `path`]")
    if batch.unreadable:
        notes.append(f"...[skipped {batch.unreadable} unreadable file(s)]")
    return notes


def _grep(ctx: ToolContext, pattern: str, path: str = ".", max_matches: int = 50) -> ToolResult:
    selected = _selected_read_path(ctx, path)
    display = Path(path) if Path(path).is_absolute() else _read_allowed_roots(ctx)[0] / path
    if selected is None:
        return ToolResult(False, error=f"refused: read outside allowed roots ({display})")
    root, relative, base = selected
    match_limit = min(max(1, int(max_matches)), _GREP_MAX_RETAINED_MATCHES)
    selector = (lambda candidate: _selected_read_path(ctx, candidate)
                ) if ctx.immutable_read_roots else None
    try:
        walked = grep_refs(
            root, relative, base, selector=selector, max_files=_GREP_MAX_FILES,
            max_entries=_GREP_MAX_ENTRIES, max_depth=_GREP_MAX_DEPTH, vcs_dirs=_VCS_DIRS,
        )
    except OSError:
        walked = None
    if walked is None:
        return ToolResult(False, error=f"not a regular file or directory: {base}")
    files, state = walked
    batch = capture_refs(files, max_file_bytes=_GREP_MAX_FILE_BYTES,
                         max_total_bytes=_GREP_MAX_TOTAL_BYTES)
    try:
        result = regex_hits(pattern, batch, max_matches=match_limit,
                            timeout=_GREP_WALL_SECONDS,
                            max_pattern_bytes=_GREP_MAX_PATTERN_BYTES)
    except TimeoutError:
        return ToolResult(False, error=f"grep exceeded its {_GREP_WALL_SECONDS:g}-second ceiling")
    except (OSError, ValueError) as exc:
        return ToolResult(False, error=str(exc))
    return ToolResult(True, _grep_notes(state, batch, result, match_limit) + result.hits)


def _immutable_directory_link(ctx: ToolContext, path: Path) -> bool:
    if not ctx.immutable_read_roots:
        return False
    return immutable_directory_link(lambda candidate: _selected_read_path(ctx, candidate), path)


def _list_dir(ctx: ToolContext, path: str = ".") -> ToolResult:
    selected = _selected_read_path(ctx, path)
    display = Path(path) if Path(path).is_absolute() else _read_allowed_roots(ctx)[0] / path
    if selected is None:
        return ToolResult(False, error=f"refused: read outside allowed roots ({display})")
    root, relative, shown = selected
    try:
        entries, truncated = directory_entries(root, relative, max_entries=_LIST_MAX_ENTRIES)
    except (OSError, ValueError):
        return ToolResult(False, error=f"not a descriptor-confined directory: {shown}")
    result = []
    for name, mode in entries:
        is_dir = stat.S_ISDIR(mode) or (
            stat.S_ISLNK(mode) and _immutable_directory_link(ctx, shown / name)
        )
        result.append(name + ("/" if is_dir else ""))
    result.sort()
    if truncated:
        result.insert(0, f"...[truncated at {_LIST_MAX_ENTRIES} entries; narrow `path`]")
    return ToolResult(True, result)
