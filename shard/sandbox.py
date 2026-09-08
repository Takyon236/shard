
from __future__ import annotations

import base64
import binascii
import hashlib
import pathlib
import subprocess
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass, field

from . import memcap
from .tools import OBS_WINDOW_CHARS, Tool, ToolContext, ToolResult, _file_index
from .witness import (CONTAINMENT_REFUSAL, DEFAULT_TIMEOUT, FATAL_SIGNAL_CODES,
                      TIMEOUT_KILL_CODES, _CONTAINMENT_ERROR, _contained_entry_env, _normalise,
                      bounded_run, entry_env, isolation_prefix, network_isolated, redact_secrets,
                      resolve_entry)
from .witnessfs import SnapshotError, SourceSnapshot

DEFAULT_EXEC_TIMEOUT = DEFAULT_TIMEOUT

MAX_EXEC_TIMEOUT = 120

EXEC_CALLS_PER_STEP = 0.6


def exec_budget(max_steps: int) -> int:
    return max(1, int(max_steps * EXEC_CALLS_PER_STEP))


MAX_EXEC_CALLS = 24

MAX_OUTPUT_CHARS = OBS_WINDOW_CHARS // 2


@dataclass
class ExecState:

    calls: int = 0
    entry_calls: int = 0
    shell_calls: int = 0
    max_calls: int = MAX_EXEC_CALLS
    network: str = "unknown"
    isolation: tuple[str, ...] | None = None
    scratch: str = ""
    secret_env_names: tuple[str, ...] = ()
    source_snapshot: SourceSnapshot | None = None
    log: list[str] = field(default_factory=list)
    refused: int = 0

    def spend(self) -> str:
        if self.calls >= self.max_calls:
            self.refused += 1
            return (f"execution budget exhausted ({self.max_calls} calls). Report what you have; "
                    f"reading is still available.")
        self.calls += 1
        return ""

    @property
    def exhausted(self) -> bool:
        return self.refused > 0

    @property
    def spent(self) -> bool:
        return self.calls >= self.max_calls

    def remaining(self) -> int:
        return max(0, self.max_calls - self.calls)



def network_mode(state: ExecState, runner=None) -> str:
    if state.isolation is None:
        state.isolation = isolation_prefix(runner or subprocess.run)
    state.network = "isolated" if network_isolated(state.isolation) else "unrestricted"
    return state.network


def _isolation(state: ExecState, runner) -> tuple[str, ...]:
    network_mode(state, runner)
    return state.isolation or ()


@contextmanager
def _source_view(state: ExecState, repo):
    owned = state.source_snapshot is None
    snapshot = state.source_snapshot or SourceSnapshot.capture(repo)
    try:
        snapshot.verify_source()
        yield snapshot.source
    finally:
        if owned:
            snapshot.close()


def _execution_scratch(state: ExecState, repo) -> pathlib.Path:
    scratch = pathlib.Path(state.scratch or tempfile.mkdtemp(prefix="shard-exec-"))
    live = pathlib.Path(repo).resolve(strict=True)
    resolved = scratch.resolve(strict=False)
    if resolved == live or resolved in live.parents or live in resolved.parents:
        raise SnapshotError("execution scratch overlaps the reviewed checkout")
    scratch.mkdir(parents=True, exist_ok=True)
    return scratch


def _source_entry(source: pathlib.Path, entry: str) -> pathlib.Path:
    resolved = resolve_entry(source, entry)
    if resolved is None or not resolved.is_file():
        raise SnapshotError("the declared entry point is absent from safe source")
    return resolved



def scope_digest(repo, paths) -> str:
    root = pathlib.Path(repo).resolve()
    h = hashlib.sha256()
    for rel in sorted(set(paths or ())):
        h.update(rel.encode("utf-8", "replace") + b"\0")
        try:
            p = (root / rel).resolve()
            p.relative_to(root)
            h.update(p.read_bytes() if p.is_file() else b"\0ABSENT\0")
        except (OSError, ValueError):
            h.update(b"\0UNREADABLE\0")
        h.update(b"\0")
    return h.hexdigest()



def payload_bytes(payload: str = "", payload_base64: str = "") -> bytes:
    if payload and payload_base64:
        return _raise("pass witness-style payload OR payload_base64, never both")
    if payload_base64:
        try:
            return base64.b64decode(payload_base64.strip(), validate=True)
        except (binascii.Error, ValueError) as e:
            return _raise(f"payload_base64 is not valid base64: {e}")
    return payload.encode("utf-8", "surrogateescape")


def _raise(msg: str):
    raise ValueError(msg)


def _capped(stdout: str, stderr: str) -> tuple[str, str]:
    out, err = stdout or "", stderr or ""
    if len(out) + len(err) <= MAX_OUTPUT_CHARS:
        return out, err
    err_cap = min(len(err), max(MAX_OUTPUT_CHARS // 2, MAX_OUTPUT_CHARS - len(out)))
    out_cap = max(0, MAX_OUTPUT_CHARS - err_cap)
    if len(out) > out_cap:
        out = out[:out_cap] + f"\n...[stdout truncated: {len(stdout) - out_cap} more chars]"
    if len(err) > err_cap:
        err = err[:err_cap] + f"\n...[stderr truncated: {len(stderr) - err_cap} more chars]"
    return out, err



def _observation(rc, stdout: str, stderr: str, note: str, state: ExecState) -> ToolResult:
    out, err = _capped(
        redact_secrets(stdout, secret_env_names=state.secret_env_names),
        redact_secrets(stderr, secret_env_names=state.secret_env_names),
    )
    return ToolResult(True, data={
        "note": note,
        "exit_code": rc,
        "stdout": out,
        "stderr": err,
        "executions_left": state.remaining(),
    })


def _run_entry_point(ctx: ToolContext, state: ExecState, *, repo, entry: str, runner,
                     payload: str = "", payload_base64: str = "") -> ToolResult:
    if refusal := state.spend():
        return ToolResult(False, error=refusal)
    resolved = resolve_entry(repo, entry)
    if resolved is None or not resolved.is_file():
        return ToolResult(False, error=f"the declared entry point {entry} no longer resolves in the checkout")
    try:
        data = payload_bytes(payload, payload_base64)
    except ValueError as e:
        return ToolResult(False, error=str(e))
    try:
        scratch = _execution_scratch(state, repo)
        input_path = scratch / "shard_probe_input"
        input_path.write_bytes(data)
    except (OSError, SnapshotError) as e:
        return ToolResult(False, error=f"could not stage the payload: {e}")

    prefix = _isolation(state, runner)
    if not network_isolated(prefix):
        return ToolResult(
            False,
            error=CONTAINMENT_REFUSAL + "this runner cannot create the private PID, mount, procfs "
            "and network boundary, so the customer-authored entry point was not executed",
        )
    state.entry_calls += 1
    try:
        with _source_view(state, repo) as source:
            safe_entry = _source_entry(source, entry)
            argv = [*prefix, "bash", "--", str(safe_entry), str(input_path)]
            with tempfile.TemporaryDirectory(prefix="shard-entry-root-") as jail_root:
                proc = runner(
                    argv, cwd=str(source), capture_output=True, text=True, errors="replace",
                    timeout=DEFAULT_EXEC_TIMEOUT,
                    env=_contained_entry_env(source, jail_root=jail_root,
                                             writable_paths=(input_path.parent,),
                                             execution_cwd=source,
                                             secret_env_names=state.secret_env_names),
                )
    except subprocess.TimeoutExpired:
        return _observation(None, "", "",
                            f"the entry point did not finish within {DEFAULT_EXEC_TIMEOUT}s. A hang is "
                            f"not a demonstration — the runner will refuse it after this run too.",
                            state)
    except (OSError, SnapshotError, subprocess.SubprocessError) as e:
        return ToolResult(False, error=f"could not execute the entry point: {type(e).__name__}: {e}")
    stderr = redact_secrets(proc.stderr or "", secret_env_names=state.secret_env_names)
    if proc.returncode == 125 and stderr.startswith(_CONTAINMENT_ERROR):
        return ToolResult(False, error=stderr.strip())

    rc = proc.returncode
    code = _normalise(rc) if isinstance(rc, int) else rc
    note = f"{entry} exited {rc}."
    if code in TIMEOUT_KILL_CODES:
        note += (" It was KILLED rather than finishing, so it produced no exit status and no complete "
                 "output for anything to observe. A payload that kills or hangs the program destroys "
                 "the evidence it was meant to produce.")
    elif code in FATAL_SIGNAL_CODES:
        note += " It died on a fatal signal."
    return _observation(rc, proc.stdout, proc.stderr, note, state)


def _run_shell(ctx: ToolContext, state: ExecState, *, repo, runner,
               command: str, timeout: int = DEFAULT_EXEC_TIMEOUT) -> ToolResult:
    if refusal := state.spend():
        return ToolResult(False, error=refusal)
    cmd = (command or "").strip()
    if not cmd:
        return ToolResult(False, error="command is empty")
    try:
        secs = max(1, min(int(timeout or DEFAULT_EXEC_TIMEOUT), MAX_EXEC_TIMEOUT))
    except (TypeError, ValueError):
        secs = DEFAULT_EXEC_TIMEOUT

    prefix = _isolation(state, runner)
    if not network_isolated(prefix):
        return ToolResult(
            False,
            error=CONTAINMENT_REFUSAL + "this runner cannot create the private PID, mount, procfs "
            "and network boundary, so the model-authored command was not executed",
        )
    state.shell_calls += 1
    state.log.append(cmd)
    argv = [*prefix, "bash", "-c", cmd]
    env = entry_env(secret_env_names=state.secret_env_names)
    try:
        scratch = _execution_scratch(state, repo)
    except (OSError, SnapshotError) as exc:
        return ToolResult(False, error=f"could not prepare execution scratch: {exc}")
    try:
        with _source_view(state, repo) as source:
            env["SHARD_SCRATCH"] = str(scratch)
            env["SHARD_REPO"] = str(source)
            with tempfile.TemporaryDirectory(prefix="shard-shell-root-") as jail_root:
                env = _contained_entry_env(
                    source, jail_root=jail_root, writable_paths=(scratch,), execution_cwd=source,
                    base=env, secret_env_names=state.secret_env_names,
                )
                proc = runner(argv, cwd=str(source), capture_output=True, text=True, errors="replace",
                              timeout=secs, env=env)
    except subprocess.TimeoutExpired:
        return _observation(None, "", "",
                            f"the command did not finish within {secs}s and was killed.", state)
    except (OSError, SnapshotError, subprocess.SubprocessError) as e:
        return ToolResult(False, error=f"could not run the command: {type(e).__name__}: {e}")
    stderr = redact_secrets(proc.stderr or "", secret_env_names=state.secret_env_names)
    if proc.returncode == 125 and stderr.startswith(_CONTAINMENT_ERROR):
        return ToolResult(False, error=stderr.strip())
    if capped := memcap.refusal(proc):
        return _observation(proc.returncode, proc.stdout or "", proc.stderr or "", capped, state)
    return _observation(proc.returncode, proc.stdout, proc.stderr,
                        f"exited {proc.returncode}.", state)


def _outline(ctx: ToolContext, path: str) -> ToolResult:
    from .tools import _is_within, _read_allowed_roots

    p = pathlib.Path(path)
    if not p.is_absolute():
        p = ctx.engine_root / path
    if not any(_is_within(p, r) for r in _read_allowed_roots(ctx)):
        return ToolResult(False, error=f"refused: read outside allowed roots ({p})")
    if not p.is_file():
        return ToolResult(False, error=f"not a file: {p}")
    lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
    index = _file_index(lines, p.suffix)
    if not index:
        return ToolResult(True, data=f"[no index for {p.suffix or 'this file type'}; {len(lines)} lines. "
                                     f"Use read_file or grep.]")
    return ToolResult(True, data=f"[{len(lines)} lines]{index}")



_RUN_ENTRY_PRIORITY = 2

_RUN_ENTRY_DESC = (
    "Execute the declared entry point on an input you supply and see EXACTLY what it does — its exit "
    "code, its stdout and its stderr. This is the same invocation the runner will make after this run "
    "ends, so what you see here is what it will see. Use it before reporting any witness: read the "
    "real output and take your marker from it rather than working one out. You are told what happened, "
    "never whether it would count."
)

_RUN_DESC = (
    "Run a shell command in the checkout. node, java, ruby, php, dotnet, gcc/g++, python and git are "
    "all installed. Use it to run the code you are reviewing, reproduce behaviour, or check an "
    "assumption. Write only under $SHARD_SCRATCH — modifying the checkout is detected and voids the "
    "run's ability to fail the build."
)


def build_exec_tools(state: ExecState, *, repo, witness_entry: str | None = None,
                     runner=None) -> list[Tool]:
    run = runner or bounded_run
    capped = runner or memcap.run
    tools: list[Tool] = []

    if witness_entry and resolve_entry(repo, witness_entry) is not None:
        tools.append(Tool(
            name="run_entry", kind="run_bash", description=_RUN_ENTRY_DESC,
            fn=lambda ctx, payload="", payload_base64="": _run_entry_point(
                ctx, state, repo=repo, entry=witness_entry, runner=run,
                payload=payload, payload_base64=payload_base64),
            args_schema={"payload": "str?", "payload_base64": "str?"},
            priority=_RUN_ENTRY_PRIORITY))

    tools.append(Tool(
        name="run", kind="run_bash", description=_RUN_DESC,
        fn=lambda ctx, command="", timeout=DEFAULT_EXEC_TIMEOUT: _run_shell(
            ctx, state, repo=repo, runner=capped, command=command, timeout=timeout),
        args_schema={"command": "str", "timeout": "int?"}))

    tools.append(Tool(
        name="outline", kind="read",
        description="List the functions and classes in a file with their line numbers, without "
                    "reading the file. Use it to find where to read before reading.",
        fn=_outline, args_schema={"path": "str"}))

    return tools


__all__ = [
    "DEFAULT_EXEC_TIMEOUT", "EXEC_CALLS_PER_STEP", "MAX_EXEC_CALLS", "MAX_EXEC_TIMEOUT",
    "MAX_OUTPUT_CHARS", "ExecState", "build_exec_tools", "exec_budget", "network_mode",
    "payload_bytes", "scope_digest",
]
