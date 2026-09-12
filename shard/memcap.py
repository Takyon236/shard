
from __future__ import annotations

import os
import signal
import subprocess
import threading

from .processcapture import MAX_CAPTURED_BYTES, Capture

DEFAULT_CAP_MB = 4096

CAP_ENV = "SHARD_MEM_CAP_MB"

POLL_SECONDS = 0.1

try:
    _PAGE_BYTES = os.sysconf("SC_PAGE_SIZE")
except (AttributeError, ValueError, OSError):
    _PAGE_BYTES = 4096


class CappedProcess(subprocess.CompletedProcess):

    def __init__(self, args, returncode, stdout, stderr, *, limit_bytes: int, peak_bytes: int):
        super().__init__(args, returncode, stdout, stderr)
        self.limit_bytes = limit_bytes
        self.peak_bytes = peak_bytes


class CaptureRefusedProcess(subprocess.CompletedProcess):

    def __init__(self, args, returncode, stdout, stderr, *, reason: str):
        super().__init__(args, returncode, stdout, stderr)
        self.reason = reason


def refusal(proc) -> str | None:
    if isinstance(proc, CaptureRefusedProcess):
        return proc.reason
    if not isinstance(proc, CappedProcess):
        return None
    return (f"KILLED BY THE MEMORY CEILING: this command and its children reached "
            f"{proc.peak_bytes // (1024 * 1024)} MB resident, over the "
            f"{proc.limit_bytes // (1024 * 1024)} MB ceiling, and the whole process group was killed. "
            f"Your program is not broken and its output below is INCOMPLETE — it is unbounded. "
            f"Bound it: emit the sample with an explicit depth/length/repeat-count limit, or build it "
            f"incrementally to a file instead of holding it in memory.")


def cap_bytes() -> int:
    raw = os.environ.get(CAP_ENV, "").strip()
    if raw:
        try:
            megabytes = int(raw)
        except ValueError:
            megabytes = 0
        if megabytes > 0:
            return megabytes * 1024 * 1024
    return DEFAULT_CAP_MB * 1024 * 1024


def _rss_bytes(pid: int) -> int:
    try:
        with open(f"/proc/{pid}/statm", "rb") as handle:
            return int(handle.read().split()[1]) * _PAGE_BYTES
    except (OSError, IndexError, ValueError):
        return 0


def descendants(root: int) -> list[int]:
    seen: set[int] = set()
    found: list[int] = []
    stack = [root]
    while stack:
        pid = stack.pop()
        if pid in seen:
            continue
        seen.add(pid)
        found.append(pid)
        try:
            tids = os.listdir(f"/proc/{pid}/task")
        except OSError:
            continue
        for tid in tids:
            try:
                with open(f"/proc/{pid}/task/{tid}/children", "rb") as handle:
                    stack.extend(int(child) for child in handle.read().split())
            except (OSError, ValueError):
                continue
    return found


def _kill_tree(root: int) -> None:
    for victim in descendants(root):
        try:
            os.kill(victim, signal.SIGKILL)
        except OSError:
            continue
    try:
        os.killpg(root, signal.SIGKILL)
    except OSError:
        pass


class _Watch:

    def __init__(self, root: int, ceiling: int):
        self.root = root
        self.ceiling = ceiling
        self.peak_bytes = 0
        self._done = threading.Event()
        self._thread = threading.Thread(target=self._poll, daemon=True)

    def _poll(self) -> None:
        while not self._done.wait(POLL_SECONDS):
            total = sum(_rss_bytes(pid) for pid in descendants(self.root))
            self.peak_bytes = max(self.peak_bytes, total)
            if total > self.ceiling:
                _kill_tree(self.root)
                return

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._done.set()
        if self._thread.ident is not None:
            self._thread.join(timeout=2)


def _popen_kwargs(capture_output: bool, cwd, env, has_input: bool):
    kwargs = {
        "cwd": cwd,
        "env": env,
        "stdin": subprocess.PIPE if has_input else subprocess.DEVNULL,
        "stdout": subprocess.PIPE if capture_output else None,
        "stderr": subprocess.PIPE if capture_output else None,
        "start_new_session": True,
        "bufsize": 0,
    }
    return kwargs


def _cleanup(proc, capture):
    try:
        _kill_tree(proc.pid)
    except AttributeError:
        try:
            proc.kill()
        except OSError:
            pass
    finally:
        capture.finish(proc)


def run(argv, *, input=None, capture_output=False, text=False, errors=None,
        cwd=None, env=None, timeout=None, limit=None, output_limit=None):
    ceiling = cap_bytes() if limit is None else int(limit)
    capture = Capture(input, text=text, errors=errors,
                      limit=MAX_CAPTURED_BYTES if output_limit is None else output_limit)
    proc = subprocess.Popen(argv, **_popen_kwargs(capture_output, cwd, env, input is not None))
    watch = _Watch(proc.pid, ceiling)
    try:
        watch.start()
        capture.start(proc)
        capture.wait(proc, timeout)
    except subprocess.TimeoutExpired:
        _cleanup(proc, capture)
        stdout, stderr = capture.output(partial=True)
        raise subprocess.TimeoutExpired(argv, timeout, output=stdout, stderr=stderr) from None
    except BaseException:
        _cleanup(proc, capture)
        raise
    finally:
        watch.stop()
    if capture.reason():
        _cleanup(proc, capture)
    note = capture.reason()
    stdout, stderr = capture.output(partial=bool(note) or watch.peak_bytes > ceiling)
    if watch.peak_bytes > ceiling:
        return CappedProcess(argv, proc.returncode, stdout, stderr,
                             limit_bytes=ceiling, peak_bytes=watch.peak_bytes)
    if note:
        return CaptureRefusedProcess(argv, proc.returncode, stdout, stderr, reason=note)
    return subprocess.CompletedProcess(argv, proc.returncode, stdout, stderr)


__all__ = ["CAP_ENV", "DEFAULT_CAP_MB", "MAX_CAPTURED_BYTES", "POLL_SECONDS", "CappedProcess",
           "CaptureRefusedProcess", "cap_bytes", "descendants", "refusal", "run"]
