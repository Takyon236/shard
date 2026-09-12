
from __future__ import annotations

import locale
import os
import subprocess
import sys
import threading
import time


MAX_CAPTURED_BYTES = 16 * 1024 * 1024
CLEANUP_SECONDS = 1.0
_CHUNK_BYTES = 64 * 1024
_POLL_SECONDS = 0.05


class _Buffer:
    def __init__(self, limit, stopped, failed):
        self.limit = limit
        self.stopped = stopped
        self.failed = failed
        self.data = bytearray()
        self.overflow = False
        self.lock = threading.Lock()

    def read(self, stream):
        try:
            while chunk := stream.read(_CHUNK_BYTES):
                with self.lock:
                    room = self.limit - len(self.data)
                    self.data.extend(chunk[:room])
                    if len(chunk) > room:
                        self.overflow = True
                        self.stopped.set()
        except Exception:
            self.failed.set()
            self.stopped.set()
        finally:
            _close(stream)

    def snapshot(self):
        with self.lock:
            return bytes(self.data)


def _close(stream):
    try:
        stream.close()
    except (OSError, ValueError):
        pass


class Capture:

    def __init__(self, input_data, *, text, errors, limit):
        if type(limit) is not int or limit <= 0:
            raise ValueError("output_limit must be a positive integer byte count")
        self.limit = limit
        self.text = bool(text or errors is not None)
        self.errors = errors if errors is not None else "strict"
        self.encoding = "utf-8" if sys.flags.utf8_mode else locale.getencoding()
        self.input = self._input_bytes(input_data)
        self.stopped = threading.Event()
        self.failed = threading.Event()
        self.buffers = {}
        self.workers = []

    def _input_bytes(self, data):
        if data is None:
            return None
        if self.text:
            if os.linesep != "\n":
                data = data.replace("\n", os.linesep)
            data = data.encode(self.encoding, self.errors)
        return memoryview(data)

    def _start(self, target, stream):
        worker = threading.Thread(target=target, args=(stream,), daemon=True)
        self.workers.append((worker, stream))
        worker.start()

    def start(self, proc):
        for name in ("stdout", "stderr"):
            stream = getattr(proc, name)
            if stream is not None:
                buffer = _Buffer(self.limit, self.stopped, self.failed)
                self.buffers[name] = buffer
                self._start(buffer.read, stream)
        if proc.stdin is not None:
            self._start(self._write, proc.stdin)

    def _write(self, stream):
        try:
            offset = 0
            while offset < len(self.input) and not self.stopped.is_set():
                written = stream.write(self.input[offset:offset + _CHUNK_BYTES])
                if not written:
                    raise OSError("stdin pipe made no progress")
                offset += written
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception:
            self.failed.set()
            self.stopped.set()
        finally:
            _close(stream)

    def pending(self):
        return any(worker.is_alive() for worker, _ in self.workers)

    def wait(self, proc, timeout):
        deadline = None if timeout is None else time.monotonic() + timeout
        exited_at = None
        while not self.stopped.is_set():
            now = time.monotonic()
            if deadline is not None and now >= deadline:
                raise subprocess.TimeoutExpired(proc.args, timeout)
            quantum = _POLL_SECONDS if deadline is None else min(_POLL_SECONDS, deadline - now)
            try:
                proc.wait(timeout=quantum)
            except subprocess.TimeoutExpired:
                continue
            if not self.pending():
                return
            exited_at = now if exited_at is None else exited_at
            if now - exited_at >= CLEANUP_SECONDS:
                self.failed.set()
                return
            self.stopped.wait(quantum)

    def finish(self, proc):
        deadline = time.monotonic() + CLEANUP_SECONDS
        try:
            proc.wait(timeout=CLEANUP_SECONDS)
        except (OSError, subprocess.TimeoutExpired):
            self.failed.set()
        owned = {stream for worker, stream in self.workers if worker.ident is not None}
        for stream in (proc.stdout, proc.stderr, proc.stdin):
            if stream is not None and stream not in owned:
                _close(stream)
        for worker, _ in self.workers:
            if worker.ident is not None:
                worker.join(timeout=max(0, deadline - time.monotonic()))
        if self.pending():
            self.failed.set()

    def reason(self):
        if any(buffer.overflow for buffer in self.buffers.values()):
            return (f"OUTPUT CEILING: captured output exceeded {self.limit} bytes on a stream. "
                    "This command's output is INCOMPLETE and cannot be used as a complete result.")
        if self.failed.is_set():
            return "OUTPUT CAPTURE FAILED: command output is INCOMPLETE; pipe I/O or cleanup failed."
        return None

    def output(self, *, partial=False):
        result = []
        for name in ("stdout", "stderr"):
            buffer = self.buffers.get(name)
            data = buffer.snapshot() if buffer is not None else None
            if data is not None and self.text:
                data = data.decode(self.encoding, "replace" if partial else self.errors)
                data = data.replace("\r\n", "\n").replace("\r", "\n")
            result.append(data)
        return tuple(result)
