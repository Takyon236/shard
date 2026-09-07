"""Run journal — append-only, resumable, observable.

Every step Shard takes (a thought, a tool call + result, a decision, a gate request) is an
append-only JSONL event. This gives (a) a live "what is Shard doing" stream, (b) durability,
and (c) **resume**: a re-run replays the journal, and any tool call whose ``key`` already has
a recorded result returns the cached result instead of re-spending budget — the same idea as
the Workflow-resume that let this session recover from a rate-limit mid-run.

Pure + dependency-free + unit-testable.
"""

from __future__ import annotations

import json
import time
from collections import Counter
from pathlib import Path
from typing import Any, Iterator

from .artefactfs import append_file, read_file, trusted_directory

# A default 40-step run records well below 1 MiB after the observation clamp; 64 MiB preserves
# hundreds of such turns while refusing a sparse or accumulated resume log before allocating it.
_MAX_JOURNAL_BYTES = 64 * 1024 * 1024


class Journal:
    """Append-only JSONL event log with content-keyed result caching for resume."""

    def __init__(self, path: Path, *, now=time.time) -> None:
        self.path = Path(path)
        # Capture the trusted parent before any model-controlled tool runs. Re-resolving ``self.path``
        # later would let a run_bash-created parent link redirect both resume reads and record appends.
        self._root = self.path.parent.resolve()
        self._name = self.path.name
        self._directory = trusted_directory(self._root, create=True)
        _path, self._parent_fd = self._directory.__enter__()
        self._now = now
        self._step = 0
        self._results: dict[str, Any] = {}
        # Per-type tally of what THIS process recorded. It exists so a run can report which mechanisms
        # actually executed without anyone re-parsing the JSONL afterwards — the sweep artifact used to
        # carry outcome only, which made a lever's firing unknowable from the results file and meant an
        # A/B could not be attributed to a mechanism that may never have run. Deliberately scoped to this
        # process (not seeded from a resumed file): the question it answers is "did this run fire it".
        self._counts: Counter = Counter()
        try:
            raw = self._bytes()
        except Exception:
            self.close()
            raise
        if raw is not None:
            self._load(raw)
        # Keys present BEFORE this process started — i.e. results from a prior (interrupted) run.
        # Only these are eligible for resume reuse; results recorded during THIS run must not be
        # served back as a "cache hit" (a same-run repeat call should re-execute, not go stale).
        self._loaded_keys: set[str] = set(self._results)

    def _load(self, raw: bytes) -> None:
        for ev in self._events(raw):
            self._step = max(self._step, int(ev.get("step", 0)))
            if ev.get("type") == "tool_result" and "key" in ev:
                self._results[ev["key"]] = ev.get("result")

    # --- write --------------------------------------------------------------
    def record(self, type: str, **data: Any) -> dict:
        self._step += 1
        ev = {"step": self._step, "ts": self._now(), "type": type, **data}
        encoded = (json.dumps(ev, default=str) + "\n").encode("utf-8")
        append_file(self._parent_fd, self._name, encoded)
        self._counts[type] += 1
        return ev

    @property
    def counts(self) -> dict[str, int]:
        """What this process recorded, by event type — the firing census for one run. A copy, so a
        caller folding it into a result dict cannot mutate the journal's tally."""
        return dict(self._counts)

    def record_result(self, key: str, result: Any, **data: Any) -> None:
        """Record a tool result under ``key`` so a later resume can return it without re-running."""
        self._results[key] = result
        self.record("tool_result", key=key, result=result, **data)

    # --- resume -------------------------------------------------------------
    def cached(self, key: str) -> tuple[bool, Any]:
        """(hit, result). Use to skip an already-completed tool call on resume."""
        return (key in self._loaded_keys, self._results.get(key))

    def has(self, key: str) -> bool:
        return key in self._loaded_keys

    def resume_keys(self) -> set[str]:
        """Keys whose results were loaded from a prior run (eligible for resume reuse)."""
        return set(self._loaded_keys)

    # --- read ---------------------------------------------------------------
    def _bytes(self) -> bytes | None:
        try:
            return read_file(self._parent_fd, self._name, max_bytes=_MAX_JOURNAL_BYTES)
        except FileNotFoundError:
            return None

    def close(self) -> None:
        """Release the parent descriptor retained across hostile tool executions."""
        directory = getattr(self, "_directory", None)
        if directory is not None:
            self._directory = None
            directory.__exit__(None, None, None)

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    def events(self) -> Iterator[dict]:
        data = self._bytes()
        if data is None:
            return
        yield from self._events(data)

    @staticmethod
    def _events(data: bytes) -> Iterator[dict]:
        # Resume must survive the exact failure it exists for: a crash mid-``record`` leaves the
        # LAST line half-written (O_APPEND writes one line at a time, so only the tail can tear).
        # Tolerate a malformed FINAL line by skipping it; a malformed NON-final line is genuine
        # mid-file corruption — re-raise rather than silently mask it.
        lines = [s for s in (line.strip() for line in data.decode("utf-8").splitlines()) if s]
        last = len(lines) - 1
        for i, line in enumerate(lines):
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                if i == last:
                    return
                raise

    def tail(self, n: int = 20) -> list[dict]:
        evs = list(self.events())
        return evs[-n:]

    @property
    def step(self) -> int:
        return self._step
