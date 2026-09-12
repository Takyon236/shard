
from __future__ import annotations

import json
import time
from collections import Counter
from pathlib import Path
from typing import Any, Iterator

from .artefactfs import append_file, read_file, trusted_directory

_MAX_JOURNAL_BYTES = 64 * 1024 * 1024


class Journal:

    def __init__(self, path: Path, *, now=time.time) -> None:
        self.path = Path(path)
        self._root = self.path.parent.resolve()
        self._name = self.path.name
        self._directory = trusted_directory(self._root, create=True)
        _path, self._parent_fd = self._directory.__enter__()
        try:
            self._now = now
            self._step = 0
            self._results: dict[str, Any] = {}
            self._counts: Counter = Counter()
            raw = self._bytes()
            if raw is not None:
                self._load(raw)
            self._loaded_keys: set[str] = set(self._results)
        except BaseException:
            self.close()
            raise

    def _load(self, raw: bytes) -> None:
        for ev in self._events(raw):
            self._step = max(self._step, int(ev.get("step", 0)))
            if ev.get("type") == "tool_result" and "key" in ev:
                self._results[ev["key"]] = ev.get("result")

    def record(self, type: str, **data: Any) -> dict:
        self._step += 1
        ev = {"step": self._step, "ts": self._now(), "type": type, **data}
        encoded = (json.dumps(ev, default=str) + "\n").encode("utf-8")
        append_file(self._parent_fd, self._name, encoded)
        self._counts[type] += 1
        return ev

    @property
    def counts(self) -> dict[str, int]:
        return dict(self._counts)

    def record_result(self, key: str, result: Any, **data: Any) -> None:
        self._results[key] = result
        self.record("tool_result", key=key, result=result, **data)

    def cached(self, key: str) -> tuple[bool, Any]:
        return (key in self._loaded_keys, self._results.get(key))

    def has(self, key: str) -> bool:
        return key in self._loaded_keys

    def resume_keys(self) -> set[str]:
        return set(self._loaded_keys)

    def _bytes(self) -> bytes | None:
        try:
            return read_file(self._parent_fd, self._name, max_bytes=_MAX_JOURNAL_BYTES)
        except FileNotFoundError:
            return None

    def close(self) -> None:
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
