"""Diagnostics — stdlib logging, opt-in, and strictly separate from the journal (ADAPT-G).

**The gap this closes.** Before this module the package had **zero** logger calls across ~19.5k LOC:
twelve `print()` calls and the journal. For an agent that runs unattended for hours against a target
that fights back, "no level, no module, no timestamp" costs a debugging session the first time a run
behaves oddly in a way the journal did not happen to capture.

**The journal is NOT a log, and they must not merge.** `journal.py` is an append-only event log whose
job is *resume* — content-keyed result caching, replayable, and load-bearing for correctness. Diagnostics
are throwaway prose for a human reading a stalled run. Putting diagnostics in the journal would grow the
file that resume must parse and invite a "helpful" cleanup to delete records a re-run depends on; putting
resume events in the log would make correctness depend on a handler nobody configured. Different
lifetimes, different consumers, different failure modes.

**Why configuration lives here rather than at the entry point.** The usual rule is that library code
configures nothing — and this module still installs no handler unless asked. But the live entry point is
the predecessor project's maintenance tooling, in a *different repo*, and the standing directive is that
nothing goes there. So an env-var-driven, idempotent, opt-in configure is the only way diagnostics can
ever be switched on for a real run without a change landing in another repo. With `SHARD_LOG` unset this
is a no-op and the package behaves exactly as before — verified by test.

Usage::

    SHARD_LOG=debug python -m pytest -q          # or on a real run, via the same env var

    from shard.diag import get_logger
    log = get_logger(__name__)
    log.debug("compaction stubbed %d observations (keep_recent=%d)", n, keep)

Always lazy `%s` formatting, never f-strings: a `log.debug` on a hot path must cost nothing when the
level is off, and these sit inside the per-step loop.
"""

from __future__ import annotations

import logging
import os

ENV_VAR = "SHARD_LOG"
_LEVELS = {"critical": logging.CRITICAL, "error": logging.ERROR, "warning": logging.WARNING,
           "warn": logging.WARNING, "info": logging.INFO, "debug": logging.DEBUG}

_ROOT = "shard"
_configured = False


def get_logger(name: str) -> logging.Logger:
    """A module logger. Named `shard.<module>`, so a consumer can filter by subsystem."""
    return logging.getLogger(name)


def resolve_level(value: str | None) -> int | None:
    """Parse a level name (or a bare integer) to a logging level; ``None`` when unset/unparseable.

    Unparseable is deliberately ``None`` rather than an exception or a default: a typo in an env var on
    a long unattended run must not be the thing that kills it, and must not silently turn logging on at
    a level nobody asked for."""
    if not value:
        return None
    v = value.strip().lower()
    if v in _LEVELS:
        return _LEVELS[v]
    return int(v) if v.isdigit() else None


def configure(level: str | None = None, *, stream=None) -> bool:
    """Install ONE stderr handler on the `shard` logger. Returns whether logging is now active.

    Idempotent: repeated calls (e.g. once per task in a sweep) do not stack handlers, which would
    duplicate every line N times. Reads ``SHARD_LOG`` when ``level`` is not given, and does nothing at
    all when neither is set — the default path installs no handler and emits nothing.

    ``propagate`` is turned off so these records do not also reach the root logger, where a host
    application's own handler would print them a second time."""
    global _configured
    lvl = resolve_level(level if level is not None else os.environ.get(ENV_VAR))
    if lvl is None:
        return False
    logger = logging.getLogger(_ROOT)
    if _configured:
        logger.setLevel(lvl)                     # honour a level change without re-adding a handler
        return True
    handler = logging.StreamHandler(stream)      # None => stderr, so stdout stays clean for artifacts
    handler.setFormatter(logging.Formatter(
        "%(asctime)s %(levelname)-7s %(name)s: %(message)s", datefmt="%H:%M:%S"))
    logger.addHandler(handler)
    logger.setLevel(lvl)
    logger.propagate = False
    _configured = True
    return True


def _reset_for_tests() -> None:
    """Drop the handler and the memo. Test-only: module state that survives between tests would make
    the "unset means silent" assertion depend on test ordering."""
    global _configured
    logger = logging.getLogger(_ROOT)
    for h in list(logger.handlers):
        logger.removeHandler(h)
    logger.setLevel(logging.NOTSET)
    logger.propagate = True
    _configured = False
