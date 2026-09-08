
from __future__ import annotations

import logging
import os

ENV_VAR = "SHARD_LOG"
_LEVELS = {"critical": logging.CRITICAL, "error": logging.ERROR, "warning": logging.WARNING,
           "warn": logging.WARNING, "info": logging.INFO, "debug": logging.DEBUG}

_ROOT = "shard"
_configured = False


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)


def resolve_level(value: str | None) -> int | None:
    if not value:
        return None
    v = value.strip().lower()
    if v in _LEVELS:
        return _LEVELS[v]
    return int(v) if v.isdigit() else None


def configure(level: str | None = None, *, stream=None) -> bool:
    global _configured
    lvl = resolve_level(level if level is not None else os.environ.get(ENV_VAR))
    if lvl is None:
        return False
    logger = logging.getLogger(_ROOT)
    if _configured:
        logger.setLevel(lvl)
        return True
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.Formatter(
        "%(asctime)s %(levelname)-7s %(name)s: %(message)s", datefmt="%H:%M:%S"))
    logger.addHandler(handler)
    logger.setLevel(lvl)
    logger.propagate = False
    _configured = True
    return True


def _reset_for_tests() -> None:
    global _configured
    logger = logging.getLogger(_ROOT)
    for h in list(logger.handlers):
        logger.removeHandler(h)
    logger.setLevel(logging.NOTSET)
    logger.propagate = True
    _configured = False
