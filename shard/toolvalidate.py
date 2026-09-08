
from __future__ import annotations

import difflib
import re

from .tools import _param_schema

_SCALARS = frozenset({"string", "integer", "number", "boolean"})


def _expected_type(spec: str) -> str:
    schema, _optional = _param_schema(str(spec))
    return schema["type"]


def _value_kind(value: object) -> str:
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return "null"


def _is_clear_mismatch(expected: str, value: object) -> bool:
    kind = _value_kind(value)
    if kind == "null" or kind == expected:
        return False
    if expected in _SCALARS and kind in ("object", "array"):
        return True
    if expected in ("integer", "number", "boolean") and kind == "string":
        return True
    return False


def _describe_value(value: object) -> str:
    kind = _value_kind(value)
    if kind == "string":
        shown = value if len(value) <= 40 else value[:37] + "..."
        return f"string {shown!r}"
    if kind in ("object", "array", "null"):
        return kind
    return f"{kind} {value!r}"


def validate_call_args(args_schema: dict, args: dict) -> str | None:
    args = args or {}

    missing = [name for name, spec in args_schema.items()
               if not str(spec).endswith("?") and name not in args]
    if missing:
        provided = sorted(args)
        labeled = ", ".join(f"{name!r} ({_expected_type(args_schema[name])})" for name in missing)
        if len(missing) == 1:
            return (f"missing required argument {labeled}; you provided keys {provided}. "
                    f"Add it and retry.")
        return (f"missing required arguments {labeled}; you provided keys {provided}. "
                f"Add them and retry.")

    for name, spec in args_schema.items():
        if name not in args:
            continue
        expected = _expected_type(spec)
        value = args[name]
        if _is_clear_mismatch(expected, value):
            return (f"argument {name!r} expects {expected}, got {_describe_value(value)}. "
                    f"Correct the type and retry.")
    return None


def _normalize(name: str) -> str:
    s = re.sub(r"[-\s]+", "_", name.strip().lower())
    s = re.sub(r"_+", "_", s)
    if s.endswith("_tool"):
        s = s[: -len("_tool")]
    return s


def suggest_tool(name: str, valid_names: list[str]) -> str | None:
    if not name or not valid_names:
        return None

    norm_to_orig: dict[str, str] = {}
    normalized_valids: list[str] = []
    for original in valid_names:
        nv = _normalize(original)
        normalized_valids.append(nv)
        norm_to_orig.setdefault(nv, original)

    target = _normalize(name)
    if target in norm_to_orig:
        return norm_to_orig[target]

    close = difflib.get_close_matches(target, normalized_valids, n=1, cutoff=0.6)
    return norm_to_orig[close[0]] if close else None
