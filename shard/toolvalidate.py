"""Pre-dispatch tool-call validation — a precise correction beats a vague handler error.

Our solver uses NATIVE function-calling, so a failed tool call is almost never MALFORMED JSON
(the provider's tool-call channel emits clean, schema-shaped JSON). The real failure mode is a
call that is VALID JSON but WRONG: a required argument omitted, an argument of the wrong type, or
a near-miss tool NAME ("readFile" for "read_file"). Left alone, such a call reaches the tool
handler and comes back as a vague, tool-specific error ("bad args for read_file: missing 'path'",
"NoneType has no ..."). The model then GUESSES at the fix and often burns another whole turn.

Nous Research's **Hermes-Agent** handles the OTHER case — it repairs malformed JSON *syntax* — but
does NO schema / required-field / type validation at dispatch: a syntactically-valid call with the
wrong arguments sails straight through to the handler. We do better. BEFORE dispatch we check the
call against the tool's own ``args_schema`` and, on a violation, hand the model ONE precise,
actionable line ("missing required argument 'path' (string); you provided keys []. Add it and
retry.") so it self-corrects in a single turn instead of decoding a downstream stack trace. And on
an unknown tool name we suggest the single nearest real tool ("did you mean 'read_file'?") —
strictly better than Hermes's plain re-dump of the whole catalogue.

The bar is deliberately **conservative**: a FALSE rejection wastes a turn and confuses the model
worse than a vague handler error would, so we flag only UNAMBIGUOUS mismatches —

  - a missing REQUIRED field (a schema key whose spec does not end in "?"); the primary check,
  - a container (object/array) where a SCALAR is required,
  - a string where an integer / number / boolean is required,

— and stay lenient on the safe coercions the model routinely relies on (an int for a "float"/number
param; a number or bool for a string param; the risky bool/int crossing; a float for an int param).
Crucially we DO NOT flag a bare scalar given for an ``array`` param: every list-typed param in this
codebase is a string-list its tool coerces from a bare/comma value (``_ids_list``, ``_taglist``,
``_instrument``), so ``instrument(probes="…")`` is a valid single-value call — flagging it would
suppress the very construction-tool firing this feature is meant to help. When unsure, we say nothing
and let the call proceed. Extra/unknown args are never flagged — tools ignore them, rejecting is too strict.

The DSL and its atom→type mapping are NOT re-implemented here. We parse each ``args_schema`` spec
with ``tools._param_schema`` — the *same* function that built the tool definition the model was
shown by ``tool_to_openai`` — so validation agrees bit-for-bit with what was advertised. A private
copy could drift from the registry and then reject calls that matched the schema the model saw (or
wave through calls that did not); reusing the one parser makes the two views provably consistent.

Otherwise pure stdlib (``difflib`` for the name suggestion), no third-party imports, no LLM, no
network — deterministically unit-testable.
"""

from __future__ import annotations

import difflib
import re

from .tools import _param_schema

# The JSON-Schema types the DSL can name (via ``tools._JSON_TYPES``); "object" never appears as an
# EXPECTED type (there is no dict atom — unknown atoms fall back to "string"), only as an actual
# value kind. Scalars are the four non-container types.
_SCALARS = frozenset({"string", "integer", "number", "boolean"})


def _expected_type(spec: str) -> str:
    """The JSON-Schema type an ``args_schema`` spec advertises, e.g. "int?" → "integer". Delegated
    to ``tools._param_schema`` so it matches the definition the model was shown."""
    schema, _optional = _param_schema(str(spec))
    return schema["type"]


def _value_kind(value: object) -> str:
    """Coarse JSON-Schema kind of a real Python value from ``json.loads``. ``bool`` is checked before
    ``int`` because it is an ``int`` subclass; anything else (incl. ``None``) is "null"."""
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
    """True only for an UNAMBIGUOUS type violation — the conservative core of the validator.

    Flags: a container where a scalar is required; a string where a number/int/bool is required.
    Everything else is left to proceed (``False``), because a wrong rejection costs more than a
    lenient pass. In particular a **scalar given for an ``array`` param is NOT flagged**: every
    list-typed param in this codebase belongs to a tool that deliberately coerces a bare/comma string
    into a list (``_ids_list``, ``_taglist``, ``_instrument``'s ``[probes] if isinstance(probes,str)``),
    so ``instrument(probes="parse.c:…")`` is a VALID single-value call, not an error — flagging it
    would suppress exactly the construction-tool firing this feature exists to help. Also lenient: an
    int for a number param, a number or bool for a string param, a bool/int crossing, a float for an
    int param, and any ``null``."""
    kind = _value_kind(value)
    if kind == "null" or kind == expected:
        return False
    # A container given where any scalar is required — always clearly wrong (no tool coerces it).
    if expected in _SCALARS and kind in ("object", "array"):
        return True
    # A string given where a numeric/boolean scalar is required — will not coerce cleanly.
    if expected in ("integer", "number", "boolean") and kind == "string":
        return True
    # NOT flagged: a scalar for an ``array`` param (string-list coercion is a codebase-wide contract),
    # plus numeric-for-string, int-for-number, bool/int crossings, float-for-int.
    return False


def _describe_value(value: object) -> str:
    """Short, vocabulary-consistent description of the offending value for a correction message:
    scalars carry their repr ("string '5'", "integer 5"); containers are named by kind ("array")."""
    kind = _value_kind(value)
    if kind == "string":
        shown = value if len(value) <= 40 else value[:37] + "..."  # type: ignore[arg-type]
        return f"string {shown!r}"
    if kind in ("object", "array", "null"):
        return kind
    return f"{kind} {value!r}"  # integer 5 / number 5.0 / boolean True


def validate_call_args(args_schema: dict, args: dict) -> str | None:
    """Check a tool call's arguments against the tool's ``args_schema`` BEFORE dispatch.

    Returns ``None`` if the call is acceptable, else ONE short, precise corrective line the harness
    feeds back as the tool observation so the model self-corrects in a single turn.

    Two checks, in priority order (missing-required is the higher-value, less-ambiguous signal):
      1. **Missing required** — every schema key whose spec does not end in "?" must be present.
         Reports the offending field(s) with their expected type and the keys the model did provide.
      2. **Clear type mismatch** — for the first provided arg whose value unambiguously violates its
         declared type (see ``_is_clear_mismatch``), reports field, expected type, and what was given.

    Deliberately does NOT flag: extra/unknown args (tools ignore them), or any lenient-but-safe type
    (int for a number param, a numeric/bool for a string param, bool/int crossings, float for int)."""
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
    """Fold a tool name to a canonical form for fuzzy matching: lowercase, hyphens/whitespace → "_",
    collapse runs, and strip a trailing "_tool". So "readFile", "read-file", and "read_file_tool"
    all fold toward "read_file"'s canonical form."""
    s = re.sub(r"[-\s]+", "_", name.strip().lower())
    s = re.sub(r"_+", "_", s)
    if s.endswith("_tool"):
        s = s[: -len("_tool")]
    return s


def suggest_tool(name: str, valid_names: list[str]) -> str | None:
    """The single nearest real tool name for an unknown ``name``, or ``None`` if nothing is close.

    Powers a "did you mean 'X'?" hint on an unknown-tool rejection. Both the input and every valid
    name are normalized (case/hyphen/whitespace/"_tool" folded away) so surface typos like
    "readFile", "read-file", or "read_file_tool" resolve to "read_file"; the remaining gap is closed
    by ``difflib.get_close_matches`` (cutoff 0.6). The match is found on normalized forms but the
    ORIGINAL registry name is returned, so the hint names a tool the caller can actually invoke."""
    if not name or not valid_names:
        return None

    norm_to_orig: dict[str, str] = {}
    normalized_valids: list[str] = []
    for original in valid_names:
        nv = _normalize(original)
        normalized_valids.append(nv)
        norm_to_orig.setdefault(nv, original)  # first registration wins on a normalized collision

    target = _normalize(name)
    if target in norm_to_orig:  # an exact match after normalization — no fuzz needed
        return norm_to_orig[target]

    close = difflib.get_close_matches(target, normalized_valids, n=1, cutoff=0.6)
    return norm_to_orig[close[0]] if close else None
