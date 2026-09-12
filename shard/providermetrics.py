
from __future__ import annotations

import math

TOKEN_FIELDS = ("input_tokens", "output_tokens", "cached_tokens")


def integer(value) -> int | None:
    return value if type(value) is int and value >= 0 else None


def duration(value) -> float | None:
    if type(value) not in (int, float) or value < 0:
        return None
    try:
        return float(value) if math.isfinite(value) else None
    except OverflowError:
        return None


def validated(value) -> dict | None:
    if not isinstance(value, dict):
        return None
    requests, seconds = integer(value.get("requests")), duration(value.get("seconds"))
    if requests is None or seconds is None or (requests == 0 and seconds != 0):
        return None
    result = {"requests": requests, "seconds": seconds}
    for field in TOKEN_FIELDS:
        coverage = field + "_reported_requests"
        if field not in value and coverage not in value:
            continue
        amount, reported = integer(value.get(field)), integer(value.get(coverage))
        if amount is None or reported is None or not 0 < reported <= requests:
            return None
        result[field], result[coverage] = amount, reported
    return result


def attempt(usage, seconds: float, *, sent: bool = True) -> dict | None:
    result = {"requests": int(sent), "seconds": seconds if sent else 0.0}
    if usage is not None and sent:
        for field, present in zip(TOKEN_FIELDS, (usage.input_reported, usage.output_reported,
                                                usage.cached_reported)):
            if present:
                result[field] = getattr(usage, field)
                result[field + "_reported_requests"] = 1
    return validated(result)


def merge(records) -> dict | None:
    result = {"requests": 0, "seconds": 0.0}
    for record in records:
        row = validated(record)
        if row is None:
            return None
        for key, value in row.items():
            result[key] = result.get(key, 0) + value
        if duration(result["seconds"]) is None:
            return None
    return result
