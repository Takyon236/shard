"""Bind mutable Action output paths to the byte digests carried on CLI stdout.

A same-run process has the same uid as the producer and can retain a writable descriptor across an
atomic rename.  The output path is therefore not an authority for what Shard decided.  The CLI's
captured stdout is separate from that filesystem race; this module validates its digest map against
the bytes the Action captured through held descriptors before any delivery occurs.
"""

from __future__ import annotations

import hashlib
import hmac


def shape_error(artefacts: dict) -> str:
    """Validate the stdout authority's SHA-256 map before any filesystem work."""
    digests = artefacts.get("sha256")
    if not isinstance(digests, dict):
        return "artefacts.sha256 is not a role-to-digest object"
    for role, digest in digests.items():
        if not isinstance(role, str) or not role:
            return "artefacts.sha256 contains an invalid role"
        if (not isinstance(digest, str) or len(digest) != 64
                or digest != digest.lower()
                or any(character not in "0123456789abcdef" for character in digest)):
            return f"artefacts.sha256[{role!r}] is not a lowercase SHA-256 digest"
    return ""


def captured_error(artefacts: dict, captured: dict[str, bytes]) -> str:
    """Bind every descriptor-captured byte string to the separate stdout digest map."""
    expected = artefacts.get("sha256")
    invalid = shape_error(artefacts)
    if invalid:
        return invalid
    assert isinstance(expected, dict)
    missing = sorted(set(captured) - set(expected))
    extra = sorted(set(expected) - set(captured))
    if missing or extra:
        detail = []
        if missing:
            detail.append(f"missing {', '.join(missing)}")
        if extra:
            detail.append(f"unexpected {', '.join(extra)}")
        return f"artefacts.sha256 does not name exactly the captured files ({'; '.join(detail)})"
    for role, data in captured.items():
        actual = hashlib.sha256(data).hexdigest()
        if not hmac.compare_digest(actual, expected[role]):
            return f"artefacts.{role} bytes do not match the stdout SHA-256 digest"
    return ""


__all__ = ["captured_error", "shape_error"]
