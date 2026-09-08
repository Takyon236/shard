
from __future__ import annotations

EXIT_OK, EXIT_GATED, EXIT_CONFIG = 0, 1, 2


class ConfigError(Exception):
    pass


FAIL_ON_CHOICES = ("none", "reproduced", "new")

DEEP_FAIL_ON_CHOICES = ("none", "reproduced")


def is_new_finding(finding, introduced) -> bool:
    from shard.diffscope import is_in_diff
    from shard.witness import INHERITED, INTRODUCED

    if not finding.gate_eligible:
        return False
    if finding.attribution in (INTRODUCED, INHERITED):
        return finding.attribution == INTRODUCED
    return is_in_diff(introduced, finding.location, finding.line)


def exit_code(solved: bool, fail_on: str, *, new: bool = False, status: str = "done") -> int:
    if fail_on in ("reproduced", "new") and status == "error":
        return EXIT_CONFIG
    if fail_on == "reproduced" and solved:
        return EXIT_GATED
    if fail_on == "new" and solved and new:
        return EXIT_GATED
    return EXIT_OK
