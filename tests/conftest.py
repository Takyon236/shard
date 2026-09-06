"""One fact, shared by every test that has to EXECUTE something: can this runner contain it?

Adjudication runs the repository's own entry point — attacker-authored content on a pull request —
inside a private user/PID/mount/procfs/network boundary. There is deliberately no uncontained
fallback, so on a machine that cannot build the boundary `adjudicate` refuses and reports it, and
every verdict below becomes `demonstrated=False` with a refusal attached.

**That environment breaks the suite in BOTH directions, which is why one shared guard decides it.**
A test asserting a demonstration goes red for the machine rather than for the code; a test asserting
a REFUSAL goes green without observing anything, which is worse — a passing dot that measured
nothing. Both are dishonest, so a test that needs the boundary asks for the `contained` fixture and
skips, by name, with the kernel's own reason.

Measured 2026-09-06: on a GitHub-hosted ubuntu runner the unprivileged user namespace is refused
(`unshare: write failed /proc/self/uid_map: Operation not permitted`) and an ordinary runner process
holds none of the capabilities the privileged form needs, so five tests here failed on the release
that shipped. Inside the Action's own container, launched with the flags the Action uses, the same
probe succeeds and a real witness demonstrates — which is why skipping here is honest rather than a
capitulation: the environment the product ships into is proved separately, by the published CI,
running a real witness inside the image.

**A skip is a result.** The header and the summary below always state the verdict, so a run in which
everything skipped cannot be mistaken for a run in which everything passed.
"""

from __future__ import annotations

import pytest

from shard.witness import containment_unavailable

#: Probed once per session. `""` means the boundary can be built here.
_REASON: str | None = None


def _reason() -> str:
    global _REASON
    if _REASON is None:
        _REASON = containment_unavailable()
    return _REASON


@pytest.fixture
def contained():
    """Skip, naming the missing capability, when this runner cannot execute contained code.

    Requested by every test whose subject is what an entry point DID. Nothing is mocked: a scripted
    boundary would score the script, and the property under test is that real execution happened.
    """
    reason = _reason()
    if reason:
        pytest.skip(reason)
    return True


def pytest_report_header(config):
    """State the verdict before the first dot, whatever the verbosity."""
    reason = _reason()
    if reason:
        return [f"shard: execution tests will SKIP — {reason}"]
    return ["shard: contained execution is available; witness verdicts are measured for real"]


def pytest_terminal_summary(terminalreporter):
    """And state it again at the end, beside the count it explains."""
    reason = _reason()
    if not reason:
        return
    skipped = len(terminalreporter.stats.get("skipped", []))
    terminalreporter.write_line(
        f"shard: {skipped} test(s) skipped because this runner cannot contain execution. "
        f"They measured nothing; they did not pass. {reason}")
