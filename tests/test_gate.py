"""The gate — the one part of Shard that can fail your build.

Everything else Shard does is a report somebody reads. This is the part that returns a non-zero exit
code and blocks a pull request, so it gets the most direct tests in the suite.

Three rules, and each is here because getting it wrong has a specific cost:

  1. **An unreproduced finding never gates.** Shard reports hypotheses as well as reproductions; only
     a finding it actually demonstrated may block a build. A gate that fired on a hypothesis would be
     an LLM's opinion stopping a release.
  2. **A run that could not run does not pass.** A review that never happened must not return a green
     check. This is the failure that looks most like success and is the most dangerous of the three.
  3. **`fail-on: new` needs BOTH conjuncts** — demonstrated, and introduced by this change.
"""

from __future__ import annotations

import pytest

from shard.gate import EXIT_CONFIG, EXIT_GATED, EXIT_OK, exit_code, is_new_finding
from shard.report import Finding


def _finding(*, gate_eligible: bool, line: int = 10, location: str = "app.py") -> Finding:
    return Finding(rule_id="shard/simple", title="t", message="m",
                   gate_eligible=gate_eligible, location=location, line=line)


# --- 1. a hypothesis can never fail a build ----------------------------------------------------


@pytest.mark.parametrize("fail_on", ["reproduced", "new"])
def test_an_unreproduced_finding_never_gates(fail_on):
    """The anti-slop guarantee, and the reason anyone would let this run on a protected branch.

    `solved` is set from a verdict that reproduced and from nothing else, so a hypothesis cannot reach
    this function in a state that gates. The test states the property anyway: it is the promise the
    product is sold on, and a promise with no test is a promise until somebody refactors.
    """
    assert exit_code(solved=False, fail_on=fail_on, new=True) == EXIT_OK


def test_a_reproduced_finding_gates_when_asked_to():
    assert exit_code(solved=True, fail_on="reproduced") == EXIT_GATED


def test_nothing_gates_when_the_gate_is_off():
    """`fail-on: none` is the default. Shard reports; it does not block until you ask it to."""
    assert exit_code(solved=True, fail_on="none", new=True) == EXIT_OK


# --- 2. a run that could not run does not pass a gate ------------------------------------------


@pytest.mark.parametrize("fail_on", ["reproduced", "new"])
def test_a_run_that_could_not_RUN_does_not_return_a_green_check(fail_on):
    """**The failure that looks exactly like success.**

    If your API key expires or your endpoint refuses every request, Shard finds nothing — and "found
    nothing" is indistinguishable from "reviewed everything and it was clean" unless the exit code
    says otherwise. In CI that is a green tick over a review that never happened.

    Reported as exit 2 (a configuration error) rather than exit 1 (a gated build), because 1 would be
    indistinguishable from a genuine reproduced finding and you would go looking for a defect that is
    not there.
    """
    assert exit_code(solved=False, fail_on=fail_on, status="error") == EXIT_CONFIG


@pytest.mark.parametrize("status", ["budget", "maxsteps"])
@pytest.mark.parametrize("fail_on", ["reproduced", "new"])
def test_a_run_stopped_by_a_CEILING_is_not_treated_as_a_broken_run(status, fail_on):
    """The deliberate other half, and it is a judgement rather than an oversight.

    `budget` and `maxsteps` are also unfinished runs, and they are NOT failed. Those runs reviewed
    something, and their counts are an honest floor that the report states plainly. Failing a build
    because a deliberately small ceiling was reached would make the cheap incremental scan unusable —
    which is the configuration most teams should be running most of the time.

    `error` is the case where nothing was concluded at all, and that is the line.
    """
    assert exit_code(solved=False, fail_on=fail_on, status=status) == EXIT_OK


def test_an_unfinished_run_still_does_not_gate_when_the_gate_is_off():
    """`fail-on: none` means report-only, and that has to hold even for a broken run — otherwise
    turning the gate off would still break builds, which is not what the setting says."""
    assert exit_code(solved=False, fail_on="none", status="error") == EXIT_OK


# --- 3. fail-on: new needs both halves ---------------------------------------------------------


def test_fail_on_new_needs_the_finding_to_be_BOTH_demonstrated_and_new():
    assert exit_code(solved=True, fail_on="new", new=True) == EXIT_GATED
    assert exit_code(solved=True, fail_on="new", new=False) == EXIT_OK
    assert exit_code(solved=False, fail_on="new", new=True) == EXIT_OK


def test_a_hypothesis_on_a_changed_line_is_still_not_new():
    """`is_new_finding` asks `gate_eligible` FIRST, and the order is the decision. A finding Shard
    could not demonstrate is not made real by sitting on a line you just wrote."""
    introduced = {"app.py": {10, 11, 12}}
    assert is_new_finding(_finding(gate_eligible=True, line=10), introduced) is True
    assert is_new_finding(_finding(gate_eligible=False, line=10), introduced) is False


def test_a_demonstrated_finding_on_an_UNCHANGED_line_is_not_new():
    """This is what stops a comment-only pull request failing on four defects it did not introduce."""
    assert is_new_finding(_finding(gate_eligible=True, line=99), {"app.py": {10, 11}}) is False


def test_a_finding_in_a_file_the_change_never_touched_is_not_new():
    assert is_new_finding(_finding(gate_eligible=True, location="other.py", line=10),
                          {"app.py": {10}}) is False
