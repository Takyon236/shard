"""Adjudication — the step that decides whether a finding is real.

This is the mechanism the whole product rests on. The model proposes; this executes the repository's
own entry point against a candidate input and decides, from what actually happened, whether a defect
was demonstrated. A finding that survives this is `gate_eligible` and may fail your build. A finding
that does not is reported as an unproven hypothesis.

Two expectations are offered and they are deliberately few:

  * `fatal_signal` — the process died on a signal. A segfault or an abort is not an opinion.
  * `output_marker` — a string the repository itself declares as the sign of the defect.

**A run that "looks wrong" is not a demonstration.** The tests below are mostly about refusing, because
every way this can wrongly say yes is a false positive that fails somebody's build.

Deterministic: the entry point is a real script executed by a real subprocess, but there is no model,
no network, and no repository but the temporary one each test writes.
"""

from __future__ import annotations

import subprocess

import pytest

from shard.witness import EXPECTATIONS, WitnessSpec, adjudicate, entry_digest, offered_expectations

#: Where a repository declares its entry point. A path, not a convention: the whole point is that the
#: repository under review chooses what "reproduced" means for its own code.
ENTRY = ".shard/entry.sh"


def _repo(tmp_path, script: str, *, name: str = ENTRY):
    """A checkout carrying one executable entry point, which is all adjudication needs."""
    entry = tmp_path / name
    entry.parent.mkdir(parents=True, exist_ok=True)
    entry.write_text(script, encoding="utf-8")
    entry.chmod(0o755)
    return tmp_path, name


def _adjudicate(tmp_path, script, expectation, *, payload=b"", marker="", timeout=60):
    """Adjudicate against a checkout, taking the baseline digest the way a real run does.

    **The baseline is taken BEFORE the agent runs**, and passing it is not a formality — `None` means
    "this entry point did not exist when the run started", which is a refusal rather than a negative
    result. A helper that skipped it would make every test below pass by refusing, which is the
    vacuous-test trap in its purest form: green, and measuring nothing.
    """
    repo, entry = _repo(tmp_path, script)
    baseline = entry_digest(repo, entry)
    return adjudicate(WitnessSpec(entry=entry, expectation=expectation, payload=payload,
                                  marker=marker), repo, baseline_digest=baseline, timeout=timeout)


# --- the vocabulary is closed --------------------------------------------------------------------


def test_only_the_offered_expectations_exist():
    """A closed vocabulary, and it is the product's honesty boundary: Shard can only demonstrate the
    things it can actually observe. Adding a member here is a claim that a new class of defect can be
    proven by execution, which is a design decision rather than a configuration."""
    assert offered_expectations() == EXPECTATIONS
    assert set(EXPECTATIONS) == {"fatal_signal", "output_marker"}


# --- demonstrating ------------------------------------------------------------------------------


# A witness entry point is run as `bash -- <entry> <input>`, so `$1` is the candidate input. These
# scripts crash on ONE input and behave on everything else, which is what a real defect looks like —
# and, as the control tests below show, is what Shard requires before it will believe one.
CRASH_ON_BOOM = '#!/bin/sh\nif grep -q BOOM "$1" 2>/dev/null; then kill -SEGV $$; fi\necho fine\n'
MARKER_ON_BOOM = ('#!/bin/sh\nif grep -q BOOM "$1" 2>/dev/null; then\n'
                  '  echo "ERROR: AddressSanitizer: heap-buffer-overflow"\nelse\n'
                  '  echo "processed 1 file"\nfi\n')


@pytest.mark.skipif(subprocess.run(["which", "bash"], capture_output=True).returncode != 0,
                    reason="needs bash")
def test_a_process_killed_by_a_signal_IS_a_demonstration(tmp_path):
    """SIGSEGV, produced by one specific input. Nothing here is interpretation: the process died on a
    signal, and it did so on the agent's payload and not on the control."""
    w = _adjudicate(tmp_path, CRASH_ON_BOOM, "fatal_signal", payload=b"BOOM")
    assert w.demonstrated is True
    assert w.refusal == "", w.refusal
    assert w.exit_code == -11


def test_an_ORDINARY_FAILURE_is_not_a_fatal_signal(tmp_path):
    """**The most important refusal in the file.** A non-zero exit is the single most common thing a
    program does when it is unhappy, and treating it as a crash would make almost every repository
    look defective. A signal is a signal; `exit 1` is a program working as designed."""
    w = _adjudicate(tmp_path, '#!/bin/sh\necho "invalid input" >&2\nexit 1\n', "fatal_signal",
                    payload=b"BOOM")
    assert w.demonstrated is False


def test_a_CLEAN_EXIT_is_not_a_demonstration(tmp_path):
    w = _adjudicate(tmp_path, "#!/bin/sh\necho ok\nexit 0\n", "fatal_signal", payload=b"BOOM")
    assert w.demonstrated is False


def test_a_declared_marker_in_the_output_IS_a_demonstration(tmp_path):
    """`output_marker` is how a repository tells Shard what its own failure looks like — an assertion
    string, a sanitiser banner, a panic line."""
    w = _adjudicate(tmp_path, MARKER_ON_BOOM, "output_marker",
                    payload=b"BOOM", marker="heap-buffer-overflow")
    assert w.demonstrated is True


def test_ORDINARY_OUTPUT_does_not_satisfy_a_marker(tmp_path):
    """The non-vacuity arm, and it is the one that catches a marker so generic it always matches. A
    check that fires on every run carries no information and costs a false positive every time."""
    w = _adjudicate(tmp_path, MARKER_ON_BOOM, "output_marker",
                    payload=b"harmless", marker="heap-buffer-overflow")
    assert w.demonstrated is False


def test_an_EMPTY_marker_cannot_demonstrate_anything(tmp_path):
    """An empty string is a substring of every output. Accepting it would make every run a finding."""
    w = _adjudicate(tmp_path, MARKER_ON_BOOM, "output_marker", payload=b"BOOM", marker="")
    assert w.demonstrated is False


# --- the benign control, which is what makes any of the above mean anything -----------------------


def test_an_entry_point_THAT_CRASHES_ON_EVERYTHING_demonstrates_nothing(tmp_path):
    """**The single most valuable check in adjudication, and the one that is easiest to leave out.**

    A witness that crashes on the agent's payload has proven nothing until you know it does NOT crash
    on an ordinary one. A broken harness, a missing build artefact or a script with a syntax error all
    produce a crash on every input — and every one of them would otherwise be reported as a
    reproducing defect in the customer's code.

    So Shard runs a benign control before it believes anything, and a witness that fails the control
    is not a finding. This script crashes unconditionally, which is exactly that case.
    """
    w = _adjudicate(tmp_path, "#!/bin/sh\nkill -SEGV $$\n", "fatal_signal", payload=b"BOOM")
    assert w.demonstrated is False
    assert w.controls, "no control was run, so the verdict rests on one observation"


def test_the_control_is_reported_so_a_reader_can_see_it_happened(tmp_path):
    """A defence nobody can see is a defence nobody can check. The verdict names the controls it ran,
    which is what lets a reviewer tell "it passed the control" from "there was no control"."""
    w = _adjudicate(tmp_path, CRASH_ON_BOOM, "fatal_signal", payload=b"BOOM")
    assert w.controls and any("payload" in c for c in w.controls), w.controls


# --- what it refuses to run ----------------------------------------------------------------------


def test_a_MISSING_entry_point_is_refused_and_says_so(tmp_path):
    w = adjudicate(WitnessSpec(entry="does-not-exist.sh", expectation="fatal_signal"),
                   tmp_path, baseline_digest="whatever")
    assert w.demonstrated is False
    assert w.refusal, "a missing entry point produced no reason"


def test_an_UNKNOWN_expectation_is_refused_and_says_so(tmp_path):
    """Refused by name rather than defaulted. A typo in a configuration file must not silently become
    a different, weaker check."""
    repo, entry = _repo(tmp_path, "#!/bin/sh\nexit 0\n")
    w = adjudicate(WitnessSpec(entry=entry, expectation="probably_bad"), repo,
                   baseline_digest=entry_digest(repo, entry))
    assert w.demonstrated is False
    assert "unknown expectation" in w.refusal


def test_an_entry_point_that_HANGS_is_stopped_and_does_not_demonstrate(tmp_path):
    """A timeout is not a crash. Left unbounded it is also a CI job that runs until the runner's own
    ceiling, which costs money and reports nothing.

    `timed_out` is set and `refusal` is NOT, and the split is deliberate: a hang IS a result about the
    customer's entry point, so they are told it hung rather than that Shard declined to look."""
    w = _adjudicate(tmp_path, "#!/bin/sh\nsleep 30\n", "fatal_signal", timeout=1)
    assert w.demonstrated is False
    assert w.timed_out is True


# --- the agent may not grade itself --------------------------------------------------------------


def test_an_entry_point_the_AGENT_CREATED_cannot_adjudicate_anything(tmp_path):
    """**The agent must not author its own grader.**

    The baseline digest is taken before the agent starts. An entry point that did not exist then, but
    does now, was written during the run — and a model that can write the script that decides whether
    it succeeded can always succeed. Refused, not scored.
    """
    repo, entry = _repo(tmp_path, "#!/bin/sh\nkill -SEGV $$\n")
    w = adjudicate(WitnessSpec(entry=entry, expectation="fatal_signal"), repo, baseline_digest=None)
    assert w.demonstrated is False
    assert "did not exist when the run started" in w.refusal


def test_an_entry_point_CHANGED_DURING_THE_RUN_is_refused_rather_than_scored(tmp_path):
    """The same guard on the other side: the agent edited the thing that grades it.

    Refused rather than reported as a negative, because "the grader was tampered with" and "the entry
    point ran and nothing happened" are different facts, and reporting the first as the second would
    hide a tamper as a clean run.
    """
    repo, entry = _repo(tmp_path, "#!/bin/sh\nexit 0\n")
    baseline = entry_digest(repo, entry)
    (repo / entry).write_text("#!/bin/sh\nkill -SEGV $$\n", encoding="utf-8")   # the agent edits it
    w = adjudicate(WitnessSpec(entry=entry, expectation="fatal_signal"), repo,
                   baseline_digest=baseline)
    assert w.demonstrated is False
    assert "changed during the run" in w.refusal


def test_an_entry_point_OUTSIDE_the_checkout_is_refused(tmp_path):
    """Containment. `witness_entry` comes from the workflow, and a path that escapes the checkout
    would let a script outside the repository under review decide the build."""
    for escape in ("../outside.sh", "/etc/passwd"):
        w = adjudicate(WitnessSpec(entry=escape, expectation="fatal_signal"), tmp_path,
                       baseline_digest="whatever")
        assert w.demonstrated is False, escape
        assert w.refusal, escape


# --- the entry point is fingerprinted ------------------------------------------------------------


def test_the_adjudicated_entry_point_is_recorded_by_DIGEST(tmp_path):
    """A verdict is about a specific entry point, and the digest is what ties them together. Without
    it, a reproduction bundle says "this script crashed" about a script that may since have changed —
    which is exactly the claim a bundle exists to make checkable."""
    w = _adjudicate(tmp_path, "#!/bin/sh\nkill -SEGV $$\n", "fatal_signal")
    assert w.entry_digest, "the verdict does not record what it ran"
