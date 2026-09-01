"""`preflight --check-entry` — the entry point validated by EXECUTION, before a paid run.

`shard.witness.check_entry` runs the empty-input baseline and every benign control the customer
declared, through the adjudicator's own staging and execution plumbing, and reports each failure
mode as the refusal adjudication would deliver it LATER — after the inference has been paid for.
Every problem id below is a refusal sentence somewhere in `witness.py`, which is the property that
makes the check worth having: it cannot disagree with the thing it is predicting.

The split the tests pin: **`problems` are what a paid run would hit; `advisories` refuse nothing on
their own.** A non-silent baseline only refuses the markers contained in its output, and a missing
benign control is the documented 4-of-4 false-gate risk rather than a certainty — reporting either
as a failure would be a check that cried wolf, and a customer who has learned to ignore a check has
learned to ignore the real rows too.

Deterministic: no model, no network, no repository but the temporary one each test writes.
"""

from __future__ import annotations

import json

from shard.witness import MAX_BENIGN_CONTROLS, check_entry

#: Where a repository declares its entry point. A path, not a convention: the whole point is that
#: the repository under review chooses what "reproduced" means for its own code.
ENTRY = ".shard/entry.sh"

#: The shape the README's contract asks for: quiet on empty, quiet on ordinary input.
GOOD_QUIET = ('#!/bin/sh\n'
              'if [ ! -s "$1" ]; then exit 0; fi\n'
              'grep -q BOOM "$1" 2>/dev/null && echo ERROR_MARKER\n'
              'exit 0\n')


def _repo(tmp_path, script: str, *, benign=(), entry: str = ENTRY):
    """A checkout carrying one entry point and, optionally, a directory of benign controls."""
    path = tmp_path / entry
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(script, encoding="utf-8")
    if benign:
        controls = tmp_path / (entry + ".benign")
        controls.mkdir(parents=True, exist_ok=True)
        for i, content in enumerate(benign):
            (controls / f"control{i}").write_text(content, encoding="utf-8")
    return tmp_path, entry


def _ids(result: dict) -> list[str]:
    return [p["id"] for p in result["problems"]]


def _advisory_ids(result: dict) -> list[str]:
    return [a["id"] for a in result["advisories"]]


def test_the_shape_the_documentation_asks_for_passes(tmp_path):
    """Quiet baseline, one clean benign control: no problems, and the answer names what ran."""
    repo, entry = _repo(tmp_path, GOOD_QUIET, benign=["ordinary input\n"])
    result = check_entry(repo, entry)
    assert result["ran"] is True
    assert result["ok"] is True, result["problems"]
    assert result["problems"] == []
    assert result["baseline"]["exit"] == 0
    assert [c["exit"] for c in result["controls"]] == [0]
    assert json.dumps(result), "the payload must survive --json"


def test_the_baseline_branch_people_leave_out_is_a_problem(tmp_path):
    """Exit 1 on an empty payload — the single most common entry-point defect. The consequence is
    precise: it breaks `fail-on: new` attribution, not just the README's etiquette."""
    repo, entry = _repo(tmp_path, '#!/bin/sh\necho "usage: entry.sh <file>" >&2\nexit 1\n')
    result = check_entry(repo, entry)
    assert result["ok"] is False
    assert "baseline_nonzero" in _ids(result)
    assert "UNATTRIBUTED" in result["problems"][0]["consequence"]
    # THE NOISE IS AN ADVISORY, NOT A SECOND PROBLEM: ordinary baseline output refuses only the
    # markers contained in it, and stacking a failure on top would bury the load-bearing row.
    assert "baseline_not_silent" in _advisory_ids(result)


def test_a_baseline_that_dies_on_a_signal_is_a_problem(tmp_path):
    """An entry point that segfaults on EMPTY input refuses every fatal_signal claim later."""
    repo, entry = _repo(tmp_path, '#!/bin/sh\nkill -SEGV $$\n')
    result = check_entry(repo, entry)
    assert "baseline_fatal_signal" in _ids(result)
    assert result["ok"] is False


def test_a_missing_runtime_is_named_and_the_controls_are_not_run(tmp_path):
    """A runtime the image does not carry is a refusal on EVERY proposal — and controls would fail
    on the same missing interpreter, so they are marked skipped rather than reported as timeouts."""
    repo, entry = _repo(tmp_path, '#!/bin/sh\nexec shard-no-such-runtime-xyz "$1"\n',
                        benign=["ordinary\n"])
    result = check_entry(repo, entry)
    assert result["ok"] is False
    assert "missing_runtime" in _ids(result)
    assert result["controls"] and result["controls"][0]["skipped"] is True


def test_a_hung_baseline_is_a_problem(tmp_path):
    """A control run that cannot be completed is a refusal, so a hanging baseline is reported
    before a paid run discovers it one witness at a time."""
    repo, entry = _repo(tmp_path, '#!/bin/sh\nsleep 30\n')
    result = check_entry(repo, entry, timeout=1)
    assert "baseline_unfinished" in _ids(result)
    assert result["ok"] is False


def test_no_benign_controls_is_an_advisory_not_a_failure(tmp_path):
    """The 4-of-4 false-gate measurement makes the ABSENCE worth naming, but a repository with no
    controls gets exactly the verdicts it always got — ok stays True, or the check would be
    stricter than the adjudicator it predicts."""
    repo, entry = _repo(tmp_path, GOOD_QUIET)
    result = check_entry(repo, entry)
    assert result["ok"] is True, result["problems"]
    assert "no_benign_controls" in _advisory_ids(result)


def test_a_benign_control_the_program_rejects_is_a_problem(tmp_path):
    """A control that exits non-zero is not a control for the branch it was meant to exercise, and
    it is the `fail-on: new` liveness probe into the bargain."""
    repo, entry = _repo(tmp_path, '#!/bin/sh\n'
                                  'if [ ! -s "$1" ]; then exit 0; fi\n'
                                  'grep -q REJECT "$1" 2>/dev/null && exit 1\n'
                                  'exit 0\n',
                        benign=["REJECT me\n"])
    result = check_entry(repo, entry)
    assert result["ok"] is False
    assert "control_nonzero" in _ids(result)
    assert result["controls"][0]["exit"] == 1


def test_a_benign_control_that_hangs_is_a_problem(tmp_path):
    repo, entry = _repo(tmp_path, '#!/bin/sh\n'
                                  'if [ ! -s "$1" ]; then exit 0; fi\n'
                                  'grep -q SLOW "$1" 2>/dev/null && sleep 30\n'
                                  'exit 0\n',
                        benign=["SLOW\n"])
    result = check_entry(repo, entry, timeout=1)
    assert "control_unfinished" in _ids(result)


def test_controls_beyond_the_cap_are_named(tmp_path):
    """`MAX_BENIGN_CONTROLS` bounds adjudication, so the check reports the same bound — a customer
    whose ninth control matters needs to know it will never run, from either."""
    benign = [f"input {i}\n" for i in range(MAX_BENIGN_CONTROLS + 2)]
    repo, entry = _repo(tmp_path, GOOD_QUIET, benign=benign)
    result = check_entry(repo, entry)
    assert len(result["controls"]) == MAX_BENIGN_CONTROLS
    assert result["controls_dropped"] == 2
    assert "controls_capped" in _advisory_ids(result)
    assert result["ok"] is True, result["problems"]


def test_no_entry_point_to_check(tmp_path):
    """Nothing declared, nothing conventional: the check says so rather than inventing a target,
    and points at the same starting place the `can gate` line does."""
    result = check_entry(tmp_path, "")
    assert result["ran"] is False
    assert _ids(result) == ["no_entry"]


def test_an_entry_outside_the_checkout_is_refused(tmp_path):
    """`resolve_entry`'s containment check, reached from the new caller: a path escaping the
    checkout must not become a script this check executes."""
    outside = tmp_path / "outside.sh"
    outside.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    (tmp_path / "repo").mkdir()
    result = check_entry(tmp_path / "repo", "../outside.sh")
    assert result["ran"] is False
    assert _ids(result) == ["no_entry"]


def test_a_benign_control_that_cannot_be_staged_is_a_problem(tmp_path, monkeypatch):
    """A declared control that vanishes between listing and staging is the refusal
    `_controlled_verdict` makes, and the check predicts it rather than passing silently."""
    repo, entry = _repo(tmp_path, GOOD_QUIET, benign=["ordinary\n"])
    monkeypatch.setattr("shard.witness._stage_controls", lambda *a: (_ for _ in ()).throw(
        OSError("gone")))
    result = check_entry(repo, entry)
    assert result["ran"] is False
    assert _ids(result) == ["control_unreadable"]
