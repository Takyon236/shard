"""The command line, driven the way a workflow drives it.

Every test above this file asks whether a component is correct. This one asks whether the thing
actually installs and runs — the gap where the most embarrassing defects live, because a package can
be entirely correct and still fail at `import shard.cli`.

`survey` needs no model endpoint and no network, so it can be driven for real here. Everything that
would need inference is checked at the surface instead: that the flag exists, that a missing key is
refused with a sentence rather than a stack trace, and that the ceilings bind.
"""

from __future__ import annotations

import json
import subprocess
import sys

import pytest

from shard.budget import Budget, BudgetExceeded, BudgetGovernor
from shard.cli import main


def _repo(tmp_path):
    """A small, ordinary repository. Nothing here is a plant — the point is that a normal tree
    surveys cleanly rather than that a specific defect is found."""
    (tmp_path / "src").mkdir(parents=True)
    (tmp_path / "src" / "app.py").write_text(
        "import os\n\n\ndef handler(payload):\n    return os.path.basename(payload)\n",
        encoding="utf-8")
    (tmp_path / "README.md").write_text("# demo\n", encoding="utf-8")
    return tmp_path


# --- it installs and it runs ----------------------------------------------------------------------


def test_the_package_imports_from_a_clean_interpreter():
    """`python -c "import shard.cli"` in a SUBPROCESS, not in this one. The test session has already
    imported half the package, so an import that only works because something else imported first
    would pass in-process and fail for a user."""
    done = subprocess.run([sys.executable, "-c", "import shard.cli, shard.action; print('ok')"],
                          capture_output=True, text=True, timeout=120)
    assert done.returncode == 0, done.stderr[-2000:]
    assert done.stdout.strip() == "ok"


def test_the_console_entry_point_answers_for_help():
    """`shard --help` is the first thing anybody runs. It must not traceback."""
    done = subprocess.run([sys.executable, "-m", "shard", "--help"],
                          capture_output=True, text=True, timeout=120)
    assert done.returncode == 0, done.stderr[-2000:]
    assert "survey" in done.stdout and "diff" in done.stdout


def test_survey_runs_end_to_end_and_writes_its_artefacts(tmp_path, capsys):
    """The one mode that needs no inference, driven for real: a repository in, artefacts out."""
    repo = _repo(tmp_path / "repo")
    out = tmp_path / "out"
    rc = main(["survey", "--repo", str(repo), "--out-dir", str(out)])
    assert rc == 0, capsys.readouterr().out
    written = sorted(p.name for p in out.iterdir())
    assert written, "survey wrote nothing at all"
    assert any(n.endswith(".md") for n in written), written


def test_survey_reports_what_it_saw_as_machine_readable_json(tmp_path, capsys):
    """`--json` is what a workflow step parses, so stdout has to be JSON and nothing else — one stray
    `print` upstream turns a parseable payload into a decode error in somebody's pipeline.

    The payload states what was READ rather than only what was concluded. A survey that walked eight
    files and a survey that walked eight thousand produce the same shape, and the counts are how a
    reader tells them apart — `truncated` in particular, because a walk that stopped at its ceiling
    reports a floor and must say so.
    """
    repo = _repo(tmp_path / "repo")
    rc = main(["survey", "--repo", str(repo), "--out-dir", str(tmp_path / "out"), "--json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["repo"]
    assert "python" in payload["languages"], payload["languages"]
    assert payload["counts"], "the survey reported no counts, so its numbers cannot be checked"
    assert payload["truncated"] is False, "a five-file repository was reported as a truncated walk"
    assert payload["artefacts"] or payload["written"], "the payload names no artefact it wrote"


# --- it refuses clearly rather than failing obscurely -----------------------------------------------


def test_a_missing_api_key_is_a_SENTENCE_not_a_stack_trace(tmp_path, monkeypatch, capsys):
    """The single most common first-run failure. A user who has not set their secret yet must get a
    line telling them so, and an exit code that means "you configured something wrong" rather than
    "a defect was found"."""
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    repo = _repo(tmp_path / "repo")
    rc = main(["diff", "--repo", str(repo), "--out-dir", str(tmp_path / "out")])
    assert rc == 2, "a configuration error must not be reported as a finding"
    combined = capsys.readouterr()
    assert "API key" in (combined.out + combined.err)


def test_a_repository_that_does_not_exist_is_refused(tmp_path, capsys):
    rc = main(["survey", "--repo", str(tmp_path / "nowhere"), "--out-dir", str(tmp_path / "out")])
    assert rc == 2
    assert capsys.readouterr()


# --- the ceilings bind ------------------------------------------------------------------------------


def test_a_spend_ceiling_stops_a_run_that_crosses_it():
    """`max_spend_usd` is a ceiling on what a run may cost you. The governor commits a spend and then
    refuses, so the ledger always reports what was really spent — including on the call that crossed."""
    gov = BudgetGovernor(Budget(usd=1.00))
    gov.spend("usd", 0.60)
    assert gov.remaining("usd") == pytest.approx(0.40)
    with pytest.raises(BudgetExceeded):
        gov.spend("usd", 0.50)
    assert gov.spent("usd") == pytest.approx(1.10), "the ledger under-reported the crossing spend"


def test_an_unmetered_resource_never_stops_a_run():
    """0 means unmetered, and it has to mean it. A ceiling that fired on an absent limit would make
    the default configuration unusable."""
    gov = BudgetGovernor(Budget())
    gov.spend("usd", 10_000.0)
    gov.check()
    assert gov.remaining("usd") == float("inf")


def test_a_run_can_ask_how_much_headroom_is_left():
    """What the loop reads before it decides whether it can afford another model call."""
    gov = BudgetGovernor(Budget(usd=2.00))
    gov.spend("usd", 1.75)
    assert gov.can_afford("usd", 0.20) is True
    assert gov.can_afford("usd", 0.50) is False
