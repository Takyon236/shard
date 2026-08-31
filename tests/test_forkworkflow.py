"""`preflight --fork-workflow` — the fork-PR workflow emitted, not transcribed.

Reviewing a fork's pull request needs a `workflow_run` workflow, because GitHub withholds secrets
from the `pull_request` event a fork triggers. The recipe has always lived in the README; what
this flag adds is that the file no longer has to be COPIED BY HAND — and the whole value of that
is three lines, because a copy-paste error in any of the three produces a green check that
reviewed nothing rather than an error:

    repository:/ref:   without them `workflow_run` reviews YOUR OWN CODE at the base branch
    fetch-depth: 0     one commit checks out nothing to diff against
    slug:              without it the alerts name YOUR repository for somebody else's code

Two invariants make the emission worth having. It must be REDIRECTABLE — stdout is the file, so
one stray report line upstream corrupts a workflow YAML somebody commits. And it must not DRIFT
from the README — the skeleton and the documentation describe the same workflow, and the
drift test below pins the load-bearing lines in both, which is the property a transcription
never had.

Deterministic: no model, no network; the only input is this repository's own README.
"""

from __future__ import annotations

import json
import pathlib

from shard.cli import main
from shard.target import fork_workflow_template

README = pathlib.Path(__file__).resolve().parent.parent / "README.md"

#: The lines a copy-paste error turns into a silent non-review. Each must be in the emitted file
#: AND in the README's fork section — the second half is what makes the skeleton unable to drift
#: from the documentation it replaces.
LOAD_BEARING = (
    "repository: ${{ github.event.workflow_run.head_repository.full_name }}",
    "ref: ${{ github.event.workflow_run.head_sha }}",
    "fetch-depth: 0",
    "persist-credentials: false",
    "base_ref: ${{ github.event.workflow_run.head_branch }}",
    "slug: ${{ github.event.workflow_run.head_repository.full_name }}",
    "OPENROUTER_API_KEY: ${{ secrets.OPENROUTER_API_KEY }}",
    "github_token: ${{ secrets.GITHUB_TOKEN }}",
    "security-events: write",
    "pull-requests: write",
)


def test_every_load_bearing_line_is_in_the_emitted_file():
    template = fork_workflow_template()
    for line in LOAD_BEARING:
        assert line in template, f"the emitted workflow lost the line that makes it work: {line}"


def test_the_skeleton_cannot_drift_from_the_readme():
    """The README is the recipe and the skeleton is the emission; the load-bearing lines must be
    in BOTH, or the two describe different workflows and one of them is wrong."""
    readme = README.read_text(encoding="utf-8")
    assert "## Reviewing a pull request from a fork" in readme, "the README section moved"
    for line in LOAD_BEARING:
        assert line in readme, f"README and emitted workflow disagree on: {line}"


def test_no_tabs_because_a_tab_is_not_yaml_indentation():
    """The classic transcription failure, caught in the emitter rather than in a workflow run at
    3am: YAML rejects a tab where a space is expected, and nothing in a copy-paste warns you."""
    assert "\t" not in fork_workflow_template()


def test_the_one_thing_the_skeleton_cannot_know_says_so():
    """The name of the fork-triggered build is the customer's fact, so the line carries a
    CHANGE-ME comment rather than a guessed default kept silently wrong."""
    template = fork_workflow_template()
    assert "workflows: [ci]" in template
    assert "CHANGE" in template.split("workflows: [ci]")[1].splitlines()[0]


def test_the_witness_warning_ships_in_the_file():
    """The README's stated-plainly caution — a witness entry point executes fork code under a
    token the pull_request job did not have — belongs in the file a customer will actually edit,
    not only in the documentation they read once."""
    template = fork_workflow_template()
    assert "witness_entry" in template
    assert "decision, not a default" in template


def test_the_flag_prints_the_file_and_nothing_else(tmp_path, capsys):
    """`--fork-workflow > .github/workflows/shard-fork.yml` must produce YAML and nothing else —
    the same redirectability contract `--entry-template` carries, and one stray print upstream
    turns a workflow file into a parse error in somebody's CI."""
    (tmp_path / "README.md").write_text("# demo\n", encoding="utf-8")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("x = 1\n", encoding="utf-8")
    rc = main(["preflight", "--repo", str(tmp_path), "--fork-workflow"])
    assert rc == 0
    out = capsys.readouterr().out
    assert out.startswith("# Shard:"), "the file does not open with its own header comment"
    assert out.rstrip().endswith("only after that decision is made."), "the file is truncated"
    # REDIRECTABILITY, asserted rather than assumed: nothing from the preflight report may leak
    # into stdout, because `your cost` in a YAML file is a workflow that never parses.
    for stray in ("repository   ", "can gate", "your cost", "free tier"):
        assert stray not in out, f"stdout is not just the file: found {stray!r}"
    json.dumps({"len": len(out)})  # the file is ordinary text; nothing exotic smuggled in
