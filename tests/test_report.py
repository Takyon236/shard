"""The artefacts a run leaves behind — the Markdown report and the SARIF upload.

These are what a customer actually sees. Two channels, and the rule that governs both is the same:
**a run that did not finish must not read as a clean one.** Almost every way this product can mislead
somebody runs through a report that says "no findings" about a review that never happened.

SARIF is the machine-readable half, uploaded to GitHub's code scanning. Its `executionSuccessful`
field is the same claim as the Markdown's "did this finish" paragraph, and the two must never
disagree — a security team reading the Security tab and a reviewer reading the pull request are
looking at one run.
"""

from __future__ import annotations

import json

from shard.report import (COMPLETED_STATUSES, RunFacts, build_markdown, build_sarif, rank,
                          write_sarif)


def _finding(*, gate_eligible=True, title="t", location="app.py", line=1, rule="shard/simple"):
    from shard.report import Finding
    return Finding(rule_id=rule, title=title, message="m", gate_eligible=gate_eligible,
                   location=location, line=line)


# --- a run that did not finish never reads as a clean one -----------------------------------------


def test_a_finished_run_with_no_findings_says_what_it_DID(tmp_path):
    """*"Shard audited this and produced no reproducing input"* is checkable. *"There is no bug here"*
    is unfalsifiable, and this product does not make that claim."""
    md = build_markdown([], status="done")
    assert "no reproducing input" in md
    assert "not a proof" in md, "a clean run overclaimed"


def test_an_UNFINISHED_run_with_no_findings_says_it_did_not_finish():
    for status in ("error", "budget", "maxsteps"):
        md = build_markdown([], status=status)
        assert "did not complete a full audit" in md, status
        assert "incomplete run rather than a clean result" in md, status


def test_the_two_channels_agree_about_whether_the_run_finished():
    """One run, two readers. The Markdown says it in a sentence and the SARIF says it in a boolean,
    and a customer whose alerts land in the Security tab must not be told something different from
    the reviewer reading the pull request."""
    for status in sorted({"done", "audited", "error", "budget", "maxsteps"}):
        finished = status in COMPLETED_STATUSES
        sarif = build_sarif([_finding()], status=status)
        assert sarif["runs"][0]["invocations"][0]["executionSuccessful"] is finished, status
        assert ("did not complete a full audit" in build_markdown([], status=status)) is not finished


# --- the SARIF is valid enough to upload -----------------------------------------------------------


def test_the_sarif_carries_the_version_and_schema_github_requires():
    sarif = build_sarif([_finding()], status="done")
    assert sarif["version"] == "2.1.0"
    assert sarif["$schema"].endswith("sarif-2.1.0.json")
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "Shard"


def test_a_finding_becomes_exactly_one_result_with_a_location():
    sarif = build_sarif([_finding(location="src/app.py", line=42)], status="done")
    results = sarif["runs"][0]["results"]
    assert len(results) == 1
    loc = results[0]["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "src/app.py"
    assert loc["region"]["startLine"] == 42


def test_a_reproduced_finding_and_a_hypothesis_do_not_carry_the_same_severity():
    """The distinction the whole product rests on, carried into the channel a security team reads.
    A hypothesis arriving as an `error`-level alert beside a demonstrated defect would erase the
    difference in the one place it matters most."""
    reproduced = build_sarif([_finding(gate_eligible=True)], status="done")
    hypothesis = build_sarif([_finding(gate_eligible=False)], status="done")
    assert (reproduced["runs"][0]["results"][0]["level"]
            != hypothesis["runs"][0]["results"][0]["level"])


def test_every_result_carries_a_STABLE_fingerprint():
    """GitHub uses `partialFingerprints` to decide whether an alert on today's run is the same alert
    as yesterday's. Without one, every scan re-raises every finding as new — the customer's Security
    tab fills with duplicates and the tool becomes something they mute.

    Stable across runs, and different for different defects: both halves, because a fingerprint that
    never changes merges unrelated findings into one alert, which is the same failure inverted.
    """
    one = build_sarif([_finding(location="app.py", line=1)], status="done")
    again = build_sarif([_finding(location="app.py", line=1)], status="done")
    other = build_sarif([_finding(location="other.py", line=99, title="different")], status="done")

    def fp(sarif):
        return sarif["runs"][0]["results"][0]["partialFingerprints"]["shardCrashSignature"]

    assert fp(one), "no fingerprint, so every run re-raises every alert as new"
    assert fp(one) == fp(again), "the same finding fingerprinted differently on two runs"
    assert fp(one) != fp(other), "two different findings share one alert identity"


def test_every_result_declares_a_rule_that_the_tool_also_defines():
    """A `ruleId` with no matching entry in `tool.driver.rules` is a dangling reference, and GitHub
    renders the alert with no description at all."""
    sarif = build_sarif([_finding(rule="shard/simple")], status="done")
    declared = {r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
    for result in sarif["runs"][0]["results"]:
        assert result["ruleId"] in declared, result["ruleId"]


def test_the_written_sarif_is_valid_json_on_disk(tmp_path):
    out = tmp_path / "shard.sarif"
    write_sarif([_finding()], out, status="done")
    assert json.loads(out.read_text(encoding="utf-8"))["version"] == "2.1.0"


def test_no_finding_still_produces_an_uploadable_sarif(tmp_path):
    """A clean run must upload too. A missing file is an upload step that fails, and a red CI step on
    a clean review is how people learn to stop uploading at all."""
    out = tmp_path / "shard.sarif"
    write_sarif([], out, status="done")
    assert json.loads(out.read_text(encoding="utf-8"))["runs"][0]["results"] == []


# --- the run's own facts reach the reader ---------------------------------------------------------


def test_the_report_names_WHICH_ceiling_stopped_the_run():
    """`budget` is one word for three different ceilings, and the customer's next move differs by
    which — so the report names the resource and the flag that raises it."""
    for limit, flag in (("usd", "--max-spend-usd"), ("tokens", "--max-tokens"),
                        ("wall_seconds", "--max-minutes")):
        md = build_markdown([], status="budget", run=RunFacts(limit_hit=limit))
        assert flag in md, limit


def test_the_report_does_not_invent_a_flag_it_does_not_have():
    """When a mode offers no argument for the ceiling that bound it, the report says so rather than
    naming a plausible one — advice to pass a flag that does not parse is worse than silence."""
    md = build_markdown([], status="maxsteps", run=RunFacts(step_flag=""))
    assert "no argument that raises it" in md


def test_a_run_whose_verification_was_cut_short_says_so():
    """A finding that was reasoned about rather than checked is not the same as one that was checked,
    and a report that cannot tell the reader which is which is a report that overstates itself."""
    md = build_markdown([], status="done", run=RunFacts(exec_refused=3))
    assert "verification cut short" in md
    assert "unconfirmed" in md


def test_a_clean_run_does_not_grow_a_row_that_says_nothing():
    """The non-vacuity arm. `exec_refused=0` means it executed and was never refused, which is a real
    answer — and a row saying "0 refused" on every clean run is a row readers learn to skip."""
    assert "verification cut short" not in build_markdown([], status="done",
                                                          run=RunFacts(exec_refused=0))


# --- ordering ------------------------------------------------------------------------------------


def test_reproduced_findings_are_ranked_above_hypotheses():
    """A reviewer reads from the top. The thing Shard can prove goes first."""
    ordered = rank([_finding(gate_eligible=False, title="guess"),
                    _finding(gate_eligible=True, title="proven")])
    assert ordered[0].title == "proven"


# --- a location's provenance is stated, in every channel -------------------------------------------


def _located(gate_eligible=True, **kwargs):
    from shard.report import Finding
    return Finding(rule_id="shard/simple", title="t", message="m", gate_eligible=gate_eligible,
                   location="src/app.py", line=17, **kwargs)


def test_a_claimed_location_is_qualified_in_the_sarif_message():
    """The finding's own `path:line`, unmeasured and not harness-anchored, is what a reviewer's
    cursor lands on in the Security tab — and until this was pinned it shipped bare, identical to a
    line a traceback produced. The clause says what it is: a claim, not a measurement."""
    from shard.report import CLAIMED_CLAUSE, _sarif_message
    assert CLAIMED_CLAUSE in _sarif_message(_located())                          # claimed
    assert CLAIMED_CLAUSE not in _sarif_message(_located(location_measured=True))  # measured


def test_a_claimed_location_is_qualified_at_both_severities():
    """A hypothesis is the common claimed-location case, but a DEMONSTRATED finding whose output
    names no file lands there too — at `error` level, which is the worst place an unqualified
    guess can sit. Both severities carry the clause."""
    from shard.report import CLAIMED_CLAUSE, _sarif_message
    for eligible in (True, False):
        assert CLAIMED_CLAUSE in _sarif_message(_located(gate_eligible=eligible)), eligible


def test_the_harness_clause_and_the_claimed_clause_never_mix():
    """Two different anchors, two different clauses. A harness-anchored finding keeps the entry-point
    clause alone; a claimed location gets the claimed clause alone. Mixing them would say the alert
    is anchored on an entry point it is not anchored on."""
    from shard.report import (ANCHOR_CLAUSE, CLAIMED_CLAUSE, _sarif_message)
    harness = _sarif_message(_located(location_is_harness=True))
    assert ANCHOR_CLAUSE in harness and CLAIMED_CLAUSE not in harness
    claimed = _sarif_message(_located())
    assert CLAIMED_CLAUSE in claimed and ANCHOR_CLAUSE not in claimed


def test_the_markdown_location_row_states_the_same_provenance():
    """Both channels, one fact. The SARIF says it in a clause; the report says it on the Location
    row — positively for a measured line (the strongest location fact there is, previously stated
    only on disagreement), as a claim for a claimed one."""
    md = build_markdown([_located(location_measured=True)], status="done")
    assert "read from the demonstration's own output" in md
    md = build_markdown([_located()], status="done")
    assert "no execution resolved this line" in md


def test_the_result_document_names_a_claimed_location_as_a_limit():
    """The third channel. `shard-result.json` is what a dashboard slices, and a consumer needs the
    same caveat the alert message now carries — without it the document that looks most precise is
    the one overstating a guess."""
    from shard.resultdoc import limits
    codes = [row["code"] for row in limits([_located()], status="done")]
    assert "location_from_claim" in codes
    for clean in (_located(location_measured=True), _located(location_is_harness=True)):
        assert "location_from_claim" not in [
            row["code"] for row in limits([clean], status="done")]


def test_a_finding_with_no_location_claims_nothing():
    """The non-vacuity arm. An empty location makes no claim to qualify, and a run whose findings
    are all location-free must not grow a limit that says one of them guessed."""
    from shard.report import Finding
    from shard.resultdoc import limits
    bare = Finding(rule_id="shard/simple", title="t", message="m", gate_eligible=True,
                   location="", line=1)
    from shard.report import CLAIMED_CLAUSE, _sarif_message
    assert CLAIMED_CLAUSE not in _sarif_message(bare)
    assert "location_from_claim" not in [row["code"] for row in limits([bare], status="done")]
