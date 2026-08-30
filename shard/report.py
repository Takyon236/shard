"""The customer deliverable — the report, the SARIF, and the reproduction bundle.

the integration guide is the output contract. Three artefacts, and the ranking rule that keeps
them inside GitHub's limits.


**Simple-safe, and by explicit owner decision rather than by convenience.** the design notes's
compile-selectively table puts *"SARIF writer, reproduction bundler, CI glue"* in the leave-in-Python
column, reason given: *"format work anyone can do"*. There is nothing here worth protecting, and both
modes emit through it, so it must be importable from the free image.

That is why `Finding` is a plain record and not a `Verdict`. This module never imports the oracle —
each mode adapts its own result into `Finding`, which is the one shape the writers understand.

## The rule that outranks every configuration

**A finding that carries no reproduction can never gate a build.** `Finding.gate_eligible` is the
single field that expresses it, `rank` sorts on it, and `write_sarif` refuses to emit `error` for
anything without it. The check-run status is decided in `cli.py` from `SolveResult.solved`, which has
exactly one source, so this module cannot weaken that promise either — it can only fail to describe it.

Hypotheses are still emitted, as `note`. A mode that reports nothing on most repositories is the
onboarding failure the integration guideb names, and silence is not the same as rigour.

## The source location, stated honestly

**Nothing in the pipeline can currently resolve a crash to a source file and line.** `Verdict` carries
`sanitizer` — the error-type line, `"ERROR: AddressSanitizer: heap-buffer-overflow on address 0x…"` —
and the frames are not on it. `oracle._top_frames` exists and is pure, but no field carries its output
out of the solve, and the journal records only the error-type line.

So `Finding.location` defaults to the HARNESS, which is a real file in the customer's repository and a
true statement: this harness reproduces a crash. It is not a claim about which line is at fault, and
nothing here manufactures one. Anchoring a customer's Security tab on a guessed line would be a false
positive in the most damaging possible place, and the whole product rests on findings being real.

the design notes records what would close it: carry `_top_frames`' output on `Verdict` and thread it
out of the solve. That is a change to the oracle and belongs in a commit that measures it.

## Ranking and capping

Code scanning rejects uploads exceeding its alert and thread-flow limits, so findings are ranked and
capped rather than dumped. **What is dropped is stated in the report**, never silently truncated —
the design notes records the cost of a silent cap: a truncated result that found
nothing reads as absence.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import os
import re
import urllib.parse
from dataclasses import dataclass, fields

# The shared prompt/report rendering boundary — see `diffscope.prompt_safe`. Used here for the ONE
# place a model-written string becomes markdown structure rather than markdown prose: the heading.
from shard.target import HARNESS_NAME
from shard.diffscope import prompt_safe
# MODULE SCOPE, and it has to be: `Finding.crash` is a property every writer here reads, so a lazy
# import would run inside the render path on the customer's runner. Free-tier and stdlib-only, which
# is what makes that safe — see `shard/crashstate.py` and `FREE_MODULES`.
from shard import crashstate

#: Conservative against code scanning's per-run alert limits. Exceeding them rejects the WHOLE upload,
#: so the cap is on our side where a drop can at least be reported.
DEFAULT_SARIF_CAP = 500

#: How much observed output the MARKDOWN carries. The report is read inline in a pull request, and a
#: full 4,000-character tail buries the finding it exists to support. The bundle keeps all of it.
_EVIDENCE_IN_REPORT = 1200

#: The run statuses that mean **the audit finished**. Everything else — `error`, `budget`, `maxsteps`,
#: `repeat` — means it stopped early, and a customer reading "no findings" is owed that difference.
#: the design notes
#:
#: One declaration, read by the markdown paragraph AND by the SARIF's `executionSuccessful`, because
#: two spellings of "did this run finish" is how the machine-readable channel and the human one come to
#: disagree. `done` was missing from the old inline test, so every finding-free DIFF run — the free
#: tier's most common outcome — told the customer its audit had not completed.
COMPLETED_STATUSES = frozenset({"done", "audited"})

#: **WHAT A CUSTOMER SHOULD DO ABOUT AN `error` RUN**, keyed by `shard.llm.classify_transport_error`.
#:
#: `status: error` is one word for every terminal transport failure. On 2026-08-22 a real run ended
#: exactly that way because the API key was revoked mid-run, and the artefact said nothing a customer
#: could act on — which is precisely what somebody with an expired key or a spent account sees. Four of
#: these six are configuration the customer fixes in a minute; two are not, and saying which is which
#: is the whole value of the row.
#:
#: **KEYED, NOT DERIVED.** The kinds come from `llm.py` because that module owns the strings it builds;
#: the wording lives here because this module owns what the customer reads. `tests/
#: test_transport_error_kinds.py` pins that every kind has advice and every advice has a kind, so the
#: two halves cannot drift into a run whose reason is classified and then rendered as nothing.
#:
#: The secret's NAME is not spelled here. Which environment variable holds the key is an installation's
#: choice (`api_key_env` on the action, `--api-key-env` on the CLI), and naming a plausible one would be
#: the wrong-ceiling defect from `RunFacts.step_flag` in a new place.
TRANSPORT_ERROR_ADVICE: dict[str, str] = {
    "auth": "your model endpoint **rejected the credential**. This is not a result about your code: "
            "the run stopped because it could no longer call the model. Check that the secret named by "
            "`api_key_env` is present, unexpired and authorised for the model you asked for",
    "credit": "your model endpoint **refused the call for billing reasons** — an exhausted balance or "
              "quota. The run stopped there, so its counts are a floor and say nothing about your code",
    "rate": "your model endpoint **rate-limited this run** for longer than its retry ladder allows. "
            "Re-running usually succeeds; a scheduled scan that hits this repeatedly is asking the "
            "endpoint for more concurrency than your account is provisioned for",
    "model": "your model endpoint **would not serve the requested model**. Check the `model` input "
             "against the identifiers your provider actually offers — a typo here stops the run "
             "before it reads a single file",
    "stall": "your model endpoint **stopped sending data mid-response** and did not recover within "
             "this run's retry ladder. That is an outage on the inference side, not a fault in your "
             "repository",
    "upstream": "your model endpoint **returned a server error** that outlasted this run's retries. "
                "That is an outage on the inference side, not a fault in your repository",
}

#: A fingerprint is used as a PATH SEGMENT and as a code-scanning identity, so it may contain only
#: characters that are safe in both. Anything else is hashed — see `Finding.fingerprint`.
_SAFE_TOKEN = re.compile(r"[A-Za-z0-9._-]{1,64}")

#: WHY AN ALERT NAMES THE ENTRY POINT. **One declaration, read by the markdown note AND by the SARIF
#: rule**, because two spellings of one disclaimer is precisely how these channels came to disagree: on
#: 2026-08-17 the markdown gained this explanation and the SARIF gained nothing, so the customer whose
#: alerts land in GitHub's Security tab — the delivery surface the integration guide is built around —
#: got two `error`-level alerts against their own test script with no statement that the script is not
#: the fault. `_sarif_message`'s docstring already says both channels must say the same thing.
ANCHOR_DISCLAIMER = (
    "An alert here names the entry point that REPRODUCES the defect, not the line at fault: Shard "
    "resolves a reproduction, not a source location, and a guessed line would be a false positive in "
    "the worst possible place. What the run observed is quoted with the finding and attached in full as "
    "a reproduction bundle.")

#: The same claim in one clause, for the per-result message. GitHub's alert LIST renders the message and
#: nothing else, and that list is where somebody decides which file is at fault.
ANCHOR_CLAUSE = "filed against the entry point that reproduces it, not the line at fault"

# --- THE REPORT NUMBER ------------------------------------------------------------------------------

#: Fixed width, so a column of report ids lines up and a reader can see one increase. Six digits reaches
#: 999,999 runs; past that the number is printed WIDER rather than truncated, because a counter that
#: wraps or clips is two runs sharing an id, which is the defect this whole idea exists to prevent.
REPORT_ID_DIGITS = 6

#: Reserved, and it means *this run was not produced by a numbered CI run* — a local invocation, a
#: `docker run` by hand, a test. GitHub's own run numbers start at 1, so `000000` can never collide with
#: one. Naming the unknown rather than inventing a plausible number is `_mode_verdict`'s rule, applied to
#: an identifier: a made-up increment is worse than an admitted absence, because it looks authoritative.
UNNUMBERED_REPORT_ID = "0" * REPORT_ID_DIGITS


def report_id(env) -> str:
    """A stable, monotonically increasing id for this run, from the CI environment.

    **`GITHUB_RUN_NUMBER` rather than a counter of our own**, and that is the whole design. A counter we
    maintained would need somewhere to live: a file on a runner that is destroyed, or a commit to the
    state repository, which is a write that can race and that only exists when a customer configured
    one. GitHub already increments a number per workflow, monotonically, and hands it over in the
    environment — so the number is authoritative, needs no storage, and cannot drift from the run it
    names.

    **A RE-RUN gets a suffix.** `GITHUB_RUN_ATTEMPT` is 2 on the second attempt of the SAME run number,
    so without it a re-run would publish a second report under an id that already meant something else.
    Two reports sharing an id is exactly the failure `report.Finding.rule_title` was fixed for in the
    same week — an identifier that does not identify.

    Pure, and takes the environment as an argument, because the core does not read `os.environ` and this
    has to be testable without one.
    """
    raw = str((env or {}).get("GITHUB_RUN_NUMBER") or "").strip()
    if not raw.isdigit():
        return UNNUMBERED_REPORT_ID
    number = int(raw)
    if number <= 0:
        return UNNUMBERED_REPORT_ID
    # `zfill` pads and NEVER truncates, so a run number past six digits widens the field instead of
    # colliding with a shorter one.
    ident = str(number).zfill(REPORT_ID_DIGITS)
    attempt = str((env or {}).get("GITHUB_RUN_ATTEMPT") or "").strip()
    if attempt.isdigit() and int(attempt) > 1:
        ident = f"{ident}.{int(attempt)}"
    return ident


def is_numbered(ident: str) -> bool:
    """Does this run have a REAL number? One predicate, because there are two ways to have none.

    `RunFacts.report_id` defaults to `""` and `report_id` returns the reserved `"000000"`, so a renderer
    testing truthiness prints `[Shard-report][000000]` on every local run — a fake identifier on the one
    line a reader trusts most. Measured the moment it was wired: the report-level test passed because it
    built a `RunFacts` with the empty default, and the end-to-end test failed because the command supplies
    the reserved value. Two spellings of "unknown" is the drift this module keeps being fixed for.
    """
    return bool(ident) and ident != UNNUMBERED_REPORT_ID


def report_label(ident: str, target: str = "", *, quoted: bool = True) -> str:
    """`[Shard-report][000042] owner/repo` — the one place this string is built.

    Read by the markdown heading, the survey heading and the action's own log heading, because three
    spellings of one identifier is how the channels come to disagree — the defect `ANCHOR_DISCLAIMER`
    below was created to end, about a different sentence.

    The tag is first and the number second so a list of reports sorts and scans on the number, which is
    the point of padding it.
    """
    head = f"[Shard-report][{ident or UNNUMBERED_REPORT_ID}]"
    if not target:
        return head
    # `quoted` because the same label goes to two renderers: markdown, where a repository name belongs in
    # backticks, and a plain-text log heading, where a backtick is literal noise. A caller stripping them
    # afterwards would be a second spelling of this string, which is what having one function prevents.
    return f"{head} `{target}`" if quoted else f"{head} {target}"


SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

TOOL_NAME = "Shard"

#: NO `informationUri`. It carried `https://github.com/shard-security/scan`, which does not exist —
#: `README.md` names `Takyon236/shard@v1` and the two never agreed, which is the tell. GitHub renders that
#: field as a link from the customer's Security tab, so shipping a placeholder puts a 404 next to every
#: alert we raise, in the one place a security team goes to decide whether to trust us. The key is
#: OPTIONAL in SARIF 2.1.0, so the honest answer is to omit it until there is a page to point at.
#: the maintainers' suite fails if a URL reappears here without one.


def _utf8_safe(text: str) -> str:
    """`text`, with anything UTF-8 cannot encode replaced. The string itself when there is nothing.

    **A lone surrogate is not exotic and it is not ours.** Two sources reach a finding: `json.loads`
    accepts `"\\ud83d"` in a model's tool call and hands back an unpaired surrogate, and `Path.iterdir`
    surrogate-escapes every byte of a filename that is not valid UTF-8 (PEP 383). Both are ordinary
    inputs to a scanner pointed at somebody else's repository.

    The value is a `str` either way, so nothing looks wrong until something tries to serialise it, and
    then it fails in two different ways depending on which writer gets there first:

      * `str.encode("utf-8")` raises `UnicodeEncodeError`. Every artefact write in `cli._emit` is
        `write_text(encoding="utf-8")`, and `Finding.fingerprint` hashes `seed.encode()` — which
        `rank` calls as a sort key, so the crash lands before a single byte is written;
      * `json.dumps` does NOT raise, because `ensure_ascii=True` writes `"pkg/caf\\udce9.py"` and calls
        it done. That is the worse half: the run reports success, and no strict JSON consumer can read
        the SARIF it produced.

    Scrubbed rather than refused. The finding is the product — losing it because a filename had a bad
    byte would be this repository's own suppression shape, a green check over work that was paid for.
    """
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return text.encode("utf-8", "replace").decode("utf-8")
    return text


@dataclass(frozen=True)
class Finding:
    """One thing to tell the customer. The shape both modes adapt into.

    `gate_eligible` is the only field that may affect a build's status, and it means exactly one thing:
    a reproduction exists and was verified by something the agent could not write to. the separate capability sets it
    from `Verdict.reproduced`; simple mode sets it from a re-executed witness.
    """

    rule_id: str
    title: str
    message: str
    gate_eligible: bool
    location: str                            # repo-relative path the alert anchors on
    line: int = 1
    #: The CLASS's name, when `title` names this INSTANCE. Falls back to `title`, so a producer that has
    #: only one name keeps working.
    #:
    #: SARIF has per-result fields and per-rule fields, and a rule describes every alert of its class.
    rule_title: str = ""
    #: **THE LOCATION IS THE ENTRY POINT THAT REPRODUCES THIS, NOT THE SITE OF THE DEFECT.** Declared by
    #: the producer, never inferred by the renderer.
    #:
    location_is_harness: bool = False
    #: The line was READ from the demonstration's own output, not taken from the agent's claim. Only a
    #: measured line may gate `fail-on:new`: an agent-claimed line on an introduced line would let the
    #: agent choose which findings gate by choosing where to point.
    location_measured: bool = False
    #: `witness.INTRODUCED` | `INHERITED` | `UNATTRIBUTED` — the CAUSAL answer to "did this change
    #: introduce it", obtained by re-running the reproducing input against the code as it was before
    #: (`witness.attribute`). It supersedes `location_measured` for `fail-on: new` wherever it is
    #: available, because a location is a statement about text and this is a statement about the
    #: program: a silent exploit has no location at all, and a defect introduced by a DELETION adds no
    #: line for one to sit on. `unattributed` is the honest default — no base revision, no entry point
    #: at base, or a base harness that could not run.
    attribution: str = "unattributed"
    attribution_reason: str = ""
    #: WHY NOTHING WAS ADJUDICATED for this finding, when a witness was proposed and never got a
    #: verdict — a killed entry point, a missing runtime, an entry point that changed mid-run. Empty
    #: when the witness ran and simply did not demonstrate, which is a different fact and the only one
    #: of the two that says anything about the customer's code.
    #:
    #: **It exists so the RUN can count them.** Until 2026-08-18 a refusal reached only the finding's
    #: prose, so a run in which every witness was killed rendered as a clean report with no findings
    #: and exited 0 — `cli._cmd_diff` had nothing to read. A per-finding sentence a human might notice
    #: is not the same as a run-level fact the gate announces.
    witness_refused: str = ""
    signature: str = ""                      # stable across runs — code scanning dedupes on it
    sanitizer: str | None = None
    replays: int = 0
    crash_count: int = 0
    doubts: tuple[str, ...] = ()
    poc_path: str | None = None              # the crashing input on disk, for the bundle
    reproduce_command: str = ""
    container_digest: str = ""
    #: WHAT WAS OBSERVED — the output the entry point or the harness actually produced. Simple mode's
    #: counterpart to `sanitizer`, and never both: one is a crash report, the other is a captured
    #: stream, and they are the same claim from two mechanisms. It was captured, capped at 4,000
    #: characters, and then discarded: no report, no bundle, no payload carried it, so a reviewer was
    #: told "nonzero_exit was observed" and shown nothing. the design notes, "Found by the first
    #: PAID container run".
    evidence: str = ""
    #: WITHIN-RUN PROPOSAL ORDINAL — simple mode's 1-based order the claim behind this finding was
    #: proposed in. `rank` reads it as a STABLE tiebreak (below `replays`, above `fingerprint`) so a
    #: correction the model made after an earlier claim renders AFTER it, rather than wherever the two
    #: fingerprints happen to sort — the ordering half of the finding-revision batch.
    #:
    #: **It is a renderer hint, never an identity.** `fingerprint` ignores it, so de-duplication across
    seq: int = 0

    def __post_init__(self) -> None:
        """Scrub un-encodable text ONCE, at the record, before any writer can be the one that fails.

        **A surrogate anywhere in this record cost the whole run, after every token was paid for.**
        `cli._emit` writes the SARIF, the report and the bundles, and `cli.main`'s broad `except` turns
        anything that escapes into `EXIT_CONFIG` — so a run that had FINISHED, adjudicated and produced
        a gate-eligible finding delivered a zero-byte report, no bundles, no alerts and exit 2. The one
        thing a customer could not get back was the thing they had already bought.

        **Here rather than in the writers, and that is the same argument `fingerprint` makes one field
        down.** `Finding` is a public record two modes construct and a third will; four writers read it
        (`build_sarif`, `build_markdown`, `write_bundle`, `write_sarif`) plus `fingerprint`'s hash and
        `urllib.parse.quote` in `_sarif_result`, and each has its own failure mode for the same byte.
        One rule in one place, or six independent chances to get it right.

        **`poc_path` is deliberately NOT scrubbed.** It is the only field here that is opened rather
        than written: `write_bundle` does `Path(finding.poc_path).read_bytes()`, and on Linux the
        surrogates in a path are how PEP 383 spells the bytes that reopen the file. Replacing them
        would break the read of a PoC we wrote ourselves. It reaches no artefact — the bundle carries
        the BYTES, and `metadata.json` records only `input_present`.

        Everything else is covered by shape rather than by a list of field names, so a field added
        later is covered on the day it is written. That is the drift this file has been fixed for
        repeatedly: two spellings of one rule, and only one of them maintained.

        No effect on the gate. `location` is compared against git's own paths in `cli._gates`, and
        `diffscope` decodes those with `errors="replace"` — so a diff path can never hold a surrogate,
        and a location that did could never have matched one.
        """
        for spec in fields(self):
            if spec.name == "poc_path":
                continue
            value = getattr(self, spec.name)
            if isinstance(value, str):
                clean: object = _utf8_safe(value)
            elif isinstance(value, tuple):
                clean = tuple(_utf8_safe(v) if isinstance(v, str) else v for v in value)
            else:
                continue
            if clean != value:
                # `object.__setattr__` because the record is frozen, which is the point: it is scrubbed
                # once, at construction, and is immutable to everything downstream.
                object.__setattr__(self, spec.name, clean)

    @property
    def level(self) -> str:
        """SARIF level. `error` is reserved for a finding that carries a reproduction.

        A hypothesis is `note`, never `warning`, because `warning` reads as "probably real" and this is
        the field a customer skims. The distinction the product sells is exactly this one.
        """
        return "error" if self.gate_eligible else "note"

    @property
    def crash(self) -> crashstate.CrashState:
        """This finding's sanitiser report, classified — or an abstaining `CrashState` when the
        observed output is not one.

        DERIVED, never stored, and that is the whole reason this needed no new producer field: every
        input it reads (`evidence`, `sanitizer`) is already on the record, set by whichever mode
        built it. A stored field would have to be populated by the separate package, by `simple.py` and
        by every future producer, and the one that forgot would emit a finding with no CWE and no
        way for a reader to tell that from a finding that has no class.

        Cheap enough to be a plain property: a handful of regexes over at most `evidence`'s cap,
        against a `DEFAULT_SARIF_CAP` of 500 findings.
        """
        return crashstate.classify(self.evidence, self.sanitizer)

    @property
    def fingerprint(self) -> str:
        """Stable identity for de-duplication across runs.

        Falls back to a hash of the rule and location when the oracle produced no signature, so that a
        finding without one does not collide with every other finding without one — which is what an
        empty string would do in code scanning's own matching.
        """
        if self.signature and _SAFE_TOKEN.fullmatch(self.signature):
            return self.signature
        # Anything else is HASHED rather than used. `cli._emit` builds `bundles/<fingerprint>/` from
        # this, so a signature of "../../escaped" would write the bundle outside the output directory —
        # verified, it lands at the resolved parent. Not reachable today (the oracle's `_behaviour_sig`
        # is a sha1 hexdigest and simple mode's `_anchor_signature` a sha256 one), so this is a latent
        # hazard rather than a live defect.
        #
        # Hardened HERE because `Finding` is a public record both modes construct and a third will, and
        # the safe property otherwise depends on every producer independently choosing a hex signature.
        # That is the shape the separate package exists to end: one rule, one place. Hashing rather than
        # refusing keeps a malformed signature from losing the finding entirely.
        seed = self.signature or f"{self.rule_id}\x00{self.location}\x00{self.title}"
        return hashlib.sha256(seed.encode()).hexdigest()[:16]


def rank(findings) -> list[Finding]:
    """Reproductions first, then by how much evidence each carries.

    Sorting is stable and total: `fingerprint` is the final key so two runs over the same findings emit
    them in the same order, and a diff between two SARIF uploads reflects real change rather than
    dictionary ordering.

    `seq` sits ABOVE the fingerprint fallback so proposal order breaks a tie before the hash does. On a
    tie the old key fell through to `fingerprint`, an ARBITRARY hex order, and a model's correction
    could render before the claim it corrected. `seq` defaults to 0, so a hand-built list and every deep
    finding (which sets no ordinal) sort exactly as before — the fingerprint still settles the 0-0 tie.
    """
    return sorted(findings,
                  key=lambda f: (not f.gate_eligible, -f.crash_count, -f.replays, f.seq, f.fingerprint))


def cap(findings, limit: int = DEFAULT_SARIF_CAP) -> tuple[list[Finding], int]:
    """Rank, then keep the first `limit`. Returns the kept findings AND how many were dropped.

    The count is returned rather than logged internally because the caller is what writes the report,
    and a drop the customer cannot see is indistinguishable from having found nothing more.
    """
    ordered = rank(findings)
    return ordered[:limit], max(0, len(ordered) - limit)


# --- SARIF -------------------------------------------------------------------------------------------

def build_sarif(findings, *, limit: int = DEFAULT_SARIF_CAP, status: str = "done") -> dict:
    """SARIF 2.1.0 for upload to code scanning.

    **`invocations[].executionSuccessful` is how a run that did not finish stops looking like a clean
    one.** the design notes: an errored run wrote `results: []` and reported `findings: 0`,
    byte-for-byte what a completed audit that found nothing reports. The markdown said so and nothing a
    CI consumer reads did — the check was green and code scanning showed nothing new.

    The exit code stays 0 and that is deliberate, not an oversight: the integration guide's first
    promise is that installing Shard does not break the build, and a transient endpoint failure must
    not fail somebody's pull request. Whether an internal error should EVER be allowed to gate remains
    the owner's call and is still recorded as open. This closes the half that needs no ruling — the run
    says what happened, in the channel built for saying it.
    """
    kept, _dropped = cap(findings, limit)
    rules, seen = [], set()
    for f in kept:
        if f.rule_id in seen:
            continue
        seen.add(f.rule_id)
        # `rule_title` FIRST. A per-instance title in a per-rule field mislabels every other alert of
        # the class — see `Finding.rule_title`.
        rule: dict = {
            "id": f.rule_id,
            "name": f.rule_id,
            "shortDescription": {"text": f.rule_title or f.title},
            "defaultConfiguration": {"level": f.level},
        }
        rule["properties"] = _rule_properties(f)
        if f.location_is_harness:
            # THE SAME SENTENCE THE MARKDOWN CARRIES, in the channel a security team actually reads.
            # `_sarif_message`'s own docstring is that both channels must say the same thing, and the
            # 2026-08-17 change that added the evidence to both left this disclaimer in the markdown
            # only — so the customer whose alerts arrive in the Security tab, which is the delivery
            # surface this product was built around, saw two `error`-level alerts filed against their
            # test script and nothing at all saying the script is not the bug. Rule-level because it is
            # true of every alert of this class, which is what a rule field means.
            #
            # THE INVARIANT THAT MAKES THAT TRUE, stated because the defect one field up was exactly a
            # per-instance value in a per-rule field: `location_is_harness` is set per MODE, not per
            # finding — deep sets it on all of them, simple on none — and a report is one mode. So the
            # first finding of a rule and every other finding of that rule agree. If a producer ever
            # mixes them under one `rule_id`, the authoritative statement is still per-alert: the same
            # claim rides in each result's own message as `ANCHOR_CLAUSE`.
            rule["fullDescription"] = {"text": ANCHOR_DISCLAIMER}
        rules.append(rule)
    finished = status in COMPLETED_STATUSES
    invocation: dict = {"executionSuccessful": finished}
    if not finished:
        # The reason travels WITH the flag. A false `executionSuccessful` and no explanation tells a
        # reviewer that something went wrong and nothing about what, which is half a defect report.
        invocation["toolExecutionNotifications"] = [{
            "level": "error",
            "message": {"text": f"Shard stopped before completing this audit (status: {status}). "
                                f"The absence of findings below is not a clean result."},
        }]
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {"driver": {"name": TOOL_NAME, "rules": rules}},
            "invocations": [invocation],
            "results": [_sarif_result(f) for f in kept],
        }],
    }


def _rule_properties(f: Finding) -> dict:
    """The rule's `properties` bag — the two fields GitHub code scanning RANKS and FILTERS on, plus
    the one that says how much to trust the alert.

    the design notes A4: a Shard rule arrived in the Security tab carrying only a
    level, so an estate could neither sort it by severity nor slice it by weakness. That document
    calls this the *"smallest fix with the largest reporting payoff"* on the CISO's list, and the
    reason is that the design notes closes the question of building a control plane — GitHub IS
    the control plane, so GitHub's taxonomy is this product's reporting surface, not a nice-to-have.

    **PER-RULE, so every field here must be true of every alert of the class.** That invariant is why
    `_rule_id` now carries the access: a `heap-buffer-overflow` READ is CWE-125 at medium and a WRITE
    is CWE-787 at high, and one rule cannot honestly state both. `rule_title` records what putting a
    per-instance value in a per-rule field already cost here once.

    **`precision` is where confidence lives, and it is separate from severity on purpose.**
    `security-severity` describes the WEAKNESS — how bad this class of defect is — and is adopted
    from ClusterFuzz's bands unchanged. How sure we are that this particular alert is real is a
    different axis, and SARIF has a field for it. A Shard `error` always carries a reproducing input
    that was replayed, so it is `very-high`; a hypothesis is `note` and makes no such claim.
    """
    state = f.crash
    props: dict = {
        "tags": list(state.tags),
        # CodeQL's convention, and the field GitHub falls back to when there is no security-severity.
        "problem.severity": "error" if f.gate_eligible else "recommendation",
        "precision": "very-high" if f.gate_eligible else "medium",
    }
    if state.security_severity:
        # A STRING, which is the schema's type and not a stylistic choice: GitHub parses this field
        # as text and a JSON number is silently ignored, which loses the ranking without an error.
        props["security-severity"] = state.security_severity
    return props


#: How much observed output rides in the SARIF message. Far below the markdown's allowance: this text
#: is rendered inside a code-scanning alert card, where a long tail pushes the sentence that matters
#: off the screen. One line is enough to tell two alerts apart, which is the entire job here.
_EVIDENCE_IN_SARIF = 300


def _sarif_message(f: Finding) -> str:
    """The alert text, with the FIRST line of what was observed appended when there is any.

    Both channels must say the same thing, and until 2026-08-17 they did not: the markdown grew an
    evidence block while `message` stayed the generic sentence, so two DISTINCT reproduced defects
    arrived in code scanning as two alerts with identical text, identical rule and identical location.
    Measured on a real repository — a path-traversal invariant and an unhandled decoder error, indistinguishable
    in the machine-readable channel. `report.py`'s own docstring calls that disagreement out as the
    thing to avoid, and this is the third time it has bitten.

    The first line only, and truncated: this is a stranger's program output. JSON encoding makes it
    inert as markup, so the risk here is length rather than injection.
    """
    first = (f.evidence or "").strip().splitlines()
    text = f.message if not first else f"{f.message} Observed: {first[0][:_EVIDENCE_IN_SARIF]}"
    if f.location_is_harness:
        # The one-clause form. `fullDescription` on the rule carries the full sentence, but GitHub's
        # alert LIST shows the message and nothing else, and that list is where somebody decides which
        # file is at fault. Short enough not to push the observed output out of view.
        text += f" ({ANCHOR_CLAUSE})"
    return text


def _sarif_result(f: Finding) -> dict:
    return {
        "ruleId": f.rule_id,
        "level": f.level,
        "message": {"text": _sarif_message(f)},
        # `partialFingerprints` is what makes an alert persist across runs instead of closing and
        # re-opening on every push. Cheap to emit and expensive to retrofit once history exists.
        #
        # **AND UNTIL 2026-08-28 IT DID THE OPPOSITE.** The value was `Finding.fingerprint`, which
        # for a deep finding is `oracle._behaviour_sig` — a hash of the whole normalised harness
        # output. Measured on one cJSON heap-buffer-overflow reported six ways that differ only as
        # two ordinary runs differ (build directory, pid, ASLR addresses, a source line moved by an
        # unrelated edit, the sanitiser's own interceptor frames): **4 identities for 1 defect.** So
        # the alert closed and re-opened on almost every push, losing its triage state and its
        # assignee — the exact failure this field exists to prevent, caused by the field.
        #
        # `crash.signature` is ClusterFuzz's crash state: the class plus the top three APPLICATION
        # frames, everything volatile discarded rather than normalised. Same six runs: 1 identity.
        #
        # ONE KEY, not two. A second key would raise a question about GitHub's matching that this
        # repository cannot answer by measurement, and the fallback answers it instead: an
        # unclassified finding keeps exactly today's value, so nothing regresses where nothing was
        # classified.
        #
        # `Finding.fingerprint` is deliberately NOT changed with it. That value names the bundle
        # DIRECTORY, where per-run uniqueness is the requirement — two findings that share a crash
        # state are one defect to code scanning and must still be two directories on disk, because
        # `_sweep_poc` records what a shared bundle path already cost: two findings, one PoC, and a
        # heap-buffer-overflow shipping a bundle that reproduces a stack-buffer-overflow.
        "partialFingerprints": {"shardCrashSignature": f.crash.signature or f.fingerprint},
        "locations": [{
            "physicalLocation": {
                # **PERCENT-ENCODED, because this field is a URI reference and a repository path is
                # not one.** SARIF 2.1.0 types `artifactLocation.uri` as `uri-reference`, and measured
                # against the published schema with jsonschema's FORMAT_CHECKER, four shapes of
                # ordinary file are REJECTED outright — `src/my file.py`, `src/100%done.py`,
                # `src\win\a.py` and `src/café/日本.py` — which rejects the WHOLE upload, so one file
                # with a space in its name loses every alert in the run.
                #
                # The fifth is worse because it passes. `src/a#b.py` validates and then re-parses as
                # the path `src/a` with the fragment `b.py`: an `error`-level alert anchored on a file
                # that does not exist, in the customer's Security tab. That is the manufactured
                # location this module's own header refuses to produce, arriving through the one field
                # whose entire job is to name a real file. None of the five is a hostile input.
                #
                # `safe="/"` keeps the separators as separators and encodes everything else, `%` and
                # `#` and `:` included, so the transform is lossless and GitHub decodes it back to the
                # path the customer has. `quote` encodes to UTF-8 and would raise on a lone surrogate;
                # it cannot meet one, because `Finding.__post_init__` scrubs the record first.
                "artifactLocation": {"uri": urllib.parse.quote(f.location, safe="/")},
                "region": {"startLine": max(1, f.line)},
            },
        }],
    }


def write_sarif(findings, path, *, limit: int = DEFAULT_SARIF_CAP, status: str = "done") -> int:
    """Write the SARIF file. Returns how many findings were dropped by the cap."""
    kept, dropped = cap(findings, limit)
    pathlib.Path(path).write_text(json.dumps(build_sarif(kept, limit=limit, status=status), indent=2),
                                  encoding="utf-8")
    return dropped


# --- the small report --------------------------------------------------------------------------------

@dataclass(frozen=True)
class RunFacts:
    """What the run DID, for the header — the facts a reader needs to know what the numbers are worth.

    **THE REPORT KNEW NONE OF THIS UNTIL 2026-08-13, and that was the weakness.** `build_markdown` was
    handed findings and a status, so a completed clean run and a run cut off at its step ceiling
    rendered as nearly the same three lines. Measured on real runs the same day: `31647698026` reported
    `findings 0` at `status maxsteps` — a truncated review whose zero means nothing — while
    `31675518894` reported `findings 0` at `done`, a genuine clean result. Telling them apart required
    reading the workflow log, and the artefact is the thing people keep.

    Every field defaults to unknown, and an unknown field omits its ROW rather than printing a zero:
    trap 7, a zero you cannot distinguish from an unknown is a lie with a number on it.
    """

    base_ref: str = ""
    files_reviewed: int | None = None
    witness_entry: str = ""
    fail_on: str = ""
    #: Which scan this was — `initial` or `followup` — and the ceiling it ran under. Empty means the
    #: mode has no such distinction, and omits the row like every other unknown here.
    #:
    #: It earns a row because it changes what `trust` MEANS. `status: budget` on a follow-up is an
    #: ordinary stop against a deliberately small ceiling; on an initial scan it means the baseline is
    #: unfinished and every count in the report is a floor. Same word, two different claims, and
    #: nothing in the header distinguished them.
    scan: str = ""
    scan_why: str = ""
    #: WHAT THE REPOSITORY IS — measured by the same walk that decided the harness, never guessed.
    #:
    #: The report was **invisible to the repository it reviewed**: verdict, trust, gate, witness and
    target_files: int | None = None
    target_bytes: int | None = None
    target_languages: tuple[str, ...] = ()
    #: `TargetProfile.truncated` — the walk hit `MAX_WALK_FILES` and **every count beside it is a
    #: floor.** Carried because the row above was born stating one as a fact, on 2026-08-17, in the same
    #: change that added it.
    #:
    #: `cli._cmd_preflight` has printed `(TRUNCATED — counts are a floor)` since preflight existed, so
    #: the two artefacts a customer reads disagreed about the same number from the same walk — and the
    #: one that disagreed is the one they keep. The case is not exotic: 200,000 source files is the cap,
    #: and a monorepo at a company large enough to buy this is where it binds first. Reporting
    #: `200,000 source file(s) · c, c++, java` for a tree that holds three million and seven languages
    #: is the floor-as-fact defect `_trust_row` exists to prevent, one row lower down the same table.
    target_truncated: bool = False
    #: WHICH ceiling stopped the run — `tokens`, `wall_seconds`, `usd` — when one did. The status says
    #: `budget` for all three, and the advice a customer needs differs by which: raise `--max-minutes`
    #: for the clock, `--max-tokens` for tokens. the maintainers' notes records the cost of telling a
    #: customer to raise the wrong ceiling — `--max-spend-usd` is inert on an unpriced route, and
    #: `cli.py` advised raising it anyway.
    limit_hit: str = ""
    #: The flag THIS MODE offers for raising its step ceiling, or `""` when it offers none. Supplied by
    #: the caller, because the caller owns the parser and the renderer cannot know what a mode accepts.
    #:
    #: `status: maxsteps` is the one ceiling that names itself and still named no flag. It is the row
    #: above's defect with the resource already known: the maintainers' notes records what advising the
    #: wrong ceiling costs, and this is the case where advising a plausible one would be WORSE than
    #:
    #: Measured, not hypothetical: run `32017001496` on a real runner ended `maxsteps` at 592,240 tokens,
    #: and the report said its counts were a floor without naming anything that would change that.
    step_flag: str = ""
    #: WHY the model calls failed, when `status` is `error` — a key of `TRANSPORT_ERROR_ADVICE`, or
    #: `""` when the failure was not one this product can classify.
    #:
    #: **THE SAME DEFECT AS `limit_hit`, one status along.** `budget` collapsed three ceilings into one
    #: word and the row above splits them, because the customer's next action differs by which. `error`
    #: collapses *every* transport failure into one word, and the difference matters more: a revoked
    #: key, a spent balance and a mistyped model name are all things the customer fixes in a minute,
    #: and a provider outage is not. Measured 2026-08-22 — a real run's key was revoked mid-run and the
    #: artefact reported a bare `status: error`, which is exactly what a customer with an expired
    #: credential sees.
    #:
    #: Supplied by the caller for the same reason `step_flag` is: `shard/llm.py` owns the error strings
    #: and `shard/cli.py` owns the run, and this module renders what it is handed.
    error_kind: str = ""
    #: How many executions the exec-budget ceiling DENIED, or `None` when the run could not execute at
    #: all. `0` means it executed and was never refused, which is a real answer and not an unknown.
    #:
    #: **A FOURTH CEILING THAT BOUND AND NEVER APPEARED IN THE ARTEFACT.** The row above covers three
    #: metered resources and `maxsteps`; the execution budget is a fifth thing that can stop a run and
    #: it reported nothing anywhere — `spend` told the model and no one else, and `status` stayed
    #: `done`. That is this class's founding defect exactly: a degraded run rendering as a clean one.
    #:
    #: It is the most expensive instance yet found, because it does not merely truncate a run, it
    #: CHANGES A FINDING. a measured run: on the first paying engagement the
    #: ceiling bound twice, and the second time the agent could not read the backend that would have
    #: cleared a candidate, so the candidate shipped to the customer as a defect. It was not one.
    exec_refused: int | None = None
    #: How many executions the agent MADE, or `None` when it could not execute at all. See
    #: `simple.SimpleRun.exec_calls` for the measurement that bought it: five real reviews of French
    #: public-administration repositories where every run executed, one of them REPRODUCING a defect in
    #: its own prose, under a header saying nothing could be proven by execution.
    #:
    #: The two facts are not in tension once both are printed, and that is the whole of the fix. The
    #: `witness` row is about ADJUDICATION — whether an observation was re-made after the loop, against
    #: controls, by something the agent cannot write to. This row is about INVESTIGATION. A reader given
    #: only the first concludes the review never ran anything.
    exec_calls: int | None = None
    #: `report_id(env)` — the run's own number, `000000` when it did not come from numbered CI. Carried
    #: rather than read here, because this module takes no environment: the caller owns `os.environ`.
    report_id: str = ""
    usd: float | None = None
    tokens: float | None = None
    #: Wall-clock, in seconds. `None` when the run does not know it — same rule as every field here.
    #: It rides in the cost row rather than getting its own, because "what did this run consume" is one
    #: question with three units; but for a CI GATE it is arguably the first of the three, since it is
    #: the one that blocks the pull request.
    seconds: float | None = None
    #: Levers the MACHINE could not run — the separate package's `unavailable_levers`. Empty tuple means
    #: "asked, none missing"; the field being empty is not the same as the run never asking, which is
    #: why the caller passes it explicitly rather than leaving it to a default.
    #:
    #: **This is this class's own founding argument, one field further out.** The docstring above
    #: records that a completed run and one cut off at its ceiling rendered as nearly the same three
    #: lines, and that telling them apart meant reading the workflow log while the artefact is the
    unavailable_levers: tuple[str, ...] = ()
    #: Whether the WORKDIR could ever have registered those levers — `True` on a benchmark target
    #: carrying a masked `:vul` image, `False` on an ordinary repository, `None` when not established.
    #:
    #: `unavailable_levers` alone is a statement about the MACHINE, and rendering it alone made the
    #: report say four levers were lost on runs that lost nothing. The two fields answer different
    #: questions and only their conjunction is a loss.
    levers_image_bound: bool | None = None
    #: Whether a STATE REPOSITORY is configured for this run. `False` means nothing accumulates
    #: between runs, so no finding here can be called new and no suppression the business has accepted
    #: can be applied; `None` means the mode never established it.
    #:
    #: Carried for the RESULT DOCUMENT rather than for this header, which is why it prints no row.
    #: the design notes A3 measured the gap it names — `--state-repo` exists on
    #: `diff` and is absent from `deep`, so every deep run starts from nothing — and the free tier has
    #: said so in its own step log since state existed (*"no state repository configured; nothing will
    #: accumulate between runs"*). A consumer of the artefacts could not read it anywhere, which is
    #: this class's founding defect: a fact the run knows, in a channel that is deleted with the runner.
    stateful: bool | None = None


#: Which statuses mean the run reached its own end. Anything else and the finding count is a floor.
def _human_bytes(n: int | None) -> str:
    """Bytes a person can read. `6.3 MB` rather than `6570572`, because the row exists to be skimmed."""
    if not n:
        return ""
    step = 1024.0
    size = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if size < step or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= step
    return f"{size:.1f} GB"


def _language_summary(langs: tuple[str, ...]) -> str:
    """The languages, and **how many were not named** when there are more than fit.

    `langs[:3]` was a silent truncation. A repository detected as c, c++, java, kotlin, swift, ruby and
    python rendered as `c, c++, java` — which does not read as an abbreviation, it reads as the answer,
    and this module's own header rule is that *what is dropped is stated in the report*. `_blind_spots`
    writes `(dir, dir, dir, …)` for the same reason; three languages with no `+4 more` is that ellipsis
    left off the one row a buyer skims first.
    """
    if not langs:
        return "no source detected"
    if len(langs) <= 4:
        return ", ".join(langs)
    return ", ".join(langs[:3]) + f", +{len(langs) - 3} more"


def _trust_row(status: str) -> str:
    if status in COMPLETED_STATUSES:
        return f"complete run (`{status}`)"
    return (f"**INCOMPLETE (`{status}`) — the counts below are a floor, not a result.** "
            f"A run cut short reports what it happened to reach")


def _duration(seconds: float) -> str:
    """Wall-clock a human reads at a glance: `47s`, `12m 03s`, `1h 24m`.

    Rendered rather than printed raw because the number's whole job is answering "can I put this on a
    pull request", and `2197.4 seconds` makes a reader do arithmetic before they can answer it.
    Sub-minute keeps its seconds; past an hour the seconds stop mattering and are dropped.
    """
    seconds = max(0.0, float(seconds))
    if seconds < 60:
        return f"{seconds:.0f}s"
    minutes, secs = divmod(int(round(seconds)), 60)
    if minutes < 60:
        return f"{minutes}m {secs:02d}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes:02d}m"


def _observed(run: RunFacts) -> tuple[str, str] | None:
    """The row answering *what did this run actually run*, or None when it could not run anything.

    **A SEAM RATHER THAN A BLOCK, for the reason `_stopped_by` is one.** `_summary_table` sat at 192
    against a 200-point readability threshold that the maintainers' suite defends, and it got there
    by having exactly this kind of one-question row lifted out of it. Inlining this one put it at 203 —
    over the line, and the ratchet's own note calls a boundary shave *"the single highest-return
    dishonest edit available anywhere in this file"*. So the answer is the honest version of the same
    move: one row, one question, one function.

    ## What the row is FOR

    **The artefact contradicted itself on one screen.** The header's `witness` row says *"none declared
    — nothing in this run could be proven by execution"*, which is a statement about ADJUDICATION: was
    an observation re-made after the loop, against controls, by something the agent cannot write to.
    Nothing said what the agent ITSELF ran while forming its claims.

    Measured across five reviews of French public-administration repositories, 2026-08-24/25
    (a measured run): all five executed — 30 shell calls on the first —
    and on the Etalab review the agent's own finding read *"I reproduced this by executing the exact
    helper …: it throws"*, two paragraphs below a header saying nothing could be proven by execution.
    Both sentences are true. Printing only one of them is what made the report wrong.

    ## Why zero is printed here and not one row up

    `exec_refused`'s zero is skipped, because "the ceiling refused nothing" is the ordinary case and a
    row for it is one a skimmer learns to skip. This zero is the opposite: it says the agent COULD run
    code and never did, so every claim in the report was reasoned from reading alone — which is the
    fact a reader weighing an unverified finding needs most, and the signal the maintainers' notes's standing
    process rule asks for by name. `None` remains not-armed, so the ablation arm in a maintenance script
    stays distinguishable from a review that declined to look.
    """
    if run.exec_calls is None:
        return None
    if run.exec_calls:
        return ("observed",
                f"the agent ran **{run.exec_calls}** command(s) in this checkout while forming these "
                f"claims. That is investigation, not adjudication — a finding is only gate-eligible "
                f"when the row above re-ran it afterwards, against controls")
    return ("observed", "the agent could run code here and **never did**, so every claim below was "
                        "reasoned from reading alone")


def _stopped_by(status: str, run: RunFacts) -> tuple[str, str] | None:
    """The one row answering *what stopped this run, and what would change it* — or None if nothing did.

    **ONE ROW, THREE SOURCES, AND AT MOST ONE OF THEM WINS.** A customer asks a single question, so the
    table must give a single answer; two rows disagreeing about why a run ended is precisely the defect
    `RunFacts.limit_hit` was added to close, one layer up.

    * a metered ceiling — `budget` names three different resources and the fix differs by which;
    * the step ceiling — `maxsteps` IS the resource, and named no flag at all until a real runner run
      ended at 592,240 tokens with nothing in the artefact naming what bound it;
    * a transport failure — `error` collapsed a revoked key, a spent balance, a mistyped model name and
      a provider outage into one word until 2026-08-22, and three of those four the reader fixes in a
      minute.

    The ceiling outranks the transport reason, and the `status == "error"` test is what keeps this
    function and `_no_finding_paragraph` — the two places that render the same advice — agreeing: a
    `budget` run carrying a stale `error_kind` must not be told its credential was refused.
    """
    stopped = run.limit_hit or ("steps" if status == "maxsteps" else "")
    if stopped:
        raise_flag = {"wall_seconds": "--max-minutes", "tokens": "--max-tokens",
                      "usd": "--max-spend-usd", "steps": run.step_flag}.get(stopped, "")
        advice = (f"raise `{raise_flag}` to let it run further" if raise_flag else
                  "and this mode has no argument that raises it, so nothing you could have passed would "
                  "have made this run go further")
        return ("stopped by", f"the **{stopped}** ceiling — {advice}. The other ceilings were not "
                              f"what bound this run")
    if status == "error" and run.error_kind:
        return ("stopped by", TRANSPORT_ERROR_ADVICE.get(
            run.error_kind, f"a transport failure this product does not classify (`{run.error_kind}`)"))
    return None


def _summary_table(findings, *, status: str, run: RunFacts | None,
                   gate_reasons=(), scope_reasons=()) -> list[str]:
    """The fixed header. Same rows, same order, every run — so "did it find anything, and can I trust
    the number" is answerable without reading prose or opening a log.

    VERDICT FIRST and TRUST SECOND, deliberately. The question a reader arrives with is the first one,
    and the second is the one that decides whether the first means anything.
    """
    reproduced = sum(1 for f in findings if f.gate_eligible)
    hypotheses = len(findings) - reproduced
    if reproduced:
        verdict = f"**{reproduced} finding(s) with a reproduction attached**"
        if hypotheses:
            verdict += f", {hypotheses} hypothesis(es)"
    elif hypotheses:
        verdict = f"**{hypotheses} hypothesis(es), none reproduced** — nothing here can fail a build"
    else:
        verdict = "**no findings**"

    rows = [("verdict", verdict), ("trust", _trust_row(status))]
    degraded = len(gate_reasons) + len(scope_reasons)
    if degraded:
        # NAMED in the header as well as quoted in full below. The reasons already reached the report
        # in 2026-08-12; what they did not reach was the part a skimmer reads.
        rows.append(("caveats", f"**{degraded} — see below.** The run answered less than it looks"))

    run = run or RunFacts()
    if run.target_files is not None:
        # `≥` and a named caveat rather than a bare number. See `RunFacts.target_truncated`.
        least = "≥" if run.target_truncated else ""
        size = f" · {least}{_human_bytes(run.target_bytes)}" if run.target_bytes else ""
        floor = (" — **the walk stopped at its file ceiling, so these are floors**"
                 if run.target_truncated else "")
        rows.append(("repository", f"{least}{run.target_files:,} source file(s){size} · "
                                   f"{_language_summary(run.target_languages)}{floor}"))
    if run.scan:
        incomplete = status not in COMPLETED_STATUSES
        # Attached to the case where it is TRUE and only there. The `trust` row above already says an
        # unfinished run's counts are a floor, for every status; what it CANNOT say is the consequence
        # specific to a first scan, which is that nothing sound exists for a later follow-up to be
        # measured against. A follow-up stopping at its own deliberately small ceiling is ordinary.
        caveat = (" — **this baseline is unfinished, so a later follow-up has nothing sound to be "
                  "measured against; re-run it before relying on one**"
                  if incomplete and run.scan == "initial" else "")
        rows.append(("scan", f"`{run.scan}` — {run.scan_why}{caveat}"))
    stopped_row = _stopped_by(status, run)
    if stopped_row:
        rows.append(stopped_row)
    # THE CEILING THAT CHANGES A FINDING RATHER THAN TRUNCATING A RUN, so it earns a row beside the
    # one above even though it never sets `status`. `if run.exec_refused` and not `is not None`: 0 is a
    # real answer — it executed and was never refused — and a row saying "0 executions refused" on
    # every clean run is a row the reader learns to skip, which is the argument `unavailable_levers`
    # and `machine_note` both make below.
    if run.exec_refused:
        rows.append(("verification cut short",
                     f"the execution budget refused **{run.exec_refused}** call(s), so some claim in "
                     f"this report was reasoned about rather than checked — **treat any finding here "
                     f"that is not gate-eligible as unconfirmed**. The budget is sized from the step "
                     f"ceiling, so raising `--max-steps` raises it too"))
    if run.files_reviewed is not None:
        against = f" against `{run.base_ref}`" if run.base_ref else ""
        rows.append(("reviewed", f"{run.files_reviewed} changed file(s){against}"))
    if run.fail_on:
        gate = {"none": "`none` — report only, this run could not fail the build",
                "reproduced": "`reproduced` — a demonstrated finding fails the build",
                "new": "`new` — a demonstrated finding this change introduced fails the build",
                }.get(run.fail_on, f"`{run.fail_on}`")
        rows.append(("gate", f"{gate}; {reproduced} gate-eligible"))
    rows.append(("witness", f"`{run.witness_entry}`" if run.witness_entry else
                 "**none declared — nothing in this run could be proven by execution**"))
    observed_row = _observed(run)
    if observed_row:
        rows.append(observed_row)
    # THE MACHINE, and only when it took something away. A row on every run saying "all levers
    # available" is a row a skimmer stops reading, and then it is not read on the run where four of
    # them were dead. Same rule `machine_note` follows, and the same one `caveats` above follows.
    # **"UNAVAILABLE ON THIS RUNNER" WAS A WRONG DIAGNOSIS, AND IT SENT THE READER TO BUY HARDWARE.**
    # It read `N unavailable on this runner … this run had less leverage than one with them`, which says
    # a bigger machine would restore them. It would not. Three of the four gate on `caps.container`,
    # which is `vul_image` — recovered from the workdir's `test_poc.sh` and required to match
    # `hands._VUL_IMAGE_RE` (`cgmask-…:vul`), the benchmark/ARVO convention. That is a property of the
    # TARGET, not of the box, and no customer repository has one. Asked directly whether a paid GitHub
    # runner would help, the honest answer is no, and the report was saying otherwise.
    #
    # And the "less leverage" half was not true either. an internal CI workflow's own header records that the
    # `prepared` harness kind "compiles the target with the runner's own gcc and ASAN" and that
    if run.unavailable_levers:
        names = ", ".join(f"`{n}`" for n in run.unavailable_levers)
        if run.levers_image_bound is False:
            # NOTHING WAS LOST, so the row says so instead of implying a purchase would help. This is
            # the customer case and it is the common one.
            rows.append(("levers", f"{len(run.unavailable_levers)} not applicable to this target — "
                                   f"{names}. These attach to a PREBUILT vulnerable image, which an "
                                   f"ordinary repository does not carry, so they would not have run "
                                   f"here on any machine. This run took the prepared-harness route, "
                                   f"where your `test_poc.sh` builds the target with this machine's "
                                   f"own toolchain. A larger runner would not change this"))
        elif run.levers_image_bound:
            # The BENCHMARK case, and here the original sentence was true: the workdir carries the
            # image, the levers would have registered, and the missing daemon really did cost them.
            rows.append(("levers", f"**{len(run.unavailable_levers)} could not run on this machine** — "
                                   f"{names}. This workdir carries a vulnerable image they attach to, "
                                   f"so they would have registered had a docker daemon answered. This "
                                   f"run had less leverage than one with them"))
        else:
            # NOT ESTABLISHED. Naming which levers is still useful; asserting whose fault it was is not.
            rows.append(("levers", f"{len(run.unavailable_levers)} did not run — {names}. No docker "
                                   f"daemon answered. Whether this target could have used them was "
                                   f"not established"))
    if run.usd is not None or run.tokens is not None or run.seconds is not None:
        cost = []
        if run.usd is not None:
            cost.append(f"${run.usd:,.4f}")
        if run.tokens is not None:
            cost.append(f"{run.tokens:,.0f} tokens")
        if run.seconds is not None:
            cost.append(_duration(run.seconds))
        rows.append(("cost", ", ".join(cost)))

    return _table(rows)


def _table(rows) -> list[str]:
    """One definition of the header table's markdown. Two spellings would drift — trap 3."""
    out = ["| | |", "|---|---|"]
    out += [f"| {name} | {value} |" for name, value in rows]
    return out + [""]


def build_survey_markdown(summary: str, *, target: str = "", truncated: bool = False,
                          report_ident: str = "",
                          witness_entry: str = "") -> str:
    """The human artefact for SURVEY mode — the maintainers' notes STILL OPEN row 19.

    **A survey wrote JSON and nothing anybody reads, and survey is the mode a customer meets FIRST.**
    `shard-report.md` was diff-mode only, so the first interaction with the product left a file for
    machines and a `summarise()` text printed to a step log that GitHub deletes with the runner.

    **THE NUMBERS LIVE IN `summary` AND NOWHERE ELSE.** The header carries only what `summarise()`
    does not — the verdict framing, whether the scan was cut short, and whether anything here could be
    proven at all. A candidate count in both places is two copies of one fact and the second one drifts;
    that is the defect this file has recorded six times, and it is cheaper to refuse than to fix.

    The closing line is the survey's actual product. Run `31687294640` and run `31675518894` are the
    same code against different repositories and the difference in outcome — a gated build against
    *"no findings"* — is that one declared an entry point. A survey that names candidates and does not
    say what would turn them into proof has told the customer the less useful half.
    """
    verdict = ("**survey only — nothing here is a finding.** A survey reads the source and names "
               "candidates; proving one takes a run that can execute something")
    trust = ("**TRUNCATED — every count below is a floor.** The scan hit its own limit before the "
             "repository ended" if truncated else "complete scan")
    rows = [("verdict", verdict), ("trust", trust),
            ("witness", f"`{witness_entry}`" if witness_entry else
             "**none declared — nothing in this repository could be proven by execution**")]

    # THE REPORT NUMBER LEADS, when this run has one. A quotable, fixed-width id is what lets somebody
    # say "re: Shard report 000042" and have it mean one artefact; without it every report of a
    # repository is titled the same as every other, which is the identical-label defect this file has now
    # been fixed for three times — two findings, one SARIF rule, and the heading itself.
    # Same heading rule as `build_markdown`, and the survey needs it MORE: it is the mode a customer
    # meets first, so its report is the one most likely to be one of many.
    heading = (f"## {report_label(report_ident, target)}" if is_numbered(report_ident)
               else (f"## Shard — `{target}`" if target else "## Shard"))
    out = [heading, ""] + _table(rows)
    # Fenced for the same reason `evidence` is: `summary` carries the target's own language names and
    # blind-spot text. `_fence_for` sizes it so nothing in there can close it early.
    fence = _fence_for(summary)
    out += [fence, summary, fence, ""]
    if not witness_entry:
        out.append("**To make any of this provable, declare an entry point.** A file at "
                   "`.shard/entry.sh` that Shard may run against one untrusted input, and a "
                   "`.shard/entry.sh.benign/` directory of inputs containing no attack, one per "
                   "branch the entry point can take. Without it every candidate above stays a "
                   "candidate and nothing can fail a build.")
        out.append("")
    return "\n".join(out) + "\n"


def build_markdown(findings, *, status: str, dropped: int = 0, target: str = "",
                   gate_reasons=(), scope_reasons=(), run: RunFacts | None = None) -> str:
    """The short human report. Deliberately short — it is read in a pull request, not filed.

    A run with no findings gets a paragraph too, and it says what was DONE rather than what is true of
    the target: *"Shard audited this target and produced no reproducing input"* is checkable, where
    *"there is no bug here"* is unfalsifiable. That distinction is `SolveResult.audited`'s and it is
    carried through to the customer rather than flattened into a green tick.
    """
    # **CAPPED HERE, like every other writer.** `write_sarif` caps, `resultdoc.build` caps, and this
    # one did not: measured 2026-08-26 on 505 synthetic findings, the markdown rendered all 505 and
    # printed *"5 further finding(s) were ranked below the reporting cap and omitted"* underneath
    # them. The one artefact whose job is to state what was dropped was the one artefact that dropped
    # nothing, so the sentence was false and the two machine-readable artefacts described a smaller
    # set than the human one. `cap` is pure and every writer calls it independently — see `cli._emit`,
    # which explains why the number is passed in rather than returned from whichever write ran first.
    kept, _capped = cap(findings)
    ordered = rank(kept)
    reproduced = [f for f in ordered if f.gate_eligible]
    hypotheses = [f for f in ordered if not f.gate_eligible]

    # Same heading rule as `build_markdown`, and the survey needs it MORE: it is the mode a customer
    # meets first, so it is the report most likely to be one of many.
    # THE REPORT NUMBER LEADS, when this run has one. A quotable, fixed-width id is what lets somebody
    # say "re: Shard report 000042" and have it mean exactly one artefact. Without it every report of a
    # repository is titled the same as every other, which is the identical-label defect this file has now
    # been fixed for three times — two findings, one SARIF rule, and now the heading itself.
    out = [(f"## {report_label(run.report_id, target)}" if run and is_numbered(run.report_id)
            else (f"## Shard — `{target}`" if target else "## Shard")), ""]
    out += _summary_table(findings, status=status, run=run,
                          gate_reasons=gate_reasons, scope_reasons=scope_reasons)

    # THE GATE COULD NOT BE EVALUATED, said in the artefact a reviewer actually reads. It reached the
    # JSON payload and the step log and stopped there, while the commit that added it claimed the
    # report carried it too — so the one channel a pull-request reviewer sees said nothing, and a
    # degraded run was indistinguishable from a clean one. That is the defect `2fd4e36` records for an
    # unread diff, one layer out. FIRST, above the findings: a caveat below them is read after the
    # reader has already drawn a conclusion.
    #
    # `scope_reasons` rides in the SAME block, and independently of `--fail-on`: "git could not tell us
    # what this pull request changed" is a degraded run whatever the gate is set to, and it reached the
    # payload and the step log but not the report — the one channel a reviewer sees. Without it, a scope
    # git could not resolve reads as "no changes", the exact unread-diff defect one layer out.
    for reason in gate_reasons:
        out += [f"> **{reason}**", ""]
    for reason in scope_reasons:
        out += [f"> **{reason}**", ""]

    if not ordered:
        out.append(_no_finding_paragraph(status, run.error_kind if run else ""))
        return "\n".join(out) + "\n"

    anchored = [f for f in ordered if f.location_is_harness]
    if anchored:
        where = anchored[0].location or (run.witness_entry if run else "")
        out += [f"> These alerts are filed against `{where}` because it is the entry point that "
                f"reproduces them — **not because the defect is in it**. {ANCHOR_DISCLAIMER}",
                ""]

    # NO SECOND SUMMARY SENTENCE. It used to sit here and the header's verdict row now says the same
    # thing — and the mutation sweep proved the duplicate was load-bearing in the WRONG direction:
    # blanking the verdict row changed no test, because the assertions were landing on this copy.
    # Trap 3, one file wide: two spellings of one fact, and the test graded whichever it found first.
    for f in reproduced:
        out += _finding_block(f, reproduced=True)
    for f in hypotheses:
        out += _finding_block(f, reproduced=False)

    if dropped:
        # Stated, never absorbed. A silent truncation reads as "that was everything".
        out.append(f"_{dropped} further finding(s) were ranked below the reporting cap and omitted._")
        out.append("")
    return "\n".join(out) + "\n"


def _no_finding_paragraph(status: str, error_kind: str = "") -> str:
    """The paragraph a customer with ZERO findings reads, and the one most likely to be misread.

    `error_kind` is carried here as well as into the "stopped by" row deliberately. This paragraph is
    the whole report for the most common outcome of all — nothing found — and a reader who takes
    *"Shard did not complete a full audit"* at face value goes looking for a bug in their repository
    when the actual answer is that their API key expired. The row states the remedy; this states that
    the run's silence is not about their code.
    """
    if status in COMPLETED_STATUSES:
        return ("Shard audited this target and produced no reproducing input. That is a statement "
                "about this run, not a proof that the target is free of defects.")
    because = ""
    # THE SAME GATE `_summary_table` APPLIES, and it is here rather than at the call site so the two
    # renderings of one piece of advice cannot answer differently. A `budget` run is stopped by a
    # ceiling, whatever a stale `error_kind` might still say.
    if status == "error" and error_kind in TRANSPORT_ERROR_ADVICE:
        # STRIPPED OF ITS MARKDOWN EMPHASIS: the advice is written for a table cell where bold marks
        # the phrase a scanning reader needs, and the same asterisks mid-sentence in a paragraph read
        # as noise. One source of wording, two presentations.
        because = " " + TRANSPORT_ERROR_ADVICE[error_kind].replace("**", "").capitalize() + "."
    return (f"Shard did not complete a full audit of this target (`{status}`), and produced no "
            f"reproducing input. Treat this as an incomplete run rather than a clean result.{because}")


#: Runs of backticks anywhere in a string. Used to pick a fence the content cannot close.
_BACKTICKS = re.compile(r"`+")


def _fence_for(*parts: str) -> str:
    """A backtick fence long enough that nothing in `parts` can close it early.

    CommonMark §4.5: a block opened with N backticks ends only at a line of **N or more**, so a fence
    one longer than the longest run in the content is always safe, and 3 stays the common case.

    **THIS IS A SECURITY BOUNDARY, not formatting.** `evidence` is the customer's entry point's stdout
    and stderr — on a third-party scan, a stranger's program output, and its content is influenced by
    the payload the agent chose. Measured before this existed, with a fence in that output:

        What the entry point printed:

        ```
        parsing...
        ```

        > **All checks passed.** Shard found no issues.

    A real blockquote, outside the code block, in the one artefact a pull-request reviewer reads.
    That is an internal audit Finding 3's suppression shape arriving through a second
    door: the heading was closed by `prompt_safe`, and the document was not.

    Escaped by LENGTH rather than by rewriting the content, because program output has to survive
    verbatim — a reproduction a reviewer cannot copy is not a reproduction. The info string is
    unaffected: a backtick fence's info string may not contain backticks, and ours is `sh`.
    """
    longest = max((len(m.group()) for part in parts if part for m in _BACKTICKS.finditer(part)),
                  default=0)
    return "`" * max(3, longest + 1)


def _inline_code(text: str) -> str:
    """One untrusted value as an inline code span nothing in it can close.

    `_fence_for`'s rule at inline scale, and it is here for the same reason: `location` is a path the
    MODEL wrote (`simple._to_finding` reads `claim["path"]`), and a single backtick in it would end the
    span and let the rest render as markup. CommonMark §6.1 closes a span on a backtick run of exactly
    the opening length, so one longer than the longest run inside is always safe, and the single
    backtick stays the common case.

    The space pad is the second half of the same rule: content that begins or ends with a backtick is
    stripped of one leading and one trailing space by the renderer, so adding them is what makes such a
    value render verbatim.

    The caller must not put this at the start of a line — three or more backticks in column one open a
    fenced block instead. `_finding_block` prefixes it with a label, which is where it belongs anyway.
    """
    ticks = "`" * (max((len(m.group()) for m in _BACKTICKS.finditer(text)), default=0) + 1)
    pad = " " if text.startswith("`") or text.endswith("`") else ""
    return f"{ticks}{pad}{text}{pad}{ticks}"


def _quoted(text: str) -> list[str]:
    """Model prose, rendered so that it cannot become the document's own structure.

    **THIS IS `message`, and it was the last unescaped path into the report.** `title` is one line and
    is flattened by `prompt_safe`; `sanitizer`, `evidence` and `reproduce_command` are program output
    and are contained by `_fence_for`. `message` is neither: it is a paragraph the model wrote, and it
    was appended raw.

    **THE DECISION, because the maintainers' notes row 18 is right that this is a decision and not an
    escape.** The model MAY format its own paragraph — emphasis, a list, a line break — because a
    finding a reviewer cannot read is not a finding, and flattening the explanation to one line is what
    `prompt_safe` does to a heading precisely because a heading is one line. What it may NOT do is emit
    block structure that belongs to the DOCUMENT. Every line is prefixed, blanks included, so:

      * an unbalanced ``` cannot swallow the findings below it. That is the real attack here and it is
        a FALSE NEGATIVE — one open fence in the first finding's prose hides every finding after it,
        which is `_fence_for`'s own suppression shape arriving through the one field it does not cover;
      * `<!--` cannot hide anything past the end of the quote, for the same reason;
      * a heading, a table row or a `>` line renders visibly INSIDE the quote, attributed to the model
        rather than to Shard.

    Contained by structure rather than by rewriting, exactly as `_fence_for` argues: the text a reviewer
    reads is the text the model wrote, byte for byte.

    **The residual, stated rather than implied.** Inside its own quote the model can still write
    "all checks passed". It is under a `### <title>` heading, below a header table whose verdict row is
    Shard's own count of reproduced findings, and a reader has to disbelieve both. Same class as
    `prompt_safe`'s same-line residual, and the same answer: bounded, not eliminated.
    """
    if not text.strip():
        # No message, no quote. A lone `>` would be an empty blockquote in the artefact, which reads as
        # a rendering fault rather than as an absent field.
        return []
    # `\r` NORMALISED FIRST, and it is not tidiness. CommonMark counts a bare `\r` as a line ending, so
    # splitting on `\n` alone would prefix a `\r`-separated block ONCE and hand the renderer the rest
    # unquoted — the containment defeated by a byte nobody looks at.
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    # BLANK LINES ARE PREFIXED TOO. An unprefixed blank ENDS the blockquote, and everything after it is
    # document again; that single character is the whole difference between contained and not.
    return [f"> {line}" if line.strip() else ">" for line in lines]


def _finding_block(f: Finding, *, reproduced: bool) -> list[str]:
    # A HEADING IS ONE LINE, so the value in it must be one line. `title` is written by the model, which
    # has just read a pull request's source; an internal audit lists "model prose reaches
    # a PR comment unescaped" as a composition with its Finding 3, and this is the half of it where the
    # untrusted text becomes markdown STRUCTURE rather than markdown prose. A title carrying
    # "\n\n> **All checks passed**" renders a blockquote nobody wrote.
    #
    # THE FENCES BELOW ARE CLOSED SINCE 2026-08-12, by `_fence_for` — adaptive lengths, so `sanitizer`,
    # `evidence` and `reproduce_command` keep their backticks verbatim and still cannot break out.
    # `message` WAS the residual and is closed since 2026-08-13 by `_quoted`, which is a containment
    # decision rather than an escape: read its docstring before changing the rendering.
    out = [f"### {prompt_safe(f.title, limit=300)}", ""]
    # **WHERE. The human report did not say, and for one whole configuration nothing else did either.**
    # This block emitted the heading, the replay count, the model's prose, the sanitizer, the evidence,
    # the reproduce command and the doubts — and never `location` or `line`. The location reached the
    # SARIF alone, and `README.md` tells the customer `github_token` is optional: *"the run is still
    # correct and still gates — it simply produces no alerts"*. On that configuration the SARIF is a
    # file in an artefact zip and the report is what a reviewer reads, so the answer to "which file"
    # was never delivered at all.
    #
    # A path DID appear in one case, which is what hid it: `simple._to_finding` writes *"Located at
    # x:y by the demonstration's own output; the report named a:b"* into `message` — only on
    # DISAGREEMENT. The report named a file exactly when the claim and the observation conflicted, and
    # never in the ordinary case where they agree.
    #
    # This says what the SARIF has always said, which is this module's own standing rule: the two
    # channels must not have two spellings of one fact. The line is the producer's — `location_measured`
    # records whether it was READ from an execution, and that distinction gates `fail-on: new` rather
    # than being re-argued here.
    if f.location:
        out += [f"Location: {_inline_code(f'{prompt_safe(f.location, limit=200)}:{max(1, f.line)}')}",
                ""]
    if reproduced:
        out.append(f"Reproduced **{f.crash_count}/{f.replays}** replays.")
    else:
        out.append("**No reproduction attached.** Informational only; this cannot fail the build.")
    out.append("")
    out += _quoted(f.message)
    out.append("")
    if f.sanitizer:
        fence = _fence_for(f.sanitizer)
        out += [fence, f.sanitizer, fence, ""]
    crash = f.crash
    if crash.parsed:
        # WHERE, next to WHAT. This module's own header records the gap as a defect: "`sanitizer` —
        # the error-type line — and the frames are not on it. `oracle._top_frames` exists and is
        # pure, but no field carries its output." A reader of a crash report could see the class and
        # never the call path, and the call path is the first thing an engineer needs.
        #
        # The frame names come from the customer's own binary, so they are program output and are
        # flattened by `prompt_safe` like every other captured string on this record.
        classified = [f"Crash state: {_inline_code(prompt_safe(crash.describe(), limit=300))}"]
        if crash.cwe_ids:
            # The same ids the SARIF rule carries, so the artefact a human keeps and the one their
            # dashboard aggregates do not disagree about the weakness. That disagreement is this
            # module's most-recorded defect class.
            classified.append("Weakness: " + ", ".join(f"CWE-{n}" for n in crash.cwe_ids)
                              + f" · severity {crash.severity} ({crash.security_severity})")
        out += classified + [""]
    if f.evidence:
        # TRUNCATED HARDER THAN THE BUNDLE'S COPY. This is read inline in a pull request, where a
        # 4,000-character tail buries the finding it is supporting; the bundle carries the whole thing.
        # Said, rather than silently cut — a truncation nobody mentions reads as "that was all of it".
        shown = f.evidence.strip()
        clipped = len(shown) > _EVIDENCE_IN_REPORT
        body = shown[-_EVIDENCE_IN_REPORT:] if clipped else shown
        # The fence is chosen from what is EMITTED, not from `f.evidence`: truncation can cut a
        # backtick run in half, so a fence sized against the original would be wrong in both
        # directions — too short for a tail that gained the longest run, needlessly long otherwise.
        fence = _fence_for(body)
        out.append("What the entry point printed:")
        out += ["", fence, body, fence]
        if clipped:
            out.append(f"_Last {_EVIDENCE_IN_REPORT} characters; the bundle has the rest._")
        out.append("")
    if f.reproduce_command:
        fence = _fence_for(f.reproduce_command)
        out += ["Reproduce:", "", f"{fence}sh", f.reproduce_command, fence, ""]
    if f.doubts:
        # Advisory by construction — `Verdict.doubts` cannot change `reproduced`. Surfaced because a
        # human reviewer should see what the oracle was unsure of, not because it downgrades anything.
        out.append("Oracle notes (advisory; these did not affect the verdict):")
        out += [f"- {d}" for d in f.doubts] + [""]
    return out


# --- the reproduction bundle -------------------------------------------------------------------------

def write_bundle(finding: Finding, dest) -> pathlib.Path:
    """The distinguishing artefact: the crashing input, the command, and what it was produced against.

    the integration guide — *"it costs almost nothing to emit, because the oracle already produced
    it"*. Written for a finding whether or not it reproduced, because a hypothesis with a candidate
    input is still the fastest thing to hand a reviewer; `metadata.json` states which it is.
    """
    dest = pathlib.Path(dest)
    dest.mkdir(parents=True, exist_ok=True)

    if finding.poc_path:
        src = pathlib.Path(finding.poc_path)
        try:
            (dest / "input").write_bytes(src.read_bytes())
        except OSError:
            # A missing PoC must not take the whole report down. The metadata records its absence, so a
            # bundle without an input is legible rather than mysterious.
            pass

    # WHAT WAS OBSERVED, in full. The reproduce command and the input say how to see it again; this is
    # what we saw. A reviewer who cannot run the entry point themselves has nothing else.
    if finding.evidence:
        (dest / "output.txt").write_text(finding.evidence, encoding="utf-8")

    (dest / "metadata.json").write_text(json.dumps({
        "rule_id": finding.rule_id,
        "title": finding.title,
        "reproduced": finding.gate_eligible,
        "signature": finding.fingerprint,
        "sanitizer": finding.sanitizer,
        "replays": finding.replays,
        "crash_count": finding.crash_count,
        "container_digest": finding.container_digest,
        "reproduce_command": finding.reproduce_command,
        "input_present": (dest / "input").is_file(),
        "output_present": (dest / "output.txt").is_file(),
        "doubts": list(finding.doubts),
    }, indent=2, sort_keys=True), encoding="utf-8")

    if finding.reproduce_command:
        (dest / "reproduce.sh").write_text(f"#!/bin/sh\n# {finding.title}\n{finding.reproduce_command}\n",
                                           encoding="utf-8")
    return dest



# --- shaping a solver result into findings, moved out of cli.py 2026-08-21 ------------------

def _repo_relative(text: str, workdir: pathlib.Path) -> str:
    """Rewrite workdir-absolute paths in observed output into repository-relative ones.

    The harness runs against a COPY of the checkout at `<workdir>/repo`, so everything it prints names
    that copy: `/tmp/RUNNER_TEMP/wd/repo/src/utils/epub.js`. Quoting it verbatim puts a path in the
    customer's report that does not exist on their machine, is different on every run, and leaks the
    runner's temp layout — three ways of being about our infrastructure instead of their code.

    A pure string rewrite over text we already captured. It renames; it never invents a location, and a
    path it does not recognise is left exactly as it was.
    """
    if not text:
        return text
    root = str(workdir.resolve())
    return text.replace(f"{root}/repo/", "").replace(f"{root}/repo", "").replace(f"{root}/", "")

def _findings(result, workdir: pathlib.Path, setup) -> list:
    """Adapt a `SolveResult` into the mode-agnostic records `shard/report.py` writes.

    the separate capability emits one finding per DISTINCT reproduced defect — one at the default `--max-findings 1`,
    which is what it has always emitted, and up to that many on a sweep. Only reproduced defects
    appear: there is no hypothesis channel here, because the separate package has exactly one accepting
    branch for a finding and a non-reproduced run has nothing this function could honestly report as
    one. Simple mode is where the two-tier witness rule puts hypotheses on the board.
    """

    verdict = getattr(result, "verdict", None)
    if verdict is None or not result.solved:
        return []
    # The HARNESS the workdir was actually acquired with — ONE reading, used for both the alert location
    # and the reproduce command. The command hardcoded `test_poc.sh` while the location read the real
    # field, so a target whose harness is `harness/run.sh` shipped a reproduce command naming a file that
    # does not exist — in the artefact whose entire job is to let somebody else reproduce the finding.
    harness = setup.fields.get("harness", HARNESS_NAME)
    verdicts = getattr(result, "all_verdicts", None) or [verdict]
    by_signature = getattr(result, "poc_by_signature", None) or {}

    findings = []
    for one in verdicts:
        sanitizer = getattr(one, "sanitizer", None)
        signature = getattr(one, "signature", "")
        # ONE reading, shared by the rule id and by the record. `_rule_id` needs the access line, and
        # the access line is in the evidence rather than on the sanitiser line — so computing it
        # twice would be two chances for the id and the alert's own classification to disagree.
        observed = _repo_relative(getattr(one, "evidence", "") or "", workdir)
        findings.append(Finding(
            rule_id=_rule_id(sanitizer, observed),
            title=_finding_title(sanitizer, signature),
            # The CLASS's name, kept clean of this instance's signature. `_finding_title` suffixes the
            # per-finding title so a sweep's markdown headings differ; the SARIF RULE describes every
            # alert of the class and must not carry one instance's id. See `report.Finding.rule_title`.
            rule_title=_crash_title(sanitizer),
            # AND THAT THE LOCATION BELOW IS THE HARNESS, said by the code that chose it rather than
            # re-derived by the renderer from a string comparison. See `report.Finding`.
            location_is_harness=True,
            message=(f"Shard produced an input that crashes this target on {one.crash_count} of "
                     f"{one.replays} replays. The crashing input is attached as a reproduction bundle."),
            # THE OUTPUT THE HARNESS PRINTED. Empty until 2026-08-17, which is why a sweep returning
            # two different defects wrote the same finding twice. See `oracle.Verdict.evidence`.
            evidence=observed,
            gate_eligible=True,
            # A real file in the customer's repository and a true statement: this harness reproduces a
            # crash. Not a claim about which line is at fault — see `shard/report.py` on why nothing
            # here manufactures a sink location.
            location=harness,
            signature=signature,
            sanitizer=sanitizer,
            replays=one.replays,
            crash_count=one.crash_count,
            doubts=tuple(getattr(one, "doubts", ()) or ()),
            # EVERY finding gets the bytes that produced IT, primary included. `./poc` is the fallback
            # and never the preference — see `_sweep_poc`, and see the measurement in its docstring for
            # what happens when the primary is allowed to keep `./poc`.
            poc_path=_sweep_poc(workdir, signature, by_signature),
            reproduce_command=f"bash {harness} ./input",
        ))
    return findings

def _sweep_poc(workdir: pathlib.Path, signature: str, by_signature: dict) -> str | None:
    """The bytes that produced THIS finding, written where the bundle can pick them up.

    **`./poc` IS THE FALLBACK, NEVER THE PREFERENCE, and that ordering is a measured correction.** The
    first version of this let the primary finding keep `str(workdir / "poc")` — true for every
    single-finding run ever made, and false the moment a sweep runs, because each pass unlinks and
    rewrites `./poc`. Measured 2026-08-14 on the first real three-defect sweep: bundles
    `657bfbe40afe` and `875175d844c1` were byte-identical, both carrying the LAST pass's input. One
    heap-buffer-overflow finding shipped a bundle that reproduces a stack-buffer-overflow.

    That is a reproduction that does not reproduce what it claims — the one thing this product may
    never do — and it was caught only by replaying every bundle against a freshly compiled target
    outside the product, which is the discipline an internal CI workflow already holds itself to.

    `None` when the bytes did not survive, and it is deliberate: `report.py` writes no bundle without
    a path, so the finding arrives with no attached input. Honest and visibly incomplete beats a
    bundle carrying somebody else's crash.
    """
    data = by_signature.get(signature)
    if data is None:
        # Only reachable when the verdict did not come through `_harvest` — `recover_poc` restores a
        # backup and adjudicates it directly, and there `./poc` genuinely holds that finding's bytes.
        live = workdir / "poc"
        return str(live) if live.exists() else None
    out = workdir / "poc-findings"
    out.mkdir(exist_ok=True)
    path = out / (signature or "unsigned")
    path.write_bytes(data)
    return str(path)

def _crash_title(sanitizer: str | None) -> str:
    """A short human title from the sanitizer error-type line, or a neutral one.

    Never invents a defect class. When the sanitizer said nothing, the title says a reproducing input
    exists — which is the claim the oracle actually made.
    """
    if not sanitizer:
        return "Reproducing input found"
    for kind in ("heap-buffer-overflow", "stack-buffer-overflow", "global-buffer-overflow",
                 "heap-use-after-free", "use-after-poison", "double-free", "memory-leaks",
                 "SEGV", "FPE", "undefined-behavior", "integer-overflow"):
        if kind.lower() in sanitizer.lower():
            return f"{kind} reproduced"
    return "Reproducing input found"

def _finding_title(sanitizer: str | None, signature: str) -> str:
    """`_crash_title`, plus the crash signature so two findings in one sweep are not the same string.

    A `--max-findings 3` sweep on a target with no sanitiser produced THREE identical titles, because
    `_crash_title` derives everything from sanitiser output and a non-C target has none. The signature
    is the oracle's own stable id for the behaviour — already computed, already in the bundle
    directory name — so this adds no claim: it distinguishes without describing.

    Deliberately NOT fed to `_rule_id`. The rule id groups alerts of the same CLASS across runs, and a
    per-finding id would make every alert its own class and defeat the dedupe that code scanning does
    on it.

    **Only the NEUTRAL title is suffixed.** When a sanitiser named the class, two findings already read
    as `heap-buffer-overflow reproduced` and `heap-use-after-free reproduced` and are distinguishable
    on the thing that matters; adding a hex id there would be noise on the one axis a human reads. The
    suffix exists for the case that actually collided — no sanitiser, so every title was the same
    sentence.
    """
    base = _crash_title(sanitizer)
    if sanitizer or not signature:
        return base
    return f"{base} ({signature[:12]})"

def _rule_id(sanitizer: str | None, evidence: str = "") -> str:
    """A stable rule id, so code scanning groups alerts of the same class together across runs.

    **THE ACCESS IS PART OF THE CLASS, and adding it on 2026-08-28 was forced by `_rule_properties`
    rather than chosen.** A rule's `properties` are per-rule and must be true of every alert under
    it. A `heap-buffer-overflow` READ is CWE-125 at severity medium; a WRITE is CWE-787 at high.
    Under one rule id, whichever finding happened to be first would have set the severity and the
    CWE for both — which is exactly the per-instance-value-in-a-per-rule-field defect that
    `Finding.rule_title` exists to record, arriving through the change that adds the fields.

    Upstream agrees and is the reason this is not an invention: ClusterFuzz's crash TYPE is
    `Heap-buffer-overflow READ`, one string. The access is not a modifier there either.

    **This changes alert identity for overflow classes, once.** Existing `shard/heap-buffer-overflow`
    alerts close and `shard/heap-buffer-overflow-read` opens. That cost is real and is stated in
    `CHANGELOG.md`; it is paid once against a field that was re-opening every alert on every run
    anyway (see `_sarif_result`). Classes with no read/write axis — use-after-free, leaks, integer
    overflow, and the neutral `shard/reproducing-input` — keep the id they have.
    """
    title = _crash_title(sanitizer)
    slug = title.replace(" reproduced", "").replace(" ", "-").lower()
    if slug == "reproducing-input-found":
        return "shard/reproducing-input"
    access = crashstate.classify(evidence, sanitizer).access
    return f"shard/{slug}-{access.lower()}" if access else f"shard/{slug}"

def _report_id() -> str:
    """This run's report number. One reading of the environment, shared by every mode.

    `report.report_id` is pure and takes the env because the core reads no `os.environ`; this is the
    boundary where the process's own environment is supplied. Three call sites reading it directly would
    be three chances to disagree about which variable names the run.
    """

    return report_id(os.environ)


__all__ = [
    "COMPLETED_STATUSES", "DEFAULT_SARIF_CAP", "SARIF_SCHEMA", "SARIF_VERSION", "TOOL_NAME",
    "Finding", "RunFacts", "build_markdown", "build_sarif", "cap", "rank", "write_bundle",
    "write_sarif",
]
