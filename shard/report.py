"""The customer deliverable — the report, the SARIF, and the reproduction bundle.

The integration guide is the output contract. Three artefacts, and the ranking rule that keeps
them inside GitHub's limits.


**Simple-safe, and by explicit owner decision rather than by convenience.** The design notes'
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
onboarding failure the integration guide names, and silence is not the same as rigour.

## The source location, stated honestly

**Nothing in the pipeline can currently resolve a crash to a source file and line.** `Verdict` carries
`sanitizer` — the error-type line, `"ERROR: AddressSanitizer: heap-buffer-overflow on address 0x…"` —
and the frames are not on it. `oracle._top_frames` exists and is pure, but no field carries its output
out of the solve, and the journal records only the error-type line.

So `Finding.location` defaults to the HARNESS, which is a real file in the customer's repository and a
true statement: this harness reproduces a crash. It is not a claim about which line is at fault, and
nothing here manufactures one. Anchoring a customer's Security tab on a guessed line would be a false
positive in the most damaging possible place, and the whole product rests on findings being real.

The design notes records what would close it: carry `_top_frames`' output on `Verdict` and thread it
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
import shlex
import stat
import subprocess
import urllib.parse
from dataclasses import dataclass, fields

from shard.inspectionview import markdown as inspection_markdown

# The shared prompt/report rendering boundary — see `diffscope.prompt_safe`. Used here for the ONE
# place a model-written string becomes markdown structure rather than markdown prose: the heading.
from shard.artefactfs import (atomic_write as _atomic_write,
                              rooted_write,
                              trusted_directory as _trusted_directory)
from shard.target import HARNESS_NAME
# `safe_directory_argv` for `head_revision` — one more NAME on an import edge this module already has,
# which is the same trade `_REPRODUCE_SH`'s collapse into one constant records. A container action runs
# as root over a checkout owned by the runner's user, and without the exception git answers nothing.
from shard.diffscope import prompt_safe, safe_directory_argv
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
#: The design notes.
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
#: the wording lives here because this module owns what the customer reads. The maintainers' suite pins that every kind has advice and every advice has a kind, so the
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


def _advice_sentence(advice: str) -> str:
    """One entry of `TRANSPORT_ERROR_ADVICE`, rendered as standalone prose instead of a table cell.

    The table is written for the cell: emphasis marks the phrase a scanning reader needs, the opening
    word is lowercase because a `| stopped by |` row has no sentence in front of it, and there is no
    terminal stop. A paragraph needs the opposite of all three. `_stopped_by` renders the entry
    unchanged and is correct to; this is the only conversion, and it sits beside the table whose
    convention it inverts rather than inside the paragraph, so the contract is stated where the
    strings that must satisfy it are written.

    **NEVER `str.capitalize()`.** It was the first fix and it damaged all six entries, because it
    upper-cases the first character and LOWER-CASES EVERY OTHER ONE. Measured 2026-09-02 in the
    shipped `shard-report.md` of a real `--model glm-5.2-typo` run: *"...would not serve the requested
    model. check the `model` input..."*, and `rate` lost its *"Re-running"* the same way. The advice is
    two sentences and only the first survived.

    **The opening word is recased only when it is a WORD.** A cause can legitimately begin with a
    lowercase identifier the customer has to copy — a model name (`glm-5.2`), a header (`x-api-key`),
    a path (`.shard/entry.sh`) — and upper-casing one produces a string their provider does not know.
    A missed capital is a cosmetic loss; a corrupted identifier is a wrong instruction, so the test is
    biased to leave the text alone. `isalpha()` rejects the digit, dot, slash and hyphen; `islower()`
    is the second half, and it is what keeps `vLLM` — a runtime this product's own README tells the
    customer to point it at — from reaching them as `VLLM`.
    """
    plain = advice.replace("**", "")
    opener = plain.split(" ", 1)[0].rstrip(",;:")
    prose = opener.isalpha() and opener.islower()
    return (plain[:1].upper() + plain[1:] if prose else plain) + "."


#: A fingerprint is used as a PATH SEGMENT and as a code-scanning identity, so it may contain only
#: characters that are safe in both. A leading dot is unsafe even when it is not `.` or `..`: the
#: shipped upload action excludes dot-path contents by default, so `.proof` succeeds locally and then
#: silently loses its input in the hosted evidence artefact. Anything unsafe is hashed — see
#: `Finding.fingerprint`.
_SAFE_TOKEN = re.compile(r"[A-Za-z0-9_-][A-Za-z0-9._-]{0,63}")

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
#: The maintainers' suite fails if a URL reappears here without one.


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
    a reproduction exists and was verified by something the agent could not write to. The separate capability sets it
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
    rule_title: str = ""
    #: **THE LOCATION IS THE ENTRY POINT THAT REPRODUCES THIS, NOT THE SITE OF THE DEFECT.** Declared by
    #: the producer, never inferred by the renderer.
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
    #: A verified immutable copy for simple-mode witnesses. Customer-authored entry points run with
    #: the same UID as this process, so a path can change after adjudication; reopening it at report
    #: time can never establish that the bytes copied are the bytes that were judged.
    poc_bytes: bytes | None = None
    reproduce_command: str = ""
    #: WHAT THE VERDICT WAS REACHED AGAINST — the checkout's `HEAD`, from `head_revision`, or `""` when
    #: this run could not name one. Third of the three things `README.md` says a bundle ships, and the
    #: one that was missing; `head_revision` has the measurement and what its absence costs.
    #:
    #: A RUN fact carried on the FINDING, and the alternative was worse. `RunFacts` is the record for
    #: per-run context and it never reaches `write_bundle`, which sees a `Finding` and a destination —
    #: so putting it there means either threading a second argument through `cliemit._emit` into every
    #: bundle write, or having the writer re-derive the repository by walking up from `dest`. The walk
    #: is a guess: `--out-dir` may sit outside the checkout, and the ancestor it would find then is a
    #: tree the verdict was never reached in. The producer already holds the real one.
    revision: str = ""
    container_digest: str = ""
    #: WHAT WAS OBSERVED — the output the entry point or the harness actually produced. Simple mode's
    #: counterpart to `sanitizer`, and never both: one is a crash report, the other is a captured
    #: stream, and they are the same claim from two mechanisms. It was captured, capped at 4,000
    #: characters, and then discarded: no report, no bundle, no payload carried it, so a reviewer was
    #: told "nonzero_exit was observed" and shown nothing. The design notes, "Found by the first
    #: PAID container run".
    evidence: str = ""
    #: The observation class and, for the marker arm, the exact marker that made this finding
    #: demonstrable. Replay cannot infer either from an exit code: ordinary input rejection is often
    #: non-zero, while an output-marker demonstration may exit zero.
    witness_expectation: str = ""
    witness_marker: str = ""
    witness_entry: str = ""
    witness_controls: tuple[str, ...] = ()
    #: WITHIN-RUN PROPOSAL ORDINAL — simple mode's 1-based order the claim behind this finding was
    #: proposed in. `rank` reads it as a STABLE tiebreak (below `replays`, above `fingerprint`) so a
    #: correction the model made after an earlier claim renders AFTER it, rather than wherever the two
    #: fingerprints happen to sort — the ordering half of the finding-revision batch.
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


def finding_names(findings) -> list[str]:
    """One name per finding, unique WITHIN a run: the fingerprint, numbered for a repeat.

    ONE DERIVATION, READ BY BOTH SIDES, and it exists because there were two. `cliemit._emit`
    numbered a repeated fingerprint's second bundle `<fp>-2` while `resultdoc._finding` re-derived
    `bundles/<fp>` unconditionally, so the canonical result document sent a consumer replaying the
    SECOND finding to the FIRST finding's input, and named the second directory in no artefact at
    all. Measured 2026-09-02 through `simple.adjudicate_all` and `cliemit._emit`, on two
    `fatal_signal` claims at one anchor: `bundles/42666e1d23297da8` (`b"AAA"`) and
    `bundles/42666e1d23297da8-2` (`b"BBB"`) on disk, both `reproduced[]` entries reading
    `bundles/42666e1d23297da8`, both `id`s `42666e1d23297da8`, and `-2` absent from the JSON, the
    SARIF and the markdown alike.

    A fingerprint repeats legitimately: identity names the defect SITE, so one defect demonstrated
    through two channels is one fingerprint and must stay ONE code-scanning alert
    (`simple._separate_anchor_collisions` keeps that collision on purpose). It is the WITHIN-RUN
    name — a directory, a dictionary key — that has to distinguish them.

    **Pass the CAPPED list, and pass the same one to both readers.** `cap` returns it already ranked
    and `rank` is a stable sort on a total key, so re-ranking is the identity and the two callers
    number the same findings in the same order. The suffix keeps the fingerprint's path-safe
    character set (`_SAFE_TOKEN`), because these names are path segments.

    Every kept finding is numbered, including one that gets no bundle written: a hypothesis with no
    candidate input shares its anchor with the demonstration beside it, so leaving it out of the
    count would hand two entries of one document the same `id` again.

    **Reserve every base fingerprint before adding suffixes.** A run containing `fault`, `fault` and
    the legitimate fingerprint `fault-2` used to allocate `fault`, `fault-2`, `fault-2`; the last
    bundle removed and replaced the second one's proof. Stable cross-run identity remains the base
    fingerprint. Only the within-run directory/id skips occupied base and generated names.
    """
    fingerprints = [f.fingerprint for f in findings]
    reserved = set(fingerprints)
    used: set[str] = set()
    next_suffix: dict[str, int] = {}
    names: list[str] = []
    for fingerprint in fingerprints:
        if fingerprint not in used:
            name = fingerprint
        else:
            suffix = next_suffix.get(fingerprint, 2)
            name = f"{fingerprint}-{suffix}"
            while name in reserved or name in used:
                suffix += 1
                name = f"{fingerprint}-{suffix}"
            next_suffix[fingerprint] = suffix + 1
        used.add(name)
        names.append(name)
    return names


# --- SARIF -------------------------------------------------------------------------------------------

def build_sarif(findings, *, limit: int = DEFAULT_SARIF_CAP, status: str = "done") -> dict:
    """SARIF 2.1.0 for upload to code scanning.

    **`invocations[].executionSuccessful` is how a run that did not finish stops looking like a clean
    one.** The design notes: an errored run wrote `results: []` and reported `findings: 0`,
    byte-for-byte what a completed audit that found nothing reports. The markdown said so and nothing a
    CI consumer reads did — the check was green and code scanning showed nothing new.

    The exit code stays 0 and that is deliberate, not an oversight: the integration guide's first
    promise is that installing Shard does not break the build, and a transient endpoint failure must
    not fail somebody's pull request. Whether an internal error should EVER be allowed to gate remains
    the owner's call and is still recorded as open. This closes the half that needs no ruling — the run
    says what happened, in the channel built for saying it.
    """
    kept, _dropped = cap(findings, limit)
    # GROUPED BY RULE ID FIRST. The rule's `properties` must be true of every alert filed under it,
    # and reading them off the first member stamped one defect's CWE and severity onto the whole
    # bucket — which matters most for `shard/reproducing-input`, the neutral id 29 of the 42 crash
    # classes fall into, spanning all three severity bands.
    by_rule: dict[str, list] = {}
    for f in kept:
        by_rule.setdefault(f.rule_id, []).append(f)
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
            # PER-RULE, and it was the last class-level field still read off ONE member. `rank` puts
            # the gate-eligible findings first, so a bucket holding a demonstration and a refuted
            # claim shipped `level: error` beside its own `problem.severity: recommendation` — one
            # rule object contradicting itself in the two fields GitHub ranks and filters on.
            "defaultConfiguration": {
                "level": "error" if _rule_all_reproduced(by_rule[f.rule_id]) else "note"},
        }
        rule["properties"] = _rule_properties(by_rule[f.rule_id])
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


def _rule_all_reproduced(group) -> bool:
    """Does EVERY alert of this rule carry a reproduction? The ONE predicate the rule's class-level
    fields are decided by — `defaultConfiguration.level` here and `precision`/`problem.severity` in
    `_rule_properties`.

    It is a function rather than the expression written twice because those three fields ARE one
    statement about the class, and they were made from two readings: the properties took the whole
    group and the level took the FIRST member, so `rank` putting the gate-eligible finding first
    produced a rule object saying `level: error` beside `problem.severity: recommendation` and
    `precision: medium`. Measured 2026-09-02 in an emitted artefact, on a free-tier run with one
    demonstrated and one refuted `output_marker` claim.
    """
    return all(f.gate_eligible for f in group)


def _rule_properties(group: "list[Finding]") -> dict:
    """The rule's `properties` bag — the two fields GitHub code scanning RANKS and FILTERS on, plus
    the one that says how much to trust the alert.

    The design notes A4: a Shard rule arrived in the Security tab carrying only a
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

    **AND IT TAKES THE WHOLE GROUP, because it used to take the FIRST finding and stamp its values on
    every alert of the rule.** The invariant above was stated and not enforced. `_rule_id` returns the
    neutral `shard/reproducing-input` for every crash class outside `_crash_title`'s eleven-string
    list — 29 of the 42 classes `crashstate` can name, spanning all three severity bands — so on a
    sweep with more than one defect in that bucket, every alert but one was filed in the customer's
    Security tab under ANOTHER defect's CWE at ANOTHER defect's severity. Which one won was decided by
    the oracle's behaviour-signature hash, through `rank`'s final tie-break.

    A field that is not true of every member is DROPPED rather than guessed. An alert with no
    `security-severity` sorts by `problem.severity` — GitHub's documented fallback — which is a worse
    ranking than a correct number and a much better one than a confident wrong number.
    """
    states = [f.crash for f in group]
    # The intersection, order-preserving from the first member so the output is stable.
    common = set(states[0].tags).intersection(*(set(s.tags) for s in states[1:])) if states else set()
    props: dict = {
        "tags": [tag for tag in states[0].tags if tag in common] if states else [],
        # CodeQL's convention, and the field GitHub falls back to when there is no security-severity.
        # ANY member that cannot gate pulls the rule down: claiming `very-high` precision for a bucket
        # that contains an unreproduced hypothesis is the same overclaim one level up.
        "problem.severity": "error" if _rule_all_reproduced(group) else "recommendation",
        "precision": "very-high" if _rule_all_reproduced(group) else "medium",
    }
    severities = {s.security_severity for s in states if s.security_severity}
    if len(severities) == 1 and len(severities) == len({s.security_severity for s in states}):
        # A STRING, which is the schema's type and not a stylistic choice: GitHub parses this field
        # as text and a JSON number is silently ignored, which loses the ranking without an error.
        props["security-severity"] = severities.pop()
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

    #: Did the run use every execution the ceiling allowed? `None` where the artefact cannot say, and
    #: the three-way split is the point — see `sandbox.ExecState.spent`. A run that spent its whole
    #: budget was reported as a `complete run` on 2026-09-03 while its own last turn opened "I have no
    #: tool budget left", because the only signal anything read was `refused`, and the model is told
    #: how many calls remain so it stops asking rather than being denied.
    executions_spent: bool | None = None
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
    #: for the clock, `--max-tokens` for tokens. The maintainers' notes records the cost of telling a
    #: customer to raise the wrong ceiling — `--max-spend-usd` is inert on an unpriced route, and
    #: `cli.py` advised raising it anyway.
    limit_hit: str = ""
    #: The flag THIS MODE offers for raising its step ceiling, or `""` when it offers none. Supplied by
    #: the caller, because the caller owns the parser and the renderer cannot know what a mode accepts.
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
    #: CHANGES A FINDING. A measured run: on the first paying engagement the
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
    #: The design notes A3 measured the gap it names — `--state-repo` exists on
    #: `diff` and is absent from `deep`, so every deep run starts from nothing — and the free tier has
    #: said so in its own step log since state existed (*"no state repository configured; nothing will
    #: accumulate between runs"*). A consumer of the artefacts could not read it anywhere, which is
    #: this class's founding defect: a fact the run knows, in a channel that is deleted with the runner.
    stateful: bool | None = None
    #: This is a measured source-read inventory, not a replacement meaning for files_reviewed.
    inspection: dict | None = None


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


def _trust_row(status: str, *, executions_spent: bool | None = None) -> str:
    if status in COMPLETED_STATUSES and executions_spent:
        # **A COMPLETED STATUS IS NOT A COMPLETE RUN when the execution ceiling was spent in full.**
        # This row said `complete run` over a review that stopped at model turn 20 of 40 with 24 of 24
        # executions used — measured 2026-09-03 — because the status is decided by how the loop ENDED
        # and the loop ended by choosing to stop. It chose to stop because it had nothing left to run.
        return (f"**complete status (`{status}`), SPENT EXECUTION BUDGET** — every execution the "
                f"ceiling allowed was used, so this run may have stopped early. Raise `--max-steps`")
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
    fact a reader weighing an unverified finding needs most, and the signal the maintainers' notes' standing
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

    rows = [("verdict", verdict),
            ("trust", _trust_row(status,
                                 executions_spent=run.executions_spent if run else None))]
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
        rows.append(("scope", f"{run.files_reviewed} changed file(s){against}"))
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
    # `target.VUL_IMAGE_RE` (`cgmask-…:vul`), the benchmark/ARVO convention. That is a property of the
    # TARGET, not of the box, and no customer repository has one. Asked directly whether a paid GitHub
    # runner would help, the honest answer is no, and the report was saying otherwise.
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


#: How many ranked candidates the HUMAN report lists. Measured 2026-09-02 by running the real
#: `shard survey` CLI at each cap over two checkouts — `libgit2` (744 candidates) and `facebook/zstd`
#: (515) — against `grep -cE 'lib/|src/|\.c:|:[0-9]+'`, which is the check F6 failed:
#:
#:     cap     libgit2      zstd     locations in the report
#:     none    1,582 B    2,202 B    0     ← F6, and the pointer-only fix scores the same 0
#:       10    2,160 B    2,914 B    10
#:       20    2,708 B    3,541 B    20
#:       50    4,422 B    5,863 B    50
#:      200   12,866 B   14,704 B    200
#:
#: **20, because a longer list here is the same undifferentiated set, longer.** `_rank_spread` states
#: the reason in `shard/survey.py`: the rank answers "could we prove it HERE", which is a property of
#: the build and not of the candidate, so on a repository with no declared entry point every candidate
#: carries one label and one reason. Extending the list adds rows, not discrimination. What the human
#: artefact owes its reader is that locations EXIST and a sample they can open now; the complete
#: answer is `shard-survey.json`, one file away, and it is what a tool should read.
#:
#: 20 roughly doubles the report on both targets and leaves it readable in a pull-request comment.
#: **Rejected: 200**, the JSON's cap — 12.9 KB of paths is a file, not a comment. **Rejected:
#: `DEFAULT_SARIF_CAP`** — 500 exists for code scanning's per-run alert limit, a constraint about
#: GitHub's API that says nothing about what a person will read.
#:
#: **It is a SAMPLE and the report has to say so.** Measured on the same two runs, the top 20 cover 2
#: of libgit2's 5 candidate kinds and 3 of zstd's 4, so a reader who takes the list for the set
#: mis-reads the scan. Saying "744 candidates" and listing 20 in silence is F23 one artefact over; the
#: `where` row is where this one says it.
SURVEY_CANDIDATES_IN_REPORT = 20


def _survey_where(ranked) -> str:
    """The header row that answers "where is the attack surface" — F6's whole subject.

    NAMING THE SIBLING IS A FACT, NOT A GUESS: `shard/cli.py` writes `shard-survey.json` into the
    `--out-dir` immediately above its only call to `build_survey_markdown`, inside the same
    `if args.out_dir:` branch, so the file this row names exists whenever this row is rendered.

    **NAMING IT WAS THE WEAKER HALF OF F6 AND IT SHIPPED ALONE FOR A DAY.** The finding's Expected
    offered two remedies — carry the top-ranked candidates with path and line, or point at the JSON —
    and only the pointer landed. Measured on the pointer-only report: `grep -cE 'lib/|\\.c:|:[0-9]+'`
    over `shard-report.md` still printed 0 on libgit2's 744 candidates. A pointer answers "where are
    the locations kept"; the customer asked where the attack surface is, and `README.md` is what
    promised them that.

    THE CAP BELONGS IN THE SAME SENTENCE, because a list under a cap that does not say so is read as
    the set. Two caps are in play and they are different numbers: this report's
    `SURVEY_CANDIDATES_IN_REPORT` and the JSON's own. Same zstd run: the JSON's `provenance` read
    `{'source': 358, 'test': 157}` over all 515 while its 200-row `candidates` array held
    `{'source': 200}` — a consumer grouping the array and a consumer reading the aggregate get two
    different breakdowns of one scan.

    **"THE 20 HIGHEST-RANKED" WAS A DESCRIPTION OF A SLICE, and it shipped for a day.** Measured
    2026-09-02 on the rebuilt artefact: on `libgit2` all 20 rows were in the vendored test framework
    and the benchmark scripts, with zero of the 415 candidates under the library's own `src/`; on
    `facebook/zstd` all 20 were in `contrib/` and none of the 148 under `lib/`; on a third target all
    20 were `parser` under one `examples/` subtree out of 1,906 candidates spanning 10 kinds. Every
    location printed was verbatim-correct — the SELECTION is what failed, and the row asserted a
    property of the selection that the run had not established.

    It happens because the rank answers *"could we prove it HERE"*, which is a property of the BUILD
    and not of the candidate (`survey._rank_spread` states this), so on a repository with no declared
    entry point every candidate carries one label. The list is still ordered by whatever key the
    assessment applies below the rank; it is simply not ordered BY RANK, and a reader who takes
    "highest-ranked" at face value concludes the attack surface is wherever that key happened to start.

    THE TIE IS MEASURED, NOT ASSUMED. This function reads `ranked` structurally and does not know the
    ordering key — `shard/survey.py` owns that and may change it. What it can check is the one thing
    the claim depends on: whether the candidate at the cut and the first one below it carry the SAME
    rank. If they do, nothing in the block outranks anything left out, whatever ordered them.

    **THE TOTAL IS HERE NOW, and the rule it appears to break is the reason.** The docstring used to
    say *"NO TOTAL HERE. It is in `summary`, four lines down, and a count lives in one place because
    the second copy is what drifts."* A count does. `20 of 744` is not a count, it is the RATIO that
    makes the block legible as a sample, and it cannot drift from `summary`'s: `summarise` prints
    `len(assessment.ranked)` and this reads `len(ranked)`, the same sequence in the same call.
    """
    total = len(ranked)
    listed = min(total, SURVEY_CANDIDATES_IN_REPORT)
    where_the_rest_is = (
        "`shard-survey.json`, written beside this report, carries the same ordering under its OWN "
        "larger cap, with each candidate's kind and matched line; read its `omitted` for how many "
        "fell below that one")
    if not listed:
        return "**this report counts; it names no file.** Nothing was ranked"
    if listed == total:
        return f"**all {total} candidate(s) are listed below, with path and line.** {where_the_rest_is}"
    if ranked[listed - 1].rank == ranked[listed].rank:
        return (f"**{listed} of {total} candidates are listed below, with path and line — a SAMPLE, "
                f"not the top of a ranking.** The cut falls inside a tie: the {listed}th and the first "
                f"one left out carry the same rank, so nothing in this block outranks what is missing "
                f"from it, and reading it as *where the attack surface is* would be wrong. "
                f"{where_the_rest_is}")
    return (f"**the {listed} highest-ranked of {total} candidates are listed below, with path and "
            f"line** — a sample; the rank separates them from the {total - listed} not shown. "
            f"{where_the_rest_is}")


def _survey_candidates(ranked) -> list[str]:
    """The top `SURVEY_CANDIDATES_IN_REPORT` as `rank kind path:line`, fenced.

    **FENCED AND NOT A MARKDOWN TABLE**, which is a security choice rather than a layout one. These
    paths come from walking the target's checkout, so `|` and a backtick are both legal bytes in one:
    a table row breaks on the first and a code span on the second, and `_fence_for` is the defence this
    file already uses for target-derived text. `prompt_safe` on top of it, because a path may contain a
    NEWLINE — `diffscope.prompt_safe` records what that cost one tier over — and a line break here
    would silently split one candidate into two.

    Fixed-width columns lead so the variable-length path cannot ragged them, matching `summarise()`.
    """
    body = "\n".join(f"{r.rank:<11}{r.surface.kind:<16}{prompt_safe(r.surface.path)}:{r.surface.line}"
                     for r in ranked[:SURVEY_CANDIDATES_IN_REPORT])
    fence = _fence_for(body)
    return [fence, body, fence, ""]


def _survey_trust(truncated: bool, partial_files: int) -> str:
    """*Can I believe these counts* — the row a reader checks first, and it said yes over a floor.

    **TWO CEILINGS, AND THIS ROW COULD ONLY SEE ONE.** `truncated` is the 4,000-FILE walk ceiling.
    `survey.Survey.files_read_in_part` counts files the walk opened and did not finish, past
    `MAX_FILE_BYTES` or past `MAX_HITS_PER_FILE` — a different ceiling, added when the first one was
    found to hide a sample behind a total, and it reached the blind-spot list and not this row.

    Measured 2026-09-02 on `facebook/zstd` and on `libgit2`: header row `| trust | complete scan |`,
    and eight lines below it, in the same file, *"10 file(s) were read only in part … so every count
    above is a floor for them"*. Both halves of one table, disagreeing, with the affirmative one on top.
    Reproduced deterministically on one 336,043-byte `.c` file whose only `strcpy(` sits past 262,144:
    `candidates 0`, `trust | complete scan`.

    NO BYTE NUMBERS HERE. `MAX_FILE_BYTES` and `MAX_HITS_PER_FILE` belong to `shard/survey.py` and the
    blind-spot line under this table already prints both; a second copy in this module is the
    two-spellings drift `_survey_where` above records, over constants this file does not own.
    """
    if truncated and partial_files:
        return (f"**TRUNCATED — every count below is a floor.** The scan hit its file ceiling before "
                f"the repository ended, and {partial_files} of the files it did reach were read only "
                f"in part")
    if truncated:
        return ("**TRUNCATED — every count below is a floor.** The scan hit its own limit before the "
                "repository ended")
    if partial_files:
        return (f"**a floor for {partial_files} file(s), complete for the rest.** Those {partial_files} "
                f"were read only in part — past the byte or the per-file candidate ceiling the scan "
                f"stops, so a marker beyond it was never reached rather than absent. The blind spots "
                f"below name both ceilings")
    return "complete scan"


def build_survey_markdown(summary: str, *, target: str = "", truncated: bool = False,
                          report_ident: str = "", ranked=(), partial_files: int = 0,
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

    **IT ANSWERED "HOW MANY" AND NEVER "WHERE", AND SAID SO NOWHERE.** Measured 2026-09-02 on
    `facebook/zstd`: 515 candidates, a 1,907-byte report, and `grep -cE 'lib/|\\.c:|:[0-9]+'` over it
    printed 0 — no path, no line. Naming `shard-survey.json` was the first half of that fix and the
    same grep still printed 0, on libgit2's 744: a report that says where the locations are kept is
    not a report that has any. `ranked` is the second half, and it is why this function takes the
    candidates rather than only the string `summarise()` made of them.

    `ranked` is a sequence of `survey.RankedSurface`, read STRUCTURALLY and never imported — this
    module is below `shard/survey.py` and stays there. Empty is the honest default: a caller with no
    assessment renders the report it rendered before.

    `partial_files` is `Survey.files_read_in_part`, passed in for exactly the reason `truncated` beside
    it is: the caller owns the scan and this module renders what it is handed. See `_survey_trust` for
    what the row said while it could see only one of the two ceilings.
    """
    verdict = ("**survey only — nothing here is a finding.** A survey reads the source and names "
               "candidates; proving one takes a run that can execute something")
    rows = [("verdict", verdict), ("trust", _survey_trust(truncated, partial_files)),
            ("where", _survey_where(ranked)),
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
    # THE LOCATIONS, below the counts they are a sample of. Its own fenced block rather than more rows
    # in the header table: the header answers "what is this artefact", and a list of twenty file paths
    # in it would bury the three sentences that do.
    if ranked:
        out += _survey_candidates(ranked)
    if not witness_entry:
        # "EVERY CANDIDATE ABOVE" NAMED NOTHING. There is no candidate above — the block above is
        # `summarise()`, which is counts. The sentence read as a reference to a list the artefact has
        # never carried, and a reader who went looking for it found the table, the counts and the end
        # of the file. It points at the file that does carry them now.
        out.append("**To make any of this provable, declare an entry point.** A file at "
                   "`.shard/entry.sh` that Shard may run against one untrusted input, and a "
                   "`.shard/entry.sh.benign/` directory of inputs containing no attack, one per "
                   "branch the entry point can take. Without it every candidate in "
                   "`shard-survey.json` stays a candidate and nothing can fail a build.")
        out.append("")
    return "\n".join(out) + "\n"


def build_markdown(findings, *, status: str, dropped: int = 0, target: str = "",
                   gate_reasons=(), scope_reasons=(), run: RunFacts | None = None,
                   bundle_names: dict[int, str] | None = None) -> str:
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
    # THE BUNDLE DIRECTORY NAMES, from the one derivation, so the report can NAME the artefact it has
    # been telling reviewers about. `finding_names`' own docstring sets the condition — *"pass the
    # CAPPED list, and pass the same one to both readers"* — and `cliemit._emit` passes `cap(findings)`
    # to it while `resultdoc` numbers the same list again. `rank` is a stable sort on a total key over
    # a list `cap` already ranked, so all three number the same findings in the same order.
    derived = finding_names(ordered)
    named = [(f, (bundle_names or {}).get(id(f), name))
             for f, name in zip(ordered, derived)]
    reproduced = [pair for pair in named if pair[0].gate_eligible]
    hypotheses = [pair for pair in named if not pair[0].gate_eligible]

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

    if run and run.inspection is not None:
        out += inspection_markdown(run.inspection)
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
    for f, name in reproduced:
        out += _finding_block(f, reproduced=True, bundle=name)
    for f, name in hypotheses:
        out += _finding_block(f, reproduced=False, bundle=name)

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
        because = " " + _advice_sentence(TRANSPORT_ERROR_ADVICE[error_kind])
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


def _finding_block(f: Finding, *, reproduced: bool, bundle: str) -> list[str]:
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
    # the bundle record and the doubts — and never `location` or `line`. The location reached the
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
        # **THE REPORT USED TO TURN AN AUDIT RECORD INTO AN EXECUTION INSTRUCTION.** It printed
        # `sh bundles/<name>/reproduce.sh`, and neither the downloaded directory nor the script inside
        # it carries producer authentication — a direct shell invitation across the credential boundary,
        # onto whichever host the reviewer happened to read the report on. The documentation verifier
        # built around that command accepted deterministic input, script, product, and post-validation
        # path swaps (an internal audit enumerates the four), so it
        # was removed rather than patched into a second adjudicator. Naming the bytes and the
        # observation keeps them visible without claiming that executing an untrusted bundle
        # re-establishes the verdict.
        #
        # THE PROCEDURE IS NAMED AND ITS PATH IS NOT. The guide ships: `packaging/the design notes, and
        # the free build script emits that whole directory as `docs/`. But this markdown is read in a pull
        # request and out of an artefact zip, where a source-tree documentation path resolves to
        # nothing, so the report names the guide and never a path to it.
        #
        # WHAT THE GUIDE OFFERS BOUNDS WHAT THIS BLOCK MAY ASK FOR. `replay.md` states that no trusted
        # acquisition or replay command ships, and that a post-download checksum "does not prove who
        # produced them": retention and inspection are what a reader can actually carry out, so the
        # sentence below asks for those and does not tell anyone to authenticate a producer the
        # shipped procedure cannot authenticate. Replay is the half that does NOT ship —
        # `_bundle_metadata` records the observation class, the marker and the control NAMES, and
        # nothing here adjudicates them — which is why this block stops at retention.
        #
        # The bundle path is exact rather than a guess, in the same way `_survey_where` naming its
        # sibling is: `cliemit._emit` writes `shard-report.md` and `bundles/` into the one `out_dir`,
        # and `resultdoc` derives `reproduction.bundle` from the same `finding_names` value, so the two
        # artefacts name one directory.
        out += ["Safe acquisition required", "",
                "`reproduce.sh` is the command recorded for this finding, not an independent replay "
                "verifier; do not execute it on a workstation or in a credentialed job. Keep the "
                "bundle with the run that produced it and retain and inspect it as the "
                "version-matched finding-bundle guide shipped with Shard directs; that guide also "
                "states what retention can and cannot establish about the producer and the source "
                "bytes. This build ships no independent replay verifier: stop after acquisition and "
                "do not use this bundle as a gate.", "",
                f"`bundles/{bundle}/` sits beside this report and holds `reproduce.sh`, `input`, "
                f"`output.txt` when captured, and `metadata.json`.", ""]
    if f.doubts:
        # Advisory by construction — `Verdict.doubts` cannot change `reproduced`. Surfaced because a
        # human reviewer should see what the oracle was unsure of, not because it downgrades anything.
        out.append("Oracle notes (advisory; these did not affect the verdict):")
        out += [f"- {d}" for d in f.doubts] + [""]
    return out


# --- the reproduction bundle -------------------------------------------------------------------------

#: A full commit object name and nothing else. `head_revision`'s output is written into a file the
#: reviewer EXECUTES, so what it returns is validated rather than trusted: git is a subprocess whose
#: stdout this module does not own, and `shlex.quote` at the call site is the second layer, not the
#: first. Full 40 hex and not an abbreviation — the design notes' own release note records what an
#: abbreviated SHA cost when it was allowed to stand for a commit.
_FULL_SHA = re.compile(r"[0-9a-f]{40}\Z")


def head_revision(repo) -> str:
    """The commit `repo` is checked out at, or `""` when nothing here can say.

    **The bundle promised this and did not carry it.** `README.md` ships the sentence *"Every reported
    finding ships a reproduction bundle: the input, the exact command, and the revision it was produced
    against"*, and `write_bundle`'s own docstring repeats the claim. Measured 2026-09-02 against the
    rebuilt 2.4.1 artefact: `grep -roE '\\b[0-9a-f]{40}\\b' <ws>/shard-out/bundles/` exited 1 with no
    output, and `metadata.json`'s twelve fields held no revision under any spelling. Two of the three
    shipped.

    **What the missing third costs is F3 restored by another route.** The bundle's program resolves the
    checkout it was unpacked into and runs the entry point there, which is right — and it will run
    whatever tree is checked out. A reviewer on another branch, or replaying a week later, gets rc=0
    with no marker: *"indistinguishable from this finding does not reproduce"*, which is the signature
    F3 was raised for, with nothing in the bundle to check against. Measured on the same artefact: the
    unmodified bundle replayed against the pre-sink revision printed the entry point's ordinary output
    at rc=0, marker absent, exit code identical to the successful reproduction.

    **`git rev-parse HEAD` and not a read of `.git/HEAD`, deliberately.** The reviewer's half of the
    check is `git -C "$root" rev-parse HEAD` inside `_REPRODUCE_SH` — a shell has no ref resolver — so
    reading the plumbing here would answer the same question with a second, worse git: a symbolic
    `HEAD`, `packed-refs`, a `.git` FILE in a worktree and a detached checkout are four shapes to get
    right, and getting one wrong makes the two halves disagree about a tree that has not moved. One
    command, both sides.

    Silent on every failure, and that is the honest shape rather than a swallowed error: a tarball
    export, a `docker build` context and a workdir copy all legitimately have no revision, and that capability's prepared workdir is VCS-stripped by construction. `""` records "nobody knows", which is what
    `metadata.json` then says and what makes the script's check skip instead of firing on nothing.
    """
    if not repo:
        # `None`, and it is a real caller rather than a defensive guard: `simple.adjudicate_all` is a
        # public entry point whose `repo` is optional — a hand-built claim from a test, a replay, or
        # the PR path may have no checkout — and `safe_directory_argv` would raise `TypeError` on it,
        # which is neither `OSError` nor a `SubprocessError` and would escape the handler below.
        return ""
    try:
        done = subprocess.run([*safe_directory_argv(repo), "-C", str(repo), "rev-parse", "HEAD"],
                              capture_output=True, text=True, errors="replace", timeout=30)
    except (OSError, subprocess.SubprocessError):
        # No git on PATH, or a `repo` that is not a directory. Both mean the same thing to a reader of
        # the bundle: this run could not name the revision, so nothing downstream may claim it did.
        return ""
    revision = done.stdout.strip()
    return revision if done.returncode == 0 and _FULL_SHA.match(revision) else ""


def _bundle_input_bytes(finding: Finding, require_input: bool) -> bytes | None:
    if require_input and finding.poc_bytes is None:
        raise FileNotFoundError(
            "the demonstrated finding has no immutable reproducing input to attach")
    if finding.poc_bytes is not None:
        return finding.poc_bytes
    if not finding.poc_path:
        return None
    try:
        return pathlib.Path(finding.poc_path).read_bytes()
    except OSError:
        # A missing hypothesis input leaves a legible metadata-only bundle. Gate-eligible callers use
        # immutable `poc_bytes`, so their missing input was refused before this read.
        if require_input:
            raise
        return None


def _bundle_metadata(finding: Finding, *, input_present: bool, output_present: bool) -> bytes:
    return json.dumps({
        "rule_id": finding.rule_id,
        "title": finding.title,
        "reproduced": finding.gate_eligible,
        "signature": finding.fingerprint,
        "sanitizer": finding.sanitizer,
        "replays": finding.replays,
        "crash_count": finding.crash_count,
        "container_digest": finding.container_digest,
        "reproduce_command": finding.reproduce_command,
        "input_present": input_present,
        "output_present": output_present,
        "witness_expectation": finding.witness_expectation,
        "witness_marker": finding.witness_marker,
        "witness_entry": finding.witness_entry,
        "witness_controls": list(finding.witness_controls),
        # Empty says this run could not name a revision; the acquisition procedure then refuses to
        # authenticate the bundle. See `head_revision`.
        "revision": finding.revision,
        "doubts": list(finding.doubts),
    }, indent=2, sort_keys=True).encode("utf-8")


def _bundle_file_size(dest_fd: int, name: str) -> int:
    """Inspect one bundle child through a no-follow descriptor, including zero-byte inputs."""
    flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(name, flags, dir_fd=dest_fd)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise OSError("bundle child is not one regular single-link file")
        return info.st_size
    finally:
        os.close(fd)


def _write_bundle_fd(finding: Finding, dest_fd: int, *,
                     require_input: bool = False) -> dict[str, bytes]:
    """Write one bundle below a held directory and return the authoritative source bytes."""
    source = _bundle_input_bytes(finding, require_input)
    files: dict[str, tuple[bytes, int]] = {}
    if source is not None:
        files["input"] = (source, 0o644)
    if finding.evidence:
        # WHAT WAS OBSERVED, in full. A reviewer who cannot run the entry point has nothing else.
        files["output.txt"] = (finding.evidence.encode("utf-8"), 0o644)
    files["metadata.json"] = (
        _bundle_metadata(finding, input_present=source is not None,
                         output_present=bool(finding.evidence)),
        0o644,
    )
    if finding.reproduce_command:
        # The title is model prose. `_shell_comment` prevents an interior newline from turning a
        # comment into a command; atomic creation with 0755 keeps the shebang's executable promise.
        script = f"#!/bin/sh\n{_shell_comment(finding.title)}\n{finding.reproduce_command}\n"
        files["reproduce.sh"] = (script.encode("utf-8"), 0o755)
    for name, (data, mode) in files.items():
        _atomic_write(dest_fd, name, data, mode=mode)
    for name, (data, _mode) in files.items():
        if _bundle_file_size(dest_fd, name) != len(data):
            raise OSError(f"bundle file {name!r} changed during publication")
    if require_input and "input" not in files:
        raise OSError("the reproduction bundle was written without its required input")
    return {name: data for name, (data, _mode) in files.items()}


def write_bundle(finding: Finding, dest, *, require_input: bool = False) -> pathlib.Path:
    """Write the crashing input, command, observation and target identity through a held directory.

    The path API remains for direct hypothesis/replay callers. The Action emitter calls the descriptor
    form above while it holds a private staging directory, so a same-run process cannot redirect a
    child write through a symlink between files.
    """
    dest = pathlib.Path(dest)
    with _trusted_directory(dest, create=True) as (_held_path, dest_fd):
        _write_bundle_fd(finding, dest_fd, require_input=require_input)
    return dest


def _shell_comment(text: str) -> str:
    """`text` as `sh` comment lines that nothing in `text` can break out of.

    **The class, and it is measured rather than assumed.** Probed 2026-09-02 with `# X<byte>echo
    OWNED` against `sh`, `bash`, `dash` and `busybox sh`: of `\\n \\r \\v \\f \\t \\x00 \\x1c \\x1d
    \\x1e \\x85 \\u2028 \\u2029 ; &`, **`\\n` alone ended the comment** and all four shells agreed.
    So a title with no uncommented newline in it cannot reach executable position whatever else it
    contains — `;`, `&` and `$(…)` included.

    `str.splitlines` and not `text.split("\\n")`, knowing that: it ALSO breaks on the eight inert
    bytes above, which costs an extra comment line and cannot admit one. Wrong in the safe direction
    for a file the reader is told to run, and it survives a shell that disagrees with those four.
    """
    return "\n".join(f"# {line}" for line in (text.splitlines() or [""]))



# --- shaping a solver result into findings, moved out of cli.py 2026-08-21 ------------------

#: The token every other artefact of a bundle already uses for the reproducing input: `write_bundle`
#: stores the payload as `input`, and `_REPRODUCE_SH` reads it as `"$here/input"` — the same one file,
#: resolved from the script rather than from a cwd. Rewriting the staged path onto this token is what
#: makes `output.txt` and `reproduce.sh` — two files in one directory — name one file rather than two.
#:
#: **`./input` STAYS THE SPELLING even though the script no longer uses it**, because this token is
#: written into OBSERVED OUTPUT (`staged_relative` rewrites the runner's staging path out of what the
#: entry point printed), not into a command. It is the reader's name for the file beside the evidence.
STAGED_INPUT_TOKEN = "./input"

#: The bundle's reproduce script, below an `entry=<shell-quoted path>` line the caller prepends.
#: **ONE DEFINITION SINCE 2026-09-02, imported by `shard/simple.py`** — see the note under the
#: program on why a pinned duplicate was the wrong end state.
#:
#: The defect it exists for was fixed on the free tier on 2026-09-02 and left standing here for a day.
#: What shipped in a deep bundle was `bash <harness> ./input`: the harness is repo-root-relative
#: (`target` declares it) and `input` is written INSIDE the bundle by `write_bundle`, so the one
#: command resolves from no working directory at all. Measured 2026-09-02 through `_findings` and
#: `write_bundle`, against a harness that crashes on the bundle's own bytes:
#:
#:     from the repository root      rc=0, no output      `./input` is not there; nothing was parsed
#:     from the bundle directory     rc=127               `bash: harness/run.sh: No such file`
#:     both paths resolved by hand   rc=-11, SHARD42      the reproduction itself is real
#:
#: The free tier's own three rows, on a bundle emitted through `simple._to_finding` against a
#: parser-shaped entry point, are the same shape: rc=0 no output / rc=127 `.shard/entry.sh` / rc=139
#: SHARD42. The first row is the defect; the second is only its symptom. rc=0 with no output is the
#: exact signature of "this finding does not reproduce", in the artefact `README.md` calls the
#: distinguishing one, handed to a reviewer looking at a build Shard has just failed.
#:
#: The walk up from the bundle is what lets it run from any directory without anyone being told a cwd,
#: since `write_bundle`'s destination sits under the checkout. POSIX `sh`, because `write_bundle`
#: writes a `#!/bin/sh` header over it; `bash` and `--` in the exec match the argv
#: `witness.adjudicate` actually ran, so the command a reviewer executes is the one the verdict was
#: reached on rather than a second spelling of it.
#:
#: **RESOLVING THE TWO PATHS WAS HALF THE FIX, and the missing half shipped for a day.** Absolute
#: paths make the program find its own two files; they say nothing about the directory the ENTRY
#: POINT resolves ITS paths from, and an entry point that reads a repo-relative sibling is ordinary —
#: a config file, a build product under `./build/`, a sourced helper. The verdict was NOT reached in
#: the reviewer's shell: `witness.adjudicate` runs the free entry point with `cwd=str(repo)` and
#: the separate package runs the harness with `cwd=str(workdir)`. Measured 2026-09-02 through
#: this constant, over five cwd-sensitive entry points x six directories a reviewer can be in
#: (the checkout root, the bundle, the bundle's parent, a checkout subdirectory, the checkout's
#: parent, an unrelated directory): **25 of 30 rows did not reproduce, every one of them at rc=0 with
#: no output** — F3's own signature, restored by the cwd alone. Only the checkout root worked, and it
#: is the one place nothing tells the reviewer to stand.
#:
#: `cd -- "$root"` is not a preference: `$entry` is spelled repo-root-relative by whoever declared it,
#: so the checkout root is the ONE directory in which that spelling is meaningful, in both tiers. No
#: `CDPATH=` on it — measured with `CDPATH` exported and the run was unaffected, because `$root` is
#: absolute and POSIX forbids the search for an absolute operand. The `here=` line one above needs it:
#: `dirname -- "$0"` is relative whenever the reviewer invokes the script by a relative path.
#:
#: WHAT THE CLAIM ABOVE THIS ONE USED TO SAY, and what it may say now. `simple._REPRODUCE_SH` asserted
#: "a half that does not resolve exits 2 with a sentence on stderr — so this can no longer look like a
#: clean run when it has run nothing", and that was measured FALSE on 2026-09-02: both halves resolved,
#: both guards passed, and the run was a silent no-op at rc=0 because the cwd was wrong. What holds
#: after the `cd` is narrower and checkable: **each of the two things THIS PROGRAM LOOKS FOR — the
#: entry point and the input — exits 2 with a sentence naming it when it cannot be had,** and 30 of 30
#: rows of the matrix above now reproduce. It says nothing about the entry point's own
#: preconditions: an unbuilt target, a missing environment variable or an absent container still decline
#: however the customer wrote them to, and this program cannot build a checkout.
#:
#: **TWO AND NOT THREE, because the `cd` CARRIES NO SENTENCE — a measurement, not an omission.** It
#: shipped for a day with one, *"$root is not enterable; the entry point resolves its own relative
#: paths from there"*, and no state of any bundle can print it: `[ -f "$root/$entry" ]` two lines above
#: cannot be true unless `$root` has the search bit, and the search bit is the only permission `cd`
#: needs. Probed 2026-09-02 as uid 1000 over eleven modes on `$root` (000 100 200 300 400 500 600 700
#: 111 444 555), a `$root` that is a symlink to the directory, and a `$root` under a parent without
#: `x`: **the two agreed on all thirteen rows**, PASS with PASS and FAIL with FAIL. A diagnostic that
#: cannot fire is worse than none, because the next reader takes the sentence as evidence the case was
#: handled, and when this was found the phrase occurred exactly once in `shard/` and `tests/` — here,
#: in the constant, with no test naming it.
#:
#: `|| exit 2` STAYS, and it is the same shape the `here=` line already uses. `sh` without `set -e`
#: runs on after a failed `cd`, so a bare one would `exec` from `$here` and restore exactly the silent
#: wrong-cwd no-op this line exists to close. Nothing a reviewer needs goes with the sentence: `cd`
#: diagnoses itself, measured under `dash` as `<script>: 3: cd: can't cd to <path>` on stderr, and the
#: program still exits on its own contract of 2. What went is the claim about a cause it cannot have
#: observed, never the stop.
#:
#: **`$rev` IS THE THIRD GUARD AND IT IS THE ONLY ONE THAT WARNS INSTEAD OF STOPPING.** The two above
#: fire when this program cannot find something it needs; this one fires when it found everything and
#: the tree is not the tree the verdict was reached in. `head_revision` records the measurement — the
#: bundle carried no revision at all, so replaying against the wrong checkout produced rc=0 with no
#: marker, which is F3's own signature restored by the one route the `cd` fix cannot close.
#:
#: **REFUSING WAS REJECTED, and it is the obvious reading of "make the program refuse".** The single
#: most valuable thing a reviewer does with a bundle is run it against their FIX branch to see the
#: defect stop reproducing — a tree that deliberately does not match. `exit 2` there would refuse the
#: one question the artefact exists to answer. What the failure needed was not a stop but a sentence
#: the reviewer reads BEFORE the silence, which is why the echo sits above the `exec` rather than
#: after the two `exit 2`s.
#:
#: `git -C "$root"` and not a read of `.git/HEAD`: `sh` has no ref resolver, and `head_revision` takes
#: the same command on the recording side for that reason — see its docstring. An unset `$rev` skips
#: the whole block, which is what a producer that never resolved one emits; `2>/dev/null` swallows
#: git's own diagnostic, so a checkout with no VCS and a machine with no git both land on the same
#: `$now` sentence rather than on a stray `fatal:` line above the entry point's output.
_REPRODUCE_SH = "\n".join((
    'here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd) || exit 2',
    "root=$here",
    'while [ ! -f "$root/$entry" ] && [ "$root" != / ]; do root=$(dirname -- "$root"); done',
    '[ -f "$root/$entry" ] || { echo "shard: $entry is in no directory above $here; unpack this'
    ' bundle inside the repository it was produced from" >&2; exit 2; }',
    '[ -r "$here/input" ] || { echo "shard: the reproducing input is missing from $here" >&2;'
    ' exit 2; }',
    'cd -- "$root" || exit 2',
    'if [ -n "$rev" ]; then',
    '    now=$(git -C "$root" rev-parse HEAD 2>/dev/null)',
    '    [ -n "$now" ] || now="a revision nothing here could read"',
    '    [ "$now" = "$rev" ] || echo "shard: this finding was produced against $rev and this checkout'
    ' is at $now, so a run that shows nothing here may mean the tree moved rather than that the'
    ' defect is gone" >&2',
    "fi",
    'exec bash -- "$root/$entry" "$here/input"',
))

# WHY THIS IS ONE CONSTANT AND NOT TWO PINNED COPIES. It shipped duplicated, verbatim, in this module
# and in `shard/simple.py` for a day, with `test_both_tiers_emit_the_same_reproduce_program` asserting
# byte-identity, because `simple` imports `report` at module scope and the reverse import would invert
# the layering — a leaf renderer pulling in agentloop, budget, journal, llm, sandbox and witness to
# format a string. That constraint bites in ONE direction only: `shard/simple.py` already imported
# `Finding` and `staged_relative` from here, so the collapse is one NAME on an import edge that
# exists, and it adds no node and no edge to the graph a maintenance script values for being
# leaf-heavy. A third module for one string would have added both, to hold something that names no job
# — "earn its place" forbids the abstraction with one member as squarely as the option nobody sets.
#
# THE PIN WAS NOT A SAFE STEADY STATE, and this is the measurement rather than the preference: a test
# that two strings are equal cannot say WHICH is right. Both copies were byte-identical and both were
# missing the `cd`, and 25 of 30 measured rows silently reproduced nothing while that test was green.
# The equality held perfectly across the whole defect.


def staged_relative(text: str, input_path: str) -> str:
    """`_repo_relative` for the FREE tier: rewrite the runner's staging directory out of observed output.

    `witness._stage_payload` writes the payload to `tempfile.mkdtemp(prefix="shard-witness-")` and hands
    a path under it to the customer's entry point as argv. An entry point that echoes its argument, or a
    parser that prints `cannot open <file>`, puts that path in `Finding.evidence` — and evidence is what
    the SARIF message, `shard-result.json`'s `observed`, the markdown and `bundles/<fp>/output.txt` all
    quote. Measured 2026-09-02 on a real emitted artefact: **8 lines across 4 files**, on the
    demonstrated finding and the informational one alike.

    That path does not exist on any machine after the job ends, is different on every run, and describes
    OUR staging layout rather than the customer's code — the same three faults `_repo_relative` was
    written for one tier up, on the tier every customer meets first.

    TWO FILENAMES, ONE DIRECTORY. The payload is staged as `shard_witness_input` and EXECUTED through a
    byte-identical copy at `shard_witness_run`, so the path a customer sees is not the one `input_path`
    names. Both are rewritten, and the directory itself after them, so an entry point that printed
    anything else from there is covered too.

    A pure string rewrite over text already captured, like its sibling: it renames, it never invents,
    and a path it does not recognise is left exactly as it was.
    """
    if not text or not input_path:
        return text
    root = str(pathlib.Path(input_path).parent)
    if not root or root == "/":
        return text
    for name in ("shard_witness_input", "shard_witness_run"):
        text = text.replace(f"{root}/{name}", STAGED_INPUT_TOKEN)
    return text.replace(f"{root}/", "").replace(root, "")


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

def _findings(result, workdir: pathlib.Path, setup, *, revision: str) -> list:
    """Adapt a `SolveResult` into the mode-agnostic records `shard/report.py` writes.

    The separate capability emits one finding per DISTINCT reproduced defect — one at the default `--max-findings 1`,
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
        # The verdict and these bytes cross the report boundary together. A path is mutable state: a
        # detached child replaced ``poc-findings/<signature>`` after `_findings` returned and the
        # emitter delivered the replacement as a reproduced input. The sweep already owns immutable
        # per-signature bytes, including restored verdicts. The report layer never reopens live
        # ``./poc``: on a partial/malformed multi-verdict result that is the LAST finding's mutable
        # path, not evidence for whichever signature is being adapted. `write_bundle` prefers these
        # bytes, and their absence makes required delivery fail closed.
        poc_bytes = by_signature.get(signature)
        poc_path = _sweep_poc(workdir, signature, by_signature) if poc_bytes is not None else None
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
            poc_path=poc_path,
            poc_bytes=poc_bytes,
            # WHAT THIS WAS PRODUCED AGAINST, on the record so `write_bundle` can put it in
            # `metadata.json` and the program can check it. See `head_revision`.
            revision=revision,
            # A PROGRAM, NOT A LINE — `_REPRODUCE_SH` has the measurement. `harness` is SHELL-QUOTED
            # because this string is executed by a reviewer's shell rather than through the argv
            # `oracle` used, where a space or a `;` in a declared harness path is just a filename.
            # `rev` is quoted on the same argument: it is git's stdout rather than ours, and
            # `head_revision` validating the shape is the first layer, not the only one.
            reproduce_command=(f"entry={shlex.quote(harness)}\nrev={shlex.quote(revision)}\n"
                               f"{_REPRODUCE_SH}"),
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
    root = workdir.resolve()
    path = root / "poc-findings" / (signature or "unsigned")
    rooted_write(root, path, data, create_parents=True)
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
