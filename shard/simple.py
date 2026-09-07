"""Simple mode — diff-scoped source hunting, and the two tiers that keep it honest.

The design notes. This is the v1 shipping artefact and the free tier, so it is also
where a false positive would actually reach a customer first.

## The ordering that is the whole design

    1. the agent hunts, with READ tools only, scoped to the diff
    2. the loop ENDS
    3. every proposed witness is adjudicated                    <-- the agent is gone by now
    4. gate_eligible is set from what was observed, not from what was claimed

**Step 3 happens after step 2 and that is not an implementation detail.** While the loop is running the
agent can call tools; once it has ended it cannot. Adjudicating during the loop would put the grader
inside the reach of the thing being graded, which is the failure the separate package exists for.

## What the agent may and may not do

It gets `read_file`, `grep` and `list_dir`. It gets **no shell, no write tool and no authoring tool at
all.** That is not caution, it is the soundness argument from `shard/witness.py`: a witness the agent
authors and is graded on is not evidence. The agent supplies DATA — a payload and which entry point to
send it to — and the runner executes something the agent did not write.

A consequence worth stating plainly: **on a repository that declares no entry point, simple mode cannot
produce a single gate-eligible finding.** Everything is a hypothesis. That is a real limit on the free
tier and it is the honest one.

## Why hypotheses are emitted at all

A mode that reports nothing on most repositories is the onboarding failure the integration guide
names, and silence is not rigour. They are emitted as `note`, they say on their face that they cannot
fail a build, and `report.Finding.level` is what enforces it.

## Simple-safe

Nothing here may import the separate package. The maintainers' suite measures it.
"""

from __future__ import annotations

import hashlib
import pathlib
import re
import shlex
import tempfile
from dataclasses import dataclass, field, replace

from shard.agentloop import ToolCallingLoop
from shard.budget import BudgetGovernor
from shard.diffscope import HUNK_RADIUS, prompt_safe
from shard.inspection import build as build_inspection
from shard.journal import Journal
from shard.llm import classify_transport_error
# `_REPRODUCE_SH` and not a second copy of it: it was duplicated verbatim here for a day under a test
# that pinned the two equal, and both copies carried the same missing `cd`. `shard/report.py` has the
# measurement and the argument; this import edge already existed for `Finding`.
from shard.report import _REPRODUCE_SH, Finding, head_revision, staged_relative
from shard.sandbox import ExecState, build_exec_tools, exec_budget, scope_digest
from shard.tools import Tool, ToolContext, ToolRegistry, ToolResult, _grep, _list_dir, _read_file
from shard.witness import (BENIGN_SUFFIX, INHERITED, INTRODUCED, SOURCE_ISOLATION_REFUSAL,
                           UNATTRIBUTED, Witness, WitnessSpec, adjudicate, attribute, bounded_run,
                           controls_digest, entry_digest, observed_location, offered_expectations,
                           self_defeating_marker, witness_contract)
from shard.witnessfs import SnapshotSet, SourceSnapshot

DEFAULT_MAX_STEPS = 40

#: Kept short. The customer's endpoint logs every prompt (the design notes), and a long one is paid
#: for on every pull request.
#: **A TEMPLATE, NOT A PROMPT, since 2026-08-19 — hence the name.** It carries one `{capability}` slot
#: and `_system` is the only thing that fills it. It was called `SYSTEM` for an hour after the slot went
#: in, which is a name that lies: `from shard.simple import SYSTEM` handed a caller a string with a
#: literal `{capability}` in it and nothing said so. Renamed rather than documented, because a constant
#: whose docstring has to warn you about its own name is one rename away from not needing the warning.
SYSTEM_TEMPLATE = """You are reviewing a pull request for security defects.

{capability}

Report a defect with `report_finding`. Two tiers, and the difference is not cosmetic:

  * If you can name an input that makes the DECLARED ENTRY POINT misbehave, pass the witness fields.
    After you finish, the runner executes that entry point with your payload and observes what happens.
    Only what it observes counts. You are not consulted.
  * Otherwise report the finding without witness fields. It is emitted as informational and can NEVER
    fail the build. That is a legitimate result, not a failure — say what you found and why you could
    not demonstrate it.

Do not report style, formatting, or anything you have not read the code for. A finding you cannot point
at a line for is not a finding.

When you have nothing further to examine, stop calling tools and say what you covered."""


#: The capability paragraph, one per arm of the maintainers' notes arm A.
#:
#: **BOTH ARMS MUST DESCRIBE THEIR OWN TOOLSET, and getting this wrong would have invalidated the
#: measurement.** The first draft of the control arm left the execution paragraph in place, so a run
#: with four tools was told it had a shell — which is the separate package's corrosive-tool finding
#: inverted, and a confound that would have made any difference between the arms unattributable.
#: `_system` selects; the maintainers' suite asserts each arm names only what it has.
#:
#: `_CAPABILITY_OFF` is the pre-2026-08-19 text, byte-for-byte, because the control has to be the
#: configuration that actually shipped rather than a reconstruction of it.
_CAPABILITY_OFF = """You have READ tools only. You cannot write files, run shells, or author anything."""

_CAPABILITY_ON = """You can read the checkout and you can RUN it. `run` is a shell in the checkout — node, java, ruby,
php, dotnet, gcc, g++, python and git are installed. `outline` maps a file's definitions so you can
read the right part of it. Write only under $SHARD_SCRATCH: changing the checkout is detected and
stops this run from being able to fail the build.

Check before you claim. Do not report behaviour you could have observed and did not."""


@dataclass
class FindingState:
    """What the agent proposed. Collected during the loop, adjudicated after it.

    A plain accumulator on purpose: it holds CLAIMS. Nothing here is a finding until `adjudicate_all`
    has run, and nothing in this object can make itself gate-eligible.
    """

    proposed: list[dict] = field(default_factory=list)

    def record(self, **kw) -> None:
        self.proposed.append(kw)


def witness_payload_bytes(claim: dict) -> bytes:
    """The bytes a claim's witness payload really is. Raises ValueError when the claim is malformed.

    **THE TEXT-ONLY CHANNEL THIS EXISTS TO CLOSE, and the measurement that sized it.** `witness_payload`
    is a `str` and was the only way to name an input, so the agent could express nothing that is not
    valid UTF-8. Measured 2026-08-12 against two canaries with planted defects
    (the design notes §P2b.4, §P2b.5):

        java  deserialiser        ObjectInputStream demands the exact header AC ED 00 05   UNREACHABLE
        c     heap-use-after-free parse_charlie fires only on buf[0] == 0xff exactly       UNREACHABLE

    Both are the SAME shape, and the rule that survived both languages is narrower than "binary formats
    cannot be witnessed": **a trigger that needs a SPECIFIC byte value is unreachable through a text
    channel; a trigger that needs a LARGE or RANGED value is usually reachable, because many values
    satisfy it and some of them are ASCII.** Java's `parseMalformed` and C's two overflows are ranged and
    were always reachable — `"Mdd"` is a count of 25700 in pure ASCII. So this field buys the
    format-signature cases and not a whole category, which is the honest size of it.

    No UTF-8 string produces a lone `0xff`: U+00FF encodes to `C3 BF`, U+FFFD to `EF BF BD`, and the
    surrogate-escape trick raises `UnicodeEncodeError` before it reaches the wire. There was no
    workaround to find.

    **Decoding is STRICT, and a malformed field is an error rather than a repair.** Whitespace is
    stripped, because a model that wraps base64 across lines has made a formatting choice and not a
    content one; everything else must decode exactly. Padding is NOT added. Silently repairing a payload
    would mean grading an input the agent did not name, and the design notes is that
    the agent supplies the data and the runner observes what that data does — an input we corrected is
    neither.
    """
    text = (claim.get("witness_payload") or "")
    encoded = (claim.get("witness_payload_base64") or "").strip()
    if not encoded:
        return text.encode("utf-8")
    if text:
        # Refused rather than ranked. A precedence rule here would be a silent decision about which
        # input was executed, and the reproduction bundle would name bytes the report did not.
        raise ValueError("give witness_payload or witness_payload_base64, not both")
    import binascii
    import base64
    try:
        return base64.b64decode("".join(encoded.split()), validate=True)
    except (binascii.Error, ValueError) as e:
        raise ValueError(f"witness_payload_base64 is not valid base64: {e}") from None


def _report_finding(ctx: ToolContext, path: str, line: int, title: str, why: str,
                    witness_expectation: str = "", witness_payload: str = "",
                    witness_marker: str = "", witness_payload_base64: str = "",
                    supersedes: int = 0, *, state: FindingState) -> ToolResult:
    """Record a proposed defect. Accepting the CALL is not accepting the FINDING.

    Returns ok for anything well-formed, including a proposal whose witness will later be refused. The
    agent is not the place to enforce the tier — telling it "your witness was rejected" mid-run invites
    it to try another one until something sticks, which is the search-for-a-passing-grade behaviour the
    whole post-loop ordering exists to prevent.

    **THE RESULT CARRIES A HANDLE — the 1-based ordinal of this claim in the run — and `supersedes`
    takes one back.** Before this the model had no channel to retract: a run that correctly changed its
    mind emitted the correction as its OWN fourth finding titled "Correction to the …report", and the
    customer artefact showed four alerts where there were two, one negating another with nothing linking
    them. Passing `supersedes=<handle>` withdraws that earlier claim in `adjudicate_all` instead.

    A handle is refused unless it points STRICTLY earlier (`1 <= supersedes < this ordinal`), so a
    cycle cannot be constructed and a claim can only ever withdraw one the model was ALREADY handed a
    handle for. Refusing a bad handle is the same judgement `_repo_relative` makes about a malformed
    path — it invites a valid handle, not a search for a passing grade. And it is safe against the
    post-loop doctrine: a handle is an IDENTIFIER for the model's own proposal, never a verdict, and
    `adjudicate_all` still runs after the loop, so `supersedes` withdraws a claim rather than revising
    one in response to a grade.

    A malformed `witness_payload_base64` IS refused here, and that is the same judgement `_repo_relative`
    makes rather than the one about tiers: telling the agent its base64 does not decode invites it to
    supply base64 that does, which is what we want. Telling it a demonstration failed invites it to hunt
    for one that passes, which is what we do not.

    **A SELF-DEFEATING MARKER IS REFUSED HERE TOO, SINCE 2026-08-18, AND IT IS THE FIRST KIND.** The
    test is not "is this feedback about the witness" — it is *"can the agent use the answer to search
    for a passing grade"*. `self_defeating_marker` is a pure function of two arguments the agent just
    supplied. It opens no file, runs no entry point and says nothing whatever about the target, so
    there is no grade in it to search for; what it lets the agent fix is an argument that cannot mean
    anything, which is exactly the base64 case. The adjudicator asks the same question again after the
    run, so a marker that talks its way past this one gains nothing.

    **This is the fix for the gate's variance**, the maintainers' notes's standing top item: two
    consecutive runs of a pinned target found the same three defects and gated 2 then 0, and the whole
    difference was one proposal putting its marker inside its own payload.
    """
    if not title.strip() or not path.strip():
        return ToolResult(False, error="report_finding needs a title and a path")
    safe_path = _repo_relative(ctx, path)
    if safe_path is None:
        return ToolResult(False, error=(
            f"path {path.strip()!r} must be relative to the repository root and inside it"))
    offered = offered_expectations()
    if witness_expectation and witness_expectation not in offered:
        return ToolResult(False, error=f"witness_expectation must be one of {list(offered)}")
    claim = {"witness_payload": witness_payload, "witness_payload_base64": witness_payload_base64}
    try:
        payload = witness_payload_bytes(claim)
    except ValueError as e:
        return ToolResult(False, error=str(e))
    if witness_expectation.strip() == "output_marker":
        if self_defeating := self_defeating_marker(witness_marker.strip(), payload):
            return ToolResult(False, error=(
                f"{self_defeating}. Report the same finding again with a marker taken from the "
                f"program's own output, or with no witness fields at all if there is none."))
    # THE HANDLE this claim will carry, and the guard on any handle it names. `n` is the 1-based ordinal
    # this proposal is about to take; a `supersedes` must point strictly earlier, so it can only name a
    # claim already recorded and a cycle is impossible by construction.
    n = len(state.proposed) + 1
    try:
        target = int(supersedes or 0)
    except (TypeError, ValueError):
        return ToolResult(False, error=(
            "supersedes must be the integer handle of one of your earlier report_finding calls"))
    if target and not (1 <= target < n):
        return ToolResult(False, error=(
            f"supersedes={target} is not an earlier handle: pass a handle from 1 to {n - 1} that this "
            f"run already returned to you, or omit it to file a new finding"))
    state.record(path=safe_path, line=max(1, int(line or 1)), title=title.strip(), why=why.strip(),
                 witness_expectation=witness_expectation.strip(),
                 witness_payload=witness_payload, witness_marker=witness_marker.strip(),
                 witness_payload_base64=witness_payload_base64.strip(), supersedes=target)
    return ToolResult(True, data={"recorded": True, "handle": n})


def _repo_relative(ctx: ToolContext, path: str) -> str | None:
    """Normalise a MODEL-SUPPLIED path to repository-relative, or None if it does not belong.

    This is the only untrusted string in simple mode that reaches an artefact a third party parses.
    `Finding.location` becomes the SARIF `artifactLocation.uri`, and code scanning requires those to be
    relative to the repository root — an absolute path or one containing `..` at best matches no file
    and at worst REJECTS THE WHOLE UPLOAD, which loses every finding in the run, not just the bad one.

    Refusing at the tool is right here, and it is not the same judgement as the witness tier. Telling
    the agent its WITNESS was rejected invites it to try another until one sticks; telling it a path is
    malformed invites it to give the correct path, which is what we want. The distinction is whether
    the feedback lets it search for a passing grade.
    """
    raw = path.strip()
    if pathlib.PurePath(raw).is_absolute():
        return None
    root = pathlib.Path(ctx.engine_root).resolve()
    try:
        resolved = (root / raw).resolve()
        return str(resolved.relative_to(root))
    except (ValueError, OSError):
        return None


def build_simple_registry(ctx: ToolContext, state: FindingState, *,
                          witness_entry: str | None = None,
                          exec_state: "ExecState | None" = None, repo=None,
                          runner=None) -> ToolRegistry:
    """The simple-mode toolset. Read the checkout, RUN the checkout, and report.

    `report_finding`'s witness fields are described to the model ONLY when an entry point exists, which
    is the registration-time gating rule the separate package settled on a measurement: a tool that fails
    when called *"is not merely useless, it is corrosive"*. Advertising a witness route on a repository
    that has no entry point would manufacture exactly that.

    **`exec_state` gates the execution tools by the same rule, one door along.** that capability's four
    memory tools default to None because *"an agent must never be shown a tool whose backing state does
    not exist"* — `run` with no `ExecState` has no budget to charge, no scratch directory to name and
    nowhere to record what it ran. Passing one is what turns execution on; `run_simple` always does,
    and a caller that does not gets the four-tool registry that shipped before 2026-08-19, unchanged.

    **THE SOUNDNESS ARGUMENT THAT USED TO SAY "READ TOOLS ONLY" IS INTACT, AND IT WAS NEVER ABOUT
    RUNNING.** It is that *a witness the agent authors and is graded on is not evidence* — so the agent
    supplies DATA and never CODE. It still does: there is no `write_poc`, no `apply_patch`, no write
    tool of any kind, the declared entry point stays read-only and digest-pinned, and `adjudicate_all`
    still runs after the loop with every anti-forgery guard firing. What changed is that the agent may
    now OBSERVE the program before describing it, which is the opposite of authoring the thing that
    grades it. `shard/sandbox.py` has the measurement that bought the change.
    """
    import functools

    registry = ToolRegistry(ctx)
    registry.register(Tool(name="read_file", kind="read", description="Read a file from the checkout.",
                           fn=_read_file,
                           args_schema={"path": "str", "offset": "int?", "max_bytes": "int?"}))
    registry.register(Tool(name="grep", kind="read",
                           description="Search the checkout for a regular expression.", fn=_grep,
                           args_schema={"pattern": "str", "path": "str?", "max_matches": "int?"}))
    registry.register(Tool(name="list_dir", kind="read", description="List a directory.",
                           fn=_list_dir, args_schema={"path": "str?"}))

    schema = {"path": "str", "line": "int", "title": "str", "why": "str", "supersedes": "int?"}
    # ONE clause, because this prompt is billed on every pull request. `supersedes` is in the BASE schema,
    # not the witness block: a correction can withdraw any earlier report, and the handle is returned
    # whether or not the finding carried a witness.
    description = ("Report a defect you have read the code for. To correct an earlier report of your "
                   "own, pass supersedes with the handle that report returned; the earlier one is "
                   "withdrawn.")
    if witness_entry:
        schema |= {"witness_expectation": "str?", "witness_payload": "str?", "witness_marker": "str?",
                   "witness_payload_base64": "str?"}
        description += (f" Pass witness_expectation (one of {list(offered_expectations())}) and "
                        f"witness_payload to have {witness_entry} executed against your input after "
                        f"this run ends. If the input needs bytes that are not valid UTF-8 — a magic "
                        f"header, a sentinel byte — pass witness_payload_base64 instead of "
                        f"witness_payload, never both."
                        # WHERE THE MARKER IS CHOSEN, which is not where the rule was stated. It was in
                        # the system prompt, hundreds of tokens before the argument it constrains, and
                        # the maintainers' notes records one run reasoning about it explicitly and the
                        # next one not — the same target, the same three defects, the gate 2 then 0.
                        f" For output_marker: witness_marker must be a string the program's OWN code "
                        f"prints. A marker that appears anywhere inside witness_payload is refused, "
                        f"because an entry point that merely echoed your input would produce it. Do "
                        f"not plant `echo MARKER` in the payload and then look for MARKER."
                        # READ THE MARKER, DO NOT CALCULATE IT. Measured 2026-08-18 over five samples
                        # of one target: the path traversal is real and reachable, and it failed to
                        # demonstrate in FOUR of them because the model proposed `path: served 54
                        # chars` (three times) and `56` (once) for a file that is 55 bytes — it
                        # counted the visible text and forgot the newline. The single run that
                        # succeeded used /dev/null, where `0 chars` is derivable with certainty.
                        # The rule above does not catch this: `54 chars` IS text the program's own
                        # code prints. The agent has read tools only and cannot run the program to
                        # check, so any value it must compute is a bet it cannot settle.
                        f" Choose a marker you have READ — a literal string in the source. Avoid one "
                        f"whose value you would have to WORK OUT, such as a byte count, a length or a "
                        f"hash: a marker that is off by one demonstrates nothing."
                        # AND THE PAYLOAD MUST LEAVE THE PROGRAM ALIVE. Measured 2026-08-18 over five
                        # samples: FOUR contained a payload built around `kill -9 $PPID`, which the
                        # model chose to prove command execution. The parent is the entry point's own
                        # shell, so the run dies at rc=137, and the adjudicator sees no exit status
                        # and no output. Verified 8 of 8 on an idle machine. It is the self-defeating
                        # marker one door over — a proposal whose success destroys its own evidence —
                        # and it cost two REAL exploits per affected run.
                        f" And your payload must leave the program ALIVE. The runner observes only "
                        f"the entry point's exit status and its output, so an input that kills or "
                        f"hangs it — `kill`, a fork bomb, an infinite loop — destroys the very "
                        f"evidence it was meant to produce. To show command execution, run something "
                        f"whose OUTPUT is distinctive and which you did not write yourself, and let "
                        f"the program finish.")
        # **THE TWO CLAUSES THAT NAME A TOOL, APPENDED ONLY WHEN THAT TOOL IS REGISTERED.**
        #
        # Both rules above exist because the model was betting on a value it could not check. When
        # `run_entry` is present it no longer has to bet, and saying so AT THE ARGUMENT rather than in
        # the system prompt is the placement the maintainers' notes records mattering: the rule was
        # hundreds of tokens away from the field it constrains, and one run reasoned about it and the
        # next did not — same target, same three defects, gate 2 then 0.
        #
        # Appended CONDITIONALLY for two reasons that point the same way. Naming a tool that is not
        # registered is the separate package's corrosive-tool finding pointed at the prompt instead of
        # the toolset. And it would confound the maintainers' notes arm A: the arms must differ in
        # WHAT THE AGENT CAN DO, not in what it was told, or any difference between them is
        # unattributable. `_CAPABILITY_OFF` / `_CAPABILITY_ON` is the same rule one level up.
        if exec_state is not None:
            description += (" You have `run_entry`: execute the entry point on your payload FIRST and "
                            "take the marker from its real output rather than calculating it — a value "
                            "you worked out is a bet you no longer have to make, and run_entry will "
                            "also show you a payload killing the program before you report it.")
    registry.register(Tool(name="report_finding", kind="report", description=description,
                           fn=functools.partial(_report_finding, state=state), args_schema=schema,
                           priority=1))
    if exec_state is not None:
        for tool in build_exec_tools(exec_state, repo=repo if repo is not None else ctx.engine_root,
                                     witness_entry=witness_entry, runner=runner):
            registry.register(tool)
    return registry


#: How many claims one run will actually EXECUTE a witness for. A backstop, never a target — the
#: distinction `budget._SWEEP_BACKSTOP` draws, and the same reason for drawing it.
#:
#: **Adjudication was the one phase with no ceiling of any kind.** Every other cost in a run is bounded:
#: tokens and dollars by the governor, the loop by `max_steps`, each execution by `witness.DEFAULT_TIMEOUT`,
#: the agent's own executions by `sandbox.exec_budget`. The number of claims was bounded by nothing at
#: all — `report_finding` may be called on every step of a 200-step run — and each surviving claim buys up
#: to ten executions of the customer's entry point (the attack, the empty baseline, `MAX_BENIGN_CONTROLS`
#: benign inputs) and, under `--fail-on new`, an `attribute` pass that does the whole of it again at the
#: base revision. At 60 seconds apiece that is ~21 minutes of runner per claim, after the last ceiling
#: the run had has already been passed.
#:
#: 20 sits five times above the largest claim count in any journal this repository has kept — the
#: measured maximum of `simple_proposed.count` across `corpora/` is **4** — so a run that reaches it has
#: a defect in the loop rather than a lot to say, and should be read as one.
MAX_ADJUDICATED = 20

#: Total wall-clock one run may spend EXECUTING witnesses after the loop has ended, in seconds.
#:
#: This is the ceiling that actually binds, and `MAX_ADJUDICATED` is the backstop underneath it: twenty
#: claims at the per-claim worst case above is seven hours, so a count alone would not bound anything a
#: customer cares about. 1,200 is chosen to sit ABOVE one whole worst-case claim, so a single expensive
#: witness is never cut off half-adjudicated, and well below `action.yml`'s own 60-minute default run
#: ceiling, so the run still has time to write the artefacts that carry the answer.
#:
#: A claim refused by either ceiling is still REPORTED. It becomes a hypothesis, which is what a claim
#: nobody executed is, and `gate_eligible` stays false — the direction every refusal in this module
#: takes.
ADJUDICATION_WALL_SECONDS = 1200.0


@dataclass(frozen=True)
class _AdjudicationPlan:
    state: FindingState
    repo: object
    witness_entry: str | None
    baseline_digest: str | None
    runner: object
    workdir: object
    base_repo: object
    tampered: str
    max_witnessed: int
    wall_seconds: float
    clock: object
    snapshots: SnapshotSet
    secret_env_names: tuple[str, ...]


def _adjudication_refusal(tampered: str, snapshot_refusal: str) -> str:
    return tampered or snapshot_refusal


def _isolation_outcome(witness: Witness, attribution: tuple[str, str], located):
    if attribution[1].startswith(SOURCE_ISOLATION_REFUSAL):
        # The base entry point shares an explicitly supplied witness work directory. An isolation
        # failure can therefore mean that it replaced the candidate file the HEAD verdict carried.
        # Refusing the gate but retaining that path would let `write_bundle` publish different bytes
        # from the ones adjudicated, so an unverified candidate leaves no evidence path behind.
        return replace(witness, demonstrated=False, refusal=attribution[1], input_path="",
                       input_bytes=None), None
    return witness, located


def adjudicate_all(state: FindingState, repo, *, witness_entry: str | None,
                   baseline_digest: str | None, runner=None, workdir=None,
                   base_repo=None, tampered: str = "",
                   source_snapshot: SourceSnapshot | None = None,
                   base_snapshot: SourceSnapshot | None = None,
                   max_witnessed: int = MAX_ADJUDICATED,
                   wall_seconds: float = ADJUDICATION_WALL_SECONDS, clock=None,
                   secret_env_names: tuple[str, ...] = ()) -> list[Finding]:
    """Turn claims into findings. The ONLY place `gate_eligible` is ever set true.

    Runs after the loop has ended, so no proposal can be revised in response to a verdict.

    **Three passes run over the claims BEFORE any Finding is built, and none of them weakens the line
    above.** (a) A claim named by a later claim's `supersedes` is dropped — the model withdrawing its
    OWN earlier report. (b) Byte-identical repeats collapse to one: the loop's repeat-breaker is
    byte-identical-ONLY (`agentloop.REPEAT_BREAK_AT`), so a model that re-issues the same
    `report_finding` has it recorded several times, and without this each mints a finding. (c) Every
    survivor carries its proposal ordinal as `Finding.seq`, which `rank` uses as a stable tiebreak so a
    correction renders after whatever it followed. A handle is an IDENTIFIER for the model's own
    proposal, not a verdict; adjudication still happens here, after the loop, so `supersedes` withdraws
    a claim rather than revising one against a grade it has seen.

    **After adjudication, `_separate_anchor_collisions` splits genuinely-distinct findings that share a
    source-location anchor** — two defects in one function — so `partialFingerprints` does not collapse
    them into a single code-scanning alert. It leaves the DESIRED collision (one defect reached through
    two channels) as one identity; a correction/target pair never reaches it, the target being gone.

    `base_repo` is the checkout as it was BEFORE this change (`diffscope.base_tree`). When one is
    given, every DEMONSTRATED finding is re-run there and `Finding.attribution` records whether this
    change introduced it — the causal answer `fail-on: new` was approximating with a line test. Absent,
    every finding is `unattributed` and the caller falls back, which is what a `reproduced` or `none`
    run does: the question is only worth a subprocess when a gate reads the answer.

    `tampered` is set when the tree that was REVIEWED is not the tree that was checked out — see
    `sandbox.scope_digest`, and `run_simple`, which is the only caller in a position to know. Every
    witness is then REFUSED rather than adjudicated, which is the same consequence `witness.adjudicate`
    already applies when its own `baseline_digest` no longer matches: a run that altered the thing
    grading it is refused rather than believed.

    It exists because simple mode gained a shell on 2026-08-19 (`shard/sandbox.py`). A write into the
    checkout cannot be PREVENTED — the container runs as root and there is no read-only mount to reach
    for — so the control is detection with a consequence, and this is the consequence. The finding is
    still REPORTED and still reaches the customer; it just cannot gate, which is what a demonstration
    nobody can re-verify is worth.

    `max_witnessed` and `wall_seconds` are the two ceilings on THIS phase — see their constants. They
    are parameters rather than literals for the reason `tampered` is: a test that has to wait twenty
    minutes to prove a ceiling exists is a test nobody runs, and a ceiling nothing exercises is the
    class of mechanism the maintainers' notes's standing process rule was written about. `clock` is
    `time.monotonic` unless injected, and monotonic rather than wall so a clock step cannot hand a run
    an unbounded phase or cut a bounded one short.
    """
    snapshots = SnapshotSet.prepare(repo, needed=bool(witness_entry), base_repo=base_repo,
                                    source=source_snapshot, base=base_snapshot)
    try:
        plan = _AdjudicationPlan(
            state, repo, witness_entry, baseline_digest, runner, workdir, base_repo, tampered,
            max_witnessed, wall_seconds, clock, snapshots, secret_env_names,
        )
        return _adjudicate_captured(plan)
    finally:
        snapshots.close()


def _adjudicate_captured(plan: _AdjudicationPlan) -> list[Finding]:
    """Adjudicate from an already-owned snapshot pair; the caller always closes it."""
    import time as _time

    (state, repo, witness_entry, baseline_digest, runner, workdir, base_repo, tampered,
     max_witnessed, wall_seconds, clock, snapshots, secret_env_names) = (
        plan.state, plan.repo, plan.witness_entry, plan.baseline_digest, plan.runner, plan.workdir,
        plan.base_repo, plan.tampered, plan.max_witnessed, plan.wall_seconds, plan.clock,
        plan.snapshots, plan.secret_env_names,
    )
    runner = runner or bounded_run
    clock = clock or _time.monotonic
    started = clock()
    witnessed = 0
    source_snapshot, base_snapshot = snapshots.source, snapshots.base
    snapshot_refusal = snapshots.refusal(SOURCE_ISOLATION_REFUSAL)
    pristine_repo = snapshots.repository(repo)
    # THE CONTROLS THIS PHASE STARTED WITH, and it is taken HERE rather than threaded from
    # `run_simple` on purpose. `run_simple`'s `watched` digest covers the LOOP and refuses every
    # witness through `tampered` when it mismatches; this covers ADJUDICATION, which is the window
    # that was open. Taking it at this function's own entry makes the two windows tile with no gap,
    # and gives the same protection to `adjudicate_all`'s other callers — a test, a replay, the PR
    # path — none of which would have remembered a new argument.
    #
    # It is what `witness.adjudicate` compares against on every claim below. Without it, an entry
    # point that deletes its own `.benign` fixtures while being run took a finding its declared
    # control REFUTES to gate_eligible=True, and every later claim in the run with it.
    baseline_controls = controls_digest(pristine_repo, witness_entry) if witness_entry else None
    # ONE RESOLUTION FOR THE WHOLE PHASE, above the loop and beside the other fact taken at this
    # function's own entry. Every finding below comes out of this one checkout, so a `git rev-parse`
    # per claim would be the same answer bought N times; and taking it HERE gives it to
    # `adjudicate_all`'s other callers — a test, a replay, the PR path — which is the argument
    # `baseline_controls` above makes for itself.
    revision = head_revision(repo)

    out: list[Finding] = []
    for ordinal, claim in _surviving_claims(state.proposed):
        # (c) `seq` is the proposal ordinal; `corrects` is the earlier handle this claim withdrew, so
        # its finding can say it replaced something rather than leave the retraction implicit.
        corrects = _supersedes_target(claim, ordinal)
        witness = None
        located = None
        attribution = (UNATTRIBUTED, "")
        refusal = _adjudication_refusal(tampered, snapshot_refusal)
        if refusal and claim.get("witness_expectation"):
            out.append(_to_finding(claim, Witness(demonstrated=False,
                                                  expectation=claim["witness_expectation"],
                                                  refusal=refusal),
                                   entry=witness_entry or "", repo=pristine_repo, seq=ordinal,
                                   corrects=corrects, revision=revision))
            continue
        if witness_entry and claim.get("witness_expectation"):
            # THE CEILING IS CHECKED BEFORE THE PAYLOAD IS EVEN DECODED, because the thing being
            # bounded is the EXECUTION and the decode is what leads to one. A claim past either
            # ceiling is refused with the reason, in the same shape `tampered` uses.
            if ceiling := _adjudication_ceiling(witnessed, clock() - started,
                                                max_witnessed, wall_seconds):
                out.append(_to_finding(claim, Witness(demonstrated=False,
                                                      expectation=claim["witness_expectation"],
                                                      refusal=ceiling),
                                       entry=witness_entry, repo=pristine_repo, seq=ordinal,
                                       corrects=corrects, revision=revision))
                continue
            witnessed += 1
            # Decoded HERE and not at report time, because a claim reaching this public entry point may
            # never have passed through `_report_finding` — a test, a replay of a stored run, or the PR
            # path reading a state repository all assemble one by hand. A malformed claim is REFUSED
            # rather than executed with an empty or repaired payload, which keeps this function's
            # invariant that nothing it does can turn into a demonstration.
            try:
                payload = witness_payload_bytes(claim)
            except ValueError as e:
                out.append(_to_finding(claim, Witness(demonstrated=False,
                                                      expectation=claim["witness_expectation"],
                                                      refusal=str(e)),
                                       entry=witness_entry, repo=pristine_repo, seq=ordinal,
                                       corrects=corrects, revision=revision))
                continue
            spec = WitnessSpec(entry=witness_entry, expectation=claim["witness_expectation"],
                               payload=payload, marker=claim.get("witness_marker") or "")
            witness = adjudicate(spec, repo, baseline_digest=baseline_digest,
                                 baseline_controls=baseline_controls, runner=runner,
                                 workdir=workdir, source_snapshot=source_snapshot,
                                 secret_env_names=secret_env_names)
            # Only for a DEMONSTRATED witness. The output of a run that showed nothing is not evidence
            # of a defect anywhere, and moving an alert onto a line because of it would be attributing
            # a fault to an execution that did not find one.
            if witness.demonstrated:
                # Absolute traces name the checkout path the customer supplied, not the private
                # snapshot path. ``adjudicate`` verified every captured source entry in that checkout
                # after execution, so resolving the location there does not execute against it.
                located = observed_location(witness.evidence, repo, payload=spec.payload)
                # ONLY for a demonstrated one, and for the same reason as `located`: re-running an
                # input that showed nothing would answer a question nobody asked, at the price of a
                # second execution of the customer's entry point per claim.
                attribution = attribute(
                    spec, base_repo, runner=runner, workdir=workdir,
                    source_snapshot=base_snapshot, protected_inputs=_protected_candidate(witness, spec),
                    secret_env_names=secret_env_names,
                )
                witness, located = _isolation_outcome(witness, attribution, located)
        out.append(_to_finding(claim, witness, entry=witness_entry or "", located=located,
                               repo=pristine_repo,
                               attribution=attribution, seq=ordinal, corrects=corrects,
                               revision=revision))
    _separate_anchor_collisions(out)
    return out


def _surviving_claims(proposed: list[dict]) -> list[tuple[int, dict]]:
    """Drop withdrawn and byte-identical claims without renumbering their proposal handles."""
    # Which ordinals a later claim WITHDREW. `_supersedes_target` re-checks the strictly-earlier edge
    # because `adjudicate_all` is public and a hand-built claim may not have passed the tool guard.
    superseded = {target for ordinal, claim in enumerate(proposed, start=1)
                  if (target := _supersedes_target(claim, ordinal))}
    survivors = []
    seen = set()
    for ordinal, claim in enumerate(proposed, start=1):
        if ordinal in superseded:
            continue
        key = tuple(sorted((name, repr(value)) for name, value in claim.items()))
        if key in seen:
            continue
        seen.add(key)
        survivors.append((ordinal, claim))
    return survivors


def _protected_candidate(witness: Witness, spec: WitnessSpec):
    return (("preserved witness input", pathlib.Path(witness.input_path), spec.payload),)


def _adjudication_ceiling(witnessed: int, elapsed: float, max_witnessed: int,
                          wall_seconds: float) -> str:
    """Why this claim will NOT be executed, or "" to adjudicate it.

    Two ceilings, and the sentence names which one bound so the customer can tell "we ran out of clock"
    apart from "you reported more than this phase will execute". Both read as `<= 0` meaning OFF rather
    than meaning zero, which is the reading `cli._budget` gives every other ceiling in this product —
    and a phase permitted zero executions is a gate that never fires, which `action.yml` already argues
    is worse than a refusal.
    """
    if max_witnessed > 0 and witnessed >= max_witnessed:
        return (f"this run reported more than the {max_witnessed} claims one review will execute a "
                f"witness for, so this one was not adjudicated and cannot gate")
    if wall_seconds > 0 and elapsed >= wall_seconds:
        return (f"the {int(wall_seconds)}s ceiling on post-review adjudication was reached before this "
                f"claim was executed, so it was not adjudicated and cannot gate")
    return ""


def _supersedes_target(claim: dict, ordinal: int) -> int:
    """The earlier proposal ordinal this claim withdraws, or 0 when it withdraws nothing.

    STRICTLY earlier only. Enforced at `_report_finding` too, but re-checked here because
    `adjudicate_all` is public and a hand-assembled claim can carry anything — and the strictly-earlier
    edge is exactly what makes a supersede cycle impossible: a claim can only ever name a handle it was
    already given, so a correction and its target can never both survive to the finding list.
    """
    target = claim.get("supersedes") or 0
    return target if isinstance(target, int) and 1 <= target < ordinal else 0


def _separate_anchor_collisions(findings: list[Finding]) -> None:
    """Split same-anchor findings that are DISTINCT defects, in place, so each gets its own alert.

    `Finding.fingerprint` is code scanning's `partialFingerprints` value, and two results carrying one
    collapse into a SINGLE alert with an arbitrary winner (`report._sarif_result`). Simple mode's
    signature is `_anchor_signature`, a SOURCE-LOCATION identity keyed on the enclosing definition — so
    two genuinely distinct defects inside one function share it (the majority case measured in
    `_source_anchor`). The separate capability can dedup blindly because `Verdict.signature` is a CRASH identity; this
    one is not, so a blind merge here would silently drop a possibly-demonstrated finding.

    Within each anchor group, findings at the SAME defect site — same `(location, line)` — are kept as
    ONE identity: that is the DESIRED collision, one defect reached through two channels
    (`_anchor_signature`'s docstring measured it and the maintainers' suite pins it), and it must stay a
    single alert. Findings at DIFFERENT sites are re-hashed apart with a within-run site ordinal. A
    correction/target pair never reaches here, because the target was withdrawn in `adjudicate_all`
    before any Finding was built.

    The trade, kept deliberately: this accepts minor cross-run identity churn for the distinct-defects
    case — the site ordinal is positional, not stable across runs — in exchange for NEVER silently
    dropping a demonstrated finding. The re-hash is `sha256(...).hexdigest()[:16]`, a clean hex token,
    so it still satisfies `report._SAFE_TOKEN` and `Finding.fingerprint` uses it verbatim.
    """
    groups: dict[str, list[int]] = {}
    for idx, f in enumerate(findings):
        # Only anchored findings collide on `partialFingerprints` this way; an empty signature falls
        # back to the prose hash, which is unstable but never colliding, so it needs no separation.
        if f.signature:
            groups.setdefault(f.fingerprint, []).append(idx)
    for fingerprint, idxs in groups.items():
        if len(idxs) < 2:
            continue
        sites: dict[tuple[str, int], list[int]] = {}
        for idx in idxs:
            sites.setdefault((findings[idx].location, findings[idx].line), []).append(idx)
        if len(sites) < 2:
            continue        # one site: the same defect (possibly via two channels) — keep one identity
        for site_ordinal, site in enumerate(sorted(sites), start=1):
            salted = hashlib.sha256(
                f"{fingerprint}\x00collision\x00{site_ordinal}".encode()).hexdigest()[:16]
            for idx in sites[site]:
                findings[idx] = replace(findings[idx], signature=salted)


#: One line per `rule_id` this module can emit, describing the CLASS rather than any one alert. Keyed on
#: the expectation because `rule_id` is `f"shard/simple-{expectation or 'hypothesis'}"`, so the two must
#: move together; the maintainers' suite asserts every offered expectation has a row.
_RULE_TITLES = {
    "fatal_signal": "Demonstrated by a fatal signal from the declared entry point",
    "output_marker": "Demonstrated by an agent-chosen marker absent from a benign control",
    "unhandled_exception": "Demonstrated by an unhandled exception from the declared entry point",
    "hypothesis": "Reported without a demonstration",
}


def _witness_never_judged(witness) -> str:
    """Why this witness never reached a verdict, or "" if it did. See `Finding.witness_refused`.

    Two sources, because `witness.py` deliberately splits them: an explicit `refusal` (the entry point
    could not be staged, run, or its digest changed) and `timed_out` (it ran and never came back). The
    second keeps `refusal` empty on purpose — a hang is a result on the HEAD side — but both mean the
    same thing to the run-level floor, which is counting how much of the review was never judged.
    """
    if witness is None:
        return ""
    refusal = getattr(witness, "refusal", "") or ""
    if refusal:
        return refusal
    if getattr(witness, "timed_out", False):
        return (getattr(witness, "evidence", "") or "the entry point did not finish") + \
               ", so nothing was adjudicated for this finding"
    return ""


def _to_finding(claim: dict, witness, entry: str = "", located=None, repo=None,
                attribution=(UNATTRIBUTED, ""), *, seq: int = 0, corrects: int = 0,
                revision: str = "") -> Finding:
    """Build the finding. Optional claim fields are read with `.get`, and that is not defensive noise.

    `_report_finding` always writes every key, so production never needs it — but `adjudicate_all` is a
    public entry point that takes a claim dict, and a caller assembling one by hand (a test, a replay of
    a stored run, the PR path reading a state repository) legitimately omits the witness fields. A
    KeyError there would be this module refusing a shape it documents as valid.

    `repo` is where the stable identity is read from; without one there is nothing to anchor on and the
    signature stays empty, which is the pre-anchor behaviour rather than a guess.

    `seq` is the claim's proposal ordinal, carried onto `Finding.seq` so `rank` can order a correction
    after what it followed. `corrects` is the earlier handle this claim withdrew (0 when none): its
    target was already dropped in `adjudicate_all`, so the message says it replaced something rather
    than leaving the retraction — the defect this batch exists for — implicit.

    `revision` is `repo`'s `HEAD`, RESOLVED BY THE CALLER and not re-derived here, because it is one
    fact about the run and this function is called once per surviving claim. It defaults to `""` for
    the same callers `repo=None` defaults for — a hand-built claim from a test or a replay — and `""`
    is what switches the bundle program's tree check off rather than a value it could fire on.
    """
    demonstrated = bool(witness is not None and witness.demonstrated)
    expectation = claim.get("witness_expectation") or ""
    message = claim.get("why") or claim["title"]
    if witness is None:
        message += "\n\nNo witness was proposed, so this is informational and cannot fail the build."
    elif demonstrated:
        message += (f"\n\nDemonstrated: the declared entry point was executed with the reported input "
                    f"and {expectation} was observed.")
        # WHAT IT WAS CHECKED AGAINST, and the limit said OUT LOUD when there was nothing to check
        # against. The design notes §P2b.1 offered three options for the `output_marker`
        # false positive and its third — "say the limit out loud" — was required whichever of the other
        # two won, because what ships today is the limit undocumented. Measured on the real canary:
        # four BENIGN fixtures with no attack in them at all demonstrated at exit 0.
        # WHO INTRODUCED IT, when the counterfactual could answer. Said in the artefact a reviewer
        # reads, because "this pull request introduced it" and "this was already here" lead to
        # different next actions and `fail-on: new` acts on the difference.
        if attribution[0] == INTRODUCED:
            message += f"\n\nIntroduced by this change: {attribution[1]}."
        elif attribution[0] == INHERITED:
            message += (f"\n\nNOT introduced by this change: {attribution[1]}. It is reported because "
                        f"it is real, and `fail-on: new` will not gate on it.")
        controls = getattr(witness, "controls", ()) or ()
        if len(controls) > 1:
            message += "\n\nChecked against " + ", ".join(controls) + "."
        elif controls:
            message += (f"\n\nChecked against {controls[0]} ONLY. This repository declares no benign "
                        f"control at {entry}{BENIGN_SUFFIX}, and an empty input takes a different "
                        f"branch through most programs — so a marker this program prints during "
                        f"ordinary operation would also have been reported here. Add one benign input "
                        f"per branch, in a directory of that name, to close that.")
    else:
        # A refused or failed witness is stated, not hidden. "The agent proposed nothing" and "the
        # agent proposed something that did not hold up" are different facts about a finding, and a
        # reviewer deciding how much to trust it needs the second one.
        #
        # **THREE REASONS, IN PRECEDENCE ORDER, AND THE MIDDLE ONE DID NOT EXIST UNTIL 2026-08-18.**
        # `refusal` is "nothing was adjudicated"; `why_not` is "it was adjudicated and here is the
        # check that said no". Everything that was not a refusal fell through to the generic sentence
        # below, which reads *"the entry point did not do what was claimed"* — a statement about the
        # CUSTOMER'S PROGRAM, made for cases that are about our refusal of the AGENT'S proposal. In
        # runs `32078795498`/`32079256653` that sentence was attached to a real pickle RCE whose only
        # defect was a marker the agent had planted in its own payload. The entry point may have done
        # exactly what was claimed; nobody looked.
        #
        # The generic is kept for a witness assembled by hand — `adjudicate_all` is public and a
        # replayed or test-built `Witness` carries neither field — and it is now written as what we
        # can actually say from an empty object: the expectation was not observed. It no longer
        # asserts a cause it does not have.
        reason = witness.refusal or getattr(witness, "why_not", "") or (
            f"{expectation or 'the expectation'} was not observed")
        message += f"\n\nWitness NOT demonstrated ({reason}); informational only."

    # A CORRECTION OF THE MODEL'S OWN EARLIER REPORT. `supersedes` already withdrew the target in
    # `adjudicate_all`, so this is the surviving half of a correction pair; the report must say it
    # replaced something, not leave a customer to reconcile two alerts where one negates the other.
    if corrects:
        message += ("\n\nThis corrects an earlier report from the same run, which has been withdrawn.")

    # WHERE the alert lands. The agent's `path`/`line` is a claim; `located` is where the execution that
    # made this finding gate-eligible said it faulted. The observation wins, and it is SAID when the two
    # disagree — moving a customer's alert silently would be the same class of thing as anchoring it on
    # a guess. Measured on the first paid run: the claim was `src/frame.py:15`, the traceback from its
    # own demonstration said line 17.
    path, line = claim["path"], int(claim.get("line") or 1)
    if located and located != (path, line):
        message += (f"\n\nLocated at {located[0]}:{located[1]} by the demonstration's own output; the "
                    f"report named {path}:{line}.")
    if located:
        path, line = located

    return Finding(
        rule_id=f"shard/simple-{expectation or 'hypothesis'}",
        title=claim["title"],
        # THE CLASS'S NAME, because `title` above names this INSTANCE. `offered_expectations()` returns
        # two values, so essentially every alert of a free-tier run shares one `rule_id` — and with
        # `rule_title` unset, `build_sarif` describes that rule with whichever finding `rank()` happened
        # to order first. A command injection, a path traversal and an unsafe pickle then arrive in the
        # customer's Security tab as three alerts of one rule labelled "Path traversal in
        # load_template", and the winner changes whenever the source does, because `rank`'s final key is
        # the fingerprint.
        rule_title=_RULE_TITLES.get(expectation or "", "Reported without a demonstration"),
        message=message,
        gate_eligible=demonstrated,
        location=path,
        line=line,
        # MEASURED when `located` resolved from the demonstration's own output — the only line
        # `fail-on:new` may gate on. A claim-only line (`located is None`) is reported but cannot gate,
        # so the agent cannot pick which findings gate by choosing where to point.
        location_measured=located is not None,
        # THE CAUSAL ANSWER, which supersedes the line test for `fail-on: new` wherever it exists: the
        # reproducing input was re-run against the code as it was BEFORE this change. A location is a
        # statement about text and this is one about the program, so it covers the two rows the line
        # test structurally cannot — a silent exploit that produced no location, and a defect a
        # DELETION introduced, which adds no line for a location to sit on. `witness.attribute`.
        attribution=attribution[0],
        attribution_reason=attribution[1],
        # NOTHING WAS ADJUDICATED, carried to the run rather than only to this finding's prose. Read
        # from `refusal` and never from `why_not`: the two are deliberately different facts, and only
        # the first one means the witness never got a verdict.
        #
        # A HANG IS THE THIRD FACT AND IT BELONGS HERE TOO. `witness.timed_out` deliberately leaves
        # `refusal` empty — on the HEAD side a hang is a result the customer is told about, which
        # the maintainers' suite pins — but "the process never finished" is exactly what the run-level
        # floor at `cli.py`'s `witness_refused` block is counting. Without this, a payload that merely
        # HANGS the entry point (`; sleep 3600`, an algorithmic-complexity trigger, a listener) is
        # missing from that floor, while a payload that KILLS it is counted. Same fact, and the hang
        # needs no host memory pressure to arrange.
        witness_refused=_witness_never_judged(witness),
        # THE STABLE IDENTITY, and it names the DEFECT SITE — file plus enclosing definition — never a
        # crash, which is what an oracle signature would falsely claim here. The previous decision was
        # "deliberately no signature", on the belief that hashing rule+location+title was "stable across
        # runs for the same finding". Measured false: two real runs over the SAME four planted defects
        # produced ZERO overlapping fingerprints, because `title` is model prose written fresh each run
        # — so a `fail-on: new` baseline would re-raise every finding on every push. `_anchor_signature`
        # on what survived measurement and what did not. Empty when nothing anchors; the fingerprint
        # falls back to the prose hash, which is unstable but never colliding.
        signature=_anchor_signature(repo, path, line) if repo is not None else "",
        replays=1 if witness is not None else 0,
        crash_count=1 if demonstrated else 0,
        # THE REPRODUCING INPUT, which is the product's first sentence and which simple mode did not
        # attach. `input_path` is the preserved copy beside the file actually executed;
        # `input_bytes` is filled only after the child and every control left that copy unchanged.
        # The bundle writes the immutable bytes, not a same-UID path a later claim could replace.
        # Carried whenever a witness ran, since a candidate input for a refuted claim is still the
        # fastest thing to hand a reviewer; `metadata.json` states which it is.
        poc_path=(getattr(witness, "input_path", "") or None) if witness is not None else None,
        poc_bytes=getattr(witness, "input_bytes", None) if witness is not None else None,
        # The ENTRY comes from the caller, not from the claim: `_report_finding` never wrote an `entry`
        # key, so `claim.get("entry", "")` was always empty and every gate-eligible finding shipped
        # `bash  <payload>` — a command with no script in it, in the artefact whose entire job is to let
        # somebody else reproduce the finding. Found on the first real container run, in a bundle that
        # had just failed a build.
        #
        # THAT FIX SUPPLIED THE SCRIPT AND LEFT THE TWO PATHS ANCHORED TO DIFFERENT DIRECTORIES, which
        # is the same defect one layer in: a command with a script in it that still reproduces nothing.
        # `_REPRODUCE_SH` has the measurement. `entry` is SHELL-QUOTED because this string is executed
        # by a reviewer's shell rather than through the argv `adjudicate` uses, where a space or a `;`
        # in a declared entry point is just a filename.
        # `rev` RIDES WITH `entry` because the program needs both before it execs anything: without it
        # a bundle replayed against another branch reproduces nothing at rc=0, which is the signature
        # F3 was raised for. `report.head_revision` records the measurement; both values are
        # shell-quoted because this string is written into a file the reviewer runs.
        reproduce_command=(f"entry={shlex.quote(entry)}\nrev={shlex.quote(revision)}\n{_REPRODUCE_SH}"
                           if demonstrated and entry else ""),
        # WHAT THE VERDICT WAS REACHED AGAINST, carried whether or not a command was emitted: a bundle
        # for a refuted claim holds a candidate input a reviewer may replay, and it deserves the same
        # answer to "against which tree" that a demonstrated one gets.
        revision=revision,
        # WHAT WAS OBSERVED. Captured, capped, and then dropped on the floor until 2026-08-08: the
        # report said "nonzero_exit was observed" and showed the reviewer nothing at all.
        evidence=staged_relative((getattr(witness, "evidence", "") or ""),
                                 getattr(witness, "input_path", "")) if witness is not None else "",
        witness_expectation=expectation if demonstrated else "",
        witness_marker=(claim.get("witness_marker") or "") if demonstrated else "",
        witness_entry=entry if demonstrated else "",
        witness_controls=tuple(getattr(witness, "controls", ()) or ()) if demonstrated else (),
        # THE PROPOSAL ORDINAL, so `rank` orders a correction after what it followed rather than by hash.
        seq=seq,
    )


#: A definition-shaped line: first column, first character an identifier character. Git's default
#: funcname rule for hunk headers, and chosen for the same reason git chose it — it is language-agnostic
#: and it is the last line a reader would name when asked "where is this?". In an indentation-structured
#: file every line between a `def` and its body is indented, so the nearest match above a defect line is
#: the enclosing definition; in brace languages it is the function head for the same reason.
_ANCHOR_SHAPE = re.compile(r"[A-Za-z_$]")


def _source_anchor(repo, path: str, line: int) -> str:
    """The nearest definition-shaped line at or above `line`, whitespace-normalised, or "".

    This is what a finding's identity keys on, and every alternative was measured against two real runs
    over the same four planted defects (canary-py, 2026-08-11) before this one was chosen:

        rule+path+title (the old fallback)   0/4 identities stable   title is fresh prose every run
        rule+path                            4/4 stable              collides four distinct defects
        path+line                            2/4 stable              the model's claimed line drifted
                                                                     (64 vs 63) between runs
        path+text of the defect line         2/4 stable              different payloads fault different
                                                                     STATEMENTS of one defect (108 vs 109)
        path+enclosing anchor (this)         4/4 stable              zero cross-defect collisions

    The decisive datum is the 108-vs-109 row: even the demonstration's OWN traceback line is not stable
    for one defect, because the faulting statement depends on the payload. The enclosing definition is
    the innermost thing both observations share, and it survives line shifts, re-worded prose, and
    re-worded claims because it is CONTENT, not a coordinate.

    `line` beyond the file clamps to its end: a hallucinated line number varies between runs, and the
    clamp maps every variant onto the same anchor rather than onto fresh prose hashes. Undecodable bytes
    are replaced, never raised — this reads customer files, the lesson of the maintainers' suite.

    ## It is the ENCLOSING CHAIN, not the nearest column-0 line, and that was a measured correction

    The first version took the nearest line whose first character sat at column 0 — git's own funcname
    rule for hunk headers. On the canary it scored 4/4 stable with zero collisions, and that number was
    worthless: **the canary is module-level `def parse_*` functions, the one file shape structurally
    incapable of showing the failure.** In Python a method body is indented and `class X:` is the only
    column-0 line above it, so EVERY METHOD OF A CLASS SHARED ONE IDENTITY. Reproduced:

        class Service:
            def run_cmd(...):  os.system(f"echo {name}")              -> 0ea534c28717c3ed
            def query(...):    db.execute(f"... {uid}")               -> 0ea534c28717c3ed
            def render(...):   render_template_string(tpl)            -> 0ea534c28717c3ed

    Three vulnerability classes, one identity. Measured over 2,779 real files (a 2,779-file real-world Python corpus):
    **67% of definitions shared an anchor with a sibling, in 64% of files.** Not the rare
    two-defects-in-one-function case the original commit admitted — the majority case.

    What it costs is customer-facing. `partialFingerprints.shardCrashSignature` is code scanning's
    alert-CORRELATION key, so two results carrying one fingerprint **collapse into a single alert**: a
    demonstrated finding, with a reproduction attached, silently absent from the Security tab that is
    the product's whole delivery surface.

    So the anchor walks the enclosing chain by INDENTATION — innermost definition first, out to column
    zero — and joins it. `class Service:` + `def query(...)` separates the siblings, and two same-named
    methods in different classes of one file stay distinct, which the innermost line alone would not do.
    A flat module-level function yields a one-element chain, so the canary's four identities are
    unchanged and the stability measurement above still holds.
    """
    try:
        text = (pathlib.Path(repo) / path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    lines = text.splitlines()
    start = min(max(line, 1), len(lines))
    chain: list[str] = []
    # The indent of the defect's own line is the floor: a head must be OUTSIDE it, which is what makes
    # this "enclosing" rather than "nearby".
    indent = _indent_of(lines[start - 1]) if lines else 0
    for i in range(start, 0, -1):
        raw = lines[i - 1]
        if not raw.strip() or not _ANCHOR_SHAPE.match(raw.lstrip()):
            # Blank lines, comments and closing punctuation are not definition heads. Matching on the
            # LSTRIPPED line is the whole change: at column 0 it is the original rule exactly.
            continue
        here = _indent_of(raw)
        # STRICTLY less, always. An equal-indent line is the defect's own statement, and keying on that
        # is the `path + text of the defect line` scheme that measured 2/4: different payloads fault
        # different statements of one defect, so the statement is not identity material.
        if here < indent:
            chain.append(" ".join(raw.split()))
            indent = here
            if here == 0:
                break
    return " | ".join(reversed(chain))


def _indent_of(raw: str) -> int:
    """Leading whitespace width, tabs counted as one. Exact widths do not matter — only the ORDERING
    does, and a file mixing tabs and spaces at one nesting level is already ambiguous to a reader."""
    return len(raw) - len(raw.lstrip())


def _anchor_signature(repo, path: str, line: int) -> str:
    """`Finding.signature` for simple mode: sha256 of (path, enclosing anchor), or "" when nothing anchors.

    Two properties are load-bearing. It is a HEX token, so `Finding.fingerprint` uses it verbatim —
    it is safe as a bundle path segment and as code scanning's `partialFingerprints` value. And it
    deliberately contains NO rule id: the rule names the demonstration channel, not the defect. Measured
    on the canary run: the same parse_command injection was demonstrated twice in one run, once by
    `output_marker` and once by `nonzero_exit`. That is one defect and must be one identity — an
    identity that shifts when a later run demonstrates the same defect through a different observation
    would re-raise the alert `fail-on: new` exists to keep quiet.
    """
    anchor = _source_anchor(repo, path, line)
    if not anchor:
        return ""
    return hashlib.sha256(f"shard-anchor-v1\x00{path}\x00{anchor}".encode()).hexdigest()[:16]


@dataclass(frozen=True)
class SimpleRun:
    """What the hunt produced, AND whether it finished.

    The status used to be dropped on the floor: `run_simple` called `loop.run()` and returned only the
    findings, so `_cmd_diff` hardcoded `status="done"` for every run it ever made. A run whose model
    refused the prompt, whose budget ran out, or whose backend died therefore reported `done`,
    `findings: 0` and exit 0 — **indistinguishable from a clean review**, on the tier that ships first.
    The design notes recorded this for the separate capability; it was worse here, because deep at least told
    the truth in its markdown.

    A record rather than a tuple because both halves are read at the call site and a bare pair invites
    somebody to unpack it in the wrong order exactly once.
    """

    findings: list[Finding]
    status: str
    #: WHICH ceiling produced a `budget` status — `tokens`, `wall_seconds` or `usd`, and `""` when the
    #: run was not stopped by one.
    limit_hit: str = ""
    #: How many executions the exec ceiling DENIED, or `None` when the run could not execute at all.
    #:
    #: The third instance of this record's founding defect, closed 2026-08-21. `status` and
    #: `limit_hit` were both once dropped on the floor here and both produced a degraded run that read
    #: as a clean one; this is the same shape for the ceiling that a measured run
    #: §1 measured cutting a verification short on a paying customer's report. A `budget` status names
    #: the three metered ceilings and has never named this one, so a run cut off by execution reports
    #: `done`.
    #:
    #: `None` IS NOT ZERO: not-armed and refused-nothing are different facts about a run, and the arms
    #: in a maintenance script need to tell them apart.
    exec_refused: int | None = None
    #: How many executions the agent actually MADE, or `None` when it could not execute at all.
    #:
    #: **THE RECORD CARRIED WHAT THE CEILING DENIED AND NOT WHAT THE RUN DID**, which is the half a
    #: reader needs first. Measured on five real reviews of French public-administration repositories,
    #: 2026-08-24/25 (a measured run): every one executed — 30 shell
    #: calls on the first — and every report said only *"none declared — nothing in this run could be
    #: proven by execution"*, which is true of the WITNESS and reads as a claim about the run. On the
    #: Etalab review the agent's own prose said *"I reproduced this by executing the exact helper …: it
    #: throws"* two paragraphs under a header stating nothing could be proven by execution. Both
    #: sentences are correct and the artefact contradicts itself on one screen, which is the defect
    #: `budget.ScanProfile` records being found the same way and for the same reason.
    #:
    #: `0` IS A REAL ANSWER AND IS REPORTED, unlike `exec_refused`'s zero. "The agent could run things
    #: and chose not to" is the review being read-only, which a customer weighing the finding needs;
    #: "the ceiling refused nothing" is the ordinary case and would be a row nobody reads. `None`
    #: stays not-armed — a maintenance script's control arm depends on that distinction.
    exec_calls: int | None = None

    #: Did the run use EVERY execution the ceiling allowed? Distinct from `exec_refused`, and the
    #: distinction is what was missing: a refusal is proof the ceiling cut the run off, while spending
    #: the last call is proof it MAY have. Measured 2026-09-03 — 24 of 24 used, `exec_refused: 0`,
    #: `status: done`, the report saying `complete run`, and the agent's own final turn opening "I have
    #: no tool budget left" at model turn 20 of an allowed 40. The model is handed `executions_left` on
    #: every tool result, so it stops asking before it is ever refused. See `sandbox.ExecState.spent`.
    executions_spent: bool | None = None
    #: WHY the model calls failed on an `error` status — a key of `report.TRANSPORT_ERROR_ADVICE`, or
    #: `""` when the run did not fail that way or the failure is not one we classify.
    #:
    #: **THE FOURTH INSTANCE OF THIS RECORD'S FOUNDING DEFECT.** `status`, `limit_hit` and
    #: `exec_refused` were each dropped on the floor here and each produced a degraded run that read as
    #: something it was not. This is the same shape again: `AgentResult.final_text` has always carried
    #: the provider's own error string, and the record that reaches the report did not carry it on, so
    #: every transport failure arrived at the customer as one undifferentiated word.
    error_kind: str = ""
    #: Source windows returned during this run, separate from scope and from security coverage.
    inspection: dict | None = None


def run_simple(*, repo, backend, journal: Journal, scope: tuple[str, ...] = (),
               witness_entry: str | None = None, model: str = "glm-5.2",
               max_steps: int = DEFAULT_MAX_STEPS, governor: BudgetGovernor | None = None,
               survey_note: str = "", runner=None, loop_factory=None,
               windows=None, base_repo=None, execution: bool = True,
               secret_env_names: tuple[str, ...] = ()) -> SimpleRun:
    """Hunt the diff, then adjudicate. Returns findings ready for `shard/report.py`, and the status.

    `loop_factory` is injected for the same reason the separate package injects `replay` and `build_registry`:
    the ordering above is the thing worth testing, and it must be testable without an LLM.

    **`execution=False` IS THE CONTROL ARM, and it exists for a measurement rather than for a
    customer.** It is the same sanctioned shape as the separate package's `contract_endpoint`, which
    says of itself *"ABLATION arm only"*: the default is the shipping configuration, and turning the
    flag off reproduces the toolset that shipped before 2026-08-19 exactly — four tools, no way to run
    anything.

    It is a parameter rather than a constant because the maintainers' notes arm A needs a control, and
    a control that has to be produced by editing the source is a control nobody runs. The maintainers' notes's
    rule against configuration nobody sets is satisfied by something setting it: a maintenance script
    --compare-execution` is the only caller that ever will, and `--no-execution` on the CLI is how it
    reaches here.

    **What it must NOT become.** If arm A says execution does not help, this flag is not the answer —
    the capability is removed and the flag with it. A permanently-on-by-default ablation switch is a
    dead option, which is the thing the maintainers' notes forbids one line above the one that permits this.
    """
    # BEFORE the model receives a shell. Capturing after ``loop.run`` would preserve exactly the
    # helper/entry forgery this boundary exists to remove.
    # Every model-facing read root uses the same credential-free source boundary as execution. GitHub
    # Actions may persist a composed Basic header in ``.git/config``; environment redaction cannot
    # recognize it, and a read-only run could otherwise retrieve it without invoking a subprocess.
    snapshots = SnapshotSet.prepare(repo, needed=True, base_repo=base_repo)
    if snapshots.failure:
        journal.record("simple_snapshot_refused", error=snapshots.failure)
        return SimpleRun(findings=[], status="error", error_kind="", exec_refused=None,
                         exec_calls=None, executions_spent=None)
    args = (repo, backend, journal, scope, witness_entry, model, max_steps, governor, survey_note,
            runner, loop_factory, windows, base_repo, execution, secret_env_names)
    try:
        return _run_simple_captured(args, snapshots)
    finally:
        snapshots.close()


def _run_simple_captured(args, snapshots: SnapshotSet) -> SimpleRun:
    """The review after its head/base source boundary has been captured."""
    (repo, backend, journal, scope, witness_entry, model, max_steps, governor, survey_note,
     runner, loop_factory, windows, base_repo, execution, secret_env_names) = args
    state = FindingState()
    source_snapshot, base_snapshot = snapshots.source, snapshots.base
    pristine_repo = snapshots.repository(repo)
    # ALL THREE ROOTS, and the fix is one line because the DEFAULTS are the defect. `ToolContext` was
    # written for a developer machine: `shard_root` falls back to `Path(__file__).parent.parent` and
    # `audit_root` to a hardcoded absolute path outside the repository, and `_read_allowed_roots` returns all
    # three. Setting only `engine_root` therefore granted the agent Shard's own source. Measured
    # 2026-08-12 (an internal audit Finding 2), on the shipping path:
    #
    # In the shipped image `shard_root` is `/app`, where the free build script puts 20 files including
    # `witness.py`, `simple.py`, `report.py` and `cli.py`, and `audit_root` ships as a developer's home
    # directory literal inside the customer's artefact.
    #
    # **The composition is the severity, not the read.** An agent that can read `witness.py` can see
    # that the anti-forgery guard is a substring test over a decode and construct a payload that
    # defeats it — read the grader, then forge the grade — which is the CRITICAL finding on the same
    # page. It also converts the known `output_marker` false positive from latent to strategic: the
    # agent learns from `adjudicate` that the baseline runs on an EMPTY payload.
    ctx = ToolContext(engine_root=pristine_repo, shard_root=pristine_repo,
                      audit_root=pristine_repo,
                      secret_env_names=secret_env_names, immutable_read_roots=True)

    # THE EXECUTION HALF, added 2026-08-19. `shard/sandbox.py` carries the measurement that bought it;
    # the short version is that this agent had four tools and none of them could run anything, inside a
    # container carrying seven language runtimes reachable only by the post-loop adjudicator, and seven
    # of fourteen measured gate losses were the agent guessing at runtime behaviour it could have read.
    #
    # The scratch directory is OUTSIDE the checkout on purpose: `run_entry` stages its probe input
    # there, so the ordinary case leaves no trace in the tree the findings point at and `scope_digest`
    # below stays quiet for the right reason rather than by luck.
    # THE CEILING IS SIZED AGAINST THIS RUN'S MOVES, not against the default this file happens to
    # declare. `MAX_EXEC_CALLS` was a literal chosen as 60% of 40; `--max-steps` is a customer flag,
    # and the first real customer audit ran at 200, where 24 was 12% of the moves and cut off a
    # verification mid-way — shipping a candidate the agent could not clear as a finding. `max_steps`
    # is a parameter of this function, so the number was always in scope here; nothing needed
    # threading, it simply was not asked for.
    exec_state = (ExecState(scratch=tempfile.mkdtemp(prefix="shard-exec-"),
                            max_calls=exec_budget(max_steps), secret_env_names=secret_env_names,
                            source_snapshot=source_snapshot)
                  if execution else None)
    registry = build_simple_registry(ctx, state, witness_entry=witness_entry,
                                     exec_state=exec_state, repo=pristine_repo, runner=runner)

    # Taken BEFORE the loop. `witness.adjudicate` refuses when it no longer matches, so a run that
    # somehow altered the thing grading it is refused rather than believed.
    baseline = entry_digest(pristine_repo, witness_entry) if witness_entry else None
    # THE SAME GUARD, WIDENED TO WHAT A SHELL CAN REACH. `entry_digest` protected the entry point back
    # when the loop had no way to touch it; `run` does. The surface that matters is the files a finding
    # may point at — the changed files — plus the WITNESS CONTRACT, which is the entry point and the
    # benign controls it declares.
    #
    # **THE CONTROLS WERE OUTSIDE BOTH DIGESTS UNTIL 2026-08-24, AND THEY ARE THE DIFFERENTIAL.** The
    # entry point was covered twice over and the files that decide whether its output means anything
    # were covered by nothing: `witness.benign_controls` returns `()` for a directory that is not
    # there, and an adjudication with no controls is the configuration an internal audit
    # measured forging four demonstrations out of four. One `rm -rf .shard/entry.sh.benign` from the
    # model's own shell bought that, and left this comparison perfectly quiet.
    #
    # `witness_contract` is evaluated HERE, before the loop, so the set being protected is the set the
    # repository declared rather than whatever is left at the end.
    watched = (*scope, *witness_contract(repo, witness_entry))
    scope_before = scope_digest(repo, watched)

    factory = loop_factory or ToolCallingLoop
    loop = factory(backend=backend, registry=registry, journal=journal,
                   system=_system(scope, witness_entry, survey_note, windows, execution=execution),
                   model=model,
                   max_steps=max_steps, governor=governor)
    inspection_start = journal.step
    result = loop.run(_goal(scope))
    # `getattr` because `loop_factory` is an injection point and a test double may return None. The
    # fallback is "error", never "done": a loop that returned something we cannot read did not tell us
    # it finished, and this whole field exists because an unfinished run once looked like a clean one.
    status = getattr(result, "status", "") or "error"
    # Same `getattr` reason, and the empty fallback is right here rather than merely safe: no resource
    # named means no ceiling bound, which is what an unstopped run should say.
    limit_hit = getattr(result, "limit_hit", "") or ""
    # WHY THE TRANSPORT FAILED, when it did. `AgentResult.final_text` carries the provider's own error
    # string on an `error` status (`agentloop._result("error", …, res.error)`), and until 2026-08-22
    # nothing read it: a revoked key, a spent balance and a mistyped model name all reached the customer
    # as the bare word `error`. Classified ONLY on that status, because `final_text` is the agent's
    # closing message on every other one and matching a report's prose against provider-error patterns
    # would invent a transport failure out of a sentence the model wrote.
    error_kind = classify_transport_error(getattr(result, "final_text", "") or "") \
        if status == "error" else ""

    # WHAT THE AGENT ACTUALLY EXECUTED. Recorded whether or not it executed anything, because "it
    # never called the tool" is the answer the maintainers' notes's standing process rule demands be checkable —
    # six mechanisms were once found built, tested, green and unreachable in production, and a lever
    # that fires zero times reads exactly like a lever that is not there.
    # RECORDED IN BOTH ARMS, and `armed` is why. A control run and a treatment run whose agent simply
    # never called a tool both report `calls=0`, and telling them apart is the whole of arm A's
    # denominator — the maintainers' notes, a zero indistinguishable from an unknown, which
    # a maintenance script has already shipped once as a column of zeros over runs that wrote no
    # journal.
    # `refused` AND `exhausted` ARE THE BIND SIGNAL, and until 2026-08-21 nothing outside the model's
    # own transcript carried it. `spend` handed the agent a refusal sentence and told no one else, so a
    # run cut off mid-verification wrote the same record as one that finished — `budget=24, calls=24`
    # says the run spent its budget and cannot say whether it WANTED a twenty-fifth. On a customer engagement it
    # wanted one, could not reach the code that would have cleared a candidate, and the candidate
    # shipped to a customer as a finding.
    #
    # `None` WHEN NOT ARMED, never 0. A control run refused nothing because it could not execute at
    # all; a treatment run that refused nothing was genuinely unconstrained. Those are different facts
    # and trap 7 is what happens when one integer stands for both — the same reason `network` says
    # "not-armed" here rather than "unknown".
    # ONE `is None` TEST FOR EIGHT FIELDS. Written as eight ternaries it was eight branches against
    # this function's cap of 20, and adding the ninth field tripped the ratchet — which is the ratchet
    # working: the shape was already the problem. The defaults differ by field on purpose, and the
    # reason is trap 7 in this file's own header: `0` is a real answer for a count and a lie for a
    # ceiling that was never armed, so an unarmed run reports `None` where a zero could not be told
    # from a measurement.
    ex = exec_state
    journal.record("simple_exec", armed=ex is not None,
                   calls=ex.calls if ex else 0,
                   entry_calls=ex.entry_calls if ex else 0,
                   shell_calls=ex.shell_calls if ex else 0,
                   network=ex.network if ex else "not-armed",
                   budget=ex.max_calls if ex else 0,
                   refused=ex.refused if ex else None,
                   exhausted=ex.exhausted if ex else None,
                   spent=ex.spent if ex else None)

    # THE SAME DENOMINATOR, FOR THE OTHER ACCUMULATION MECHANISM. `state.py` feeds what we already
    # believe about this codebase into the SYSTEM message through `survey_note`, on every run since it
    # landed, and NOTHING has ever measured whether it changes anything — it has no arm in this file's
    # sibling a maintenance script and none in a maintenance script. `--no-survey` is the control, and
    # this record is what makes the control readable.
    #
    # **`given` IS THE COLUMN THAT MATTERS AND IT IS NOT THE FLAG.** A treatment run whose survey held
    # no candidates gets `survey_note("") == ""` and is byte-identical to a control run, so a sweep
    # comparing them measures nothing while looking like it measured a null. That is trap 7 again, one
    # mechanism along from `armed` above: the flag says what we INTENDED, `given` says what the model
    # was actually handed. `chars` is a LENGTH and never the text — the note carries the customer's
    # paths, and `shard/telemetry.py` states the rule this obeys.
    journal.record("simple_survey", given=bool(survey_note), chars=len(survey_note or ""))

    # THE CONSEQUENCE OF THE SHELL, and it is deliberately a comparison rather than a permission check.
    # A digest that could not be computed does not read as "untouched": `scope_digest` returns a hash
    # over whatever it could reach, so an unreadable file digests differently from a readable one and
    # the mismatch arm is the one that fires.
    tampered = ""
    if scope_digest(repo, watched) != scope_before:
        tampered = ("the checkout changed during this run, so nothing observed in it can be "
                    "re-verified; the witness was refused rather than adjudicated")
        journal.record("simple_scope_tampered", scope=len(scope), watched=len(watched))

    journal.record("simple_proposed", count=len(state.proposed), status=status)
    findings = adjudicate_all(state, repo, witness_entry=witness_entry, baseline_digest=baseline,
                              runner=runner, base_repo=base_repo, tampered=tampered,
                              source_snapshot=source_snapshot, base_snapshot=base_snapshot,
                              secret_env_names=secret_env_names)
    journal.record("simple_adjudicated", findings=len(findings),
                   gate_eligible=sum(1 for f in findings if f.gate_eligible))
    # THE SAME ONE TEST, for the same reason as the journal record above.
    exec_facts = ({"exec_refused": exec_state.refused, "exec_calls": exec_state.calls,
                   "executions_spent": exec_state.spent} if exec_state else
                  {"exec_refused": None, "exec_calls": None, "executions_spent": None})
    return SimpleRun(findings=findings, status=status, limit_hit=limit_hit,
                     error_kind=error_kind,
                     inspection=_inspection(journal, inspection_start, scope, pristine_repo, windows),
                     **exec_facts)


def _inspection(journal, start, scope, repo, windows):
    """A retained transcript may predate this scan; only events after its start belong to it.

    A failed journal read leaves an unknown, never an inventory claiming that no files were read.
    Source paths are normalized before the immutable snapshot is removed, without reopening source.
    """
    try:
        events = (event for event in journal.events() if event.get("step", 0) > start)
        return build_inspection(scope, events, repo=repo, windows=windows)
    except (OSError, ValueError, TypeError, AttributeError):
        return None


def _system(scope: tuple[str, ...], witness_entry: str | None, survey_note: str,
            windows=None, execution: bool = True) -> str:
    """The system prompt, with only the clauses this target actually earns.

    Every gate answers "is this REALLY here", never "was it requested" — the rule the separate package
    states and the free-target audit's §4 was opened because it had been broken.

    **THE PARAGRAPH STRUCTURE HERE IS THE THING BEING PROTECTED.** Clauses are joined on a blank line,
    so a value that can write one is a value that can write a clause. Every interpolated field is
    rendered through `diffscope.prompt_safe`; `test_the_system_prompt_has_the_shape_ITS_OWN_code_gave_it`
    is what says so structurally, by comparing the line count against benign input of the same shape
    rather than by looking for any particular attack string.

    `witness_entry` is included even though it arrives from the workflow file rather than from the pull
    request, on the ground that a guard which holds only because of a fact about the CALLER is the
    weaker kind — and this one costs a function call.
    """
    parts = [SYSTEM_TEMPLATE.format(
        capability=_CAPABILITY_ON if execution else _CAPABILITY_OFF)]
    if witness_entry:
        parts.append(f"The declared entry point is {prompt_safe(witness_entry)}. "
                     f"It is read-only to you.")
    else:
        parts.append("No entry point is declared for this repository, so nothing you report can be "
                     "demonstrated. Report what you find as informational and say so.")
    if survey_note:
        parts.append("Known about this codebase already:\n" + survey_note)
    if scope:
        parts.append(_scope_clause(scope, windows))
    return "\n\n".join(parts)


def _scope_clause(scope: tuple[str, ...], windows) -> str:
    """The changed files, and WHERE in them the change is.

    The design notes: the measured commit changed one line of a 7,980-line file and was priced as
    a full-file audit, because the scope named the file and the line numbers — already parsed — never
    reached the agent. This is the cheap half of that: tell it where the change is.

    It states plainly that reading the whole file is still allowed. Narrowing attention is the intent;
    narrowing CAPABILITY would make the saving unfalsifiable, since a run that cannot look somewhere
    cannot report that it did not look there.

    **EVERY PATH IS RENDERED THROUGH `prompt_safe`, AND THAT IS A SECURITY BOUNDARY RATHER THAN
    TIDINESS.** This text goes into the SYSTEM message, above the goal, and the paths in it come from an
    untrusted pull request. Git C-quotes control characters in a path regardless of `core.quotePath`,
    `diffscope._header_path` decodes them faithfully so that `café.c` opens, and a filename containing
    real newlines therefore wrote its own paragraph here on every diff run — no state repository, no
    prior survey, nothing to opt into. An internal audit Finding 3 has the transcript;
    `prompt_safe`'s docstring has the reasoning and the residual.
    """
    windows = windows or {}
    lines = []
    for path in scope[:60]:
        spans = windows.get(path) or ()
        shown = prompt_safe(path)
        if spans:
            where = ", ".join(f"{lo}-{hi}" for lo, hi in spans[:12])
            lines.append(f"  {shown}  (changed around lines {where})")
        else:
            # No post-image line to anchor on. A removed bounds check looks exactly like this, so the
            # file is named WITHOUT a range rather than dropped — `diffscope.hunk_windows` on why.
            lines.append(f"  {shown}  (changed, but the change added no lines — read it whole)")
    return ("Changed files in this pull request, and where the change is. The ranges include "
            f"{HUNK_RADIUS} lines of context either side; you may still read anything in the "
            "checkout, and should when following what the changed code calls.\n" + "\n".join(lines))


def _goal(scope: tuple[str, ...]) -> str:
    if not scope:
        return ("No changed files were resolved for this pull request. Say so and stop; do not hunt "
                "the whole repository, which is deep mode's job and is not budgeted here.")
    return ("Review the changed files listed in your instructions. Read them, follow what they call, "
            "and report what you find.")


__all__ = [
    "DEFAULT_MAX_STEPS", "SYSTEM_TEMPLATE", "FindingState", "SimpleRun",
    "adjudicate_all", "build_simple_registry", "run_simple", "witness_payload_bytes",
]
