"""Execution tools for simple mode — the free tier's answer to "the agent cannot run anything".

**WHY THIS MODULE EXISTS, in the numbers that bought it.**

Until 2026-08-19 the free-tier registry held four tools (`read_file`, `grep`, `list_dir`,
`report_finding`) and its system prompt said so: *"You have READ tools only."* The container it runs
in ships node 22, a JRE, ruby, php-cli, dotnet 8, gcc/g++ and git — **209 MB -> 529 MB**, added
2026-08-17 so that a demonstration could execute — and every one of those runtimes was reachable ONLY
by `witness.adjudicate`, which runs AFTER the loop has ended. The agent that decides what to propose
could not observe the thing it was proposing about.

The cost is measured, not argued. A measured run, N=5 on a
pinned target at temperature 0, byte-identical revisions:

    findings        4 4 4 4 4     stdev 0.00     the report is PERFECTLY stable
    gate_eligible   1 2 0 0 2     stdev 1.00     3 builds pass, 2 fail, same commit

    cause, as the artefact printed it                          n     what ONE execution would have shown
    the marker 'path: served 54 chars' is not present          4     `path: served 55 chars`
    the entry point was KILLED (rc=137) rather than finishing   3     the program dying, producing nothing
    it exited 1 rather than dying on a fatal signal            4     exit 1

Seven of those fourteen are the agent betting on runtime behaviour it had no instrument to check, and
the run doc says so in as many words: *"it has read tools only and by design cannot run the program
once to look."* Two of the three `rc=137` losses were REAL exploits, refused because the payload
(`kill -9 $PPID`, reproduced 8 of 8 on an idle machine) destroyed the evidence it was meant to produce.

**The shipped mitigation for both was PROSE.** `simple.build_simple_registry` carries 1,421 characters
of instruction inside `report_finding`'s description — *"Choose a marker you have READ"*, *"your
payload must leave the program ALIVE"* — billed to the customer's endpoint on every pull request. That
is a missing tool being paid for in tokens.

**WHAT THIS MODULE DOES NOT DO, and the decision it keeps intact.**

`simple.adjudicate_all` runs after the loop *"so no proposal can be revised in response to a verdict"*,
and `simple._repo_relative` warns that telling the agent its witness was rejected *"invites it to try
another until one sticks"*. **That rule is untouched.** These tools return an OBSERVATION — exit code,
stdout, stderr — and never a verdict. Nothing here calls `witness.adjudicate`, imports `Witness`, or
can tell the agent whether a finding will gate. The grader still re-runs independently after the loop,
on the digest-pinned entry point, with `self_defeating_marker`, `_marker_is_not_the_payload`, the
empty-payload baseline and the benign controls all firing exactly as before.

The distinction is the whole design: **observation is not adjudication.** A marker READ from real
output does not weaken the anti-forgery guard — it makes the guard fire on a proposal that was worth
making.

**THE PERIMETER, stated honestly rather than claimed away.**

`run_entry` adds no new KIND of execution: it is `bash -- <entry> <input>` with `entry_env()`, in the
checkout, which is byte-for-byte what `witness.adjudicate` already does post-loop. It adds instances.

`run` DOES add a new kind — arbitrary argv — and the residual is named in `_run_shell` rather than
buried. The library design: *"an agent whose context includes attacker-influenced text, holding
a tool that can address a network, is a prompt-injection primitive"*, and this repository has already
had that exact hole live once (the separate package's `harness_contract`, 2026-08-18). What is done about
it here is real and partial, and both halves are recorded.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import pathlib
import subprocess
import tempfile
from dataclasses import dataclass, field

from . import memcap
from .tools import OBS_WINDOW_CHARS, Tool, ToolContext, ToolResult, _file_index
from .witness import (DEFAULT_TIMEOUT, FATAL_SIGNAL_CODES, NETWORK_ISOLATION, TIMEOUT_KILL_CODES,
                      bounded_run,
                      _normalise, entry_env, isolation_prefix, redact_secrets, resolve_entry)

#: Seconds one `run` / `run_entry` call may take. DERIVED from the adjudicator's own timeout
#: (`witness.DEFAULT_TIMEOUT`) rather than restating a number: this file claims `run_entry` is
#: "byte-for-byte what `witness.adjudicate` does", and an entry point that only just finishes for the
#: agent must be one that only just finishes for the grader — a smaller value here would let a run
#: "hang" for the agent while it still demonstrates under adjudication.
DEFAULT_EXEC_TIMEOUT = DEFAULT_TIMEOUT

#: Hard ceiling on the timeout the model may ask for. The model controls this argument and the loop has
#: no wall clock of its own; the maintainers' notes records the same gap on `run_bash`'s timeout.
MAX_EXEC_TIMEOUT = 120

#: What fraction of a run's MOVES may be executions. The relation the ceiling below was always meant
#: to express, written as the relation rather than as its value at one particular default.
#:
#: **0.6 IS CHOSEN TO PRESERVE 24 AT THE DEFAULT. It is NOT the 0.5 the old comment claimed.** That
#: comment read *"24 is roughly max_steps/2"*, and 24/40 is 0.6, not 0.5 — the prose and the arithmetic
#: disagreed by twenty percent and the prose is the half a reader believes. Naming the true ratio is
#: the point of writing it as a relation: 0.5 would ship 20 and quietly cut every default run's
#: execution budget by a sixth, which is a behaviour change nobody asked for and no measurement
#: supports. So the value is back-solved from the shipping number deliberately, and said so here rather
#: than dressed up as a principle.
#:
#: What IS a judgement is the shape: above half, because a review that only reads cannot check what it
#: claims; below one, because a run whose every move is a subprocess has stopped reviewing and started
#: fuzzing. 0.6 satisfies both and happens to be what shipped.
EXEC_CALLS_PER_STEP = 0.6


def exec_budget(max_steps: int) -> int:
    """Executions a run of `max_steps` moves may pay for.

    **THE CEILING WAS A LITERAL SIZED AGAINST A DEFAULT THAT CALLERS OVERRIDE, and it produced a false
    positive on the first real customer audit.** `--max-steps` is a customer flag;
    a measured run records a 1,960-file engagement run at 200, where the fixed
    24 was **12% of the run's moves** rather than the 60% the comment above claims. It bound twice. Once
    it merely stopped a confirmation. The second time the agent could not reach the backend that
    constructs `onboarding_url`, could not clear a candidate, and **shipped a finding that was not a
    defect** — a false positive on a customer report, which is the exact outcome the
    reproducing-input doctrine exists to prevent.

    So the ceiling now tracks the run it is bounding. A run given 200 moves gets 120 executions; a run
    given 40 still gets 24. `--max-tokens` is the bound that actually costs money and it is unchanged —
    this one only stops execution from crowding out the rest of the loop.

    Never below 1: a run permitted zero executions inside a container shipping seven language runtimes
    is the four-tool agent that the design notes — *"Simple mode can run the program it reviews"* —
    was written to end, reintroduced by arithmetic.
    """
    return max(1, int(max_steps * EXEC_CALLS_PER_STEP))


#: Executions one RUN may pay for, across both tools, WHEN NO STEP COUNT IS SUPPLIED. Not a safety
#: control — the env scrub and the digest check are — but a COST control: each call is a subprocess
#: plus a full transcript re-send, and the maintainers' notes records a run that retrieved 206,732
#: bytes for 1,479,494 tokens by repeating a cheap call.
#:
#: THE VALUE AT THE DEFAULT, kept as a constant because `ExecState` must be constructible without a
#: step count — a maintenance script and the maintainers' suite both do it.
#:
#: **IT IS A HAND-SYNCHRONISED COPY, WHICH THIS REPOSITORY HAS ALREADY BEEN BITTEN BY, so it is held
#: by a test rather than left to good intentions.** Commit `880f0f7` found the last one:
#: `variance.py`'s `READ_DEFAULT_BYTES` drifted from the constant it was meant to mirror and would
#: have mis-baselined an instrument silently. That fix derived by IMPORT, which is the better answer
#: and is unavailable here — `simple.py` imports this module, so importing `DEFAULT_MAX_STEPS` back
#: would be a cycle. So the relation is held the other way `880f0f7` used, an identity assertion:
#: the maintainers' suite asserts `exec_budget(DEFAULT_MAX_STEPS) == MAX_EXEC_CALLS`, the same shape
#: as the maintainers' suite's identity test over the observation-window sites.
MAX_EXEC_CALLS = 24

#: Characters of combined stdout+stderr returned to the model per call. The loop clamps a serialized
#: observation with a head-slice (`agentloop` `[:max_obs_chars]`), so this is cut here, at the tail,
#: where the loss is visible and announced — not there, where it is silent. Derived as half the
#: observation window (`tools.OBS_WINDOW_CHARS`) so the "must stay below max_obs_chars" relation this
#: comment asserts is STRUCTURAL: it cannot drift above the window it has to sit under.
MAX_OUTPUT_CHARS = OBS_WINDOW_CHARS // 2


@dataclass
class ExecState:
    """What this run has executed, and under what containment. One per `run_simple`.

    Threaded into the tools by CLOSURE, never by `functools.partial`. The maintainers' notes and
    the separate package's `harness_contract` note record why: **a partial keyword is a DEFAULT, not a
    binding.** `toolvalidate` never flags unknown args, `agentloop` passes `tc.arguments` verbatim, and
    `ToolRegistry.call` does `tool.fn(self.ctx, **args)` — so a model emitting `state=` or `entry=`
    replaces the injected value. That chain was executed end to end on this repository once already.
    """

    calls: int = 0
    entry_calls: int = 0
    shell_calls: int = 0
    max_calls: int = MAX_EXEC_CALLS
    #: "isolated" (a network namespace was entered), "unrestricted" (the kernel refused), or "unknown"
    #: (never probed). Reported, never assumed — see `network_mode`.
    network: str = "unknown"
    #: Where the model may write. Outside the checkout, so the ordinary case leaves no trace in the
    #: tree the findings point at.
    scratch: str = ""
    #: Every command line the shell tool ran, for the journal. The agent's own moves are evidence about
    #: the run and the artefact could not previously say whether it executed anything at all.
    log: list[str] = field(default_factory=list)
    #: How many executions the ceiling DENIED. Not a duplicate of `calls >= max_calls`, and the
    #: difference is the whole point: a run that spent its last call and then stopped asking is a run
    #: that finished, while a run that asked again and was refused is a run that was CUT OFF. Only the
    #: second is evidence about the ceiling.
    #:
    #: **It was invisible everywhere but the model's own transcript.** `spend` returned the refusal
    #: sentence to the agent and told nothing else — not the journal, not the payload, not the report,
    #: not either instrument — and `status` stayed `done`. So a run that could not finish verifying
    #: reported as a clean one. On a customer engagement that silence is what let a candidate the agent could not
    #: clear reach a customer's report as a finding (a measured run).
    refused: int = 0

    def spend(self) -> str:
        """Charge one execution, or return the refusal sentence when the ceiling is reached."""
        if self.calls >= self.max_calls:
            self.refused += 1
            return (f"execution budget exhausted ({self.max_calls} calls). Report what you have; "
                    f"reading is still available.")
        self.calls += 1
        return ""

    @property
    def exhausted(self) -> bool:
        """Did the ceiling actually stop this run doing something it tried to do?

        Read off `refused` rather than off `calls`, because "spent every call" and "was denied a call"
        are different claims and only the second one indicts the ceiling. A run that used all 24 and
        had nothing further to ask was not constrained by anything.

        **THAT LAST SENTENCE IS FALSE FOR THIS LOOP, and `spent` below is why it needed a companion
        rather than a correction.** It assumes the model learns the ceiling by hitting it. It does
        not: every tool result carries `executions_left`, so the model reads 0 and stops asking BEFORE
        it is ever refused. The ceiling then binds in perfect silence — `refused` stays 0, `exhausted`
        stays False, and every completeness field describes a truncated run as a whole one.
        """
        return self.refused > 0

    @property
    def spent(self) -> bool:
        """Did this run use every execution it was given?

        **Measured 2026-09-03 on a live diff against a real repository.** The agent's own last turn
        opened "I have no tool budget left, so let me consolidate what I established", at model turn
        20 of an allowed 40, with `calls == budget == 24` and `refused == 0`. The report's trust row
        said `complete run`, `shard-result.json` said `"complete": true, "limit_hit": ""`, and the run
        log said "the execution ceiling refused nothing, so no claim here was cut short by it".

        A SECOND SIGNAL RATHER THAN A WIDER `exhausted`, because the distinction that docstring draws
        is real and worth keeping: being denied a call is evidence the ceiling CUT the run off, and
        spending the last one is evidence it may have. What was wrong was reporting the second as no
        constraint at all. Three states, three sentences — see `telemetry.execution_lines`.
        """
        return self.calls >= self.max_calls

    def remaining(self) -> int:
        return max(0, self.max_calls - self.calls)


# ── network containment ─────────────────────────────────────────────────────────────────────────────

#: The probe, and the prefix, kept together so they cannot drift apart — and since 2026-08-24 they live
#: in `witness`, which is the module the ADJUDICATOR reads. Re-exported under the old name because this
#: module's callers name it, and because a second literal `("unshare", "-n", "--")` is exactly the
#: two-copies-of-one-value drift the maintainers' notes is about.
_UNSHARE = NETWORK_ISOLATION


def network_mode(state: ExecState, runner=None) -> str:
    """Probe whether this container can enter a network namespace; cache it on the state.

    **This is a real control where it works and an honest `unrestricted` where it does not**, which is
    the shape `containment.py` already argues for: confirming containment is the burden of proof, and
    ambiguity is failure — so ambiguity is REPORTED rather than resolved in our favour.

    `unshare -n` needs `CAP_SYS_ADMIN`. Docker's default capability set does not include it, so on a
    stock GitHub-hosted runner this is expected to return "unrestricted" and the residual in
    `_run_shell` is the live one. It is probed rather than assumed because the answer depends on the
    customer's runner configuration, not on ours, and a self-hosted runner with a wider capset gets the
    stronger arm for free.

    The probe itself is `witness.isolation_prefix`, so the answer the AGENT's tools get and the answer
    the ADJUDICATOR gets come from one implementation. They were two, and the second one did not
    exist: the model's shell was wrapped and the customer's entry point never was. This function keeps
    its own cache because `ExecState.network` is journalled — the word in the record has to be the word
    this run acted on.
    """
    if state.network != "unknown":
        return state.network
    state.network = "isolated" if isolation_prefix(runner or subprocess.run) else "unrestricted"
    return state.network


def _isolation(state: ExecState, runner) -> tuple[str, ...]:
    """The argv prefix for one execution, routed through `network_mode` so the journal's word and the
    argv agree. Two call sites — the shell and the entry point — and neither may have its own."""
    return NETWORK_ISOLATION if network_mode(state, runner) == "isolated" else ()


# ── tamper detection ────────────────────────────────────────────────────────────────────────────────

def scope_digest(repo, paths) -> str:
    """A digest over the files a finding may point at, taken before the loop and re-checked after.

    **Prevention is not available and this does not pretend otherwise.** The container runs as root, so
    read-only bits do not bind, and `unshare -n` (where it works at all) isolates the network rather
    than the filesystem. The honest control is therefore DETECTION with a consequence: if the tree the
    findings describe is not the tree that was reviewed, `run_simple` refuses to gate.

    It mirrors `witness.entry_digest`, which has protected the entry point the same way since the loop
    could not touch it — the difference being that a shell CAN, so the surface has to widen to the
    changed files as well.

    A path that does not exist contributes its absence rather than being skipped: a run that DELETED a
    changed file must not digest the same as one that left it alone. It took two mutation passes to
    get a bench row that actually scores this — rewriting a file never reaches the branch, and deleting
    a NON-empty one is caught by the vanished content regardless, so only an EMPTY file deleted tells
    the two implementations apart.

    **TWO LIMITS, stated because a control that over-claims is worse than one that is narrow.**

    * **It covers the paths it is GIVEN.** `run_simple` passes the diff scope plus the entry point,
      which is where a diff-scoped mode's findings live — but a claim naming a file outside the scope
      has no baseline here, because the "before" digest must be taken before the loop and the claim
      arrives during it. Widening to the whole checkout was rejected on cost, not on principle.
    * **Modify-then-restore digests clean.** An agent that edited a file, observed it, and put it back
      leaves this quiet. **That is load-bearing on the SECOND control rather than a hole**: the gate
      re-executes the entry point after the loop, against the tree as it finally stands, so a
      demonstration obtained from code that no longer exists does not reproduce and does not gate. This
      digest is the belt over that brace — it catches the case where the tree was left changed, which
      is the one the brace cannot speak to.
    """
    root = pathlib.Path(repo).resolve()
    h = hashlib.sha256()
    for rel in sorted(set(paths or ())):
        h.update(rel.encode("utf-8", "replace") + b"\0")
        try:
            p = (root / rel).resolve()
            p.relative_to(root)
            h.update(p.read_bytes() if p.is_file() else b"\0ABSENT\0")
        except (OSError, ValueError):
            h.update(b"\0UNREADABLE\0")
        h.update(b"\0")
    return h.hexdigest()


# ── payload staging ─────────────────────────────────────────────────────────────────────────────────

def payload_bytes(payload: str = "", payload_base64: str = "") -> bytes:
    """The bytes the model meant, or ValueError.

    Deliberately the same contract as `simple.witness_payload_bytes` — one field or the other, never
    both — so the agent learns ONE rule and uses it at both the observation and the reporting end. A
    payload that runs here and is then re-encoded differently for `report_finding` would make this tool
    actively misleading, which is worse than not having it.
    """
    if payload and payload_base64:
        return _raise("pass witness-style payload OR payload_base64, never both")
    if payload_base64:
        try:
            return base64.b64decode(payload_base64.strip(), validate=True)
        except (binascii.Error, ValueError) as e:
            return _raise(f"payload_base64 is not valid base64: {e}")
    return payload.encode("utf-8", "surrogateescape")


def _raise(msg: str):
    raise ValueError(msg)


def _capped(stdout: str, stderr: str) -> tuple[str, str]:
    """Split `MAX_OUTPUT_CHARS` across the two streams, announcing any cut IN the stream it happened to.

    stderr is favoured when both are large: a traceback, a sanitiser report and `command not found` all
    arrive there, and they are what the agent is usually looking for.
    """
    out, err = stdout or "", stderr or ""
    if len(out) + len(err) <= MAX_OUTPUT_CHARS:
        return out, err
    err_cap = min(len(err), max(MAX_OUTPUT_CHARS // 2, MAX_OUTPUT_CHARS - len(out)))
    out_cap = max(0, MAX_OUTPUT_CHARS - err_cap)
    if len(out) > out_cap:
        out = out[:out_cap] + f"\n...[stdout truncated: {len(stdout) - out_cap} more chars]"
    if len(err) > err_cap:
        err = err[:err_cap] + f"\n...[stderr truncated: {len(stderr) - err_cap} more chars]"
    return out, err


# ── the tools ───────────────────────────────────────────────────────────────────────────────────────

def _observation(rc, stdout: str, stderr: str, note: str, state: ExecState) -> ToolResult:
    """One execution, as the model sees it. **An observation, never a verdict.**

    `note` leads, for the reason `_grep` puts its markers first: the loop head-slices a serialized
    observation, so anything appended last is the first thing dropped — and the note is what says the
    run was killed, or truncated, or that the budget is nearly gone.

    There is deliberately no `demonstrated`, no `expectation` and no `why_not` here. Those words belong
    to `witness.Witness`, which is built after this loop has ended and which this module never imports
    a verdict from.

    **REDACTED HERE TOO, and this site is worse than the adjudicator's.** `witness.redact_secrets`
    explains why `entry_env` alone does not hold: the child is root in our container and
    `/proc/1/environ` still carries the block the kernel copied at exec time. Everything this function
    returns goes into the model's message history, and from there into the journal, the transcript and
    any artifact that carries them — so a `cat /proc/1/environ` through `run` would publish the key
    even on a run that never reached adjudication at all.
    """
    out, err = _capped(redact_secrets(stdout), redact_secrets(stderr))
    return ToolResult(True, data={
        "note": note,
        "exit_code": rc,
        "stdout": out,
        "stderr": err,
        "executions_left": state.remaining(),
    })


def _run_entry_point(ctx: ToolContext, state: ExecState, *, repo, entry: str, runner,
                     payload: str = "", payload_base64: str = "") -> ToolResult:
    """Execute the DECLARED entry point on the model's input and hand back what happened.

    **Byte-for-byte the adjudicator's invocation**, and that is the requirement rather than a
    convenience: `witness.adjudicate` runs `bash -- <resolved entry> <staged input>` with `cwd=repo`,
    `env=entry_env()`, `text=True, errors="replace"` and a timeout. Any difference here would let the
    agent observe one program and be graded on another, which is a worse instrument than none.

    `errors="replace"` is load-bearing for the same reason it is there: this executes the CUSTOMER'S
    script, and a witness that demonstrates a memory-safety bug puts raw memory and sanitiser output on
    stdout. Strict utf-8 would raise `UnicodeDecodeError`, which is neither `TimeoutExpired` nor
    `OSError` and would escape every handler here.

    **The input is staged OUTSIDE the checkout** (`state.scratch`), so a run that observes a payload
    leaves the tree the findings point at unchanged and `scope_digest` stays quiet.
    """
    if refusal := state.spend():
        return ToolResult(False, error=refusal)
    resolved = resolve_entry(repo, entry)
    if resolved is None or not resolved.is_file():
        # Registration already gates on this, so reaching it means the entry point moved DURING the
        # run. Refusing beats executing something else under its name.
        return ToolResult(False, error=f"the declared entry point {entry} no longer resolves in the checkout")
    try:
        data = payload_bytes(payload, payload_base64)
    except ValueError as e:
        return ToolResult(False, error=str(e))
    try:
        scratch = pathlib.Path(state.scratch or tempfile.mkdtemp(prefix="shard-exec-"))
        scratch.mkdir(parents=True, exist_ok=True)
        input_path = scratch / "shard_probe_input"
        input_path.write_bytes(data)
    except OSError as e:
        return ToolResult(False, error=f"could not stage the payload: {e}")

    state.entry_calls += 1
    # THE SAME PREFIX THE ADJUDICATOR USES, for the same reason the timeout and the environment are
    # the same: this function's whole worth is that what the agent observes is what the grader will
    # observe, and a program with a network here and none there is a different program. `()` wherever
    # the kernel refuses — see `witness.isolation_prefix`.
    argv = [*_isolation(state, runner), "bash", "--", str(resolved), str(input_path)]
    try:
        proc = runner(argv, cwd=str(repo), capture_output=True, text=True, errors="replace",
                      timeout=DEFAULT_EXEC_TIMEOUT, env=entry_env())
    except subprocess.TimeoutExpired:
        return _observation(None, "", "",
                            f"the entry point did not finish within {DEFAULT_EXEC_TIMEOUT}s. A hang is "
                            f"not a demonstration — the runner will refuse it after this run too.",
                            state)
    except (OSError, subprocess.SubprocessError) as e:
        return ToolResult(False, error=f"could not execute the entry point: {type(e).__name__}: {e}")

    rc = proc.returncode
    # **NORMALISE BEFORE COMPARING, and this was a live bug in this function for its first hour.**
    # `witness._normalise`: *"`128 + N` is what a shell reports; `subprocess` reports a DIRECT child's
    # signal as `-N`"*. The membership tests below were written against the shell's form and the smoke
    # run produced `-9` — so the single most valuable note this tool has, the one that closes the
    # measured `kill -9 $PPID` loss, silently did not fire on the commonest shape of it.
    #
    # The constants and the normaliser are IMPORTED from `witness` rather than restated. This tool's
    # whole worth is that what the agent observes is what the grader will observe; two copies of the
    # signal table are two chances for them to disagree.
    code = _normalise(rc) if isinstance(rc, int) else rc
    note = f"{entry} exited {rc}."
    # THE ONLY INTERPRETATION THIS TOOL OFFERS, and it is about the PROCESS, not about the finding.
    # a measured run: four of five post-fix samples carried a
    # payload built on `kill -9 $PPID`, two of them REAL exploits, and the run's status was still
    # `done`. Naming the kill is not a verdict on the claim — it is telling the agent that the thing it
    # is standing on collapsed underneath it.
    if code in TIMEOUT_KILL_CODES:
        note += (" It was KILLED rather than finishing, so it produced no exit status and no complete "
                 "output for anything to observe. A payload that kills or hangs the program destroys "
                 "the evidence it was meant to produce.")
    elif code in FATAL_SIGNAL_CODES:
        note += " It died on a fatal signal."
    return _observation(rc, proc.stdout, proc.stderr, note, state)


def _run_shell(ctx: ToolContext, state: ExecState, *, repo, runner,
               command: str, timeout: int = DEFAULT_EXEC_TIMEOUT) -> ToolResult:
    """Run a shell command in the checkout. **The new perimeter, and its residual, stated here.**

    WHAT IS CONTROLLED:

    * **Credentials.** `entry_env()` strips the whole `INPUT_*` namespace and every name that looks
      like a secret, so the child cannot read `OPENROUTER_API_KEY` or `INPUT_GITHUB_TOKEN`. That hole
      was live once — an entry point of `#!/bin/sh` + `env` put both verbatim into a report published
      back to the pull request's author — and this tool would have re-opened it exactly.
    * **The clock.** Bounded per call and clamped to `MAX_EXEC_TIMEOUT`; the model controls the
      argument, so the ceiling is ours.
    * **The count.** `ExecState.max_calls`, shared with `run_entry`.
    * **The tree.** Writes are not PREVENTED (root ignores the write bit; there is no read-only mount
      to reach for), so they are DETECTED: `scope_digest` is taken before the loop and re-checked
      after, and `run_simple` refuses to gate a run that altered what it reviewed.
    * **The network, WHERE THE KERNEL ALLOWS IT.** `network_mode` probes `unshare -n` once and the
      command is wrapped when it works.

    **THE RESIDUAL, and it is not small.** On a stock GitHub-hosted runner Docker grants no
    `CAP_SYS_ADMIN`, so `unshare -n` fails and this tool has unrestricted egress. The agent's context
    contains the pull request's diff, which on a fork PR is written by someone who does not otherwise
    have the base repository's source. That is the library design's prompt-injection primitive
    with a real asset behind it.

    What makes it *acceptable rather than ignored*, and the customer is told the same thing in
    `README.md` rather than discovering it: the container ALREADY executes an attacker-authored
    `.shard/entry.sh` with network access on every gated run, so egress is not a capability this tool
    introduces to the perimeter. What it introduces is egress under the MODEL's direction rather than
    under the entry point's. The closing move is a network-denied runner or an egress proxy — a
    deployment control, named in the docs, not something this process can assert about itself.
    """
    if refusal := state.spend():
        return ToolResult(False, error=refusal)
    cmd = (command or "").strip()
    if not cmd:
        return ToolResult(False, error="command is empty")
    try:
        secs = max(1, min(int(timeout or DEFAULT_EXEC_TIMEOUT), MAX_EXEC_TIMEOUT))
    except (TypeError, ValueError):
        secs = DEFAULT_EXEC_TIMEOUT

    state.shell_calls += 1
    state.log.append(cmd)
    argv = [*_isolation(state, runner), "bash", "-c", cmd]
    env = entry_env()
    # The scratch directory is ANNOUNCED rather than enforced by cwd. Setting cwd outside the checkout
    # would prevent nothing (`cd` exists) and would break every relative path the other three tools
    # speak, which are all repo-relative. Telling the model where it may write, and detecting it when
    # it writes elsewhere, is the pair that actually holds.
    env["SHARD_SCRATCH"] = state.scratch or tempfile.gettempdir()
    env["SHARD_REPO"] = str(repo)
    try:
        proc = runner(argv, cwd=str(repo), capture_output=True, text=True, errors="replace",
                      timeout=secs, env=env)
    except subprocess.TimeoutExpired:
        return _observation(None, "", "",
                            f"the command did not finish within {secs}s and was killed.", state)
    except (OSError, subprocess.SubprocessError) as e:
        return ToolResult(False, error=f"could not run the command: {type(e).__name__}: {e}")
    # THE MEMORY CEILING, reported as an OBSERVATION rather than a refusal — this tool's whole contract
    # is "you are told what happened, never whether it would count", and the run DID happen. What the
    # agent must not conclude is that its program is wrong: `memcap.refusal` says which of the two it
    # was. `run_entry` is deliberately NOT capped; see `shard/memcap.py` and the design notes A6.
    if capped := memcap.refusal(proc):
        return _observation(proc.returncode, proc.stdout or "", proc.stderr or "", capped, state)
    note = f"exited {proc.returncode}."
    if state.network == "unrestricted":
        note += " (this container could not enter a network namespace; the command had network access)"
    return _observation(proc.returncode, proc.stdout, proc.stderr, note, state)


def _outline(ctx: ToolContext, path: str) -> ToolResult:
    """The definitions in a file with their line numbers — the map, without the file.

    The machinery is `tools._file_index` and it already ships; until now it was only ever APPENDED to a
    partial `read_file`, so the only way to obtain a map was to pay for a window of source you did not
    want. `tools.py`'s own measurement over 29 real runs is the case for making it callable: 831 of
    1,022 `read_file` calls carried an offset — the agent PAGES — and the paging thrashes, re-fetching
    windows it had already seen. The maintainers' notes has the worst observed instance: one 3,339-line
    file read 64 times in windows about six lines apart, 206,732 bytes retrieved for 1,479,494 tokens,
    the run still hitting its step ceiling with nothing proposed.

    Same confinement as every read tool, same heuristic labelling: unknown extensions get NO index
    rather than a guessed one, because a confidently wrong map is worse than none.
    """
    from .tools import _is_within, _read_allowed_roots

    p = pathlib.Path(path)
    if not p.is_absolute():
        p = ctx.engine_root / path
    if not any(_is_within(p, r) for r in _read_allowed_roots(ctx)):
        return ToolResult(False, error=f"refused: read outside allowed roots ({p})")
    if not p.is_file():
        return ToolResult(False, error=f"not a file: {p}")
    lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
    index = _file_index(lines, p.suffix)
    if not index:
        return ToolResult(True, data=f"[no index for {p.suffix or 'this file type'}; {len(lines)} lines. "
                                     f"Use read_file or grep.]")
    return ToolResult(True, data=f"[{len(lines)} lines]{index}")


# ── registration ────────────────────────────────────────────────────────────────────────────────────

#: `run_entry` is listed ABOVE `report_finding`, and that is the point of the ordering rather than a
#: detail. `tools.ToolRegistry.openai_tools` cites the measurement — on a weak open model the
#: first-listed of two comparable tools wins 76.7% to 0.0% — and the whole reason this module exists is
#: that the agent reported witnesses it had never run. Unmeasured on THIS registry and recorded as such:
#: simple mode's measured configuration is the four-tool one, which adding these tools already changes.
_RUN_ENTRY_PRIORITY = 2

_RUN_ENTRY_DESC = (
    "Execute the declared entry point on an input you supply and see EXACTLY what it does — its exit "
    "code, its stdout and its stderr. This is the same invocation the runner will make after this run "
    "ends, so what you see here is what it will see. Use it before reporting any witness: read the "
    "real output and take your marker from it rather than working one out. You are told what happened, "
    "never whether it would count."
)

_RUN_DESC = (
    "Run a shell command in the checkout. node, java, ruby, php, dotnet, gcc/g++, python and git are "
    "all installed. Use it to run the code you are reviewing, reproduce behaviour, or check an "
    "assumption. Write only under $SHARD_SCRATCH — modifying the checkout is detected and voids the "
    "run's ability to fail the build."
)


def build_exec_tools(state: ExecState, *, repo, witness_entry: str | None = None,
                     runner=None) -> list[Tool]:
    """The execution half of the simple-mode toolset, as a list the registry builder registers.

    Every tool is a CLOSURE over exactly the model's own parameters. `functools.partial` is not used
    and must not be: `ToolRegistry.call` does `tool.fn(self.ctx, **args)` and `toolvalidate` never
    flags an unknown argument, so a partial keyword is a default the model can overwrite — the chain
    that let a model redirect `harness_contract`'s endpoint and post the customer's harness source to
    an address of its choosing. A closure taking only `payload`/`payload_base64`/`command`/`timeout`
    makes `state=`, `repo=`, `entry=` and `runner=` a `TypeError` the registry reports as bad args.

    `run_entry` is registered ONLY when an entry point is declared AND resolves. That is
    the separate package's capability rule, measured: a tool that fails when called *"is not merely
    useless, it is corrosive"* — `instrument` failed 56% of its calls and the agent rationally stopped
    reaching for the tools that could have helped it.
    """
    # `bounded_run` and NOT `subprocess.run`, and it is the SAME default `witness.adjudicate` took on
    # 2026-09-01. That is what keeps this identical rather than what breaks it: the rule below is that
    # `run_entry` must be byte-for-byte what the grader re-runs, so the two have to move together, and
    # they now share one function. What is bounded is OUR reading of the pipe, not the child's argv,
    # its environment or its exit status.
    run = runner or bounded_run
    # TWO DEFAULTS, AND THE ASYMMETRY IS THE POINT. `run` executes MODEL-AUTHORED argv, so it gets
    # `memcap`'s resident ceiling over the whole process tree. `run_entry` executes the CUSTOMER's
    # declared entry point, and its entire justification is that it is byte-for-byte what
    # `witness.adjudicate` re-runs after the loop — a ceiling on the tool but not on the grader would
    # make this module's "what you see here is what it will see" claim false.
    #
    # **`memcap` NEVER COVERED THE OUTPUT DIRECTION, on either side.** It watches the child tree's
    # RESIDENT SET; a child running `cat /dev/zero` uses almost none itself while the reader
    # accumulates every byte. `capture_output=True` reads to EOF before any truncation happens, so
    # both defaults held an unbounded stream in this process. The design notes A6 is about the memory
    # ceiling on the entry point, which is still deliberately absent; this is the other axis.
    capped = runner or memcap.run
    tools: list[Tool] = []

    if witness_entry and resolve_entry(repo, witness_entry) is not None:
        tools.append(Tool(
            name="run_entry", kind="run_bash", description=_RUN_ENTRY_DESC,
            fn=lambda ctx, payload="", payload_base64="": _run_entry_point(
                ctx, state, repo=repo, entry=witness_entry, runner=run,
                payload=payload, payload_base64=payload_base64),
            args_schema={"payload": "str?", "payload_base64": "str?"},
            priority=_RUN_ENTRY_PRIORITY))

    tools.append(Tool(
        name="run", kind="run_bash", description=_RUN_DESC,
        fn=lambda ctx, command="", timeout=DEFAULT_EXEC_TIMEOUT: _run_shell(
            ctx, state, repo=repo, runner=capped, command=command, timeout=timeout),
        args_schema={"command": "str", "timeout": "int?"}))

    tools.append(Tool(
        name="outline", kind="read",
        description="List the functions and classes in a file with their line numbers, without "
                    "reading the file. Use it to find where to read before reading.",
        fn=_outline, args_schema={"path": "str"}))

    return tools


__all__ = [
    "DEFAULT_EXEC_TIMEOUT", "EXEC_CALLS_PER_STEP", "MAX_EXEC_CALLS", "MAX_EXEC_TIMEOUT",
    "MAX_OUTPUT_CHARS", "ExecState", "build_exec_tools", "exec_budget", "network_mode",
    "payload_bytes", "scope_digest",
]
