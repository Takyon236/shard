"""The witness — simple mode's answer to "how do you know that is real?"

the design notes: simple mode is two-tier. A finding with an executable witness the
runner re-executes is gate-eligible; everything else is informational and can never fail a build. This
module is the adjudicator, and it is the only thing that may set the gate-eligible bit.

## The conclusion that shaped this module, and it is not the obvious one

The obvious design is: the agent writes a script demonstrating the defect, the runner executes it, a
non-zero exit means demonstrated. **That design is unsound and this repository has already paid for
learning why.**

the separate package exists because `write_poc(path="./test_poc.sh", text="echo __EXIT__=1\\n")` was an
accepted tool call that made every replay report a reliable 5/5 crash against a `./poc` that reproduced
nothing. An agent-authored script graded on its own exit status is that defect with the names changed:
`echo "vulnerable"; exit 1` satisfies it, and so does `kill -SEGV $$` for any signal-based rule. **A
witness the agent both authors and is graded on is not evidence.**

So the sound shape is the one the separate capability already uses, and the asymmetry is the whole design:

    the agent supplies DATA            an input, arguments, a payload
    the runner executes SOMETHING ELSE an entry point the agent did not write
    the adjudicator observes           exit status and output, and nothing else

`Witness.demonstrated` is computed from the observation alone. No model opinion reaches it, exactly as
`Verdict.reproduced` is computed from replay exit codes alone.

## The consequence, stated rather than hidden

**Simple mode can only produce a gate-eligible finding on a repository that declares a runnable entry
point.** On a repository that declares none, every finding is a hypothesis. That is a real limit on the
free tier and it is the honest one: the alternative is a gate that fires on the agent's own say-so,
which would make the product's central claim false on the mode that ships first.

An entry point is declared by the customer, in `.shard/`, and is read-only to the agent for the same
reason `test_poc.sh` is. `entry_digest` is taken BEFORE the agent runs and re-checked at adjudication,
so a run that modified the thing grading it is refused rather than believed.

## What the adjudicator can observe

Four expectations, and they are the complete set a subprocess can actually witness. Anything richer
would be the model's opinion wearing a checker's clothes.

| expectation | demonstrated when | baseline run |
|---|---|---|
| `fatal_signal` | the entry point died on SIGILL/ABRT/BUS/FPE/SEGV | never needed |
| `nonzero_exit` | it exited non-zero, and NOT on a timeout kill | `DIFFERENTIAL_NONZERO_EXIT` (also gates the OFFER) |
| `output_marker` | its output contains a marker the CUSTOMER's entry point prints | always |
| `unhandled_exception` | it exited non-zero AND printed a traceback | always |

`output_marker` is safe for the same reason the others are: the marker comes out of an entry point the
agent did not write. A marker the agent could print itself would be worthless, which is why the payload
is never echoed back into the observation — see `_marker_is_not_the_payload`.

### MEASURED 2026-08-12 (W9, canary-java): the paragraph above is TOO STRONG, in the same way

The sentence "safe for the same reason the others are" survives only for entry points whose output does
not depend on the payload. **For an entry point that DISPATCHES on its input — which all four canaries
are, and which any parser-shaped entry point is — `output_marker` demonstrates on a healthy run.** The
baseline runs on an EMPTY payload and takes the entry point's empty branch, so none of the program's
ordinary output appears in it, so every string the program prints on real input is attributable to the
agent's payload. Measured against the real adjudicator on fixtures containing no attack at all:

    benign_command.bin  'processing'     demonstrated=True   exit 0    <- gate-eligible, healthy program
    benign_path.bin     'path: served'   demonstrated=True   exit 0
    benign_xxe.bin      'xxe:'           demonstrated=True   exit 0

This is the SAME defect the section below records for `nonzero_exit` — the baseline is payload-free and
the behaviour is payload-dependent — sitting in the expectation that ships **ON** and is the only route
that works for every managed language. It is language-neutral and reproduces on `canary-js` unchanged.
The `"a"`/`" "` measurement that justified the baseline was taken against an entry point with
payload-independent output, where the baseline genuinely does refute a common marker; it did not
generalise and nothing asked whether it had. `_marker_is_not_the_payload` is unaffected and still stops
the agent reading its own text back — a different attack.

the maintainers' suite::test_the_empty_baseline_does_NOT_make_output_marker_sound_on_a_dispatching_entry_point`
pins it.

### CLOSED 2026-08-12, opt-in: the control the CUSTOMER declares (`benign_controls`)

A benign input beside the entry point — `.shard/entry.sh.benign`, a file or a directory of them — is
run as a further control, and any control reproducing the observation refutes it. Measured against the
real `canary-java` with four controls declared, one per dispatch branch:

    BENIGN fixtures, no attack present        4 of 4 refused   (was 4 of 4 demonstrated)
    honest markers on real attacks            5 of 5 still demonstrate
    the marker 'java.lang' on a real attack   refused  <- benign_deser.bin prints "loaded java.lang.String"

That last row is the `"a"`/`" "` class caught a second time: the attack is real and the marker
evidences nothing, which only a control that reaches the program's ordinary output can tell you.

**Three things about the shape, each of which was measured rather than chosen.** The control must be
the CUSTOMER's — an agent that supplies its own control supplies its own grade. It must be a DIRECTORY,
because one control exercises one branch and a single file closed one of the four rows. And the default
is UNCHANGED: a repository declaring nothing gets exactly the verdicts it got before, so this needed no
lever, and `simple._to_finding` says so on the face of every demonstration reached without one.

**It does NOT fix `nonzero_exit`, and that corrects the design notes §P2b.1 and
an internal audit, which both said one mechanism would do both.** A benign control is a
VALID input, so it exits 0, and a designed rejection is exactly "exits non-zero on input that is not
valid". Measured, and pinned by `test_a_BENIGN_control_does_not_make_nonzero_exit_sound_either`. The
control that lever needs is another input the program correctly REJECTS — a different fixture answering
a different question, and nobody has proposed one.

## The managed-language hole, and why `nonzero_exit` is now WITHHELD until its baseline is active

the design notes names the blocking defect for every language after C. **For C,
`nonzero_exit` is never used** — `fatal_signal` is available and is strictly better.

> **MEASURED 2026-08-12 (W9 §P2b.5): "available" was assumed, and it covers 1 of 3.** The C canary was
> given the `.shard/` entry point it had never had, and the three planted memory-safety bugs were run
> through this adjudicator. `fatal_signal` demonstrated **one**. **ASAN's default is
> `abort_on_error=0`** — it prints its report and calls `exit(1)`, which is not a signal, so the
> sanitiser's own findings do not satisfy the expectation built for them. The one row that is a signal
> is `parse_bravo`, and it is **glibc's FORTIFY check** aborting (`*** buffer overflow detected ***`),
> not ASAN; it would fire without a sanitiser at all. The reachable ASAN bug is witnessed by
> `output_marker` on the banner text — the same route every managed language uses. Nothing here is
> broken and no default is changed; the sentence above is simply narrower than it reads, and C is less
> different from the managed languages than this module has been assuming. For Python, Java,
JavaScript and C# there is no fatal signal, so `nonzero_exit` is the only crash-shaped observation there
is, and WITHOUT a differential baseline its rule is satisfied by a program *rejecting malformed input
exactly as designed*:

> **CORRECTED 2026-08-13 on a runner, and the correction came from the model rather than from here.**
> "For Python … there is no fatal signal" is false for one class, and it is the class that matters
> most. Run `31687294640` reviewed a Python target with a shell-injection defect and the model chose
> the payload `C; kill -SEGV $PPID`: the INJECTED command signals the interpreter, and because
> `entry.sh` `exec`s python3 the fatal signal is the entry point's own. Verified by hand — exit 139 at
> head, exit 0 at base. **Command injection turns any language into a fatal-signal language**, so
> `fatal_signal` reaches the highest-severity managed-language class with no lever and no baseline.
> It does NOT generalise: in the same run the model declined to witness a pickle RCE, an unbounded
> `struct.unpack_from` and a path traversal, and said why — none of them can signal, and
> `struct.error` *"is not a fatal signal"*. That last sentence is `nonzero_exit`'s gap, described
> accurately by the thing it blocks. The paragraph below stands for every class that cannot spawn a
> process.

    rejecting malformed input, as designed    exit 1     demonstrated=True
    argparse usage error                      exit 2     demonstrated=True
    file not found                            exit 1     demonstrated=True
    an actual unhandled defect                exit 1     demonstrated=True

All four would gate a customer's build. This is the measured hole and it is kept as evidence: `nonzero_exit`
shipped in `EXPECTATIONS` — offered to the model and adjudicated as `code != 0` — with NO baseline
behind it, while `output_marker` was given a differential baseline after markers of `"a"` and `" "`
were measured demonstrating against healthy output. Nothing noticed because **no C run ever took the
branch**: `fatal_signal` covers C and is strictly better, so the defective arm was reachable only on the
managed languages that had not shipped yet. A correct-looking expectation, dead in every configuration
that ran and unsound in every one that would.

**The unsound middle state — offered without a baseline — is deleted.** `nonzero_exit` is no longer in
`EXPECTATIONS`; `offered_expectations()` appends it ONLY when `DIFFERENTIAL_NONZERO_EXIT` is on, so the
offer and the sound adjudication turn on together and there is no state in which the model can propose it
without the baseline that makes it mean something. This closes the hole in the conservative direction:
until the baseline is measured, `nonzero_exit` simply cannot be proposed, so a designed rejection is
refused as an unknown expectation rather than believed.

### MEASURED 2026-08-11 (W9 P2): the baseline is NECESSARY AND NOT SUFFICIENT

The paragraph above implies that turning the baseline on makes `nonzero_exit` sound. **It does not, and
the correction is the reason the lever is still off.** `_baseline_contradicts` asks exactly one
question — did the entry point already exit non-zero on an EMPTY payload — which rules out an entry
point broken for every input. It cannot distinguish *"exited non-zero because of a defect"* from
*"exited non-zero because it correctly rejected THIS payload"*, because a designed rejection is
payload-dependent by definition and the baseline is payload-free.

Measured on a CORRECT program — a JSON validator with no defect, which rejects bad input as a
well-written CLI does — with the lever forced on:

    payload                      exit   demonstrated
    b"AAAA"        (not JSON)       1       True      <- gates the build on correct behaviour
    b"{oops"  (malformed JSON)      2       True      <- same
    b"{}"             (valid)       0       False

So rows one and two of the table above are STILL demonstrated with the baseline active. The hole
narrowed; it did not close.

The measurement against the JavaScript canary passed both criteria — 0 demonstrations on
baseline/benign/silent fixtures, 1 on the honest attack — and **that result is vacuous**: `canary-js`
is built so only a planted defect ever exits non-zero, so the no-false-positives arm scored 0 out of 0.
The corpus could not show the failure, which is the trap the maintainers' notes records four times in
one afternoon, and it is recorded here rather than quietly discarded.

This is LANGUAGE-NEUTRAL. Nothing in it is specific to node, so it governs the Python flip that W9 P1.3
left open as well. the maintainers' suite::test_the_differential_baseline_does_NOT_make_nonzero_exit_sound`
pins it.

Two levers still compose here, and **both are constants set to OFF**:

- `DIFFERENTIAL_NONZERO_EXIT` — the floor, and the GATE ON THE OFFER too. Language-neutral, and it
  reuses the mechanism `output_marker` already has: demonstrate only when the payload faults and an
  empty payload does not. **A floor, not a proof** — see the measurement immediately above.
- `UNHANDLED_EXCEPTION` — the precision. A stricter expectation keyed on an interpreter traceback,
  which is the managed-language statement closest to a fatal signal in spirit: the program did not
  intend to be here.

Neither flips until it has a number against a canary with planted defects. That is the maintainers' notes's standing
rule — *a lever lands OFF until it is measured, because a default is a claim* — and the W9
measure-then-flip stays a one-line change to the constant in the commit that carries the measurement,
exactly as hunk scoping shipped.

## Simple-safe

Nothing here is protected. It is subprocess plumbing plus a comparison, which the design notes puts
in the leave-in-Python column, and the free image must contain it because the free image is where simple
mode ships.
"""

from __future__ import annotations

import hashlib
import pathlib
import re
import subprocess
import tempfile
from dataclasses import dataclass

#: Fatal FAULT signals, as a shell reports them (128 + N): ILL, ABRT, BUS, FPE, SEGV. SIGKILL (137) and
#: SIGTERM (143) are deliberately absent — those are how a timeout kills a hang, and counting a hang as
#: a demonstration is the false positive this whole module exists to avoid. Identical reasoning, and
#: identical membership, to `deep/oracle._FATAL_SIGNAL_CODES`.
FATAL_SIGNAL_CODES = frozenset({132, 134, 135, 136, 139})

#: A timeout kill is never a demonstration. Matches `deep/oracle._TIMEOUT_KILL_CODES`.
TIMEOUT_KILL_CODES = frozenset({124, 137, 143})

#: Environment variable names whose VALUE is a credential, stripped before the customer's entry point
#: is executed. Matched on shape as well as by name because `action.yml`'s `api_key_env` input lets the
#: customer NAME the variable holding their model key, so the exact name is not knowable here.
_SECRET_ENV_SUFFIXES = ("_TOKEN", "_KEY", "_SECRET", "_PASSWORD", "_PASSWD", "_CREDENTIALS")
_SECRET_ENV_NAMES = frozenset({"GITHUB_TOKEN", "GH_TOKEN", "AWS_SESSION_TOKEN", "AWS_SECRET_ACCESS_KEY",
                               "AWS_ACCESS_KEY_ID", "ANTHROPIC_AUTH_TOKEN"})


def entry_env(base=None) -> dict:
    """The environment the CUSTOMER'S entry point runs under, with our credentials removed.

    **THE ENTRY POINT IS ATTACKER-AUTHORED CONTENT ON A PULL REQUEST.** It is a file in the repository
    under review, so whoever opens the pull request writes it — and `adjudicate` executes it and then
    writes its stdout and stderr into `Witness.evidence`, which reaches `bundles/*/output.txt`, the
    markdown report, and from there the PR comment `action.py` posts and the artifact the README's own
    workflow uploads. Inheriting the runner's environment therefore turned a four-line `.shard/entry.sh`
    reading `env` into an exfiltration of every secret the job holds, published back to its author.

    Measured before the fix: an entry point of `#!/bin/sh` + `env` put both `OPENROUTER_API_KEY` and
    `INPUT_GITHUB_TOKEN` verbatim into `Witness.evidence`.

    Two rules, and the first is the one that matters most:

    * **the whole `INPUT_*` namespace goes.** GitHub Actions exports every input of the running action
      that way, so it is exactly the set of values the CUSTOMER handed US — including `github_token`
      and whatever `api_key_env` names. Nothing in a customer's build has any business reading our
      inputs, which makes this the one rule with no legitimate loss.
    * names that LOOK like credentials go, by suffix or by a short list of well-known ones.

    **This is a denylist, and a denylist is not airtight** — a job that exports `NPM_AUTH` under a name
    matching nothing here still reaches the entry point. The airtight version is an allowlist, and it
    is not what ships because the entry point is the customer's own build script: it may legitimately
    need `CC`, `JAVA_HOME`, `LD_LIBRARY_PATH` or anything else their toolchain reads, and denying those
    by default would break real targets to close a narrower hole than the two rules above already
    close. Recorded as a deliberate trade rather than an oversight.
    """
    import os

    source = os.environ if base is None else base
    out = {}
    for name, value in source.items():
        upper = name.upper()
        if upper.startswith("INPUT_") or upper in _SECRET_ENV_NAMES:
            continue
        if any(upper.endswith(suffix) for suffix in _SECRET_ENV_SUFFIXES):
            continue
        out[name] = value
    return out


#: The shortest secret value worth substring-matching for. Below this a "secret" is a common word —
#: a job that exports `CI_TOKEN=1` would otherwise turn every `1` in a sanitiser trace into
#: `[redacted]`, destroying the evidence to protect a value that is not one.
_REDACT_MIN_LEN = 8


def secret_values(base=None) -> tuple[str, ...]:
    """The literal strings that must never appear in anything we publish.

    Exactly the values `entry_env` refuses to pass on, read back out of the SAME environment by the
    SAME rule — so a name that becomes a secret there becomes one here in the same commit. Longest
    first, so a value that contains another is replaced whole rather than left with a redacted hole
    in the middle of it.
    """
    import os

    source = os.environ if base is None else base
    kept = set(entry_env(source))
    values = {v for name, v in source.items()
              if name not in kept and isinstance(v, str) and len(v) >= _REDACT_MIN_LEN}
    return tuple(sorted(values, key=len, reverse=True))


def redact_secrets(text: str, base=None) -> str:
    """Remove our credentials from output we are about to publish, by VALUE rather than by name.

    **`entry_env` is not enough on its own, and the reason is the container's own privilege.** It
    strips the credentials from the child's environment, but the child runs as root in the same
    container as this process, so `/proc/1/environ` and `/proc/<our pid>/environ` still hold the
    original block — a copy the kernel made at exec time, which no later mutation of `os.environ`
    rewrites. Four lines of `.shard/entry.sh` recover `OPENROUTER_API_KEY` from there, and the
    entry point's stdout is published back to whoever opened the pull request through
    `Witness.evidence`, the markdown report, `bundles/*/output.txt` and the PR comment.

    Egress is not the channel that matters here and closing it would not have helped: the value
    reaches its author by being PRINTED, not by being sent. So the control is at the last place the
    text is still ours — every capture of a customer-authored program's output goes through this.

    It is applied BEFORE adjudication and not only before reporting, so the attack output and every
    control output are redacted alike and the differential is unchanged. A marker built on a
    credential therefore cannot demonstrate anything either, which is the right answer to a claim
    whose evidence is our own key.

    **The residual, named rather than implied.** This substitutes values we can see in our own
    environment. A secret the runner holds that never enters this process — one read from a file, or
    one this job was never given — is not here to match on, and this cannot redact what it does not
    know.
    """
    if not text:
        return text
    for value in secret_values(base):
        if value in text:
            text = text.replace(value, "[redacted]")
    return text


# ── network containment, for anything that executes customer-authored content ────────────────────────

#: `--` stops `unshare` parsing further options, the same belt-and-braces applied to `bash` below.
NETWORK_ISOLATION: tuple[str, ...] = ("unshare", "-n", "--")

#: The probe's answer for the default runner, computed once per process. `None` = not yet asked.
_ISOLATION_CACHE: tuple[str, ...] | None = None


def isolation_prefix(runner=None) -> tuple[str, ...]:
    """The argv prefix that denies a child process a network, or `()` where the kernel refuses.

    **The customer's entry point is attacker-authored content on a pull request** — `entry_env` says
    so at length — and until 2026-08-24 it was the ONE customer-authored thing that never got this
    treatment. `sandbox._run_shell` wrapped the model's shell commands and `adjudicate`, `attribute`,
    the differential baseline and `run_entry` did not, so the script whose output is published back to
    its author had unrestricted egress on a runner where the model's own shell did not. That is the
    weaker half of the perimeter protecting the stronger one.

    `unshare -n` needs `CAP_SYS_ADMIN`, which Docker's default capability set does not grant, so on a
    stock GitHub-hosted runner this returns `()` and the residual `_run_shell` documents is the live
    one at both sites. It is PROBED rather than assumed because the answer belongs to the customer's
    runner configuration: a self-hosted runner with a wider capset gets the stronger arm without
    being told to ask for it.

    An INJECTED runner is never cached. The cache exists so a run pays for one probe rather than one
    per execution; a test that scripts the probe must get the answer it scripted.
    """
    global _ISOLATION_CACHE
    if runner is not None:
        return _probe_isolation(runner)
    if _ISOLATION_CACHE is None:
        _ISOLATION_CACHE = _probe_isolation(subprocess.run)
    return _ISOLATION_CACHE


def _probe_isolation(runner) -> tuple[str, ...]:
    """Ask the kernel once. Anything other than a clean exit means we did NOT get a namespace —
    `containment.py`'s rule, that confirming containment is the burden of proof and ambiguity is
    failure, applied to the one control this module can assert about itself."""
    try:
        proc = runner([*NETWORK_ISOLATION, "true"], capture_output=True, text=True,
                      errors="replace", timeout=10)
    except (OSError, subprocess.SubprocessError):
        return ()
    return NETWORK_ISOLATION if proc.returncode == 0 else ()


def reset_isolation_cache() -> None:
    """Forget the probe's answer. For tests, which must not inherit a verdict from an earlier one."""
    global _ISOLATION_CACHE
    _ISOLATION_CACHE = None


#: What the agent may propose today, UNCONDITIONALLY. Both are sound on their own observation:
#: `fatal_signal` cannot be arranged by choosing a string, and `output_marker` is decided against a
#: differential baseline. `nonzero_exit` is deliberately ABSENT — it is offered only when its baseline
#: is active (`DIFFERENTIAL_NONZERO_EXIT`), because without that baseline it is unsound. See
#: `offered_expectations` and the module docstring.
EXPECTATIONS = ("fatal_signal", "output_marker")

#: Proposable only while their lever is on. Kept OUT of `EXPECTATIONS` deliberately: that tuple is what
#: `shard/simple.py` prints into the tool description and validates a claim against, so appending to it
#: would offer the model an unmeasured expectation — which is what shipping a lever ON means here.
UNMEASURED_EXPECTATIONS = ("unhandled_exception",)

#: **OFF until measured, and it now gates the OFFER as well as the adjudication.** When on, `nonzero_exit`
#: is both proposable AND decided against a baseline run on an empty payload, so a program that exits
#: non-zero on ANY input cannot demonstrate. When off, `nonzero_exit` is not offered at all — the
#: unsound middle state where it was offered without a baseline is gone. See the module docstring:
#: without the baseline, a Python entry point rejecting malformed input as designed was a gate-eligible
#: finding.
DIFFERENTIAL_NONZERO_EXIT = False

#: **OFF until measured.** Offer and adjudicate the `unhandled_exception` expectation.
#: **MEASURED 2026-08-18 AGAINST `corpora/false-positive-witnessed.json`, AND IT STAYS OFF.** The arm
#: STILL OPEN row 2 asked for finally ran: the same five clean trees, same ceilings, lever ON.
#:
#:     lever OFF   5/5 complete, 80 changed lines, 1 finding,  0 gate-eligible
#:     lever ON    5/5 complete, 80 changed lines, 5 findings, 0 gate-eligible
#:
#: **It was exercised, so the zero is not the trivial kind** — two findings proposed a witness and both
#: chose `unhandled_exception`; both were refused with *"the entry point exited 0, so no exception went
#: unhandled"*. It refused correctly, twice.
#:
#: **And two proposals is not a precision figure.** Zero false gates over 80 changed lines bounds the
#: rate at something very coarse, not at zero, and turning a GATE on against that is the mistake
#: `tools.MIN_READ_BYTES` was measured twice to avoid.
#:
#: The useful result is why the corpus cannot settle this, and it is structural: **the declared entry
#: points do not reach the code these diffs change**, so most cases produce no witness proposal
#: whatever is offered — the pyyaml report says so itself, that the entry point runs `yaml.safe_load`
#: and never imports `setup.py`. A corpus that could answer this needs cases whose diffs sit in code
#: the entry point executes, which is a different selection rule and a bigger piece of work.
#:
#: Measured cost of the absence, from the same day: the model chose `fatal_signal` for a Python
#: traceback in 4 of 5 canary samples, because it is the only exception-shaped route offered.
UNHANDLED_EXCEPTION = False

DEFAULT_TIMEOUT = 60

#: How much captured output is kept as evidence. Enough to show a reviewer why, small enough that a
#: runaway entry point cannot fill an artifact upload.
MAX_EVIDENCE_CHARS = 4000

#: CPython's uncaught-exception banner, and the table stops at one entry ON PURPOSE.
#:
#: A traceback is unforgeable in the same sense a fatal signal is — a correct program does not print one
#: — but only for a runtime whose banner is actually known. Phase 1 of the design notes is
#: Python, and nothing here has been measured against node, the JVM or the CLR. Guessing at their shapes
#: would produce a table that, in the words `survey._MARKERS` already carries, *would look more thorough
#: and be no more true*: a wrong pattern is a false negative on the language it names and, if it
#: overmatches, a gate-eligible finding on a program doing nothing wrong.
#:
#: A runtime absent from this table simply cannot use `unhandled_exception`, and that is the honest
#: limit. It loses nothing it had: the language-neutral half of the fix is `DIFFERENTIAL_NONZERO_EXIT`,
#: which knows about no runtime at all.
#:
#: **THE JVM's BANNER IS NOW MEASURED, AND ITS ROW IS DELIBERATELY NOT HERE YET.** Against canary-java
#: with `UNHANDLED_EXCEPTION` forced on, 2026-08-12:
#:
#:     table                        demonstrated on attacks   false positives
#:     cpython only (as shipped)              0/5                  0/12       <- inert for Java
#:     + `Exception in thread "`               5/5                  0/12
#:
#: So one row would take Java from cannot-use to 5/5 — the sixth-mechanism pattern again, a lever that
#: would be dead in a language on the day somebody turned it on. It is held back because the row and
#: the lever belong in ONE commit: adding the token while `UNHANDLED_EXCEPTION` is off changes nothing
#: observable, and adding it silently would mean the eventual flip ships a runtime whose 0/12 nobody
#: re-read. **That 0/12 is also vacuous** — canary-java is built so only a planted defect ever exits
#: non-zero, so the no-false-positives arm scored 0 out of 0, exactly as the `nonzero_exit`
#: measurement against canary-js did. Deciding `UNHANDLED_EXCEPTION` needs a correct-program corpus,
#: which is the same thing `DIFFERENTIAL_NONZERO_EXIT` needs and does not have.
TRACEBACK_TOKENS = ("Traceback (most recent call last):",)


def offered_expectations() -> tuple[str, ...]:
    """What the agent may propose, read AT CALL TIME so a lever is a decision and not an import order.

    `shard/simple.py` uses this in both places that matter — the tool description the model reads, and
    the validation `report_finding` applies — so an unmeasured expectation is neither advertised nor
    accepted while its lever is off, and turning the lever on needs no second edit anywhere.
    """
    return (EXPECTATIONS
            + (("nonzero_exit",) if DIFFERENTIAL_NONZERO_EXIT else ())
            + (UNMEASURED_EXPECTATIONS if UNHANDLED_EXCEPTION else ()))


@dataclass(frozen=True)
class WitnessSpec:
    """What the agent proposed: an input, and what the entry point should be observed doing.

    The agent controls `payload` and `marker`. It does NOT control `entry`, which the customer
    declared, nor the adjudication below.

    **There is deliberately no `args` field.** One existed and was removed: no caller ever populated
    it, so it was a dead option in the maintainers' notes's sense, and its own docstring claimed the agent
    controlled it — a false statement about the code that would have read as a reviewed decision. If
    passing extra arguments is ever needed, adding it back is one line, and the commit that does it
    owns the question this one did not have to answer: extra argv elements land as positional
    parameters of the customer's script, so a script using unquoted `$@` would expand agent-chosen
    text.
    """

    entry: str                         # repo-relative path to the customer's entry point
    expectation: str                   # one of EXPECTATIONS
    payload: bytes = b""               # written to a file and passed to the entry point
    marker: str = ""                   # required by, and only used by, output_marker


@dataclass(frozen=True)
class Witness:
    """What was observed. `demonstrated` is ground truth and nothing may override it."""

    demonstrated: bool
    expectation: str
    exit_code: int | None = None
    entry_digest: str = ""
    evidence: str = ""
    refusal: str = ""                  # why adjudication did not happen at all
    #: Why adjudication DID happen and said no — a different fact from `refusal`, and the artefact said
    #: neither until 2026-08-18. Every non-demonstration rendered as *"the entry point did not do what
    #: was claimed"*, a sentence about the CUSTOMER'S PROGRAM, including for the two cases that are
    #: about our refusal of the agent's proposal (a marker inside its own payload; a traceback the
    #: payload carried) and for a control that refuted it. `_adjudge` writes it and is the only thing
    #: that may, so the reason cannot name a check the verdict did not come from.
    why_not: str = ""
    #: What the observation was checked AGAINST — the control inputs it had to be absent on, in the
    #: order they were run. Empty when the expectation needs no control (`fatal_signal`) or when the
    #: first run did not look like a hit, so nothing was paid for.
    #:
    #: Recorded because the strength of a demonstration is a property of its CONTROLS, and until
    #: 2026-08-12 no artefact said what they were. the design notes is the same complaint about
    #: which expectation demonstrated a finding: a measurement that does not state its own
    #: configuration is what made the P1.3 discrepancy need forensics on raw `output.txt`.
    controls: tuple[str, ...] = ()
    #: The entry point ran out of clock rather than reaching a verdict. Distinct from `refusal`, which
    #: this deliberately does NOT set — on the HEAD side a hang is a result the customer is entitled to
    #: be told about, and the maintainers' suite pins that.
    #:
    #: It exists because `attribute` needs the opposite reading of the same event. Its ladder is
    #: `refusal` -> `demonstrated` -> else INTRODUCED, so a base run that only timed out was scored the
    #: same as a base revision that is clean, and an INHERITED defect failed the build as the change's
    #: fault. A hang at the base revision is "we do not know", never "it is not there".
    timed_out: bool = False
    #: Where the payload this verdict was reached on is ON DISK, so the bundle can carry it.
    #: The product's first sentence is that it reports findings *"only when it can attach a reproducing
    #: input"*, and until 2026-08-08 simple mode attached none: the payload was staged here, executed,
    #: and dropped. Measured on the first real container run — a gate-eligible finding that FAILED a
    #: build shipped `input_present: false` and a reproduce command with an empty path in it.
    input_path: str = ""

    @property
    def gate_eligible(self) -> bool:
        """The ONLY route to a finding that may fail a build in simple mode."""
        return self.demonstrated


def resolve_entry(repo, entry: str) -> pathlib.Path | None:
    """The entry point's real path, or None if it does not belong to this checkout.

    **The containment check the adversarial pass found missing entirely.** `entry` arrives from the
    workflow (`--witness-entry`), and until this existed nothing checked it — unlike every path in
    the separate package. Measured against an empty repository:

        --witness-entry ../outside/evil.sh    -> demonstrated=True, rc=3
        --witness-entry /abs/outside/evil.sh  -> demonstrated=True, rc=3

    Both were GATE-ELIGIBLE, so under `--fail-on reproduced` a script outside the checkout decided the
    build. The absolute case worked because `pathlib.Path(repo) / "/abs/x"` discards `repo` entirely.

    It also refuses an entry whose resolved name begins with `-`. `adjudicate` runs
    `bash <entry> <input>`, and with the CLI's default `--repo .` a `--witness-entry -c` collapses to
    the bare string `-c`, so bash parses it as an OPTION and executes the input path as a command.
    `--` is passed as well, so the refusal and the argv guard are belt and braces rather than either
    alone.
    """
    raw = (entry or "").strip()
    if not raw or pathlib.PurePath(raw).is_absolute():
        return None
    root = pathlib.Path(repo).resolve()
    try:
        resolved = (root / raw).resolve()
        resolved.relative_to(root)
    except (ValueError, OSError):
        return None
    if resolved.name.startswith("-"):
        return None
    return resolved


#: The customer's "this is what ORDINARY input looks like" fixture, beside the entry point they already
#: declared: `.shard/entry.sh` -> `.shard/entry.sh.benign`, a file OR a directory of them.
BENIGN_SUFFIX = ".benign"

#: How many benign controls one adjudication will run. Each is a full execution of the customer's entry
MAX_BENIGN_CONTROLS = 8


def benign_controls(repo, entry: str) -> tuple[tuple[pathlib.Path, ...], int]:
    """The customer's benign fixtures for this entry point, and how many were dropped by the cap.

    **A DIRECTORY, NOT JUST A FILE, AND THAT IS THE MEASUREMENT RATHER THAN GENEROSITY.** Implemented as
    a single file first and measured against the real `canary-java` — it closed ONE of the four rows:

        control declared: benign_command.bin        demonstrated   what it means
        benign_command.bin  marker 'processing'         False      <- closed
        benign_path.bin     marker 'path: served'       True       <- still forged
        benign_xxe.bin      marker 'xxe:'               True       <- still forged
        benign_deser.bin    marker 'deser: loaded'      True       <- still forged

    Because that entry point DISPATCHES on the first byte — `C`, `P`, `X`, `D` — so one control
    exercises one branch, and the whole defect is about entry points that dispatch. A single-file
    convention would have closed a quarter of the hole and read as a fix.

    **WHY THE CONTROL HAS TO BE THEIRS, and this is the whole design constraint.** The empty payload is
    not the payload's counterfactual — it takes a DIFFERENT BRANCH through the program. Measured
    2026-08-12 against the real `canary-java` entry point on fixtures with no attack in them at all
    (the design notes §P2b.1):

        benign_command.bin  marker 'processing'      demonstrated=True  exit 0   <- healthy program
        benign_path.bin     marker 'path: served'    demonstrated=True  exit 0   <- healthy program

    A dispatching entry point emits none of its ordinary output on an empty input, so every string it
    prints on a real one is absent from the baseline and attributable to the agent. Language-neutral —
    it reproduces on `canary-js` unchanged, so it was live in every canary measurement this project has
    ever taken, and `output_marker` is the route that ships ON.

    The control cannot be DERIVED from the agent's payload (truncate it, zero the dispatch byte) and it
    cannot be derived from the agent at all: an agent that supplies its own control supplies its own
    grade, which is the separate package's recorded failure — `write_poc(path="./test_poc.sh",
    text="echo __EXIT__=1")` made every replay report a reliable 5/5 crash. A mutation of the payload is
    also a guess about the input format that will be silently wrong for some.

    **A CONVENTION, NOT A FIFTEENTH ACTION INPUT.** The customer declares the entry point by path
    already; this is a file beside it. Every input added to `action.yml` is another row in the
    `INPUT_*` naming class that made eleven of fourteen inputs inert on a real runner, and a file the
    customer creates in their own repository has no naming rule to get wrong.

    Containment comes from `resolve_entry`, unchanged and for the same reason: this path is joined
    against the checkout root and must resolve inside it.

    Never raises. A control tree we cannot read yields nothing here and the caller keeps the empty
    control it always had — but a control we can SEE and cannot STAGE is a refusal in `adjudicate`,
    because those are different facts.
    """
    resolved = resolve_entry(repo, (entry or "") + BENIGN_SUFFIX)
    if resolved is None:
        return (), 0
    try:
        if resolved.is_file():
            return (resolved,), 0
        if not resolved.is_dir():
            return (), 0
        # Sorted, so the controls a run used are reproducible from the repository rather than from the
        # filesystem's iteration order. Files only: a nested directory is not an input.
        found = sorted(p for p in resolved.iterdir() if p.is_file())
    except OSError:
        return (), 0
    return tuple(found[:MAX_BENIGN_CONTROLS]), max(0, len(found) - MAX_BENIGN_CONTROLS)


def witness_contract(repo, entry: str | None) -> tuple[str, ...]:
    """Every repository path whose CONTENTS decide a verdict, repo-relative and sorted.

    **A digest over the entry point alone protected the weaker half of the adjudicator.** The entry
    point has been covered since the loop could not touch it and `sandbox.scope_digest` widened that
    to the changed files when the loop gained a shell — but the benign controls were never in either
    set, and they are the whole of the differential that makes `output_marker` sound.

    What that left open, in the module's own measured terms: an internal audit closed a
    4-of-4 false-gate rate by running the customer's declared benign inputs, and `benign_controls`
    returns `()` for a directory that is not there. One `rm -rf .shard/entry.sh.benign` from the
    model's shell therefore restored the configuration that was MEASURED to forge four demonstrations
    out of four, and left `scope_digest` — taken over the diff and the entry point — perfectly quiet.
    Emptying one control file does the same thing one file at a time.

    So the contract is the entry point plus the controls it declares, and `run_simple` digests the
    set it saw BEFORE the loop. A control that DISAPPEARS or CHANGES is caught by its own path; a
    control ADDED during the run is not in the before-set and is not caught, which is the right
    asymmetry — an extra benign input can only refuse a demonstration, never manufacture one.

    Paths outside the checkout are dropped rather than digested: `scope_digest` resolves against the
    repository root and would score them `UNREADABLE`, which is a mismatch on every run rather than
    on a tampered one.
    """
    if not entry:
        return ()
    root = pathlib.Path(repo).resolve()
    out = {entry}
    controls, _dropped = benign_controls(repo, entry)
    for path in controls:
        try:
            out.add(path.resolve().relative_to(root).as_posix())
        except (OSError, ValueError):
            continue
    return tuple(sorted(out))


#: `File "<path>", line <n>` — a Python traceback. Kept separate from the generic form below because
#: the path is quoted and may contain characters the bare `path:line` shape would stop at.
_PY_FRAME = re.compile(r'File "([^"]+)", line (\d+)')

#: `<path>.<ext>:<line>`, optionally `:<column>`. The shape gcc, clang, the sanitisers, node and most
#: linters use. The extension is required: without it every `foo:12` in ordinary prose is a candidate.
_PATH_LINE = re.compile(r"([\w./+-]+\.[A-Za-z][\w+]*):(\d+)(?::\d+)?")

#: A V8 stack frame: `    at fn (/abs/file.js:12:5)` or the anonymous `    at /abs/file.js:12:5`.
#: Anchored to the whole line, and the column is REQUIRED — both narrow it away from the generic form
#: above, which would otherwise match any `path:line` sitting in ordinary prose. Node is the only
#: runtime here that prints a column on every frame, and that is what makes the shape identifiable.
_NODE_FRAME = re.compile(r"^\s+at (?:.*?\()?([^\s()]+):(\d+):\d+\)?$", re.M)

#: Which end of a runtime's stack is the INNERMOST frame — the one nearest the fault. It is not a
#: convention anybody agrees on: CPython prints the innermost LAST, V8 and the sanitisers print it
#: FIRST, and getting it backwards is wrong in every case rather than most of them.
FIRST, LAST = 0, -1

#: **ONE ROW PER RUNTIME, and adding a language is a row plus a measurement — never a new branch.**
#:
#: This started as two hand-written arms bolted onto one `if` chain, and the second one was landed only
#: after the first was found inert in a language it had never been measured against. A third arm would
#: have been a third branch and a fourth chance for the ends to be assumed rather than measured, which
#: is exactly the shape the design notes exists to stop repeating.
#:
#: `end` is NOT a default and must not be guessed. Every row cites the measurement that fixed it, taken
#: against a canary whose ground truth was read out of its own source:
#:
#:   cpython  LAST   canary-py 3/3 (first-frame would be 0/3) — W9 P1.0a
#:   v8       FIRST  canary-js 5/5 (last-frame  would be 0/5) — W9 P2.1
#:   jvm      FIRST  canary-java 5/5 (last-frame would be 0/5) — W9, 2026-08-12. Supersedes the
#:                   original citation, "openjdk 17, nested throw, fault line named first — W9 P2b",
#:                   which was a two-frame synthetic. The row was already right; it is now right on
#:                   five planted defects whose stacks run through java.base reflection frames, three
#:                   java.util.Properties frames, a `Caused by:` block and a secondary class.
#:   ruby     FIRST  ruby 3.2,   nested raise, fault line named first — W9 P2b
#:   go       FIRST  go 1.23,    nested panic, fault line named first — W9 P2b
#:   clr      FIRST  .NET 8,     nested throw, fault line named first — W9 P2b
#:
#: **TWO LANGUAGES DELIBERATELY HAVE NO ROW, and that is a measured result rather than an omission.**
#:
#:   rust  — a backtrace frame is `    at ./src/main.rs:2:5`, which is the V8 shape exactly, and Rust
#:           is innermost-first like V8. The existing row already resolves it correctly; measured on a
#:           real `rustc 1.90` panic. A separate row would be the same pattern under another name.
#:   php   — PHP prints the fault in the HEADER (`Uncaught …: msg in /w/boom.php:3`) and its numbered
#:           `#0 /w/boom.php(6)` frames are the CALLERS ONLY, in `path(line)` form the generic pattern
#:           does not match. So exactly one `path:line` resolves and the generic arm answers correctly.
#:           **A frame-shaped row here would be actively WRONG** — it would return the caller, 6, where
#:           the truth is 3. Measured on php 8.3.
#:
#: Both were verified against real stacks before being left out, which is the only way that claim is
#: worth anything: the maintainers' suite::test_the_runtimes_with_no_row_still_resolve` pins them.
#:
#: A runtime absent from this table is not broken: its frames still reach the generic `_PATH_LINE` arm
#: below, which answers when exactly one in-repository location resolves and refuses otherwise. That is
#: the honest limit and it is what every language had before any of these rows existed.
#: `\tat pkg.Class.method(File.java:12)` — the JVM, and Kotlin and Scala on it. The parenthesised
#: `file:line` with NO column is what separates it from the V8 shape above.
#:
#: **THIS ROW READS THE RIGHT END OF THE STACK AND RESOLVES NOTHING ON A REAL JAVA PROJECT**, and the
#: reason is in the shape above rather than in the pattern: the JVM puts the package in the METHOD name
#: and prints a BARE BASENAME for the file. There is no `src/main/java/...` in a frame, ever. `_inside`
#: joins that basename onto the checkout root and requires the result to exist, so — measured through
#: this function against canary-java, 2026-08-12:
#:
#:     source really at                       observed_location
#:     Entry.java                             ('Entry.java', 166)   5/5   <- the flat canary
#:     src/main/java/com/example/Entry.java   None                  0/5   <- every Maven/Gradle project
#:
#: Left as-is deliberately: the honest behaviour of the narrow rule is to refuse, and answering would
#: mean searching the checkout for a basename — which is a change to `_inside`, affects every runtime,
#: and needs its own measurement of how often two files share a name. Recorded in
#: the design notes rather than fixed by feel.
_JVM_FRAME = re.compile(r"^\s+at\s+\S+\((\S+?):(\d+)\)\s*$", re.M)

#: `boom.rb:2:in 'inner'`, and the continuation lines `\tfrom boom.rb:5:in 'middle'`. The `:in ` suffix
#: is the discriminator; without it this would be the generic `path:line` shape.
_RUBY_FRAME = re.compile(r"^\s*(?:from\s+)?(\S+?):(\d+):in[ \t]", re.M)

#: Go prints the function on one line and its position on the next, indented: `\t/w/boom.go:6 +0x19`.
#: The leading TAB and the bare path are the whole shape — Go names no `at`, no parens, no column.
_GO_FRAME = re.compile(r"^\t(\S+?\.go):(\d+)(?:\s|$)", re.M)

#: `   at Boom.Inner(Int32[] a) in /src/Program.cs:line 3` — the CLR. `:line N` with a SPACE is unique
#: to .NET and is why nothing else here matches it: the generic `path:line` shape needs a digit
#: straight after the colon, so a C# stack resolved to NOTHING before this row existed.
_CLR_FRAME = re.compile(r"^\s+at\s+.*?\sin\s(\S+?):line\s+(\d+)\s*$", re.M)

_RUNTIME_FRAMES: tuple[tuple[str, re.Pattern[str], int], ...] = (
    ("cpython", _PY_FRAME, LAST),
    ("v8", _NODE_FRAME, FIRST),
    ("jvm", _JVM_FRAME, FIRST),
    ("ruby", _RUBY_FRAME, FIRST),
    ("go", _GO_FRAME, FIRST),
    ("clr", _CLR_FRAME, FIRST),
)


def payload_readings(payload: bytes) -> tuple[str, ...]:
    """Every reading of the agent's bytes that a tolerant entry point might reconstruct.

    **THIS FUNCTION EXISTS BECAUSE ONE BYTE DEFEATED THE PRODUCT'S CENTRAL GUARD, AND IT IS A HARDENING
    OVER A KNOWN SET — NOT A PROOF.** Read the second half of this docstring before trusting it.

    Three guards subtract the payload from the evidence — `_marker_is_not_the_payload`,
    `_traceback_not_from_payload`, and `observed_location`'s `forged` set — and each of them asks its
    question against TEXT. Until `b0df78a` that was sound for a reason nobody wrote down:
    `WitnessSpec.payload` was `str.encode("utf-8")`, so `payload.decode("utf-8", errors="replace")`
    was **lossless and injective** and there was exactly one reading to subtract. `b0df78a` made the
    payload arbitrary bytes, and the same decode became lossy — in the one direction that matters,
    because it DESTROYS marker text that a tolerant entry point REASSEMBLES:

        payload   b"ui\\xffd="                     what the guard saw   'ui\\ufffdd='   marker absent
        entry     decode(errors="ignore")         what it printed      'uid='          marker present
        verdict   demonstrated=True, gate_eligible=True, exit 1, against a program with NO defect

    Measured 2026-08-12 (an internal audit Finding 1, appendix A1) through the shipping
    chain, not in a component test. `b"ui\\xffd=".decode("utf-8", "ignore") == "uid="` is the whole
    defect in one line, and a tolerant parser is not exotic: a tokenizer, `tr -cd '[:print:]'`, a
    sanitising error message and an ordinary C string copy all do this.

    **The obvious fix — refuse non-UTF-8 payloads for `output_marker` — is WRONG and is not what this
    is.** It would regress the capability won the same morning: `parse_charlie` was demonstrated with
    `witness_payload_base64 "Q/9Y"` (= `43 FF 58`) *and* `marker 'AddressSanitizer'`. The blocking rule
    and the new capability are one code path. `Q/9Y` survives here because `AddressSanitizer` appears in
    none of its readings; the forgery does not, because `uid=` appears in three of the forgery's.

    Subtracting a SET can only ever refuse more, never demonstrate more, so it fails in the direction a
    gate must: a legitimate demonstration lost is a report the customer still receives, and a forged one
    kept is a build failed against code that is not broken.

    **THE RESIDUAL, stated because a list of decodings cannot close this class.** An entry point that
    genuinely TRANSFORMS its input — gunzip, base64-decode, ROT13, a decryption — still launders a
    marker through, and no set of readings will see it. The sound version is causal (origin-tracking of
    the marker, i.e. taint), which this product does not have and should not guess at; that is recorded
    as the open half in an internal audit "The unifying root cause" and it is a different
    problem from the empty-baseline defect on the same page. What is closed here is the ENCODING route.
    """
    if not payload:
        return ("",)
    readings = [
        # The historical reading, kept first and kept verbatim: this function must never be weaker than
        # what it replaced, and every earlier mutation test was written against this exact string.
        payload.decode("utf-8", errors="replace"),
        # The cheap forgery, and the one measured: an invalid byte VANISHES rather than becoming U+FFFD,
        # so the surrounding text closes up into the marker again.
        payload.decode("utf-8", errors="ignore"),
        # Lossless and total — every byte is one character. This is what a `latin-1` or byte-oriented
        # entry point echoes, and it is the reading that catches a marker spelled in raw high bytes.
        payload.decode("latin-1"),
        # An ASCII-only parser drops the high bytes entirely. Distinct from utf-8/ignore, which KEEPS a
        # well-formed multi-byte sequence: b"u\\xc3\\xa9id=" reads as "uéid=" there and "uid=" here.
        bytes(b for b in payload if b < 0x80).decode("ascii"),
        # `tr -cd '[:print:]'` — control bytes are valid UTF-8, so nothing above sees b"ui\\x01d=".
        bytes(b for b in payload if 0x20 <= b <= 0x7e).decode("ascii"),
        # A BOM-aware or wide-character parser. Both ends, because the payload names the encoding and
        # the agent picks it: "uid=".encode("utf-16") is invisible to every reading above.
        payload.decode("utf-16-le", errors="ignore"),
        payload.decode("utf-16-be", errors="ignore"),
    ]
    #: Ordered dedupe, first reading kept. A pure-ASCII payload — the ordinary case — collapses to
    #: three: the text itself and the two wide readings of it, which do not coincide with anything.
    #:
    #: NOT narrowed further, deliberately. The wide readings could be skipped unless the payload holds
    #: a NUL, which is true of UTF-16-encoded ASCII and false for a marker that is not ASCII, and the
    #: saving would be a few regex scans against a function that has just paid for a SUBPROCESS. A
    #: soundness guard is the wrong place to trade correctness for a cost nobody can measure.
    return tuple(dict.fromkeys(readings))


def observed_location(evidence: str, repo, *, payload: bytes = b"") -> tuple[str, int] | None:
    """Where the entry point SAID it faulted, when the answer is unambiguous. Otherwise None.

    The agent supplies `path` and `line` with its claim, and until 2026-08-08 that guess was what the
    SARIF alert anchored on — including for findings the runner had gone on to DEMONSTRATE. Measured on
    the first paid container run: the alert landed on `src/frame.py:15`, and the traceback produced by
    the very execution that made the finding gate-eligible said line 17. Two lines out, in the field a
    reviewer's cursor lands on, with ground truth sitting unread in `Witness.evidence`.

    **The rule is deliberately narrow: exactly one distinct in-repository location, or nothing.** Every
    candidate must resolve to a file that EXISTS inside the checkout, which is what makes this a
    resolution rather than a second guess. When several survive, this returns None and the claim stands
    — a traceback's innermost frame is its LAST for Python and its FIRST for the sanitisers, and
    choosing between them without a measurement would be manufacturing a location, which
    `shard/report.py` says this product does not do. the design notes holds the wider question.

    **The Python arm exists because the narrow rule was measured INERT on every Python demonstration.**
    The rule above was landed and measured on C, where the sanitiser names one in-repository frame and
    the unique-or-nothing test therefore answers. A CPython traceback names one frame per stack level,
    so an in-repository defect is ALWAYS ambiguous and this always returned None — the alert fell back
    to the agent's guess on exactly the findings the runner had gone on to demonstrate, which is the
    defect the design notes records being closed for C on 2026-08-08, reappearing in a language the
    fix did not reach. Another lever correct in one configuration and silently dead in another.

    The docstring above said choosing between first and last *"without a measurement would be
    manufacturing a location"*. So it was measured, on the Python canary
    (the reference harness's `targets/canary-py`) against ground truth read out of the
    source rather than assumed:

        fixture                in-repo frames   last   defect line   match
        attack_command.bin     [151, 146, 64]     64            64    True
        attack_path.bin        [151, 146, 79]     79            79    True
        attack_deser.bin       [151, 146, 90]     90            90    True

    **3/3, and the sample is three planted defects on one synthetic target** — it is a measurement, not
    a rate, and it is recorded as such. The leading frames are the dispatch scaffolding; the last is the
    vulnerable call every time, which is simply what "innermost" means for a Python traceback.

    The arm is deliberately narrow. It fires only when the evidence carries Python frames and NOTHING
    of the generic `path:line` shape resolves inside the checkout — a mixed report (a Python program
    shelling out to a sanitised binary) is exactly the ambiguity the original rule refuses, and it
    still refuses it. The two patterns do not overlap in practice: the Python form has no colon between
    the path and the line, so `_PATH_LINE` does not match it.

    **The node arm exists because the SAME thing happened a third time, and it reads the OTHER END.**
    W9 P2.0 measured this function inert on node for the same structural reason it was inert on Python:
    a V8 stack names one frame per level and several resolve in-repo, so unique-or-nothing refuses. The
    fix is not a copy of the Python arm, because the direction is reversed — measured on the JavaScript
    canary (the reference harness's `targets/canary-js`, five planted defects, ground
    truth read out of the source by its own `verify.js`):

        fixture                in-repo frames        first   defect line   match
        attack_command.bin     [67, 192, 196]           67            67    True
        attack_path.bin        [81, 192, 196]           81            81    True
        attack_deser.bin       [92, 192, 196]           92            92    True
        attack_malformed.bin   [112, 192, 196]         112           112    True
        attack_pollute.bin     [145, 153, 192, 196]    145           145    True

    **FIRST is 5/5 and LAST — the Python rule — is 0/5.** Node sides with the sanitisers, Python does
    not, and copying either arm to the other language would be wrong in every case measured. Five
    planted defects on one synthetic target is a measurement and not a rate, exactly as canary-py's 3/3
    is recorded.

    One limit worth stating where the rule lives. For a two-part class the innermost frame is the SINK,
    not the defect: canary-js's prototype pollution resolves to the gadget that executed the polluted
    key, not to the merge that wrote it. That anchor is honest — it is where the entry point said it
    faulted — but a reviewer sent there still has to walk back. This function's contract has never been
    "root cause", and node makes the gap visible rather than introducing it.

    Language-agnostic by construction everywhere else: it matches shapes and then asks the filesystem.

    **The payload is subtracted, for the same reason the marker and the traceback are.** An entry point
    that echoes its input would otherwise let the agent smuggle `File "src/anything.py", line 1` through
    the payload and relocate the customer's SARIF alert onto any file:line it chose. Both sibling guards
    (`_marker_is_not_the_payload`, `_traceback_not_from_payload`) already do this; this one did not.

    **And subtracting the FULL MATCHED TEXT was not enough — measured 2026-08-11, on both arms.** An
    echo that reformats defeats it, because the matched text carries the evidence's own whitespace:

        payload   " at evil (/repo/innocent.js:1:1)"     one leading space
        evidence  "    at evil (/repo/innocent.js:1:1)"  re-indented to four by the entry point
        result    ('innocent.js', 1)                     the agent chose the customer's alert location

    The Python arm had the same hole from a different angle — a payload naming `src/x.py` does not
    literally contain the evidence's absolute `/repo/src/x.py`.

    **So what is subtracted is the set of LOCATIONS the payload itself claims**, parsed out of the
    payload with the same three patterns and resolved the same way. Comparing `(rel, line)` rather than
    raw bytes is what makes it survive reformatting, re-rooting and requoting, and it stays precise: a
    forged `entry.js:1` no longer suppresses a real `entry.js:145` in the same file, which a
    path-only subtraction did — that over-reach was caught by
    `test_a_node_frame_the_payload_supplied_is_not_a_location` before it shipped.

    A payload that asserts the exact location the run then reports is still dropped, and this returns
    None — falling back to the agent's own claim, which is where this function stood before 2026-08-08.
    That direction loses a correction; the other hands an attacker the customer's alert location.
    """
    if not evidence:
        return None
    root = pathlib.Path(repo).resolve()

    def _locations(pattern, text):
        """Ordered (rel, line) for every match in `text` that resolves to a file inside the checkout."""
        return [(rel, int(m.group(2))) for m in pattern.finditer(text)
                if (rel := _inside(root, m.group(1))) is not None]

    #: What the AGENT's own payload asserts, read with the SAME patterns. Subtracting this instead of
    #: comparing raw text is what makes the guard survive reformatting and re-rooting: it compares the
    #: CLAIM (`src/x.py`, 1) rather than the bytes that spell it, so the entry point is free to re-indent,
    #: absolutise or requote what it echoes and the smuggled location is still recognised as the agent's.
    #:
    #: Read over EVERY reading of the payload, not one — `payload_readings` on why a single UTF-8 decode
    #: stopped being injective, and on the forged `('src/victim.py', 1)` that measured it here.
    forged = set()
    for payload_text in payload_readings(payload):
        forged |= set(_locations(_PATH_LINE, payload_text))
        for _name, _pattern, _end in _RUNTIME_FRAMES:
            forged |= set(_locations(_pattern, payload_text))

    def _claims(pattern):
        return [loc for loc in _locations(pattern, evidence) if loc not in forged]

    other = set(_claims(_PATH_LINE))
    runtimes = [(name, _claims(pattern), end) for name, pattern, end in _RUNTIME_FRAMES]

    # WHAT MAKES EVIDENCE "MIXED" IS DISAGREEMENT, NOT THE NUMBER OF ROWS THAT MATCHED.
    #
    # The first version of this refused whenever two rows matched, and measuring Rust showed why that
    # is wrong: a Rust backtrace frame is `    at ./src/main.rs:2:5`, which the V8 pattern also matches
    # exactly. Two rows, one runtime, one set of frames — refusing there would break Rust the moment
    # its own row landed, and it would have looked like a Rust bug rather than a table bug.
    #
    # So each matching row is asked for its ANSWER and they must agree. Overlapping patterns that read
    # the same frames the same way agree by construction and cost nothing. A genuinely mixed report —
    # a Python program shelling out to a sanitised binary — produces two different answers and is
    # refused, which is the contract.
    answers, covered = set(), set()
    for _name, claims, end in runtimes:
        if claims:
            answers.add(claims[end])
            covered |= set(claims)

    # `other - covered` and not `not other`: the generic pattern re-finds some runtimes' own frames, so
    # requiring it to be empty would make those rows unreachable. What survives is a second, non-runtime
    # claim — a sanitiser line, a linter message — and that is mixed evidence too.
    if len(answers) == 1 and not (other - covered):
        return answers.pop()

    # No row matched, or the rows disagree. The generic arm is what every language had before any row
    # existed: answer only when exactly one in-repository location resolves anywhere.
    found = other | covered
    return found.pop() if len(found) == 1 else None


def _inside(root: pathlib.Path, raw: str) -> str | None:
    """`raw` as a repository-relative path to a file that is really there, or None.

    Absolute paths are accepted here — unlike `resolve_entry`, which refuses them — because this string
    came from the entry point's own output rather than from configuration, and a traceback naturally
    prints absolute paths. It must still land INSIDE the checkout, and the file must exist: those two
    together are the whole claim being made.
    """
    try:
        resolved = (root / raw).resolve() if not pathlib.PurePath(raw).is_absolute() else \
            pathlib.Path(raw).resolve()
        rel = resolved.relative_to(root)
    except (ValueError, OSError):
        return None
    return str(rel) if resolved.is_file() else None


def entry_digest(repo, entry: str) -> str | None:
    """SHA-256 of the customer's entry point, or None when there is nothing to hash.

    `None` now covers "outside the checkout" as well as "unreadable", and both are correct: a caller
    gets no baseline, so `adjudicate` refuses rather than scoring.

    Reads BYTES. A text read would normalise line endings on some platforms and a tamper that only
    changes them is still a tamper — the same reasoning, and the same prefix length, as
    `deep/permit.harness_digest`.
    """
    resolved = resolve_entry(repo, entry)
    if resolved is None:
        return None
    try:
        data = resolved.read_bytes()
    except OSError:
        return None
    return hashlib.sha256(data).hexdigest()[:16]


def adjudicate(spec: WitnessSpec, repo, *, baseline_digest: str | None,
               runner=subprocess.run, timeout: int = DEFAULT_TIMEOUT,
               workdir=None) -> Witness:
    """Execute the customer's entry point against the agent's payload and observe what happens.

    `baseline_digest` is taken BEFORE the agent runs. A mismatch is a REFUSAL, not a negative result:
    "the agent changed the thing that grades it" and "the entry point ran and nothing happened" are
    different facts, and reporting the first as the second would hide a tamper as a clean run.

    Every failure path returns `demonstrated=False`. There is no exception that could be caught by a
    caller and turned into a pass, which is the direction this must fail in — a false positive here
    gates a customer's build on the agent's say-so.

    The body reads in refusal-precedence order, and each helper holds the reasoning for its own arm:
    `_preconditions` (nothing has run yet), `_stage_payload` (where attacker-shaped bytes may land),
    then the execution itself — kept HERE, because the runner executing something the agent did not
    write is the asymmetry the module docstring rests on — then `_nothing_adjudicated` (the run
    delivered no observation) and `_controlled_verdict` (the observation, against its controls).
    """
    refusal, resolved, digest = _preconditions(spec, repo, baseline_digest)
    if refusal is not None:
        return refusal

    try:
        input_path = _stage_payload(spec.payload, workdir)
    except OSError as e:
        return _refuse(spec, f"could not stage the payload: {e}", digest=digest)

    # `--` before the script: bash stops parsing options there, so a path that survived the checks and
    # still begins with `-` cannot become an option. Belt and braces with `resolve_entry`'s own refusal.
    #
    # THE ISOLATION PREFIX GOES ON `argv` ITSELF, not on this one call, and that is the point:
    # `_controlled_verdict` builds every baseline and every benign control as `argv[:-1] + [control]`,
    # so the attack run and the runs it is scored against cannot end up on different sides of the
    # perimeter. A control with a network the attack did not have would be a differential over two
    # different programs. `isolation_prefix` is `()` wherever the kernel refuses — see its docstring.
    argv = [*isolation_prefix(), "bash", "--", str(resolved), str(input_path)]
    try:
        # errors="replace": this runs the CUSTOMER'S witness entry point, and a witness that
        # demonstrates a memory-safety bug crashes — raw memory, sanitiser output and arbitrary bytes
        # on stdout are its EXPECTED output, not a corner case. `text=True` alone decodes strict utf-8
        # and raises UnicodeDecodeError, which is neither TimeoutExpired nor OSError, so it escapes
        # every `except` here and kills the run. See the separate package`, which had already
        # settled this for the same reason.
        # `env=` and not the inherited environment — see `entry_env`. This script is written by whoever
        # opened the pull request, and its output is published back to them.
        proc = runner(argv, cwd=str(repo), capture_output=True, text=True, errors="replace",
                      timeout=timeout, env=entry_env())
    except subprocess.TimeoutExpired:
        # A hang is not a demonstration. It is also not nothing, so it is recorded as evidence — and the
        # input that caused it is the most useful thing a reviewer could be handed, so it is carried too.
        #
        # `timed_out` is set and `refusal` is NOT. That split is deliberate and both halves are load
        # bearing. On the HEAD side a hang IS a result — the maintainers' suite pins that in as many
        # words, *"a hang is a result, not a refusal to adjudicate"* — so the customer keeps being told
        # their entry point hung rather than that we declined to look.
        #
        # On the BASE side it is not a result at all, and reading it as one was a WRONG BUILD RESULT.
        # `attribute` tests `before.refusal`, then `before.demonstrated`, and otherwise returns
        # INTRODUCED — so a base run that merely ran out of clock was indistinguishable from a base
        # revision that is clean, and a defect present in BOTH revisions failed the build as though the
        # change had introduced it. That is what `diffscope.introduced_line_index` refuses in its own
        # docstring: *"how a tool starts blaming people for code they did not write"*.
        #
        # A flag rather than a reused `refusal` because the two sides genuinely need different answers,
        # and rather than sniffing `evidence` for its own wording at the one call site that cares.
        return Witness(demonstrated=False, expectation=spec.expectation, entry_digest=digest,
                       evidence=f"the entry point did not finish within {timeout}s",
                       why_not=f"the entry point did not finish within {timeout}s, and a hang is not "
                               f"a demonstration",
                       timed_out=True,
                       input_path=str(input_path))
    except (OSError, subprocess.SubprocessError) as e:
        return _refuse(spec, f"the entry point could not be executed: {e}", digest=digest)

    # REDACTED BEFORE IT IS READ, never only before it is reported. Everything downstream — the
    # marker test, `observed_location`, `Witness.evidence`, the bundle, the PR comment — sees the same
    # scrubbed text, so a demonstration cannot be built on our own credential and the differential
    # below stays a comparison of like with like. See `redact_secrets`.
    output = redact_secrets((proc.stdout or "") + (proc.stderr or ""))
    if refused := _nothing_adjudicated(spec, proc, output, digest=digest, input_path=input_path):
        return refused
    return _controlled_verdict(spec, repo, runner=runner, timeout=timeout, argv=argv,
                               input_path=input_path, digest=digest, proc=proc, output=output)


def _preconditions(spec: WitnessSpec, repo, baseline_digest: str | None
                   ) -> tuple[Witness, None, None] | tuple[None, pathlib.Path, str]:
    """What must hold before anything runs: `(refusal, None, None)` or `(None, resolved, digest)`.

    The checks run in refusal-precedence order — the sentence a caller gets names the FIRST thing
    wrong with the proposal, and reordering them would change which refusal a doubly-bad one receives.
    The admitted pair returns alongside deliberately: the entry point is hashed exactly once, here, so
    the digest compared against `baseline_digest` is the digest the eventual `Witness` carries — a
    re-hash after this check would reopen the tamper window the comparison closes.
    """
    if spec.expectation not in offered_expectations():
        return _refuse(spec, f"unknown expectation {spec.expectation!r}"), None, None
    if spec.expectation == "output_marker" and not spec.marker:
        return _refuse(spec, "output_marker requires a marker to look for"), None, None

    resolved = resolve_entry(repo, spec.entry)
    if resolved is None:
        return _refuse(spec, f"entry point {spec.entry!r} is not a repository-relative path inside "
                             f"the checkout; the customer declares it in .shard/"), None, None
    digest = entry_digest(repo, spec.entry)
    if digest is None:
        return (_refuse(spec, f"no entry point at {spec.entry!r}; the customer declares it in .shard/"),
                None, None)
    if baseline_digest is None:
        # Absent-at-setup, present-at-adjudication. The agent authored its own grader, which is the
        # arm the separate package records as a Devil insight rather than a blueprint requirement.
        return _refuse(spec, "the entry point did not exist when the run started"), None, None
    if digest != baseline_digest:
        return _refuse(spec, "the entry point changed during the run", digest=digest), None, None
    return None, resolved, digest


def _stage_payload(payload: bytes, workdir) -> pathlib.Path:
    """Write the payload where the entry point will read it. Raises OSError; the caller refuses on it.

    MEASURED 2026-08-12: THE DEFAULT IS ALSO WHAT BLOCKS A DISPLACED WITNESS, AND IT FAILS SILENTLY.

    the design notes records that the free image carries no JVM, node, ruby, php or
    dotnet, so the entry point for five of the twelve detected languages cannot execute inside the
    artefact at all. The obvious answer is to execute it where the customer's toolchain already is —
    the runner — and the seam for that is `adjudicate`'s `runner=` parameter, which was PROVEN to
    carry it: driving `adjudicate` with a runner that executes in a different filesystem namespace
    reproduces in-process results EXACTLY, anti-forgery refusal included.

    It reproduces them only when the payload is somewhere BOTH sides can see. With just the checkout
    shared — which is exactly what a container action is given — the executor cannot open the path
    below, and the result is not an error and not a refusal:

        shared            marker_command  marker_xxe  attack_malformed  forged
        checkout + workdir     True          True          True          False   <- matches in-process
        checkout only          False         False         False         False   <- rc=1, no refusal

    Every row False, every exit code 1, nothing said. A displaced witness staged here would report
    every finding as unwitnessed and pass the build, which is `2fd4e36`'s green-check-that-reviewed-
    nothing in a second place. **Any design that moves execution off the adjudicator must pass
    `workdir` explicitly**, and the honest place for it is a path shared with the executor and still
    outside the checkout — on a GitHub container action `/github/home` is a candidate and is
    UNVERIFIED here, which is the one thing only a real runner can settle.

    STAGED OUTSIDE THE CHECKOUT unless a caller names somewhere. The payload is attacker-shaped bytes
    the agent chose, and the repository under review is the one place they must not land:
    the design notes is explicit that we never write there, a stray file dirties
    the customer's working tree for every later step in their workflow, and a payload written next to
    their sources could overwrite one. Defaulting to the repo made the unsafe path the DEFAULT and
    `run_simple` never passed a workdir, so every real call took it.
    """
    if workdir is not None:
        work = pathlib.Path(workdir)
        work.mkdir(parents=True, exist_ok=True)
        input_path = work / "shard_witness_input"
        input_path.write_bytes(payload)
    else:
        scratch = tempfile.mkdtemp(prefix="shard-witness-")
        input_path = pathlib.Path(scratch) / "shard_witness_input"
        input_path.write_bytes(payload)
    return input_path


def _nothing_adjudicated(spec: WitnessSpec, proc, output: str, *, digest: str,
                         input_path: pathlib.Path) -> Witness | None:
    """The refusal owed when the run delivered nothing TO adjudicate, or None when a verdict is possible.

    Two arms, and both carry `refusal`: an entry point whose interpreter the image does not hold, and
    a process that was KILLED rather than finishing. `demonstrated=False` alone is the value a clean
    non-demonstration produces, so a run that never delivered an observation must say so explicitly
    or it reads as a clean result — the fail-open each arm's comment records being measured.
    """
    # **THE ENTRY POINT'S OWN INTERPRETER IS MISSING, and until 2026-08-13 that was SILENT.**
    # an internal audit: the free image is `python:3.12-slim` plus `git`, so
    # `node`, `java`, `ruby`, `php` and `dotnet` are absent — and the audit's own words for the C case
    # are *"the failure when it is not done is quiet"*. It was quiet for every language.
    #
    # A `.shard/entry.sh` that `exec`s a runtime the image does not carry makes bash exit **127**, and
    # nothing here distinguished that from a program that simply did not demonstrate. So the customer
    # was told "no reproduction attached" — which reads as *we looked and found nothing* — when the
    # truth is *we could not run your entry point at all*. That is the degraded-run-as-clean shape,
    # inside the one mechanism the product's central claim rests on.
    #
    # A REFUSAL, not a non-demonstration, because those are different facts and only one of them is
    # the customer's to fix. Keyed on 127 AND on the shell's own words, because a wrapper script that
    # catches the failure and exits 0 still leaves the sentence in its output.
    if missing := _missing_runtime(proc.returncode, output):
        return _refuse(spec, f"the entry point could not run: {missing}. Nothing was adjudicated, so "
                             f"this is NOT a clean result — the free image carries python3 and bash "
                             f"and no other runtime, and an entry point needing one cannot execute "
                             f"inside it", digest=digest)

    # **A KILLED WITNESS IS A REFUSAL, NOT A NEGATIVE RESULT — 2026-08-18, and this is a fail-open.**
    #
    # `_adjudge` already refuses to score a kill, which is right: a destroyed process demonstrates
    # nothing. But `demonstrated=False` with no refusal is the SAME value a witness that ran cleanly
    # and observed nothing produces, so the finding dropped to informational, the run status stayed
    # `done`, and the build PASSED with nobody told the witness never finished.
    #
    # **THE CAUSE IS THE AGENT'S OWN PAYLOAD, AND THE FIRST VERSION OF THIS COMMENT SAID OTHERWISE.**
    # It blamed host memory pressure, on the strength of 45 idle executions that produced no kills —
    # and those executions used payloads I invented, not the ones the model writes. `write_bundle` now
    # keeps a refused witness's input (the fix directly above this one), and the preserved payloads
    # settle it:
    #
    #     C; kill -9 $PPID                                            8 of 8 killed, idle machine
    #     Creport.txt; kill -9 $PPID || kill -9 $(ps -o ppid= -p $$)  8 of 8 killed
    #     Dcos\nsystem\n(S'kill -9 $PPID'\ntR.                        8 of 8 killed
    #     C; id                            <- one I invented          0 of 8, exit 0
    #
    # The model demonstrates command execution by KILLING THE PARENT, which is the entry point's own
    # shell. That is the self-defeating marker one door over: a proposal whose success destroys the
    # thing that would have observed it. 4 of 5 samples in a post-fix batch contained one.
    #
    # So the sentence names the payload FIRST, because that is the measured common case, and the
    # environment second. Evidence and `input_path` are KEPT rather than discarded — the input is what
    # settled this, and `_refuse` alone would drop both.
    code = _normalise(proc.returncode)
    if code in TIMEOUT_KILL_CODES:
        return Witness(
            demonstrated=False, expectation=spec.expectation, exit_code=proc.returncode,
            entry_digest=digest, evidence=output[-MAX_EVIDENCE_CHARS:], input_path=str(input_path),
            refusal=f"the entry point was KILLED (rc={code}) rather than finishing, so nothing was "
                    f"adjudicated and this is NOT a clean result. The commonest cause is the reported "
                    f"input itself — a payload that kills or hangs the entry point leaves no exit "
                    f"status and no output to observe, so it destroys the evidence it was meant to "
                    f"produce. Read the preserved input in the bundle before suspecting the machine")
    return None


def _controlled_verdict(spec: WitnessSpec, repo, *, runner, timeout: int, argv: list[str],
                        input_path: pathlib.Path, digest: str, proc, output: str) -> Witness:
    """The verdict on what was observed — after every control had its chance to refute it.

    `_adjudge` decides from the observation alone. A demonstration then pays for its controls — the
    empty payload first, then each benign input the customer declares — and ANY control reproducing
    the observation refutes the demonstration. A control that cannot be RUN is a refusal instead:
    grading against fewer controls than the repository asked for is the quiet-degradation shape this
    module exists to refuse.
    """
    demonstrated, why_not = _adjudge(spec, proc.returncode, output)
    ran: list[str] = []

    if demonstrated and _baseline_required(spec):
        # THE BASELINE RUN, and it is what makes an agent-chosen observation mean anything.
        #
        # The AGENT chooses the marker. Without this, a marker of "a" or " " is present in any healthy
        # entry point's output, so the agent could hand itself a gate-eligible finding against a target
        # doing nothing wrong — `echo "vulnerable"; exit 1` with extra steps, which is precisely the
        # defect this module's docstring says it exists to prevent. Measured before this landed: markers
        # "a", "e", " " and "in" all returned demonstrated=True against the benign output
        # "parsing input file / validation passed / done".
        #
        # A minimum marker LENGTH would not fix it — a long marker can still be common — so the rule is
        # causal instead: the observation must be absent when the entry point runs on an empty payload
        # and present when it runs on the agent's. That makes the claim "my input caused this" checkable
        # rather than "this string appears".
        #
        # The SAME argument is what `nonzero_exit` never had, and the module docstring holds why it went
        # unnoticed for C. A program that exits 1 on every input it dislikes is not demonstrating a
        # defect, and "it exited non-zero" cannot tell the two apart on its own.
        #
        # Only paid when the first run already looks like a hit, so an ordinary non-demonstrating
        # witness still costs exactly one execution.
        #
        # **TWO CONTROLS SINCE 2026-08-12, AND THE SECOND IS THE ONE THAT WORKS ON A REAL PROGRAM.**
        # The empty payload is not the payload's counterfactual — it takes a different BRANCH — so a
        # dispatching entry point emits none of its ordinary output there and every string it prints on
        # a real input reads as caused by the agent. `benign_control` carries the measurement. The
        # empty control is KEPT rather than replaced: it is what refutes a marker of "a" or " " against
        # an entry point whose output does not depend on its input, which is the case it was landed for.
        #
        # ANY control reproducing the observation refutes it. More controls can only ever refuse more,
        # which is the direction a gate must fail in.
        try:
            controls, dropped = _stage_controls(input_path, repo, spec)
        except OSError as e:
            # A control the customer DECLARED and we could not stage is a refusal, not a quiet fallback
            # to the weaker one. Silently grading against fewer controls than the repository asked for
            # is the same shape as `2fd4e36`'s green check on a diff nobody read.
            return _refuse(spec, f"the benign control declared at {spec.entry}{BENIGN_SUFFIX} could not "
                                 f"be staged ({e}), so nothing was adjudicated", digest=digest)
        if dropped:
            output += (f"\n[shard] {dropped} further benign control(s) beyond the first "
                       f"{MAX_BENIGN_CONTROLS} were NOT run; this verdict is checked against fewer "
                       f"controls than {spec.entry}{BENIGN_SUFFIX} declares")
        for what, control in controls:
            baseline = _run(runner, argv[:-1] + [str(control)], repo, timeout)
            if baseline is None:
                return _refuse(spec, f"the run on {what} could not be completed, so "
                                     f"{_OBSERVED[spec.expectation]} could not be attributed to the "
                                     f"payload", digest=digest)
            ran.append(what)
            contradiction = _baseline_contradicts(spec, *baseline, control=what)
            if contradiction:
                demonstrated = False
                why_not = f"{contradiction}, so it was not caused by the reported input"
                # THE MARKER WAS WRONG, AND THIS RUN ALREADY KNOWS THE RIGHT ONE. Measured on a real
                # GLM-5.2 run 2026-08-21 against the pinned canary: three genuine defects — command
                # injection, path traversal and pickle RCE — were each EXECUTED, each printed the
                # attacker's own sentinel to stdout, and all three were refused here and shipped as
                # informational, because the agent named the program's ordinary completion message
                # (`command: done`) instead of the string its payload injected
                # (`INJECTED_BY_ATTACKER`). The customer paid and was told nothing could fail the build.
                #
                # The refusal stays — the marker really does not discriminate — but the reason now
                # carries the sentinel the agent should have named, so its next turn can re-propose
                # instead of guessing again. the maintainers' notes records a marker the model had to
                # COMPUTE costing 4 of 5 real losses; this is the same defect answered with an
                # OBSERVATION rather than with better instructions.
                hint = _payload_sentinels(spec.payload, output, baseline[1])
                if hint:
                    why_not += (f". These string(s) came from the payload, appear in this run's "
                                f"output and are ABSENT from the control: {hint} — one of them is "
                                f"the marker that would discriminate")
                output += f"\n[shard] {why_not}"
                break

    return Witness(
        demonstrated=demonstrated,
        expectation=spec.expectation,
        exit_code=proc.returncode,
        entry_digest=digest,
        evidence=output[-MAX_EVIDENCE_CHARS:],
        input_path=str(input_path),
        controls=tuple(ran),
        # Passed straight through, with no `"" if demonstrated else ...` guard, because the invariant
        # is `_adjudge`'s and belongs where it can be enforced: it returns "" exactly when it says
        # True, and the contradiction loop above only ever writes a reason in the same statement that
        # sets `demonstrated = False`. A guard here would be unreachable, and unreachable code that
        # looks like a safety net is what the maintainers' notes's "earn its place" refuses — it would also have
        # made this file's own mutation sweep report a kill it did not make.
        why_not=why_not,
    )


#: `attribute`'s three answers. Strings rather than an enum because they travel into JSON, SARIF and a
#: markdown report, and a value a customer reads should not need a lookup table.
INHERITED, INTRODUCED, UNATTRIBUTED = "inherited", "introduced", "unattributed"


def attribute(spec: WitnessSpec, base_repo, *, runner=subprocess.run, timeout: int = DEFAULT_TIMEOUT,
              workdir=None) -> tuple[str, str]:
    """Did THIS change introduce the demonstrated defect? Returns `(verdict, why)`.

    **THE CAUSAL ANSWER TO A QUESTION `fail-on: new` WAS ANSWERING LEXICALLY.** Until 2026-08-12 "new"
    meant *the finding's line is one the diff added*, which needs a location and needs the defect to sit
    on an added line. Measured (an internal audit item 7), every row a DEMONSTRATED
    finding:

        introduced defect, demonstration named the line    gated
        introduced defect, the exploit was SILENT          did NOT gate   <- no stack, so no location
        defect on a line this PR DELETED                   did NOT gate   <- a deletion adds no line
        pre-existing defect                                did not gate   <- correct

    Rows 2 and 3 are the ones the owner ruled must gate. Neither is answerable from text: a silent
    exploit produces no location at all, and a removed bounds check introduces a defect while adding no
    line anywhere. **With a reproducing input in hand the question is answerable directly** — run that
    input against that entry point in the code as it was BEFORE the change:

        the payload demonstrates at base      the defect was already there   -> INHERITED
        the payload does NOT demonstrate      this change introduced it      -> INTRODUCED

    That needs no location, so it covers both rows; and it is strictly better evidence than the line
    test even where the line test works, because a defect can move to an added line without being new.

    **THE HARNESS LIVENESS PROBE, and without it this function would be dangerous.** "Did not
    demonstrate at base" and "could not run at base" produce the same silence. A base checkout has no
    build artifacts — `git archive` carries tracked files only — so an entry point that compiles
    lazily rebuilds (every canary does), and one that expects a binary an earlier workflow step
    produced finds nothing and fails. Read as "did not reproduce", that failure would attribute EVERY
    inherited defect to the pull request and fail the build on code the author never touched, which is
    the exact defect `introduced_line_index` refuses to commit and is worse than the gap being closed.

    So a non-reproduction at base is trusted only when the base entry point **exits 0 on its control**
    — the customer's benign input if they declared one, otherwise the empty payload. That is not a new
    assumption: `_baseline_contradicts` already treats a non-zero run on an empty payload as "this
    entry point does not exit 0 on nothing", and the canaries' own entry points document it as a
    requirement. Anything else is `UNATTRIBUTED`, and the caller decides what an unanswered question
    means rather than this function guessing.

    Never raises, and every failure path returns `UNATTRIBUTED` — the direction where the gate does not
    fire on evidence we do not have.
    """
    if base_repo is None:
        return UNATTRIBUTED, "no base revision was available to compare against"
    digest = entry_digest(base_repo, spec.entry)
    if digest is None:
        return UNATTRIBUTED, (f"{spec.entry} did not exist at the base revision, so the defect could "
                              f"not be re-run against the code as it was")

    # THE PROBE FIRST. It is the cheap half and it decides whether the expensive half means anything.
    probe = _base_control(spec, base_repo, runner=runner, timeout=timeout, workdir=workdir)
    if probe != 0:
        return UNATTRIBUTED, (f"the entry point did not run cleanly at the base revision "
                              f"(exit {probe}), so a non-reproduction there is not evidence the "
                              f"defect is new — a base checkout carries no build artifacts")

    before = adjudicate(spec, base_repo, baseline_digest=digest, runner=runner, timeout=timeout,
                        workdir=workdir)
    if before.refusal:
        return UNATTRIBUTED, f"the defect could not be re-run at the base revision: {before.refusal}"
    if before.timed_out:
        # A base run that ran out of clock answered NOTHING. Falling through to the INTRODUCED arm below
        # made "we could not finish" mean "the base revision is clean", so a defect present in both
        # revisions failed the build as this change's fault — and the slower the OLD code was on the
        # payload, the likelier that was. The direction here is the same one `_base_control` above
        # takes for a probe that did not exit cleanly: no attribution beats a wrong one.
        return UNATTRIBUTED, (f"the defect could not be re-run at the base revision: "
                              f"{before.evidence}, so a non-reproduction there is not evidence the "
                              f"defect is new")
    if before.demonstrated:
        return INHERITED, ("the same input demonstrates the same defect at the base revision, so this "
                           "change did not introduce it")
    return INTRODUCED, ("the same input does NOT demonstrate at the base revision, so this change "
                        "introduced it")


def _base_control(spec: WitnessSpec, base_repo, *, runner, timeout, workdir) -> int | None:
    """The base entry point's exit code on its control input, or None if it could not be run at all."""
    resolved = resolve_entry(base_repo, spec.entry)
    if resolved is None:
        return None
    controls, _dropped = benign_controls(base_repo, spec.entry)
    try:
        scratch = pathlib.Path(workdir) if workdir is not None else pathlib.Path(
            tempfile.mkdtemp(prefix="shard-attribute-"))
        scratch.mkdir(parents=True, exist_ok=True)
        probe = scratch / "shard_base_control"
        probe.write_bytes(controls[0].read_bytes() if controls else b"")
    except OSError:
        return None
    result = _run(runner, [*isolation_prefix(), "bash", "--", str(resolved), str(probe)],
                  base_repo, timeout)
    return None if result is None else result[0]


def _stage_controls(input_path: pathlib.Path, repo,
                    spec: WitnessSpec) -> tuple[list[tuple[str, pathlib.Path]], int]:
    """The inputs the observation must be ABSENT on, in the order they are run. Raises OSError.

    Every one is staged BESIDE the payload rather than read from the checkout, so all executions take an
    identical argv shape from an identical directory. That matters for the displaced-witness seam
    documented in `adjudicate`: an executor that can see the payload can see its controls.

    The empty control comes FIRST and is never dropped. It is the cheapest refutation — a marker of "a"
    or " " dies on it — and ordering it first means the common rejection costs one execution rather
    than N.
    """
    controls = [("an empty payload", _stage_baseline(input_path))]
    benign, dropped = benign_controls(repo, spec.entry)
    root = pathlib.Path(repo).resolve()
    for i, source in enumerate(benign):
        staged = input_path.with_name(f"{input_path.name}{BENIGN_SUFFIX}{i}")
        staged.write_bytes(source.read_bytes())
        # NAMED by the path in the CUSTOMER's repository, not by where it was staged: the sentence is
        # read by someone deciding which of their own fixtures to go and look at.
        controls.append((f"the benign input this repository declares at {source.relative_to(root)}",
                         staged))
    return controls, dropped


def _stage_baseline(input_path: pathlib.Path) -> pathlib.Path:
    """An EMPTY payload beside the real one — the "no attack" input the marker must not survive."""
    baseline = input_path.with_name(input_path.name + ".baseline")
    baseline.write_bytes(b"")
    return baseline


def _run(runner, argv: list[str], repo, timeout: int) -> tuple[int | None, str] | None:
    """One execution as `(exit code, output)`, or None if it could not be completed. Never raises.

    The exit code joins the output here because `DIFFERENTIAL_NONZERO_EXIT` grades a baseline on its
    STATUS, where `output_marker` grades one on its text. A `TimeoutExpired` baseline lands in the None
    arm — `subprocess.TimeoutExpired` is a `SubprocessError` — and `adjudicate` refuses rather than
    scoring, which is the direction this must fail in.
    """
    try:
        # errors="replace" — see the note in `adjudicate`. Without it this function raises, and its
        # docstring above promises it never does.
        #
        # `env=entry_env()` for the same reason as `adjudicate`, and it has to be BOTH: this is the
        # path the baseline and the control runs take, and they execute the same customer-authored
        # entry point. Scrubbing one call site and not the other would leave the hole open on every
        # run that reaches a differential baseline.
        proc = runner(argv, cwd=str(repo), capture_output=True, text=True, errors="replace",
                      timeout=timeout, env=entry_env())
    except (OSError, subprocess.SubprocessError):
        return None
    # Redacted on the control side too, for `adjudicate`'s reason on the attack side: the two texts are
    # compared, so scrubbing one and not the other would make our own key look like a marker the
    # payload introduced.
    return proc.returncode, redact_secrets((proc.stdout or "") + (proc.stderr or ""))


#: What each expectation's baseline is attributing to the payload, for the refusal sentence.
_OBSERVED = {
    "output_marker": "the marker",
    "nonzero_exit": "the failure",
    "unhandled_exception": "the traceback",
    "fatal_signal": "the fatal signal",
}


def _baseline_required(spec: WitnessSpec) -> bool:
    """Whether this expectation is decided against a run on an empty payload.

    **`fatal_signal` SAID "never needs one and never will", AND THAT ARGUED THE WRONG QUESTION.** Its
    reasoning — an entry point dying on SIGSEGV "is not something the agent can arrange by choosing a
    string" — is about FORGERY, and it is correct about forgery. Causation is a different question, and
    nothing was asking it: an entry point that faults on EVERY input demonstrates on the agent's attack,
    on a benign input, and on an EMPTY payload alike.

    Measured 2026-08-19, with the customer's own benign controls declared and never run:

        the agent's 'attack'   demonstrated=True  gate_eligible=True  rc=-11  controls=()
        a BENIGN input         demonstrated=True  gate_eligible=True  rc=-11  controls=()
        an EMPTY payload       demonstrated=True  gate_eligible=True  rc=-11  controls=()

    A startup segfault in a shipped build, a library constructor, or a `set -u` trap therefore lets ONE
    real fault carry N unrelated findings to the gate — and `fatal_signal` is the arm that gates, so
    each one fails a build. `output_marker` gained a control after markers `"a"` and `" "` demonstrated
    against healthy output; this is the same lesson one expectation over, and the same fix.

    The cost is one execution, paid only when the first run ALREADY looks like a hit — the cheapest
    possible place to spend it, and the direction of the change can only ever REDUCE demonstrations.

    `nonzero_exit` is the lever — see the module docstring for what it costs to be wrong in either
    direction.
    """
    if spec.expectation == "nonzero_exit":
        return DIFFERENTIAL_NONZERO_EXIT
    return spec.expectation in ("output_marker", "unhandled_exception", "fatal_signal")


#: A sentinel has to be long enough that finding it in the output is not a coincidence. Four is the
#: shortest run of identifier characters this will offer; `echo` and `id` are real payload words and
#: would match half of any program's ordinary output.
MIN_SENTINEL_CHARS = 4

#: How many candidates to name. One is usually right and a list of forty is not advice.
MAX_SENTINELS = 3


def _payload_sentinels(payload: bytes, attack_output: str, control_output: str) -> str:
    """Strings the PAYLOAD put into the output that the control does not produce.

    **The soundness of this rests entirely on the payload conjunct, and dropping it would be a
    disaster.** "A token the attack output has and the control does not" is satisfied by any input
    that changes any output — a timestamp, a length, a filename — so offering those as markers would
    turn *the output differed* into *a defect was demonstrated*, and every distinct input demonstrates
    something. Requiring the token to have come from the agent's own payload is what makes it evidence:
    the attacker's string went in and came out the other side, which is what an injection IS.

    It is deliberately conservative and will decline plenty of real defects. The path-traversal finding
    in the 2026-08-21 canary run is one: its payload is `P/etc/passwd` and its proof is a CHARACTER
    COUNT (`served 3934 chars`), so no payload string appears in the output and nothing is offered
    here. That is the right answer — a count is weaker evidence and this must not manufacture a
    marker for it.

    Returns a rendered list, or "" when nothing qualifies. It never decides anything; `adjudicate`'s
    refusal stands either way and this only names what the agent could propose instead.
    """
    # THROUGH `payload_readings`, LIKE EVERY OTHER GUARD THAT SUBTRACTS THE PAYLOAD, and
    # `test_every_guard_that_subtracts_the_payload_goes_through_the_shared_readings` is what caught
    # this file decoding for itself. The reason is the same one that function was written for: a
    # payload is arbitrary BYTES, `errors="replace"` is lossy, and a tolerant entry point REASSEMBLES
    # text that the lossy reading destroyed. There it produced a false demonstration; here it would
    # produce a missed sentinel — the agent told there is no better marker when its own payload
    # printed one. The direction of the error differs and the fix is the same reading.
    words: set[str] = set()
    for reading in payload_readings(payload):
        words |= set(re.findall(r"[A-Za-z0-9_]{%d,}" % MIN_SENTINEL_CHARS, reading))
    found = sorted(w for w in words if w in attack_output and w not in control_output)
    # LONGEST FIRST: a longer sentinel is less likely to collide with a control this run did not
    # execute, and `MAX_BENIGN_CONTROLS` means there can be controls it did not execute.
    found.sort(key=len, reverse=True)
    return ", ".join(repr(w) for w in found[:MAX_SENTINELS])


def _baseline_contradicts(spec: WitnessSpec, rc: int | None, output: str, *, control: str) -> str:
    """Why a control run refutes the demonstration, or "" if it does not.

    Each arm asks the SAME question in the vocabulary of its own observation: did the entry point
    already do this without the agent's payload?

    `control` names WHICH control answered, and it is a parameter rather than the literal "an empty
    payload" this said until 2026-08-12 because there are now two. A refusal that named the wrong one
    would send a customer to look at the wrong file.
    """
    if spec.expectation == "output_marker":
        if spec.marker in output:
            return f"the marker {spec.marker!r} is also present when the entry point runs on {control}"
        return ""
    if spec.expectation == "fatal_signal":
        # The causal question in this expectation's own vocabulary: does it already fault on nothing?
        # A control that is itself KILLED is deliberately not a refutation — `TIMEOUT_KILL_CODES` are
        # excluded from `FATAL_SIGNAL_CODES` for the same reason `_adjudge` checks them first, and a
        # loaded machine must not be able to refute a real crash.
        code = _normalise(rc) if rc is not None else None
        if code in FATAL_SIGNAL_CODES:
            return (f"the entry point also dies on a fatal signal (rc={code}) when it runs on "
                    f"{control}, so the payload is not what causes the fault")
        return ""
    if spec.expectation == "nonzero_exit":
        code = _normalise(rc) if rc is not None else None
        if code != 0:
            # Includes a baseline that itself died on a signal or a timeout kill. All of them say the
            # same thing — this entry point does not exit 0 on nothing — and none of them let the
            # payload take credit.
            return f"the entry point also exits non-zero (rc={code}) when it runs on {control}"
        return ""
    if _traceback_not_from_payload(spec, output):
        return f"a traceback is also produced when the entry point runs on {control}"
    return ""


def _adjudge(spec: WitnessSpec, rc: int | None, output: str) -> tuple[bool, str]:
    """`(demonstrated, why not)` — the verdict and the sentence naming which check said no.

    **ONE function rather than a predicate plus an explainer, and that is the whole point of the
    shape.** The two would be separate implementations of the same rule, so they would drift, and the
    drift would be silent: a report naming a cause the adjudicator did not act on is worse than the
    generic sentence this replaced. the maintainers' notes's trap 3, applied to a reason instead of to
    evidence.

    **The sentence is written for a CUSTOMER, and its subject matters.** Two of these branches are
    facts about the customer's program ("it exited 0") and two are facts about OUR refusal of the
    agent's proposal (a marker inside its own payload, a traceback the payload carried). Until
    2026-08-18 all four rendered as *"the entry point did not do what was claimed"* — which blames the
    program for a proposal we rejected before its behaviour was the question. Measured in runs
    `32078795498`/`32079256653`: the refused finding was a REAL pickle RCE, and the report told the
    customer their entry point had not done what was claimed.

    `""` exactly when demonstrated, so the two halves cannot disagree about which case this is.
    """
    if rc is None:
        return False, "the entry point produced no exit status"
    code = _normalise(rc)
    if code in TIMEOUT_KILL_CODES:
        # Checked FIRST and for every expectation. A hang exits non-zero, so a `nonzero_exit` rule that
        # asked its own question before this one would report every timeout as a demonstration.
        return False, (f"the entry point was killed (rc={code}) rather than finishing, and a kill is "
                       f"not a demonstration whatever the expectation was")
    if spec.expectation == "fatal_signal":
        if code in FATAL_SIGNAL_CODES:
            return True, ""
        return False, f"the entry point exited {code} rather than dying on a fatal signal"
    if spec.expectation == "nonzero_exit":
        if code != 0:
            return True, ""
        return False, "the entry point exited 0"
    if spec.expectation == "unhandled_exception":
        # STRICTLY STRONGER than `nonzero_exit`, and deliberately conjunctive. The status alone cannot
        # separate a defect from a designed rejection; a traceback alone cannot separate an uncaught
        # exception from one an `except` block chose to PRINT, which is ordinary error handling and
        # exits 0. Requiring both is what makes this the managed-language reading of "the program did
        # not intend to be here".
        if code == 0:
            return False, "the entry point exited 0, so no exception went unhandled"
        if not _traceback_not_from_payload(spec, output):
            if any(token in output for token in TRACEBACK_TOKENS):
                return False, ("the only traceback in the output is text the payload itself carried, "
                               "so it is not evidence the entry point raised anything")
            return False, (f"the entry point exited {code} but printed no traceback, which is a "
                           f"designed rejection rather than an unhandled exception")
        return True, ""
    if not spec.marker:
        return False, "no marker was proposed, so there was nothing to look for"
    if self_defeating := self_defeating_marker(spec.marker, spec.payload):
        # OUR refusal, said as ours. The entry point may well have done exactly what was claimed; the
        # marker was refused before its behaviour was the question.
        return False, self_defeating
    if spec.marker in output:
        return True, ""
    if near := _near_miss(spec.marker, output):
        # **THE COMMONEST WAY A REAL DEFECT FAILS TO DEMONSTRATE, and the artefact could not say so.**
        # Measured 2026-08-18 over five samples of one target: a genuine path traversal was lost in
        # FOUR of them to `path: served 54 chars` against a 55-byte file — the model counted the
        # visible text and forgot the newline. "The marker is not present" is true and useless there;
        # naming the line that differs only in its digits turns it into something a reviewer can act
        # on in one glance, and tells them the defect probably IS real.
        return False, (f"the marker {spec.marker!r} is not present in the entry point's output, but "
                       f"{near!r} is — they differ only in their digits, so this looks like a marker "
                       f"whose numbers were WORKED OUT rather than read")
    return False, f"the marker {spec.marker!r} is not present in the entry point's output"


#: Digits, for `_near_miss`. Every run of them collapses to one placeholder, so `54` and `1234` are
#: the same shape — the failure being detected is "the model guessed a number", not "the model was off
#: by less than ten".
_DIGITS = re.compile(r"\d+")


def _near_miss(marker: str, output: str) -> str:
    """A line the entry point printed that differs from `marker` ONLY in its digits, or "".

    **DIAGNOSIS, NEVER ADJUDICATION.** This cannot make anything demonstrate — `_adjudge` has already
    decided `False` by the time it is called, and the only thing it changes is the sentence. That
    boundary is deliberate: a near-miss is exactly the shape a customer wants explained and exactly the
    shape a gate must never accept, because "close to the marker" is not evidence of anything.

    Requires the marker to contain a digit at all, so an ordinary absent marker does not get an
    irrelevant sentence attached; and compares whole lines, because a marker matching a fragment of
    some longer line after digit-blanking is a coincidence rather than a near-miss.
    """
    if not marker or not _DIGITS.search(marker):
        return ""
    shape = _DIGITS.sub("#", marker)
    for line in output.splitlines():
        line = line.strip()
        if line and line != marker and _DIGITS.sub("#", line) == shape:
            return line
    return ""


def _traceback_not_from_payload(spec: WitnessSpec, output: str) -> str:
    """The traceback banner the entry point PRINTED, or "" — the payload's own text does not count.

    Same guard, and the same reason, as `_marker_is_not_the_payload`: an entry point that echoes its
    input would otherwise let the agent supply `Traceback (most recent call last):` as the payload and
    read it straight back. The agent does not choose the token here, as it chooses a marker, but it does
    choose every byte that goes in, and that is enough.

    Subtracted over every reading of those bytes, for the reason `payload_readings` gives: the banner is
    pure ASCII, so a payload carrying it with one invalid byte wedged inside was invisible to a single
    UTF-8 decode and reassembled by any tolerant entry point.
    """
    readings = payload_readings(spec.payload)
    for token in TRACEBACK_TOKENS:
        if token in output and not any(token in text for text in readings):
            return token
    return ""


def _marker_is_not_the_payload(spec: WitnessSpec, output: str) -> bool:
    """The marker must have come OUT of the entry point, not gone IN from the agent.

    An entry point that echoes its input would otherwise let the agent supply the marker as the payload
    and read it straight back — the agent grading itself through a pipe. Subtracting the payload is the
    same guard `deep/oracle._effective_exit` applies to a sanitizer banner, and for the same reason:
    what matters is that the evidence was not supplied by the thing being judged.

    **The subtraction is over `payload_readings`, and that is load-bearing rather than defensive.** This
    is the guard an internal audit Finding 1 defeated with one byte, and `output_marker`
    is the product's only shipping demonstration route — `fatal_signal` measured 0 of 3 on a minimal C
    trigger (`6317e54`), so there is no second route to fall back on when this one is wrong.

    The subtraction itself lives in `self_defeating_marker`, because since 2026-08-18 the SAME question
    is asked of a proposal before the run. Two spellings of it would let the earlier check accept what
    this one refuses, which is the defect that check exists to prevent.
    """
    if not spec.marker:
        return False
    if self_defeating_marker(spec.marker, spec.payload):
        return False
    return spec.marker in output


def self_defeating_marker(marker: str, payload: bytes) -> str:
    """Why this marker can never evidence anything, or "" if it can. A property of the PROPOSAL alone.

    **This is the mechanism behind the gate's variance, and naming it is what makes it fixable.** Two
    consecutive runs of a pinned target found the SAME three defects and reported `gate-eligible 2`
    then `0` (runs `32078795498`, `32079256653`). What differed was one proposal: a pickle RCE whose
    payload was `(S'echo PKL_CONFIRMED'` with the marker `PKL_CONFIRMED`. The exploit was real and it
    executed — and the agent had planted the evidence in its own input, so nothing observable
    distinguished a program that ran the payload from one that echoed it.

    **The answer is a function of the agent's own two arguments and of nothing else.** It reads no
    file, runs no entry point, and says nothing about the target — which is exactly what makes it safe
    to answer at proposal time. `_report_finding`'s rule is that feedback which lets the agent search
    for a passing GRADE is forbidden and feedback that lets it fix a MALFORMED argument is wanted; this
    is the second kind, the same judgement `witness_payload_base64` already gets. It cannot be gamed
    into a demonstration because `_marker_is_not_the_payload` still asks it again after the run.

    Subtracted over `payload_readings` rather than over the raw bytes, for the reason that function
    gives: an internal audit Finding 1 defeated a single-decode version of this guard
    with one invalid byte wedged inside an ASCII marker.
    """
    if not marker:
        return ""
    if any(marker in text for text in payload_readings(payload)):
        return (f"the marker {marker!r} appears in the payload itself, so an entry point that merely "
                f"echoed the input would produce it — a marker has to be text the program's OWN code "
                f"prints, not text the payload carries")
    return ""


def _normalise(rc: int) -> int:
    """`128 + N` is what a shell reports; `subprocess` reports a DIRECT child's signal as `-N`.

    Both spellings occur: `./target "$1"` yields 139 for SIGSEGV while `exec ./target "$1"` makes the
    target the runner's direct child and yields -11. Measured, and identical to the normalisation
    `deep/oracle._effective_exit` performs — -11 maps to 139 and -6 to 134, while -9 (137) and -15 (143)
    stay out of the fatal set and inside the timeout set.
    """
    return 128 - rc if rc < 0 else rc


def _refuse(spec: WitnessSpec, why: str, *, digest: str = "") -> Witness:
    return Witness(demonstrated=False, expectation=spec.expectation, entry_digest=digest, refusal=why)


__all__ = [
    "BENIGN_SUFFIX", "DEFAULT_TIMEOUT", "DIFFERENTIAL_NONZERO_EXIT", "EXPECTATIONS",
    "FATAL_SIGNAL_CODES", "INHERITED", "INTRODUCED", "MAX_BENIGN_CONTROLS", "MAX_EVIDENCE_CHARS",
    "NETWORK_ISOLATION",
    "TIMEOUT_KILL_CODES", "TRACEBACK_TOKENS", "UNATTRIBUTED", "UNHANDLED_EXCEPTION",
    "UNMEASURED_EXPECTATIONS", "Witness", "WitnessSpec", "adjudicate", "attribute", "benign_controls",
    "entry_digest", "entry_env", "isolation_prefix", "observed_location", "offered_expectations",
    "payload_readings", "redact_secrets", "reset_isolation_cache", "resolve_entry",
    "secret_values",
    "self_defeating_marker", "witness_contract",
]


#: What a shell says when the thing it was asked to `exec` is not installed. Both spellings, because
#: bash and dash disagree and the free image's `/bin/sh` is dash.
_NOT_FOUND = re.compile(r"(?:^|\n)[^\n]*?:\s*(?:line \d+:\s*)?([\w./+-]+):\s*(?:command )?not found",
                        re.I)


def _missing_runtime(code: int, output: str) -> str:
    """Name the interpreter the entry point needed and the image does not carry, or "".

    **127 ALONE IS NOT ENOUGH and neither is the message alone**, so both are accepted and either is
    sufficient. A shell exits 127 for "command not found" — but a wrapper that catches the failure and
    exits 0 still prints the sentence, and a program can legitimately exit 127 of its own accord. The
    conjunction would miss the first case; the message alone would miss a shell configured to say
    nothing. Reporting a NAME matters more than the precision of the trigger: "node: not found" tells
    the customer what to do and "the entry point failed" does not.

    Returns a sentence rather than a bool, for the same reason `scope_reasons` are sentences: the
    caller is writing something a customer reads, not branching on a flag.
    """
    found = _NOT_FOUND.search(output or "")
    if found:
        return f"{found.group(1)!r} is not installed in the image running it"
    if code == 127:
        return ("the shell exited 127, which is 'command not found' — the entry point asked for a "
                "program that is not installed in the image running it")
    return ""
