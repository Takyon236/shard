"""The witness — simple mode's answer to "how do you know that is real?"

The design notes: simple mode is two-tier. A finding with an executable witness the
runner re-executes is gate-eligible; everything else is informational and can never fail a build. This
module is the adjudicator, and it is the only thing that may set the gate-eligible bit.

## The conclusion that shaped this module, and it is not the obvious one

The obvious design is: the agent writes a script demonstrating the defect, the runner executes it, a
non-zero exit means demonstrated. **That design is unsound and this repository has already paid for
learning why.**

The separate package exists because `write_poc(path="./test_poc.sh", text="echo __EXIT__=1\\n")` was an
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

The maintainers' suite::test_the_empty_baseline_does_NOT_make_output_marker_sound_on_a_dispatching_entry_point`
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

The design notes names the blocking defect for every language after C. **For C,
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
left open as well. The maintainers' suite::test_the_differential_baseline_does_NOT_make_nonzero_exit_sound`
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
import os
import pathlib
import re
import signal
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass

from shard.witnessfs import SnapshotError, SourceSnapshot, original_paths

SOURCE_ISOLATION_REFUSAL = "witness source isolation failed: "
CONTAINMENT_REFUSAL = "witness execution containment failed: "

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

# GitHub's command files are capabilities, not ordinary build configuration. Appending one line to
# GITHUB_ENV or GITHUB_PATH changes the environment of every later workflow step; GITHUB_OUTPUT,
# GITHUB_STATE and GITHUB_STEP_SUMMARY cross the process boundary too. The location names expose the
# live checkout or shared runner directories to code that is supposed to see only a disposable trial.
_COMMAND_FILE_ENV_NAMES = frozenset({
    "GITHUB_ENV", "GITHUB_PATH", "GITHUB_OUTPUT", "GITHUB_STEP_SUMMARY", "GITHUB_STATE",
})
_LOCATION_ENV_NAMES = frozenset({
    "GITHUB_WORKSPACE", "GITHUB_ACTION_PATH", "RUNNER_TEMP", "RUNNER_TOOL_CACHE", "RUNNER_WORKSPACE",
    "SHARD_ACTION_SNAPSHOT_ROOT",
})
_CONTROL_SOCKET_ENV_NAMES = frozenset({
    "CONTAINER_CONNECTION", "CONTAINER_HOST", "DBUS_SESSION_BUS_ADDRESS", "DOCKER_CONTEXT",
    "DOCKER_HOST", "GNUPGHOME", "GPG_AGENT_INFO", "KUBECONFIG", "PODMAN_SOCKET",
    "SSH_AUTH_SOCK", "SSH_AGENT_PID", "XDG_RUNTIME_DIR",
})
_ENTRY_CAPABILITY_ENV_NAMES = (
    _COMMAND_FILE_ENV_NAMES | _LOCATION_ENV_NAMES | _CONTROL_SOCKET_ENV_NAMES
)


def _secret_env_name(name: str, configured=()) -> bool:
    upper = name.upper()
    configured_names = {str(item).upper() for item in configured if item}
    return (upper.startswith("INPUT_") or upper in _SECRET_ENV_NAMES or upper in configured_names
            or any(upper.endswith(suffix) for suffix in _SECRET_ENV_SUFFIXES))


def entry_env(base=None, *, secret_env_names=()) -> dict:
    """The environment the CUSTOMER'S entry point runs under, with our credentials removed.

    **THE ENTRY POINT IS ATTACKER-AUTHORED CONTENT ON A PULL REQUEST.** It is a file in the repository
    under review, so whoever opens the pull request writes it — and `adjudicate` executes it and then
    writes its stdout and stderr into `Witness.evidence`, which reaches `bundles/*/output.txt`, the
    markdown report, and from there the PR comment `action.py` posts and the artifact the README's own
    workflow uploads. Inheriting the runner's environment therefore turned a four-line `.shard/entry.sh`
    reading `env` into an exfiltration of every secret the job holds, published back to its author.

    Measured before the fix: an entry point of `#!/bin/sh` + `env` put both `OPENROUTER_API_KEY` and
    `INPUT_GITHUB_TOKEN` verbatim into `Witness.evidence`.

    Five rules, and the first two are installation-specific rather than guesses:

    * **the whole `INPUT_*` namespace goes.** GitHub Actions exports every input of the running action
      that way, so it is exactly the set of values the CUSTOMER handed US — including `github_token`
      and whatever `api_key_env` names. Nothing in a customer's build has any business reading our
      inputs, which makes this the one rule with no legitimate loss.
    * the exact environment name configured by ``api_key_env`` goes, even when it is an arbitrary
      provider name such as ``NPM_AUTH`` that matches none of the generic credential spellings.
    * names that LOOK like credentials go, by suffix or by a short list of well-known ones.
    * GitHub's five command files and its workspace/runner location capabilities go. A command-file
      path is write authority over a later workflow step, not harmless metadata; the private root also
      omits the underlying file, so guessing its path does not bypass this filter.
    * host control-socket variables go, by name, socket suffix or a ``unix:`` value. A network
      namespace does not isolate pathname AF_UNIX sockets; the private root is the primary control,
      and withholding the address prevents accidental clients from finding a socket cheaply.

    **This is a denylist, and a denylist is not airtight** — an arbitrary secret variable not selected
    as ``api_key_env`` and matching none of the generic rules still reaches the entry point. The
    airtight version is an allowlist, and it is not what ships because the entry point is the
    customer's own build script: it may legitimately need `CC`, `JAVA_HOME`, `LD_LIBRARY_PATH` or
    anything else their toolchain reads, and denying those by default would break real targets to
    close a narrower hole than the credential rules above close. Recorded as a deliberate trade
    rather than an oversight.
    """
    import os

    source = os.environ if base is None else base
    out = {}
    for name, value in source.items():
        upper = name.upper()
        socket_address = isinstance(value, str) and value.lower().startswith(("unix:", "unix://"))
        if (_secret_env_name(name, secret_env_names) or upper in _ENTRY_CAPABILITY_ENV_NAMES
                or upper.endswith(("_SOCK", "_SOCKET")) or socket_address):
            continue
        out[name] = value
    return out


#: The shortest secret value worth substring-matching for. Below this a "secret" is a common word —
#: a job that exports `CI_TOKEN=1` would otherwise turn every `1` in a sanitiser trace into
#: `[redacted]`, destroying the evidence to protect a value that is not one.
_REDACT_MIN_LEN = 8


def secret_values(base=None, *, secret_env_names=()) -> tuple[str, ...]:
    """The literal strings that must never appear in anything we publish.

    Exactly the values the credential half of `entry_env` refuses to pass on, read out of the SAME
    environment by the SAME name rule. GitHub command and location capabilities are also removed from
    the child but are paths rather than secrets; treating GITHUB_WORKSPACE as a secret would erase
    ordinary source locations from every trace. Longest first, so a value containing another is
    replaced whole rather than left with a redacted hole in the middle of it.
    """
    import os

    source = os.environ if base is None else base
    values = {v for name, v in source.items()
              if (_secret_env_name(name, secret_env_names) and isinstance(v, str)
                  and len(v) >= _REDACT_MIN_LEN)}
    return tuple(sorted(values, key=len, reverse=True))


#: The re-spellings of a secret that a four-line shell script produces without effort. Each is a
#: DETERMINISTIC function of a value we already hold, so covering it costs one `str.replace` and
#: cannot false-positive on anything shorter than `_REDACT_MIN_LEN` encoded.
#:
#: **Measured 2026-09-01: the literal-only version was defeated by one pipe.** `redact_secrets`
#: replaced the exact bytes and nothing else, so `printenv OPENROUTER_API_KEY | base64` published the
#: credential through `Witness.evidence`, the markdown report, `bundles/*/output.txt` and the pull
#: request comment — every channel the docstring below lists — with the redaction firing on none of
#: them. The value never appeared; a lossless spelling of it did.
def _secret_spellings(value: str) -> tuple[str, ...]:
    """Every cheap encoding of one secret, longest first."""
    import base64
    import urllib.parse

    raw = value.encode("utf-8", "surrogateescape")
    forms = {value}
    for encoder in (base64.b64encode, base64.urlsafe_b64encode):
        encoded = encoder(raw).decode("ascii")
        forms.add(encoded)
        forms.add(encoded.rstrip("="))          # `base64 -w0 | tr -d '='` and every language's default
    forms.add(raw.hex())
    forms.add(raw.hex().upper())                # `xxd -p`, `od -A n -t x1`, `printf %02X`
    forms.add(urllib.parse.quote(value, safe=""))
    return tuple(sorted(forms, key=len, reverse=True))


def redact_secrets(text: str, base=None, *, secret_env_names=()) -> str:
    """Remove our credentials from output we are about to publish, by VALUE rather than by name.

    **`entry_env` was not enough on its own, because the container's procfs held the parent's original
    environment.** Four lines of `.shard/entry.sh` could recover `OPENROUTER_API_KEY` from
    `/proc/<our pid>/environ`, then publish it through `Witness.evidence`, the markdown report,
    `bundles/*/output.txt` and the PR comment. Customer-authored executions now enter a private PID
    namespace with a private procfs, and the namespace process receives only `entry_env`; the parent
    and its original environment do not exist in that view. That process boundary is the closure.

    Egress is not the channel that matters here and closing it would not have helped: the value
    reaches its author by being PRINTED, not by being sent. So the control is at the last place the
    text is still ours — every capture of a customer-authored program's output goes through this.

    It is applied BEFORE adjudication and not only before reporting, so the attack output and every
    control output are redacted alike and the differential is unchanged. A marker built on a
    credential therefore cannot demonstrate anything either, which is the right answer to a claim
    whose evidence is our own key.

    **THE RESIDUALS, named rather than implied, and there are three.**

    1. This substitutes values we can see in our OWN environment. A secret the runner holds that never
       enters this process — one read from a file, or one this job was never given — is not here to
       match on, and this cannot redact what it does not know.
    2. It matches the value and the encodings in `_secret_spellings`. Those are the ones a shell
       one-liner reaches for; they are not all of them. A transform we do not enumerate — compress,
       encrypt, rot13, reverse, print one character per line — still publishes the credential, and no
       finite list closes that. What the list buys is that the CHEAP attempt now fails.
    3. **Splitting is not covered and deliberately so.** `echo ${KEY:0:20}; echo ${KEY:20}` emits two
       fragments and neither is a value we hold. Matching fragments means matching substrings of a
       credential, which turns a short secret into a filter that eats ordinary trace text — the very
       trade `_REDACT_MIN_LEN` exists to refuse.

    This substitution is defense in depth, not the closure: the private procfs removes the copied
    parent environment and `entry_env` removes the child's copy. If customer code obtains the same
    secret from another file or service, these residual transforms still describe the last-line
    filter accurately.
    """
    if not text:
        return text
    for value in secret_values(base, secret_env_names=secret_env_names):
        for spelling in _secret_spellings(value):
            if spelling in text:
                text = text.replace(spelling, "[redacted]")
    return text


# ── process containment, for anything that executes customer-authored content ──────────────────────

#: PID 1 must outlive the customer entry long enough to preserve its real exit status. `unshare`
#: propagates ordinary exits but reports 0 when its namespace child dies by signal. This tiny init
#: waits for the entry as PID 2, translates a signal to the shell's `128 + N`, then exits; Linux kills
#: any double-forked processes still in the namespace at that boundary. It also makes the capability
#: probe check `getpid() == 1` without inspecting procfs.
_CONTAINMENT_PATHS_ENV = "_SHARD_CONTAINMENT_PATHS"
_CONTAINMENT_ERROR = "shard containment setup failed: "

_NAMESPACE_INIT = f"""\
import ctypes
import errno
import json
import os
import sys

ERROR = {_CONTAINMENT_ERROR!r}
PATHS_ENV = {_CONTAINMENT_PATHS_ENV!r}

def fail(message):
    os.write(2, (ERROR + message + "\\n").encode("utf-8", "replace"))
    raise SystemExit(125)

if os.getpid() != 1 or len(sys.argv) < 2:
    fail("namespace init did not become PID 1")

try:
    manifest = json.loads(os.environ.pop(PATHS_ENV, "{{}}"))
    readonly = manifest.get("readonly", [])
    writable = manifest.get("writable", [])
    execution_cwd = manifest.get("execution_cwd")
    jail_root = manifest.get("jail_root", "")
    overlay = manifest.get("overlay")
    bind_files = manifest.get("bind_files", [])
    protected_relatives = manifest.get("protected_relatives", [])
    if overlay is not None:
        overlay_paths = [overlay.get(name, "") for name in
                         ("lower", "target", "upper", "work", "storage")]
        writable = writable + [overlay_paths[4]]
    else:
        overlay_paths = []
    # Ancestors first, then descendants. Binding an ancestor after its child hides the child's mount
    # and makes the later remount address an ordinary dentry (EINVAL). Both nesting directions occur:
    # witness trials protect descendants of writable scratch, while run_entry writes a scratch child
    # beneath a read-only checkout.
    paths = sorted(set(writable + readonly), key=lambda path: (path.count(os.sep), path))
    if (not isinstance(manifest, dict) or not isinstance(readonly, list)
            or not isinstance(writable, list)
            or not isinstance(bind_files, list)
            or not all(isinstance(pair, list) and len(pair) == 2
                       and all(isinstance(path, str) and path for path in pair)
                       for pair in bind_files)
            or not isinstance(protected_relatives, list)
            or not all(isinstance(path, str) and path and not path.startswith("/")
                       and ".." not in path.split("/") for path in protected_relatives)
            or (overlay is not None and not isinstance(overlay, dict))
            or (execution_cwd is not None and not isinstance(execution_cwd, str))
            or not isinstance(jail_root, str) or not jail_root
            or not all(isinstance(path, str) and path for path in paths + overlay_paths)):
        fail("invalid protected-path manifest")
    if any(path in ("/", "/home", "/root", "/run", "/tmp", "/var", "/var/run")
           for path in paths):
        fail("a declared execution root is too broad")
except (TypeError, ValueError) as exc:
    fail("invalid protected-path manifest: " + str(exc))

libc = ctypes.CDLL(None, use_errno=True)
libc.mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
                       ctypes.c_ulong, ctypes.c_void_p]
libc.mount.restype = ctypes.c_int
MS_RDONLY = 1
MS_REMOUNT = 32
MS_BIND = 4096
MS_REC = 16384

class MountAttr(ctypes.Structure):
    _fields_ = [("attr_set", ctypes.c_uint64), ("attr_clr", ctypes.c_uint64),
                ("propagation", ctypes.c_uint64), ("userns_fd", ctypes.c_uint64)]
try:
    mount_setattr = libc.mount_setattr
except AttributeError:
    def mount_setattr(directory, path, flags, attr, size):
        return libc.syscall(442, directory, path, flags, attr, size)
mount_setattr.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint,
                          ctypes.POINTER(MountAttr), ctypes.c_size_t]
mount_setattr.restype = ctypes.c_int
AT_FDCWD = -100
AT_RECURSIVE = 0x8000
MOUNT_ATTR_RDONLY = 1
MOUNT_ATTR_NOSUID = 2
MOUNT_ATTR_NODEV = 4

if overlay is not None:
    lower, target, upper, work, storage = overlay_paths
    MS_NOSUID = 2
    MS_NODEV = 4
    MS_NOEXEC = 8
    # The outer Action filesystem is itself overlayfs. Linux refuses an overlay whose upper/work
    # directories sit on that same overlay (EINVAL), which made containment pass on the host and fail
    # in the shipping image. Put the private upper on tmpfs first; after mounting the trial overlay, a
    # second empty read-only tmpfs hides those bookkeeping paths from customer code without removing
    # the mounted overlay's references to them.
    if libc.mount(b"tmpfs", os.fsencode(storage), b"tmpfs", MS_NOSUID | MS_NODEV,
                  ctypes.c_char_p(b"size=64m")) != 0:
        fail("could not allocate private trial storage: errno " + str(ctypes.get_errno()))
    try:
        os.mkdir(upper, 0o700)
        os.mkdir(work, 0o700)
    except OSError as exc:
        fail("could not prepare private trial storage: " + str(exc))
    upper_fd = os.open(upper, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    options = "lowerdir=" + lower + ",upperdir=" + upper + ",workdir=" + work
    if libc.mount(b"overlay", os.fsencode(target), b"overlay", 0,
                  ctypes.c_char_p(os.fsencode(options))) != 0:
        fail("could not mount a private writable trial: errno " + str(ctypes.get_errno()))
    if libc.mount(b"tmpfs", os.fsencode(storage), b"tmpfs",
                  MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC,
                  ctypes.c_char_p(b"size=4096")) != 0:
        fail("could not hide private trial storage: errno " + str(ctypes.get_errno()))

# Bind retained evidence over its historical path only inside this namespace. The command therefore
# sees the same argv and BASH_SOURCE/$0 layout as the customer contract, while a live-path rewrite
# cannot change which bytes execute or which candidate bytes the harness opens.
for source, target in bind_files:
    if not os.path.exists(target):
        try:
            descriptor = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(descriptor)
        except OSError as exc:
            fail("could not create an immutable file target: " + str(exc))
    if (not os.path.isabs(source) or not os.path.isabs(target)
            or not os.path.isfile(source) or not os.path.isfile(target)):
        fail("an immutable file binding disappeared before execution")
    if libc.mount(os.fsencode(source), os.fsencode(target), None, MS_BIND, None) != 0:
        fail("could not bind immutable evidence: errno " + str(ctypes.get_errno()))
    if libc.mount(None, os.fsencode(target), None, MS_BIND | MS_REMOUNT | MS_RDONLY, None) != 0:
        fail("could not make immutable evidence read-only: errno " + str(ctypes.get_errno()))

# A read-only host root still exposes every path whose name an attacker knows. Build a new root from
# an allowlist instead: runtimes, the explicitly declared read/write roots, a private procfs and the
# minimum device files ordinary commands need. Nothing else is mounted, so an arbitrary host path is
# absent rather than merely immutable. The caller owns ``jail_root`` and removes it after this mount
# namespace exits; mounting tmpfs over it keeps all root construction out of the host filesystem.
MS_NOSUID = 2
MS_NODEV = 4
MS_NOEXEC = 8
if (not os.path.isabs(jail_root) or jail_root == "/" or not os.path.isdir(jail_root)
        or os.path.islink(jail_root)):
    fail("the private execution root is unavailable")
if libc.mount(b"tmpfs", os.fsencode(jail_root), b"tmpfs", MS_NOSUID | MS_NODEV,
              ctypes.c_char_p(b"size=128m")) != 0:
    fail("could not allocate the private execution root: errno " + str(ctypes.get_errno()))
new_root = os.path.join(jail_root, "root")
try:
    os.mkdir(new_root, 0o700)
except OSError as exc:
    fail("could not prepare the private execution root: " + str(exc))
if libc.mount(os.fsencode(new_root), os.fsencode(new_root), None, MS_BIND, None) != 0:
    fail("could not bind the private execution root: errno " + str(ctypes.get_errno()))

def target_for(path, directory):
    target = new_root + path
    try:
        os.makedirs(os.path.dirname(target), mode=0o755, exist_ok=True)
        if directory:
            os.makedirs(target, mode=0o755, exist_ok=True)
        elif not os.path.exists(target):
            descriptor = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(descriptor)
    except OSError as exc:
        fail("could not prepare an allowed path: " + str(exc))
    return target

def expose(path, readonly_path, harden=False):
    if not os.path.isabs(path) or not os.path.exists(path):
        fail("an allowed path disappeared before execution")
    directory = os.path.isdir(path)
    target = target_for(path, directory)
    flags = MS_BIND | (MS_REC if directory else 0)
    if libc.mount(os.fsencode(path), os.fsencode(target), None, flags, None) != 0:
        fail("could not expose an allowed path: errno " + str(ctypes.get_errno()))
    if readonly_path or harden:
        attrs = (MOUNT_ATTR_RDONLY if readonly_path else 0)
        if harden:
            attrs |= MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV
        attr = MountAttr(attrs, 0, 0, 0)
        recursive = AT_RECURSIVE if directory else 0
        if mount_setattr(AT_FDCWD, os.fsencode(target), recursive,
                         ctypes.byref(attr), ctypes.sizeof(attr)) != 0:
            fail("could not make an allowed path read-only: errno " + str(ctypes.get_errno()))

# Keep command availability without carrying the host root into the namespace. These are executable
# distribution roots, not customer or runner state. Debian's /bin and /lib are symlinks into /usr,
# but binding the historical names preserves shebangs and dynamic-loader paths on both layouts.
runtime_roots = [path for path in ("/usr", "/bin", "/lib", "/lib64", "/sbin")
                 if os.path.exists(path)]
runtime_roots += [path for path in ("/etc/alternatives", "/etc/ld.so.cache")
                  if os.path.exists(path)]
# Debian-family JDKs deliberately keep their runtime security policy outside /usr and link
# ``$JAVA_HOME/conf`` into one versioned directory here. Omitting it leaves ``java`` executable but
# breaks ObjectInputStream, XML parsing and other ordinary standard-library operations with
# ``InternalError: Error loading java.security file``. Expose only the versioned distribution
# configuration, never /etc itself or a symlink that could redirect this exception to host state.
try:
    java_configs = [
        os.path.join("/etc", name) for name in os.listdir("/etc")
        if (name.startswith("java-") and name.endswith("-openjdk")
            and name[5:-8].isdigit()
            and os.path.isdir(os.path.join("/etc", name))
            and not os.path.islink(os.path.join("/etc", name)))
    ]
except OSError:
    java_configs = []
runtime_roots += java_configs
for path in runtime_roots:
    expose(path, True)

# Parent mounts precede descendants. A writable trial may contain a retained read-only input, and a
# read-only checkout may contain a disposable writable scratch child; the deeper binding decides.
allowed = [(path, False) for path in writable]
allowed += [(path, True) for path in readonly]
if overlay is not None:
    allowed.append((overlay_paths[1], False))
allowed.sort(key=lambda item: (item[0].count(os.sep), item[0], item[1]))
for path, readonly_path in allowed:
    expose(path, readonly_path, True)

# A fresh procfs is tied to this PID namespace. Only ordinary character devices are carried across;
# /dev/shm, disks and host sockets are deliberately absent.
proc_target = target_for("/proc", True)
if libc.mount(b"proc", os.fsencode(proc_target), b"proc", MS_NOSUID | MS_NODEV | MS_NOEXEC,
              None) != 0:
    fail("could not mount the private procfs: errno " + str(ctypes.get_errno()))
target_for("/dev", True)
for device in ("/dev/null", "/dev/zero", "/dev/random", "/dev/urandom"):
    if os.path.exists(device):
        expose(device, False)
try:
    # Compilers and language runtimes expect a writable /tmp even when the declared workdir lives
    # elsewhere. This directory belongs to the private tmpfs root; exposing the host's /tmp would
    # recover cross-trial state and every pathname socket placed there.
    os.makedirs(new_root + "/tmp", mode=0o1777, exist_ok=True)
    os.chmod(new_root + "/tmp", 0o1777)
    os.makedirs(new_root + "/etc", mode=0o755, exist_ok=True)
    with open(new_root + "/etc/passwd", "w", encoding="utf-8") as stream:
        stream.write("root:x:0:0:root:/root:/bin/sh\\n")
    with open(new_root + "/etc/group", "w", encoding="utf-8") as stream:
        stream.write("root:x:0:\\n")
    for link, target in (("/dev/fd", "/proc/self/fd"), ("/dev/stdin", "/proc/self/fd/0"),
                         ("/dev/stdout", "/proc/self/fd/1"), ("/dev/stderr", "/proc/self/fd/2")):
        os.symlink(target, new_root + link)
except OSError as exc:
    fail("could not prepare private runtime files: " + str(exc))

if execution_cwd is not None:
    visible = writable + readonly + ([overlay_paths[1]] if overlay is not None else [])
    if not any(execution_cwd == root or execution_cwd.startswith(root.rstrip("/") + "/")
               for root in visible):
        fail("the execution directory is outside the allowed roots")

old_root = os.path.join(new_root, ".old-root")
try:
    os.mkdir(old_root, 0o700)
except OSError as exc:
    fail("could not prepare the old-root detachment: " + str(exc))
try:
    pivot_root = libc.pivot_root
except AttributeError:
    fail("pivot_root is unavailable on this runner")
pivot_root.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
pivot_root.restype = ctypes.c_int
if pivot_root(os.fsencode(new_root), os.fsencode(old_root)) != 0:
    fail("could not pivot into the private execution root: errno " + str(ctypes.get_errno()))
try:
    os.chdir("/")
except OSError as exc:
    fail("could not enter the private execution root: " + str(exc))
libc.umount2.argtypes = [ctypes.c_char_p, ctypes.c_int]
libc.umount2.restype = ctypes.c_int
MNT_DETACH = 2
if libc.umount2(b"/.old-root", MNT_DETACH) != 0:
    fail("could not detach the host root: errno " + str(ctypes.get_errno()))
try:
    os.rmdir("/.old-root")
except OSError as exc:
    fail("could not remove the detached host root: " + str(exc))
if execution_cwd is not None:
    try:
        os.chdir(execution_cwd)
    except OSError as exc:
        fail("could not enter the contained working directory: " + str(exc))

# Namespace root is needed only to construct the mounts. Customer code must not retain CAP_SYS_ADMIN:
# it could otherwise unmount the read-only bind and reach the live checkout underneath it. NOROOT
# prevents uid 0 from regaining capabilities on exec; the bounding and ambient sets close the other
# routes, and no_new_privs makes the transition permanent for descendants.
PR_SET_SECUREBITS = 28
PR_CAPBSET_DROP = 24
PR_SET_NO_NEW_PRIVS = 38
PR_SET_DUMPABLE = 4
PR_CAP_AMBIENT = 47
PR_CAP_AMBIENT_CLEAR_ALL = 4
SECURE_LOCKED = 1 | 2 | 4 | 8
# PID 1 retains the overlay-verification descriptor until the hostile child exits. Making the trusted
# init non-dumpable prevents that same-UID child reaching it through /proc/1/fd; exec restores the
# ordinary dumpable state for the child itself.
if libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
    fail("could not protect the namespace init descriptors: errno " + str(ctypes.get_errno()))
if libc.prctl(PR_SET_SECUREBITS, SECURE_LOCKED, 0, 0, 0) != 0:
    fail("could not lock root capability semantics: errno " + str(ctypes.get_errno()))
for capability in range(64):
    if libc.prctl(PR_CAPBSET_DROP, capability, 0, 0, 0) != 0 and ctypes.get_errno() != errno.EINVAL:
        fail("could not drop the capability bounding set: errno " + str(ctypes.get_errno()))
libc.prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0)

class CapHeader(ctypes.Structure):
    _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]
class CapData(ctypes.Structure):
    _fields_ = [("effective", ctypes.c_uint32), ("permitted", ctypes.c_uint32),
                ("inheritable", ctypes.c_uint32)]
header = CapHeader(0x20080522, 0)
data = (CapData * 2)()
if libc.capset(ctypes.byref(header), ctypes.byref(data)) != 0:
    fail("could not clear process capabilities: errno " + str(ctypes.get_errno()))
if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
    fail("could not set no_new_privs: errno " + str(ctypes.get_errno()))

child = os.fork()
if child == 0:
    os.execvp(sys.argv[1], sys.argv[1:])
_, status = os.waitpid(child, 0)
if overlay is not None:
    for relative in protected_relatives:
        try:
            os.stat(relative, dir_fd=upper_fd, follow_symlinks=False)
        except FileNotFoundError:
            continue
        except OSError as exc:
            fail("could not verify private trial changes: " + str(exc))
        fail("protected trial state changed while the entry point was running: witness execution "
             "transiently changed pristine source: " + relative)
if os.WIFEXITED(status):
    code = os.WEXITSTATUS(status)
    # 128+signal is reserved for a signal the supervisor observed through waitpid. A hostile shell can
    # `exit 139`; remapping ordinary high exits makes that textually identical forgery distinguishable
    # from an exec'd target that the kernel actually terminated with SIGSEGV.
    raise SystemExit(code if code < 128 else 124)
raise SystemExit(128 + os.WTERMSIG(status))
"""

#: A private user namespace supplies the capability needed to create the PID namespace and mount its
#: own procfs without asking the host for root. `--kill-child` binds timeout cleanup to the namespace
#: init, while `--` stops `unshare` parsing further options.
_PID_NAMESPACE = (
    "unshare", "--user", "--map-root-user", "--pid", "--fork", "--kill-child", "--mount-proc",
    "--propagation", "private",
)
_PID_INIT = ("--", sys.executable, "-c", _NAMESPACE_INIT)
PID_ISOLATION: tuple[str, ...] = (*_PID_NAMESPACE, *_PID_INIT)

#: The process boundary with a private network. Pathname AF_UNIX sockets survive a network namespace,
#: so `_NAMESPACE_INIT` also pivots into an allowlisted root before hostile code starts. Every
#: attacker-authored execution requires the complete prefix and that private-root setup.
NETWORK_ISOLATION: tuple[str, ...] = (
    *_PID_NAMESPACE, "--net", *_PID_INIT,
)

# A Docker action cannot create another user namespace under the default container mapping. Its
# launcher can grant CAP_SYS_ADMIN inside the container instead; this form uses that already-namespaced
# capability, then `_NAMESPACE_INIT` drops it before customer code starts. It is never selected on an
# ordinary host unless the probe proves the complete PID/procfs/network/mount boundary.
_PRIVILEGED_PID_NAMESPACE = (
    "unshare", "--pid", "--fork", "--kill-child", "--mount-proc", "--propagation", "private",
)
PRIVILEGED_NETWORK_ISOLATION: tuple[str, ...] = (
    *_PRIVILEGED_PID_NAMESPACE, "--net", *_PID_INIT,
)
_NETWORK_PREFIXES = (NETWORK_ISOLATION, PRIVILEGED_NETWORK_ISOLATION)


def network_isolated(prefix: tuple[str, ...]) -> bool:
    """Whether a probed prefix carries the complete hostile-execution boundary."""
    return prefix in _NETWORK_PREFIXES

#: The probe's answer for the default runner, computed once per process. `None` = not yet asked.
_ISOLATION_CACHE: tuple[str, ...] | None = None

#: What the LAUNCHER must hold for `PRIVILEGED_NETWORK_ISOLATION` to build the boundary, in the order
#: the probe hits them. Measured 2026-09-06 inside the shipping free image, one capability at a time,
#: against `action.yml`'s own `--security-opt seccomp=unconfined --security-opt apparmor=unconfined`:
#:
#:     --cap-drop ALL --cap-add SYS_ADMIN     `could not mount a private writable trial: errno 13`
#:     + DAC_OVERRIDE                         `could not lock root capability semantics: errno 1`
#:     + SETPCAP                              a real witness demonstrated: exit 139, control ran
#:
#: Dropping any one of the three returns the probe to `()`. That is not a property of one kernel:
#: `prctl(PR_SET_SECUREBITS)` has required CAP_SETPCAP since it existed, so `--cap-add SYS_ADMIN`
#: ALONE — what `action.yml` shipped until this commit — could never have contained anywhere.
CONTAINMENT_CAPABILITIES: tuple[str, ...] = ("CAP_SYS_ADMIN", "CAP_DAC_OVERRIDE", "CAP_SETPCAP")

#: The stderr of the last refused probe, per prefix, so a refusal can quote the kernel rather than
#: guess. Written by `_probe_isolation` and read by `containment_unavailable`.
_ISOLATION_DIAGNOSIS: tuple[str, ...] = ()


def isolation_prefix(runner=None) -> tuple[str, ...]:
    """A verified private PID and network namespace prefix, or `()` where the kernel refuses it.

    **The customer's entry point is attacker-authored content on a pull request** — `entry_env` says
    so at length — and until 2026-08-24 it was the ONE customer-authored thing that never got this
    treatment. `sandbox._run_shell` wrapped the model's shell commands and `adjudicate`, `attribute`,
    the differential baseline and `run_entry` did not, so the script whose output is published back to
    its author had unrestricted egress on a runner where the model's own shell did not. That is the
    weaker half of the perimeter protecting the stronger one.

    Sanitising the child's environment does not hide this process or its siblings in a shared procfs.
    A witness can also double-fork into a new session, close its streams and mutate protected state
    after `bounded_run` returns. The private PID namespace closes both routes: its procfs contains
    only the new namespace, and Linux kills every remaining member when namespace PID 1 exits.

    There is deliberately no uncontained execution fallback. Callers interpret `()` as a refusal.
    PID-only isolation is not sufficient. The contained root exposes only runtime distribution paths
    and roots the caller names; arbitrary host files and control sockets are absent. A runner that
    cannot create the network and mount boundary refuses the execution before customer code starts.

    An INJECTED runner is never cached. The cache exists so a run pays for one probe rather than one
    per execution; a test that scripts the probe must get the answer it scripted.
    """
    global _ISOLATION_CACHE
    if runner is not None:
        return _probe_isolation(runner)
    if _ISOLATION_CACHE is None:
        _ISOLATION_CACHE = _probe_isolation(subprocess.run)
    return _ISOLATION_CACHE


def containment_unavailable(runner=None) -> str:
    """`""` when this runner can build the hostile-execution boundary, else WHY it cannot.

    One probe, one sentence, and the sentence NAMES the missing capability instead of saying
    "unsupported". It exists because a runner that cannot contain is the single environment in which
    every witness verdict on this machine is `refusal`, and the three places that have to notice —
    the shipped suite, the regression bench and the image check — were each guessing separately.

    The reason quotes the probe's own stderr. On a GitHub-hosted ubuntu runner that reads
    `unshare: write failed /proc/self/uid_map: Operation not permitted`, which is the AppArmor
    restriction on unprivileged user namespaces, and the privileged form then fails for want of
    `CONTAINMENT_CAPABILITIES`.

    An injected `runner` is passed straight through, so a caller that scripts the probe is answered
    from its script and never from this process's cached verdict.
    """
    if network_isolated(isolation_prefix(runner)):
        return ""
    measured = "; ".join(line for line in _ISOLATION_DIAGNOSIS if line)
    return ("this runner cannot build the private user/PID/mount/procfs/network boundary, so no "
            "attacker-authored code may be executed here: it needs either an unprivileged user "
            "namespace or a launcher granting " + ", ".join(CONTAINMENT_CAPABILITIES)
            + (" — measured: " + measured if measured else ""))


def _probe_isolation(runner) -> tuple[str, ...]:
    """Prove PID 1, private procfs/network, overlay and pivot before trusting the boundary."""
    global _ISOLATION_DIAGNOSIS
    diagnosis: list[str] = []
    with tempfile.TemporaryDirectory(prefix="shard-containment-probe-") as probe_root:
        root = pathlib.Path(probe_root)
        protected = root / "protected"
        hidden = root / "hidden"
        lower, target = root / "lower", root / "target"
        storage, upper, work = root / "storage", root / "storage/upper", root / "storage/work"
        jail = root / "jail"
        for path in (protected, lower, target, upper, work, jail):
            path.mkdir(parents=True, exist_ok=True)
        hidden.write_text("must not be visible", encoding="utf-8")
        env = _contained_entry_env(
            protected,
            jail_root=jail,
            overlay=(lower, target, upper, work, storage),
            execution_cwd=target,
            base={"PATH": os.environ.get("PATH", "")},
        )
        check = ("[ ! -e \"$1\" ] && [ ! -S /var/run/docker.sock ] "
                 "&& [ ! -S /run/docker.sock ]")
        for prefix in _NETWORK_PREFIXES:
            try:
                proc = runner(
                    [*prefix, "bash", "-c", check, "bash", str(hidden)],
                    capture_output=True, text=True, errors="replace", timeout=10, env=env,
                )
            except (OSError, subprocess.SubprocessError) as exc:
                diagnosis.append(f"{prefix[0]}: {exc}")
                continue
            if proc.returncode == 0:
                _ISOLATION_DIAGNOSIS = ()
                return prefix
            # A scripted probe need not carry streams; a real one always does. Keep the LAST line,
            # which is where `unshare` and the namespace init both put the reason.
            said = (getattr(proc, "stderr", "") or "").strip().splitlines()
            diagnosis.append(said[-1] if said else f"exit {proc.returncode}")
    _ISOLATION_DIAGNOSIS = tuple(diagnosis)
    return ()


def _resolved_existing_paths(candidates) -> list[str]:
    """Canonical existing paths, once each; unavailable optional roots stay unavailable."""
    resolved = []
    for candidate in candidates:
        if not candidate:
            continue
        try:
            path = pathlib.Path(candidate).resolve(strict=True)
        except (OSError, RuntimeError):
            continue
        rendered = str(path)
        if rendered not in resolved:
            resolved.append(rendered)
    return resolved


def _resolved_bindings(bind_files) -> list[list[str]]:
    """Canonical source/target pairs for immutable file binds."""
    bindings = []
    for source_path, target_path in bind_files:
        try:
            binding_source = str(pathlib.Path(source_path).resolve(strict=True))
            target_candidate = pathlib.Path(target_path)
            try:
                target = str(target_candidate.resolve(strict=True))
            except FileNotFoundError:
                target = str(target_candidate.parent.resolve(strict=True) / target_candidate.name)
        except (OSError, RuntimeError):
            continue
        pair = [binding_source, target]
        if pair not in bindings:
            bindings.append(pair)
    return bindings


def _resolved_overlay(overlay) -> dict[str, str] | None:
    """Canonical overlay paths, or no overlay when an optional path disappeared."""
    if overlay is None:
        return None
    names = ("lower", "target", "upper", "work", "storage")
    try:
        values = [str(pathlib.Path(path).resolve(strict=True)) for path in overlay]
    except (OSError, RuntimeError):
        return None
    return dict(zip(names, values, strict=True)) if len(values) == len(names) else None


def _contained_entry_env(*readonly_paths, jail_root, writable_paths=(), bind_files=(),
                         protected_relatives=(), overlay=None,
                         execution_cwd=None, base=None, secret_env_names=()) -> dict:
    """Sanitise entry env and describe the only host paths the private root may expose.

    The private manifest is removed before the customer process is forked. Runtime distribution roots
    are added by the trusted init; everything else is absent unless a caller names it here. Command
    files and host sockets are therefore unreachable even when hostile code guesses their paths.
    """
    import json

    source = os.environ if base is None else base
    protected = _resolved_existing_paths(readonly_paths)
    writable = _resolved_existing_paths(writable_paths)
    bindings = _resolved_bindings(bind_files)
    env = entry_env(source, secret_env_names=secret_env_names)
    # An inherited TMPDIR can point outside the allowlist. All temporary state belongs in the
    # private root instead, and these conventional spellings keep compilers and managed runtimes
    # working without exposing the host's shared temporary directory.
    env.update({"TMPDIR": "/tmp", "TMP": "/tmp", "TEMP": "/tmp"})
    env[_CONTAINMENT_PATHS_ENV] = json.dumps({
        "jail_root": str(pathlib.Path(jail_root).resolve(strict=True)),
        "readonly": protected,
        "writable": writable,
        "bind_files": bindings,
        "protected_relatives": list(protected_relatives),
        "overlay": _resolved_overlay(overlay),
        "execution_cwd": (str(pathlib.Path(execution_cwd).resolve(strict=True))
                          if execution_cwd is not None else None),
    }, separators=(",", ":"))
    return env


def reset_isolation_cache() -> None:
    """Forget the probe's answer. For tests, which must not inherit a verdict from an earlier one."""
    global _ISOLATION_CACHE, _ISOLATION_DIAGNOSIS
    _ISOLATION_CACHE = None
    _ISOLATION_DIAGNOSIS = ()


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
#: How much of a customer-authored program's output we will HOLD, per stream. Nothing downstream
#: wants more — `MAX_EVIDENCE_CHARS` is 4,000 — so this is not a display limit, it is a bound on this
#: process's memory while an attacker-authored program is running.
#:
#: **`memcap` DOES NOT COVER THIS DIRECTION and that is why the bound is here.** It watches the child
#: tree's resident set; a child running `cat /dev/zero` uses almost none itself while OUR process
#: accumulates every byte it writes. `capture_output=True` reads to EOF, so the truncation at
#: `evidence=output[-MAX_EVIDENCE_CHARS:]` happens after the whole stream is already in memory.
#: 16 MB is generous on purpose: a sanitiser report with a deep stack is large, and refusing a real
#: finding to save memory would be the wrong direction to fail in.
MAX_CAPTURED_BYTES = 16 * 1024 * 1024

#: Appended when a stream hit `MAX_CAPTURED_BYTES`, so a truncated capture never reads as a complete
#: one. A silent truncation would make "the program printed nothing more" and "we stopped listening"
#: the same observation, which is the ambiguity this repository refuses everywhere else.
TRUNCATION_NOTE = "\n[shard: output truncated at {} bytes]\n"


def _finished_capture(chunks: list[bytes], seen: list[int], *, cap: int,
                      text: bool, errors: str | None) -> str | bytes:
    """Render one drained stream without hiding that bytes past the cap were discarded."""
    raw = b"".join(chunks)
    if seen[0] > cap:
        raw += TRUNCATION_NOTE.format(seen[0]).encode()
    return raw.decode("utf-8", errors or "replace") if text else raw


def bounded_run(argv, *, cwd=None, capture_output=True, text=True, errors="replace",
                timeout=None, env=None, cap: int = MAX_CAPTURED_BYTES, **kw):
    """`subprocess.run`'s contract, with a ceiling on how much output is held in memory.

    A DROP-IN for `subprocess.run` because the runner is an injected seam: `adjudicate`, `attribute`
    and the sandbox all take `runner=`, tests pass fakes through it, and the displaced-witness design
    depends on that signature. Bounding the DEFAULT leaves every one of those callers unchanged.

    **It keeps draining after the ceiling rather than closing the pipe.** A child that fills a pipe
    nobody reads blocks in `write()`, and a blocked child produces a timeout instead of the exit code
    it was about to return — which would turn a bounded capture into a lost verdict. Bytes past the
    ceiling are read and discarded, so the child runs to completion and its status is real.

    Raises `subprocess.TimeoutExpired` exactly as `subprocess.run` does, because `_run` catches
    `SubprocessError` and refuses on it.
    """
    import threading

    def drain(stream, sink: list, seen: list) -> None:
        try:
            while True:
                chunk = stream.read(65536)
                if not chunk:
                    return
                room = cap - seen[0]
                if room > 0:
                    sink.append(chunk[:room])
                seen[0] += len(chunk)
        except (OSError, ValueError):
            return
        finally:
            try:
                stream.close()
            except OSError:
                pass

    # A child that closes its streams and leaves a background writer behind can otherwise mutate the
    # preserved candidate after the post-run check. One session per entry lets this runner reap that
    # whole execution tree before returning an observation.
    kw["start_new_session"] = True
    # The runner process may itself have a pipe or terminal on fd 0. Hostile code has no business
    # inheriting bytes addressed to Shard: a workflow secret piped to the CLI otherwise survives the
    # private root and appears as `/proc/self/fd/0`. A caller that deliberately supplies `stdin=` keeps
    # subprocess semantics; omission means a closed input, never ambient authority.
    stdin = kw.pop("stdin", subprocess.DEVNULL)
    proc = subprocess.Popen(argv, cwd=cwd, stdin=stdin, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, env=env, **kw)
    out: list[bytes] = []
    err: list[bytes] = []
    out_seen, err_seen = [0], [0]
    readers = [threading.Thread(target=drain, args=(proc.stdout, out, out_seen), daemon=True),
               threading.Thread(target=drain, args=(proc.stderr, err, err_seen), daemon=True)]
    for r in readers:
        r.start()
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill_process_group(proc.pid)
        proc.wait()
        for r in readers:
            r.join(timeout=5)
        raise
    _kill_process_group(proc.pid)
    for r in readers:
        r.join(timeout=5)

    return subprocess.CompletedProcess(argv, proc.returncode,
                                       stdout=_finished_capture(out, out_seen, cap=cap, text=text,
                                                                errors=errors),
                                       stderr=_finished_capture(err, err_seen, cap=cap, text=text,
                                                                errors=errors))


class ContainmentUnavailable(RuntimeError):
    """A hostile host command was refused before its payload started."""


def contained_run(argv, *, cwd, readonly_paths=(), writable_paths=(), timeout=None,
                  base_env=None, secret_env_names=()):
    """Run a trusted runtime processing hostile bytes in the proved allowlisted root.

    Compilers are the primary caller. There is deliberately no raw fallback: inability to build the
    complete root/PID/network boundary is a refusal, not permission to inspect the host filesystem.
    """
    prefix = isolation_prefix()
    if not network_isolated(prefix):
        raise ContainmentUnavailable(
            "the required private PID, mount, procfs and network boundary is unavailable"
        )
    with tempfile.TemporaryDirectory(prefix="shard-host-command-root-") as jail_root:
        proc = bounded_run(
            [*prefix, *argv], cwd=str(cwd), capture_output=True, text=True, errors="replace",
            timeout=timeout,
            env=_contained_entry_env(
                *readonly_paths, jail_root=jail_root, writable_paths=writable_paths,
                execution_cwd=cwd, base=base_env, secret_env_names=secret_env_names,
            ),
        )
    stdout = redact_secrets(proc.stdout or "", secret_env_names=secret_env_names)
    stderr = redact_secrets(proc.stderr or "", secret_env_names=secret_env_names)
    if proc.returncode == 125 and stderr.startswith(_CONTAINMENT_ERROR):
        raise ContainmentUnavailable(stderr.strip())
    return subprocess.CompletedProcess(proc.args, proc.returncode, stdout, stderr)


def _kill_process_group(pid: int) -> None:
    try:
        os.killpg(pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


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
class _TrialPlan:
    snapshot: SourceSnapshot
    prefix: tuple[str, ...]
    runner: object
    timeout: int
    input_path: pathlib.Path
    run_path: pathlib.Path
    digest: str
    protected: tuple[tuple[str, pathlib.Path, bytes], ...]
    secret_env_names: tuple[str, ...]


@dataclass(frozen=True)
class _TrialExecution:
    """Process-boundary inputs that are constant for one pristine trial."""

    prefix: tuple[str, ...]
    runner: object
    timeout: int
    protected: tuple[tuple[str, pathlib.Path, bytes], ...] = ()
    logical_input: str | None = None
    verify_original: bool = True
    expected_input: bytes | None = None
    secret_env_names: tuple[str, ...] = ()


@dataclass(frozen=True)
class _ProtectedInput:
    label: str
    path: pathlib.Path
    expected: bytes
    device: int
    inode: int


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
    #: 2026-08-12 no artefact said what they were. The design notes is the same complaint about
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
    #: The exact verified bytes behind `input_path`. A later claim or delayed same-UID writer can
    #: change a filesystem path after adjudication; the bundle must never reopen one and call the new
    #: bytes evidence. `None` means no input survived the integrity boundary.
    input_bytes: bytes | None = None

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
    `shard/report.py` says this product does not do. The design notes holds the wider question.

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


def controls_digest(repo, entry: str | None) -> str:
    """SHA-256 over the benign controls this entry point declares — their paths AND their bytes.

    **`entry_digest` guarded one half of the contract and the other half was guarded by nothing after
    the loop ended.** The entry point is re-hashed on every claim in `_preconditions` and a mismatch
    is a refusal; the CONTROLS were resolved and read inside `_stage_controls`, which runs AFTER the
    customer's entry point has already executed, and nothing compared what ran against what the
    repository declared.

    Measured 2026-09-02 on the shipping path, one entry point that dispatches on the first byte and
    runs `rm -rf "$(dirname "$0")/entry.sh.benign"` when it sees the attack byte:

        entry point                     controls at staging   demonstrated   gate_eligible
        leaves its fixtures alone               1              False          False   <- refuted
        deletes them while it runs              0              True           True    <- forged

    Both runs are the same payload against the same marker. The second is an internal audit's 4-of-4 false-gate configuration, restored from inside the adjudication phase where
    `run_simple`'s `scope_digest` comparison has already been taken and will not be taken again. It
    also survives the claim: every LATER claim in the same run is graded against the controls that are
    left, so a second finding whose payload is byte-identical to the customer's own benign fixture
    demonstrated and gated too.

    The bytes and not just the paths, for `entry_digest`'s reason: emptying one control file weakens
    the differential exactly as deleting it does.

    **A control we can see and cannot read digests differently from one that is not there**, so
    breaking a fixture is not quieter than removing it.

    `dropped` is digested as well. With more than `MAX_BENIGN_CONTROLS` declared, the first eight are
    what run and the rest are an announcement in the evidence; deleting only the announced ones leaves
    every executed control identical and still changes what the customer was told.

    ASYMMETRIC WITH `witness_contract` ON PURPOSE, and this is the one place the two differ.
    That function deliberately ignores an ADDED control — during the loop an extra benign input can
    only refuse a demonstration, never manufacture one. Here an addition changes this digest and
    becomes a refusal. Refusing is the fail-closed direction and the surface is one fixture directory
    rather than the whole diff, so the cost of the stricter reading is a refusal on an entry point
    that writes into its own control directory while being adjudicated. No entry point under
    `corpora/entries/` or `targets/` does.

    **THE BENCH IS NOT EVIDENCE ABOUT THIS FUNCTION, and saying so is the point.** a maintenance script
    is 199 ok either way — but traced, its 41 `controls_digest` calls see a benign control ZERO times,
    because no bench row declares one. The corpus that does (`corpora/entries/*.benign`) is
    a maintenance script's, which needs a model. So the bench establishes that the no-control path
    is untouched and nothing more; the with-control behaviour is pinned by the maintainers' suite
    alone.

    Never raises, for `benign_controls`' reason: an unreadable control tree is a value here, and the
    caller compares values.
    """
    controls, dropped = benign_controls(repo, entry or "")
    root = pathlib.Path(repo).resolve()
    digest = hashlib.sha256()
    digest.update(f"dropped:{dropped}\n".encode())
    for path in controls:
        try:
            name = path.resolve().relative_to(root).as_posix()
        except (OSError, ValueError):
            name = path.name
        try:
            data = path.read_bytes()
        except OSError:
            data = b"\x00SHARD-UNREADABLE-CONTROL"
        # Lengths before the values: without them `("ab", "c")` and `("a", "bc")` feed the same bytes.
        digest.update(f"{len(name)}:{name}:{len(data)}:".encode())
        digest.update(data)
    return digest.hexdigest()[:16]


def adjudicate(spec: WitnessSpec, repo, *, baseline_digest: str | None,
               baseline_controls: str | None = None,
               runner=bounded_run, timeout: int = DEFAULT_TIMEOUT,
               workdir=None, source_snapshot: SourceSnapshot | None = None,
               protected_inputs: tuple[tuple[str, pathlib.Path, bytes], ...] = (),
               secret_env_names: tuple[str, ...] = ()) -> Witness:
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

    `source_snapshot` is captured before the model on the shipping path. Every execution receives a
    fresh writable materialisation of it; no attack, control or base trial shares filesystem state.
    Direct callers that omit it get a snapshot immediately, before their first execution.

    `baseline_controls` retains the phase-boundary check for callers that captured those fixtures
    earlier. Trial verification is the other half: an entry point that replaces itself or any captured
    helper is refused before its output is interpreted. `None` leaves only that full-source boundary.
    """
    owned = source_snapshot is None
    if source_snapshot is None:
        try:
            source_snapshot = SourceSnapshot.capture(repo)
        except SnapshotError as e:
            return _refuse(spec, SOURCE_ISOLATION_REFUSAL +
                           f"source could not be staged as a pristine tree: {e}; "
                           f"nothing was adjudicated")
    try:
        return _adjudicate_pristine(spec, source_snapshot, baseline_digest=baseline_digest,
                                    baseline_controls=baseline_controls, runner=runner,
                                    timeout=timeout, workdir=workdir,
                                    protected_inputs=protected_inputs,
                                    secret_env_names=secret_env_names)
    finally:
        if owned:
            source_snapshot.close()


def _adjudicate_pristine(spec: WitnessSpec, snapshot: SourceSnapshot, *,
                         baseline_digest: str | None, baseline_controls: str | None,
                         runner, timeout: int, workdir,
                         protected_inputs: tuple[tuple[str, pathlib.Path, bytes], ...],
                         secret_env_names: tuple[str, ...]) -> Witness:
    """Adjudicate only from the pre-model tree, with one new tree per execution."""
    repo = snapshot.source
    try:
        snapshot.verify_original()
        snapshot.verify_source()
    except SnapshotError as e:
        return _refuse(spec, SOURCE_ISOLATION_REFUSAL +
                       f"pristine source verification failed: {e}; nothing was adjudicated")

    refusal, _resolved, digest = _preconditions(spec, repo, baseline_digest)
    if refusal is not None:
        return refusal
    # AFTER `_preconditions`, so a proposal with a bad entry point is still told about that first —
    # the controls are only meaningful once there is an entry point to grade, and `digest` does not
    # exist until the pair above is admitted.
    if changed := _controls_changed(spec, repo, baseline_controls, digest,
                                    when="before this claim was adjudicated"):
        return changed

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
    # different programs. `isolation_prefix` is `()` wherever the kernel refuses; that is a refusal,
    # never permission to execute the witness without the private PID and network boundary.
    # ONE EXECUTION PATH FOR EVERY RUN, and the argument for it is the paragraph above applied to
    # the FILENAME. Until 2026-09-01 the attack ran on `shard_witness_input` and each control on
    # `shard_witness_input.baseline` / `.benign<N>`, so the last element of argv was a string this
    # adjudicator introduced on the attack side and on NO control side. `_adjudge` and
    # `_baseline_contradicts` both ask `spec.marker in output`, and an entry point that echoes its own
    # argument is ordinary — so a marker overlapping the END of that path is present in the attack
    # output and absent from every control by construction. That is a forged differential, built out
    # of our own staging convention rather than out of the customer's code.
    #
    # The payload keeps its own path: `Witness.input_path` and the bundle are what a customer opens.
    # Execution goes through a copy, so every run takes a BYTE-IDENTICAL argv.
    run_path = input_path.with_name("shard_witness_run")
    try:
        run_path.write_bytes(spec.payload)
    except OSError as e:
        return _refuse(spec, f"could not stage the payload for execution: {e}", digest=digest)
    prefix = isolation_prefix()
    if not network_isolated(prefix):
        return _refuse(
            spec,
            CONTAINMENT_REFUSAL + "this runner cannot create the private PID, mount, procfs and "
            "network boundary, so no customer-authored entry point was executed",
            digest=digest,
        )
    try:
        # errors="replace": this runs the CUSTOMER'S witness entry point, and a witness that
        # demonstrates a memory-safety bug crashes — raw memory, sanitiser output and arbitrary bytes
        # on stdout are its EXPECTED output, not a corner case. `text=True` alone decodes strict utf-8
        # and raises UnicodeDecodeError, which is neither TimeoutExpired nor OSError, so it escapes
        # every `except` here and kills the run. See the separate package`, which had already
        # settled this for the same reason.
        # `env=` and not the inherited environment — see `entry_env`. This script is written by whoever
        # opened the pull request, and its output is published back to them.
        protected = (*protected_inputs,
                     ("preserved witness input", input_path, spec.payload))
        proc = _execute_trial(snapshot, spec.entry, run_path, _TrialExecution(
            prefix, runner, timeout, protected=protected, expected_input=spec.payload,
            secret_env_names=secret_env_names,
        ))
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
                       timed_out=True, input_path=str(input_path), input_bytes=spec.payload)
    except SnapshotError as e:
        return _refuse(spec, SOURCE_ISOLATION_REFUSAL +
                       f"pristine witness trial was refused: {e}; nothing was adjudicated",
                       digest=digest)
    except (OSError, subprocess.SubprocessError) as e:
        return _refuse(spec, f"the entry point could not be executed: {e}", digest=digest)

    # REDACTED BEFORE IT IS READ, never only before it is reported. Everything downstream — the
    # marker test, `observed_location`, `Witness.evidence`, the bundle, the PR comment — sees the same
    # scrubbed text, so a demonstration cannot be built on our own credential and the differential
    # below stays a comparison of like with like. See `redact_secrets`.
    output = redact_secrets(
        original_paths((proc.stdout or "") + (proc.stderr or ""), snapshot),
        secret_env_names=secret_env_names,
    )
    if refused := _nothing_adjudicated(spec, proc, output, digest=digest, input_path=input_path):
        return refused
    # AFTER the run and BEFORE the verdict, because the run is what may have changed them and the
    # verdict is what reads them. `_nothing_adjudicated` goes first: an entry point whose interpreter
    # is missing, or one that was killed, has a more specific thing wrong with it than its fixtures.
    plan = _TrialPlan(snapshot, prefix, runner, timeout, input_path, run_path, digest, protected,
                      secret_env_names)
    return _controlled_verdict(spec, plan, proc=proc, output=output)


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


def _controls_changed(spec: WitnessSpec, repo, baseline_controls: str | None, digest: str, *,
                      when: str) -> Witness | None:
    """Refuse controls that differ from an earlier caller-owned phase snapshot."""
    if baseline_controls is None or controls_digest(repo, spec.entry) == baseline_controls:
        return None
    return _refuse(spec, f"the benign controls declared at {spec.entry}{BENIGN_SUFFIX} changed "
                         f"{when}, so this finding would be graded against different controls from "
                         f"the ones this repository declared, and nothing was adjudicated",
                   digest=digest)


def _stage_payload(payload: bytes, workdir) -> pathlib.Path:
    """Write the payload where the entry point will read it. Raises OSError; the caller refuses on it.

    MEASURED 2026-08-12: THE DEFAULT IS ALSO WHAT BLOCKS A DISPLACED WITNESS, AND IT FAILS SILENTLY.

    The design notes records the historical image that lacked the JVM, node, ruby, php
    and dotnet. Those runtimes were added later. The displaced-runner experiment remains relevant for
    a runtime or build SDK the current image does not carry: driving `adjudicate` with a runner that
    executes in a different filesystem namespace reproduced in-process results exactly, anti-forgery
    refusal included.

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
        parent = pathlib.Path(workdir)
        parent.mkdir(parents=True, exist_ok=True)
        work = pathlib.Path(tempfile.mkdtemp(prefix="claim-", dir=parent))
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
    # an internal audit measured the earlier image before its current runtimes were
    # added. The refusal remains necessary for a runtime or build SDK the release image still lacks.
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
                             f"this is NOT a clean result — the release image does not carry every "
                             f"runtime or build SDK. Build the target in an earlier trusted step or "
                             f"use an adapter supported by the image; preflight reports its runtime "
                             f"inventory", digest=digest)

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
            input_bytes=spec.payload,
            refusal=f"the entry point was KILLED (rc={code}) rather than finishing, so nothing was "
                    f"adjudicated and this is NOT a clean result. The commonest cause is the reported "
                    f"input itself — a payload that kills or hangs the entry point leaves no exit "
                    f"status and no output to observe, so it destroys the evidence it was meant to "
                    f"produce. Read the preserved input in the bundle before suspecting the machine")
    return None


def _controlled_verdict(spec: WitnessSpec, plan: _TrialPlan, *, proc, output: str) -> Witness:
    """The verdict on what was observed — after every control had its chance to refute it.

    `_adjudge` decides from the observation alone. A demonstration then pays for its controls — the
    empty payload first, then each benign input the customer declares — and ANY control reproducing
    the observation refutes the demonstration. A control that cannot be RUN is a refusal instead:
    grading against fewer controls than the repository asked for is the quiet-degradation shape this
    module exists to refuse.

    Controls are read from the immutable snapshot, not from the tree the attack just ran in. Each is
    then executed in another materialisation at the same stable path, so argv stays byte-identical
    without sharing the attack's files.
    """
    demonstrated, why_not = _adjudge(spec, proc.returncode, output)
    ran: list[str] = []
    repo = plan.snapshot.source

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
            controls, dropped = _stage_controls(repo, spec)
        except OSError as e:
            # A control the customer DECLARED and we could not stage is a refusal, not a quiet fallback
            # to the weaker one. Silently grading against fewer controls than the repository asked for
            # is the same shape as `2fd4e36`'s green check on a diff nobody read.
            return _refuse(spec, f"the benign control declared at {spec.entry}{BENIGN_SUFFIX} could not "
                                 f"be staged ({e}), so nothing was adjudicated", digest=plan.digest)
        if dropped:
            output += (f"\n[shard] {dropped} further benign control(s) beyond the first "
                       f"{MAX_BENIGN_CONTROLS} were NOT run; this verdict is checked against fewer "
                       f"controls than {spec.entry}{BENIGN_SUFFIX} declares")
        for what, control in controls:
            # THE SAME `argv`, NOT `argv[:-1] + [control]`. The control's bytes are copied over the
            # one execution path so the differential compares two runs of one command line. Building
            # a new argv per control is what let the staged filename become a marker.
            try:
                plan.run_path.write_bytes(control)
            except OSError as e:
                return _refuse(spec, f"the run on {what} could not be staged: {e}",
                               digest=plan.digest)
            try:
                baseline = _run_trial(
                    plan.snapshot, spec.entry, plan.run_path, prefix=plan.prefix,
                    runner=plan.runner, timeout=plan.timeout,
                    protected=plan.protected, expected_input=control,
                    secret_env_names=plan.secret_env_names,
                )
            except SnapshotError as e:
                return _refuse(spec, SOURCE_ISOLATION_REFUSAL +
                               f"the run on {what} was refused: {e}; nothing was adjudicated",
                               digest=plan.digest)
            if baseline is None:
                return _refuse(spec, f"the run on {what} could not be completed, so "
                                     f"{_OBSERVED[spec.expectation]} could not be attributed to the "
                                     f"payload", digest=plan.digest)
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
                # instead of guessing again. The maintainers' notes records a marker the model had to
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
        entry_digest=plan.digest,
        evidence=output[-MAX_EVIDENCE_CHARS:],
        input_path=str(plan.input_path),
        input_bytes=spec.payload,
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


def attribute(spec: WitnessSpec, base_repo, *, runner=bounded_run, timeout: int = DEFAULT_TIMEOUT,
              workdir=None, source_snapshot: SourceSnapshot | None = None,
              protected_inputs: tuple[tuple[str, pathlib.Path, bytes], ...] = (),
              secret_env_names: tuple[str, ...] = ()) -> tuple[str, str]:
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
    owned = source_snapshot is None
    if source_snapshot is None:
        try:
            source_snapshot = SourceSnapshot.capture(base_repo)
        except SnapshotError as e:
            return UNATTRIBUTED, SOURCE_ISOLATION_REFUSAL + \
                f"the base revision could not be snapshotted: {e}"
    try:
        try:
            return _attribute_pristine(spec, source_snapshot, runner=runner, timeout=timeout,
                                       workdir=workdir, protected_inputs=protected_inputs,
                                       secret_env_names=secret_env_names)
        except SnapshotError as e:
            return UNATTRIBUTED, SOURCE_ISOLATION_REFUSAL + str(e)
    finally:
        if owned:
            source_snapshot.close()


def _attribute_pristine(spec: WitnessSpec, snapshot: SourceSnapshot, *, runner, timeout: int,
                        workdir,
                        protected_inputs: tuple[tuple[str, pathlib.Path, bytes], ...],
                        secret_env_names: tuple[str, ...],
                        ) -> tuple[str, str]:
    base_repo = snapshot.source
    try:
        snapshot.verify_original()
        snapshot.verify_source()
    except SnapshotError as e:
        raise SnapshotError(f"the base revision's pristine source could not be verified: {e}") from e
    digest = entry_digest(base_repo, spec.entry)
    if digest is None:
        return UNATTRIBUTED, (f"{spec.entry} did not exist at the base revision, so the defect could "
                              f"not be re-run against the code as it was")

    # SNAPSHOTTED BEFORE THE PROBE, not before the re-run. `_base_control` executes the BASE entry
    # point, which is customer-authored too, so the base fixtures can be gone by the time the re-run
    # reads them — and the base side reads `benign_controls(base_repo, ...)` in two separate places.
    # Its own digest and never the HEAD one: the base revision is entitled to different fixtures, and
    # comparing across revisions would refuse every pull request that edits a control.
    base_controls = controls_digest(base_repo, spec.entry)

    # THE PROBE FIRST. It is the cheap half and it decides whether the expensive half means anything.
    try:
        probe = _base_control(spec, snapshot, runner=runner, timeout=timeout, workdir=workdir,
                              protected_inputs=protected_inputs,
                              secret_env_names=secret_env_names)
    except SnapshotError as e:
        return UNATTRIBUTED, SOURCE_ISOLATION_REFUSAL + \
            f"the defect could not be re-run at the base revision: {e}"
    if probe != 0:
        return UNATTRIBUTED, (f"the entry point did not run cleanly at the base revision "
                              f"(exit {probe}), so a non-reproduction there is not evidence the "
                              f"defect is new — a base checkout carries no build artifacts")

    before = adjudicate(spec, base_repo, baseline_digest=digest, baseline_controls=base_controls,
                        runner=runner, timeout=timeout, workdir=workdir,
                        source_snapshot=snapshot, protected_inputs=protected_inputs,
                        secret_env_names=secret_env_names)
    if before.refusal:
        if before.refusal.startswith(SOURCE_ISOLATION_REFUSAL):
            return UNATTRIBUTED, before.refusal
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


def _base_control(spec: WitnessSpec, snapshot: SourceSnapshot, *, runner, timeout, workdir,
                  protected_inputs: tuple[tuple[str, pathlib.Path, bytes], ...],
                  secret_env_names: tuple[str, ...]) -> int | None:
    """The base entry point's exit code on its control input, or None if it could not be run at all."""
    base_repo = snapshot.source
    resolved = resolve_entry(base_repo, spec.entry)
    if resolved is None:
        return None
    controls, _dropped = benign_controls(base_repo, spec.entry)
    try:
        scratch = pathlib.Path(workdir) if workdir is not None else pathlib.Path(
            tempfile.mkdtemp(prefix="shard-attribute-"))
        scratch.mkdir(parents=True, exist_ok=True)
        probe = scratch / "shard_base_control"
        probe_bytes = controls[0].read_bytes() if controls else b""
        probe.write_bytes(probe_bytes)
    except OSError:
        return None
    protected = (*protected_inputs, ("base control input", probe, probe_bytes))
    prefix = isolation_prefix()
    if not network_isolated(prefix):
        return None
    result = _run_trial(
        snapshot, spec.entry, probe, prefix=prefix, runner=runner, timeout=timeout,
        protected=protected, expected_input=probe_bytes, secret_env_names=secret_env_names,
    )
    return None if result is None else result[0]


def _stage_controls(repo, spec: WitnessSpec) -> tuple[list[tuple[str, bytes]], int]:
    """The inputs the observation must be ABSENT on, in the order they are run. Raises OSError.

    Every declared control is read into memory before any control runs. Staging all of them beside the
    payload let the first customer-authored run rewrite a later control before that control was copied
    to the stable execution path. The immutable bytes keep all executions on an identical argv without
    leaving the differential itself in a directory the entry point can edit.

    The empty control comes FIRST and is never dropped. It is the cheapest refutation — a marker of "a"
    or " " dies on it — and ordering it first means the common rejection costs one execution rather
    than N.
    """
    controls = [("an empty payload", b"")]
    benign, dropped = benign_controls(repo, spec.entry)
    root = pathlib.Path(repo).resolve()
    for source in benign:
        data = source.read_bytes()
        # NAMED by the path in the CUSTOMER's repository, not by where it was staged: the sentence is
        # read by someone deciding which of their own fixtures to go and look at.
        controls.append((f"the benign input this repository declares at {source.relative_to(root)}",
                         data))
    return controls, dropped


def _execute_trial(snapshot: SourceSnapshot, entry: str, input_path: pathlib.Path,
                   execution: _TrialExecution):
    """Run one input in a fresh tree and refuse changed source or evidence."""
    if not network_isolated(execution.prefix):
        raise SnapshotError(
            "the private PID, mount, procfs and network boundary is unavailable; the entry point "
            "was not executed"
        )
    if execution.verify_original:
        snapshot.verify_original()
    expected_input, sealed, staged_input, staged_identity = _prepare_trial_input(
        snapshot, input_path, execution.expected_input, execution.protected,
    )
    repo = snapshot.materialize()
    resolved = resolve_entry(repo, entry)
    if resolved is None:
        raise SnapshotError(f"entry point {entry!r} disappeared from a materialised trial")
    if execution.logical_input is None:
        # Keep the historical argv for deterministic/external runners. Inside the namespace the fresh
        # staged file is bound onto that name, while its parent is only an ephemeral jail directory:
        # sibling state an attack writes cannot reach the host or the next control's fresh root.
        bindings = ((staged_input, input_path),)
        executed_entry, executed_input = str(resolved), str(input_path)
        visible_inputs = (input_path,)
    else:
        logical_target = repo / execution.logical_input
        bindings = ((staged_input, logical_target),)
        # Preserve the harness contract's working-directory-relative argv. BASH_SOURCE/$0-relative
        # helpers then resolve inside the pristine trial, while the exact candidate is mounted onto
        # the historical name only in the child namespace.
        executed_entry, executed_input = entry, execution.logical_input
        visible_inputs = ()
    argv = [*execution.prefix, "bash", "--", executed_entry, executed_input]
    failure = None
    proc = None
    with tempfile.TemporaryDirectory(prefix="shard-witness-overlay-") as overlay_storage:
        private = pathlib.Path(overlay_storage)
        storage, jail = private / "overlay", private / "jail"
        upper, work = storage / "upper", storage / "work"
        for path in (upper, work, jail):
            path.mkdir(parents=True, exist_ok=True)
        try:
            proc = execution.runner(
                argv, cwd=str(repo), capture_output=True, text=True, errors="replace",
                timeout=execution.timeout,
                env=_contained_entry_env(
                    *visible_inputs,
                    jail_root=jail,
                    writable_paths=(),
                    bind_files=bindings,
                    protected_relatives=(entry.path for entry in snapshot.manifest
                                         if entry.kind != "dir"),
                    overlay=(snapshot.source, repo, upper, work, storage),
                    execution_cwd=repo,
                    secret_env_names=execution.secret_env_names,
                ),
            )
        except (OSError, subprocess.SubprocessError) as e:
            failure = e
        # Every boundary is checked even when an earlier one failed. Same-UID entry code can locate
        # the snapshot store as well as its disposable trial, and it can reach the preserved candidate
        # beside `shard_witness_run`; a short-circuit would leave one unchecked after the child ran.
        failures = _trial_boundary_failures(
            snapshot, sealed, staged_input, expected_input, staged_identity, upper,
            verify_original=execution.verify_original,
        )
    if failures:
        raise SnapshotError(
            "protected trial state changed while the entry point was running: " + "; ".join(failures)
        )
    if failure is not None:
        raise failure
    stderr = redact_secrets(proc.stderr or "", secret_env_names=execution.secret_env_names)
    if (getattr(proc, "returncode", None) == 125
            and stderr.startswith(_CONTAINMENT_ERROR)):
        raise SnapshotError(stderr.strip())
    return proc


def _prepare_trial_input(snapshot: SourceSnapshot, input_path: pathlib.Path,
                         expected: bytes | None,
                         protected: tuple[tuple[str, pathlib.Path, bytes], ...],
                         ) -> tuple[bytes, tuple[_ProtectedInput, ...], pathlib.Path,
                                    _ProtectedInput]:
    """Seal the caller's input and give this trial an independently backed immutable copy."""
    if expected is None:
        try:
            expected = input_path.read_bytes()
        except OSError as exc:
            raise SnapshotError(f"trial input became unreadable: {exc}") from exc
    input_identity = _read_protected_input("trial input", input_path, expected)
    sealed = (*_seal_protected_inputs(protected), input_identity)
    staged = snapshot.materialize_input(expected)
    staged_identity = _read_protected_input("fresh trial input", staged, expected)
    return expected, sealed, staged, staged_identity


def _trial_boundary_failures(snapshot: SourceSnapshot, sealed: tuple[_ProtectedInput, ...],
                             staged: pathlib.Path, expected: bytes,
                             staged_identity: _ProtectedInput, upper: pathlib.Path, *,
                             verify_original: bool) -> list[str]:
    """Run every post-execution identity check; one failure must not mask a second."""
    checks = [
        lambda: _verify_protected_inputs(sealed),
        lambda: _read_protected_input("fresh trial input", staged, expected,
                                      identity=staged_identity),
        lambda: _verify_overlay(snapshot, upper),
        snapshot.verify_trial,
        snapshot.verify_source,
    ]
    if verify_original:
        checks.append(snapshot.verify_original)
    failures = []
    for check in checks:
        try:
            check()
        except SnapshotError as exc:
            failures.append(str(exc))
    return failures


def _verify_overlay(snapshot: SourceSnapshot, upper: pathlib.Path) -> None:
    """Refuse any copy-up or whiteout of a manifested file, even when its bytes were restored."""
    for expected in snapshot.manifest:
        if expected.kind == "dir":
            continue
        candidate = upper.joinpath(*pathlib.PurePosixPath(expected.path).parts)
        if os.path.lexists(candidate):
            raise SnapshotError(
                f"witness execution transiently changed pristine source: {expected.path}"
            )


def _seal_protected_inputs(
        protected: tuple[tuple[str, pathlib.Path, bytes], ...]) -> tuple[_ProtectedInput, ...]:
    return tuple(_read_protected_input(label, path, expected) for label, path, expected in protected)


def _verify_protected_inputs(protected: tuple[_ProtectedInput, ...]) -> None:
    """Require every external input to retain its regular-file identity and exact bytes."""
    for sealed in protected:
        _read_protected_input(sealed.label, sealed.path, sealed.expected, identity=sealed)


def _read_protected_input(label: str, path: pathlib.Path, expected: bytes, *,
                          identity: _ProtectedInput | None = None) -> _ProtectedInput:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as e:
        raise SnapshotError(f"{label} became unreadable or stopped being a regular file: {e}") from e
    try:
        status = os.fstat(descriptor)
        if not stat.S_ISREG(status.st_mode) or status.st_nlink != 1:
            raise SnapshotError(f"{label} stopped being one private regular file")
        if status.st_size != len(expected):
            raise SnapshotError(f"{label} no longer has the size supplied to the entry point")
        if identity is not None and (status.st_dev, status.st_ino) != (
                identity.device, identity.inode):
            raise SnapshotError(f"{label} was replaced after it was staged")
        chunks = []
        remaining = len(expected)
        while remaining:
            block = os.read(descriptor, min(remaining, 1024 * 1024))
            if not block:
                break
            chunks.append(block)
            remaining -= len(block)
        actual = b"".join(chunks)
        if remaining or os.read(descriptor, 1) or actual != expected:
            raise SnapshotError(f"{label} no longer contains the bytes supplied to the entry point")
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass
    return _ProtectedInput(label, path, expected, status.st_dev, status.st_ino)


def _run_trial(snapshot: SourceSnapshot, entry: str, input_path: pathlib.Path, *,
               prefix: tuple[str, ...], runner, timeout: int,
               protected: tuple[tuple[str, pathlib.Path, bytes], ...] = (),
               expected_input: bytes | None = None,
               secret_env_names: tuple[str, ...] = (),
               ) -> tuple[int | None, str] | None:
    """A control execution as ``(exit, output)``, or ``None`` when execution could not finish."""
    try:
        proc = _execute_trial(snapshot, entry, input_path, _TrialExecution(
            prefix, runner, timeout, protected=protected, expected_input=expected_input,
            secret_env_names=secret_env_names,
        ))
    except (OSError, subprocess.SubprocessError):
        return None
    rendered = original_paths((proc.stdout or "") + (proc.stderr or ""), snapshot)
    return proc.returncode, redact_secrets(rendered, secret_env_names=secret_env_names)


def _run(runner, argv: list[str], repo, timeout: int, *,
         secret_env_names: tuple[str, ...] = ()) -> tuple[int | None, str] | None:
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
                      timeout=timeout, env=entry_env(secret_env_names=secret_env_names))
    except (OSError, subprocess.SubprocessError):
        return None
    # Redacted on the control side too, for `adjudicate`'s reason on the attack side: the two texts are
    # compared, so scrubbing one and not the other would make our own key look like a marker the
    # payload introduced.
    return proc.returncode, redact_secrets(
        (proc.stdout or "") + (proc.stderr or ""), secret_env_names=secret_env_names,
    )


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
    generic sentence this replaced. The maintainers' notes's trap 3, applied to a reason instead of to
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
    "CONTAINMENT_CAPABILITIES",
    "NETWORK_ISOLATION", "PID_ISOLATION", "PRIVILEGED_NETWORK_ISOLATION",
    "TIMEOUT_KILL_CODES", "TRACEBACK_TOKENS", "UNATTRIBUTED", "UNHANDLED_EXCEPTION",
    "UNMEASURED_EXPECTATIONS", "Witness", "WitnessSpec", "adjudicate", "attribute", "benign_controls",
    "containment_unavailable", "controls_digest",
    "entry_digest", "entry_env", "isolation_prefix", "network_isolated", "observed_location",
    "offered_expectations",
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
