"""A resident-memory ceiling on the subprocesses that run model-authored code.

**WHY THIS EXISTS, in the numbers that bought it.** Observed live on 2026-08-28 rather than reasoned
about — the measurement corpus is named in the maintainers' backlog, not here, because this module SHIPS IN THE
FREE ARTEFACT and that artefact is public: a developer path in it resolves for whoever reads it, and
the build refuses one. §3b: available memory went 21 GiB -> 454 MiB in under three
minutes and swap 0 -> 17 GiB of 19. One process did it.

    26.5 GiB   python3 gen3.py 100 tern              via run_bash      killed dockerd + both sweeps
    25.5 GiB   python3 -   (writing seeds/deep)      via emit_struct   caught by a memory monitor
    25.6 GiB   python3 seeds/mk_deep.py seeds/deep   via run_bash      caught by a watchdog

Three occurrences in one session through two different tools, every one a deeply-nested-input
generator — the RIGHT construction strategy for a parser stack-exhaustion bug, with no bound on the
way it is built. The kernel reaped the first one and both running sweeps with it, losing three
in-flight tasks. On a customer's CI runner that is the job dying, and on a self-hosted runner every
other job on the machine with it.

**THIS DOES NOT NARROW THE CAPABILITY, and that is the constraint the design is under.**
The design notes A6 records the honest tension that `run_bash` is why the separate capability
works. Every one of the 36 generators this product ships peaks between **8.4 and 9.7 MiB** (measured
2026-08-31, all 36 run through `construction_assets.construction_registry()`). The default ceiling is
400x the largest of them and 6x below the smallest observed failure, so it refuses only runs that
were going to fail anyway.

## Why RSS from /proc, and not the three mechanisms FINDINGS names

Measured on this host 2026-08-31, not assumed:

  * **`ulimit -v` (RLIMIT_AS) is REJECTED, and it would have broken the harness.** It caps ADDRESS
    SPACE. AddressSanitizer reserves a 0xdfff0001000-byte (~15.7 TiB) shadow mapping at startup, so a
    1 GiB address-space cap kills an ASan binary before `main` — measured rc=-6,
    `ReserveShadowMemoryRange failed while trying to map 0xdfff0001000 bytes`. The separate package
    builds every synthesized target with `-fsanitize=address` and `run_bash` invokes
    `bash test_poc.sh ./poc` in ~29% of runs, so an address-space cap does not refuse a bug, it
    refuses the harness. **RLIMIT_DATA fails identically** (since Linux 4.7 it counts private
    anonymous mappings, shadow included) — measured, same rc, same message.
  * **`systemd-run --scope -p MemoryMax=` works here and does not travel.** It killed a hog at rc=-9
    on this host with no password. It needs a systemd session; the product ships two Dockerfiles and
    neither runs systemd, so it is unavailable exactly where the customer runs.
  * **`docker run --memory` IS used, where a container exists** — the separate package's generator
    route passes it. It covers one of the four execution paths and nothing on the host.

What is left is reading RSS out of `/proc`, which is also what actually caught two of the three live
occurrences.

## Two measurements that decided the shape

**The tree, not the process.** The failure was `bash -lc 'python3 gen3.py 100 tern'`: the allocator is
the GRANDCHILD. Accounting the direct child alone would have measured bash, at ~4 MiB, and missed
every one of the three.

**The descendant walk, not a `/proc` scan.** Summing RSS over the session by scanning all of `/proc`
costs **7.615 ms/poll** on this 622-process host; walking `/proc/<pid>/task/<tid>/children` from the
root costs **0.017 ms** and returns the identical sum (60.9 MiB on the same tree). 448x, and at a
100 ms interval the difference is 7.62% of one core against 0.02%.

## What this does NOT do, stated rather than left to be discovered

  * **It is a poller, so it overshoots.** Measured against a ~3.5 GiB/s allocator on a 64 MiB cap:
    116 MiB overshoot at a 50 ms interval, 304 MiB at 100 ms, 684 MiB at 250 ms. The ceiling bounds
    the ORDER of magnitude, not the byte. That is the whole requirement — 26.5 GiB was the defect.
  * **A double-forked process reparented to init leaves the walk** and stops being accounted. The
    KILL is deliberately broader than the accounting: the child gets its own session, so the whole
    process group dies with it whether the walk saw it or not.
  * **Without `/proc` the ceiling never fires.** Every measured surface is Linux; on anything else the
    walk reads nothing, the peak stays 0, and the run proceeds exactly as it does today.
  * **It does not bound the CUSTOMER's own entry point.** `sandbox._run_entry_point` runs the
    declared entry on a model-authored INPUT, and its justification is that it is byte-for-byte what
    `witness.adjudicate` re-runs after the loop. A ceiling on one and not the other would make the
    tool lie about what the grader will see. See the design notes A6.
"""

from __future__ import annotations

import os
import signal
import subprocess
import threading

#: Megabytes a model-authored subprocess and its descendants may hold resident. 4096 sits between two
#: measured numbers rather than being chosen: the largest generator this product ships peaks at
#: 9.7 MiB, and the smallest observed host-killing run held 25.5 GiB. It also leaves a standard
#: 7 GiB GitHub-hosted runner alive while its one capped child is at the ceiling.
DEFAULT_CAP_MB = 4096

#: The one knob. A self-hosted runner with 128 GiB may legitimately want a bigger ceiling, and the
#: deterministic tests need a small one to prove the mechanism without allocating 26 GiB. Read in the
#: PARENT at call time, so a model-authored `export` inside `run_bash` cannot raise its own ceiling.
CAP_ENV = "SHARD_MEM_CAP_MB"

#: Seconds between polls. 100 ms costs 0.02% of one core with the descendant walk and overshoots a
#: ~3.5 GiB/s allocator by ~300 MiB; see the module docstring for the 50/100/250 ms measurements.
POLL_SECONDS = 0.1

try:
    _PAGE_BYTES = os.sysconf("SC_PAGE_SIZE")
except (AttributeError, ValueError, OSError):   # not POSIX; the walk below reads nothing anyway
    _PAGE_BYTES = 4096


class CappedProcess(subprocess.CompletedProcess):
    """A `CompletedProcess` whose child was killed by the ceiling rather than by its own logic.

    A SUBCLASS rather than a sentinel return code, because `run` has to stay drop-in for
    `subprocess.run` — `sandbox.build_exec_tools` takes an injectable `runner` whose fakes return a
    plain `CompletedProcess`, and those must read as "not capped" without knowing this module exists.
    """

    def __init__(self, args, returncode, stdout, stderr, *, limit_bytes: int, peak_bytes: int):
        super().__init__(args, returncode, stdout, stderr)
        self.limit_bytes = limit_bytes
        self.peak_bytes = peak_bytes


def refusal(proc) -> str | None:
    """The sentence a tool shows the agent when the ceiling fired, or None when it did not.

    **The refusal has to be legible or the ceiling makes things worse.** An agent that cannot tell "I
    was killed for memory" from "my script has a bug" rewrites the generator and runs the same
    unbounded construction again — which is precisely how §3b recurred within 20 seconds of a watchdog
    being installed. So this names the mechanism, the peak and the ceiling, and says the output is
    incomplete.

    It does NOT name `CAP_ENV`. The model cannot set a variable in our process, and a refusal that
    suggests raising a limit the reader cannot raise is the corrosive-tool shape the separate package
    measured at 56% failed calls: the agent stops reaching for the tool. The bound belongs in the
    generator, and that is what the sentence asks for.
    """
    if not isinstance(proc, CappedProcess):
        return None
    return (f"KILLED BY THE MEMORY CEILING: this command and its children reached "
            f"{proc.peak_bytes // (1024 * 1024)} MB resident, over the "
            f"{proc.limit_bytes // (1024 * 1024)} MB ceiling, and the whole process group was killed. "
            f"Your program is not broken and its output below is INCOMPLETE — it is unbounded. "
            f"Bound it: emit the sample with an explicit depth/length/repeat-count limit, or build it "
            f"incrementally to a file instead of holding it in memory.")


def cap_bytes() -> int:
    """The ceiling in bytes, from `CAP_ENV` if it names a positive integer, else `DEFAULT_CAP_MB`."""
    raw = os.environ.get(CAP_ENV, "").strip()
    if raw:
        try:
            megabytes = int(raw)
        except ValueError:
            megabytes = 0
        if megabytes > 0:
            return megabytes * 1024 * 1024
    return DEFAULT_CAP_MB * 1024 * 1024


def _rss_bytes(pid: int) -> int:
    """Resident bytes of one process. `statm` field 2 is resident pages — one small read, no parse."""
    try:
        with open(f"/proc/{pid}/statm", "rb") as handle:
            return int(handle.read().split()[1]) * _PAGE_BYTES
    except (OSError, IndexError, ValueError):
        return 0                                # exited between the walk and the read, or no /proc


def descendants(root: int) -> list[int]:
    """`root` and every process reachable from it through `/proc/<pid>/task/<tid>/children`.

    Depth-first with a seen set: a pid that exits mid-walk simply contributes nothing, and the cycle
    guard is there because the walk reads a live kernel structure, not a snapshot.
    """
    seen: set[int] = set()
    found: list[int] = []
    stack = [root]
    while stack:
        pid = stack.pop()
        if pid in seen:
            continue
        seen.add(pid)
        found.append(pid)
        try:
            tids = os.listdir(f"/proc/{pid}/task")
        except OSError:
            continue
        for tid in tids:
            try:
                with open(f"/proc/{pid}/task/{tid}/children", "rb") as handle:
                    stack.extend(int(child) for child in handle.read().split())
            except (OSError, ValueError):
                continue
    return found


def _kill_tree(root: int) -> None:
    """SIGKILL every descendant, then the whole process group.

    Both, in that order, because neither alone is enough: the walk misses a process reparented away
    from `root`, and `killpg` misses one that called `setpgid` for itself. The group kill is safe only
    because `run` starts the child in its own session — `os.getpgid(root)` on a child of OUR group
    would name our own.
    """
    for victim in descendants(root):
        try:
            os.kill(victim, signal.SIGKILL)
        except OSError:
            continue                            # already gone
    try:
        os.killpg(os.getpgid(root), signal.SIGKILL)
    except OSError:
        pass                                    # the leader exited; its group went with it


class _Watch:
    """Polls the tree's resident total and kills it on breach. Records the peak either way.

    It OWNS a thread rather than subclassing one. Subclassing cost a debugging pass: `Thread` already
    defines a private `_stop()`, so the obvious `self._stop = threading.Event()` shadowed it and every
    `join()` died on `'Event' object is not callable`.
    """

    def __init__(self, root: int, ceiling: int):
        self.root = root
        self.ceiling = ceiling
        self.peak_bytes = 0
        self._done = threading.Event()
        self._thread = threading.Thread(target=self._poll, daemon=True)

    def _poll(self) -> None:
        # `wait` rather than `sleep`: it returns the moment `stop()` fires, so a fast command does not
        # hold the interpreter open for a poll interval it has no use for.
        while not self._done.wait(POLL_SECONDS):
            total = sum(_rss_bytes(pid) for pid in descendants(self.root))
            self.peak_bytes = max(self.peak_bytes, total)
            if total > self.ceiling:
                _kill_tree(self.root)
                return

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._done.set()
        self._thread.join(timeout=2)


def _popen_kwargs(capture_output: bool, text: bool, errors: str | None, cwd, env, has_input: bool):
    """The `Popen` keywords, assembled so `errors` is passed ONLY when set.

    `Popen(errors=...)` implies TEXT mode whether or not `text` was asked for, so passing
    `errors="replace"` through unconditionally would silently decode `emit_struct`'s binary sample.
    """
    kwargs = {
        "cwd": cwd,
        "env": env,
        "stdin": subprocess.PIPE if has_input else subprocess.DEVNULL,
        "stdout": subprocess.PIPE if capture_output else None,
        "stderr": subprocess.PIPE if capture_output else None,
        # The child leads its own session, which is what makes the group kill above addressable. Its
        # consequence is closed rather than left: detached from the terminal's foreground group, a
        # command that reads a TTY would take SIGTTIN and stop, so stdin is DEVNULL unless the caller
        # supplied one. Model-authored code also stops being able to eat the operator's keystrokes.
        "start_new_session": True,
    }
    if text:
        kwargs["text"] = True
    if errors is not None:
        kwargs["errors"] = errors
    return kwargs


def run(argv, *, input=None, capture_output=False, text=False, errors=None,  # noqa: A002
        cwd=None, env=None, timeout=None, limit=None):
    """`subprocess.run` with a resident-memory ceiling over the child AND its descendants.

    Returns a `CappedProcess` when the ceiling fired — ask `refusal(proc)`, which is None otherwise —
    and a plain `CompletedProcess` when it did not. Raises `subprocess.TimeoutExpired` exactly where
    `subprocess.run` does, with the partial output attached.

    **The timeout path kills the TREE, which `subprocess.run` does not.** `subprocess.run`'s own
    timeout handler kills the direct child only, so today a `run_bash` that times out leaves the
    grandchild python still allocating — the §3b process, surviving the tool call that spawned it.
    """
    ceiling = cap_bytes() if limit is None else int(limit)
    proc = subprocess.Popen(argv, **_popen_kwargs(capture_output, text, errors, cwd, env,
                                                  input is not None))
    watch = _Watch(proc.pid, ceiling)
    watch.start()
    try:
        stdout, stderr = proc.communicate(input=input, timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill_tree(proc.pid)
        stdout, stderr = proc.communicate()
        raise subprocess.TimeoutExpired(argv, timeout, output=stdout, stderr=stderr) from None
    except BaseException:
        # KeyboardInterrupt included, and it is the reason this arm is not `except Exception`. The new
        # session means Ctrl-C at the terminal no longer reaches the child, so an unkilled child here
        # would outlive the run that owns it.
        _kill_tree(proc.pid)
        raise
    finally:
        watch.stop()
    if watch.peak_bytes > ceiling:
        return CappedProcess(argv, proc.returncode, stdout, stderr,
                             limit_bytes=ceiling, peak_bytes=watch.peak_bytes)
    return subprocess.CompletedProcess(argv, proc.returncode, stdout, stderr)


__all__ = ["CAP_ENV", "DEFAULT_CAP_MB", "POLL_SECONDS", "CappedProcess", "cap_bytes",
           "descendants", "refusal", "run"]
