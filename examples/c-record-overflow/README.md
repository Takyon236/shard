# Example — a C record reader that trusts a declared length

**What it demonstrates:** `fatal_signal`, via AddressSanitizer.

**The defect:** `record.c` sizes its heap buffer from what the file actually holds and then copies as
many bytes as the file's header *claims*. Those two numbers agree in every well-formed record, which
is why this shape survives review — every fixture written by hand agrees with itself.

## Run it by hand first

```bash
cd examples/c-record-overflow

bash .shard/entry.sh /dev/null                            # silent, exit 0   <- the baseline
bash .shard/entry.sh .shard/entry.sh.benign/short.rec     # silent, exit 0
bash .shard/entry.sh .shard/entry.sh.benign/rejected.rec  # silent, exit 0

printf '400\nhi\n' > /tmp/attack.rec
bash .shard/entry.sh /tmp/attack.rec                      # AddressSanitizer: heap-buffer-overflow
echo $?                                                   # 134 — SIGABRT
```

`134` is `128 + 6`: the shell's way of saying the process died on signal 6, `SIGABRT`. That is the
observation `fatal_signal` names, and it is why the entry point sets `ASAN_OPTIONS=abort_on_error=1`.

## The one line that decides whether this gates anything

```bash
export ASAN_OPTIONS=abort_on_error=1
```

**Without it, ASAN prints its report and calls `exit(1)`** — and an exit status of 1 is
indistinguishable from the program rejecting malformed input. This build adjudicates `fatal_signal`
and `output_marker`; a plain non-zero exit is measured and deliberately not among them. So a real,
correctly detected memory-safety defect would produce a run where every finding stayed a hypothesis
and nothing explained why.

## Building inside the entry point is the exception here, not the pattern

This container carries `gcc` and `g++`, so a small self-contained witness like this one can compile
itself. Anything with a real build belongs in an earlier workflow step: there is **no JDK and no .NET
SDK** in the image, only a JRE and the .NET runtime, and a build that cannot run fails *quietly* —
the review completes, nothing gates, and nothing says why. `shard preflight` names the runtimes your
repository needs and does not find, before you spend anything.

## Then point Shard at it

```bash
shard survey --repo examples/c-record-overflow --out-dir /tmp/shard-out
shard preflight --repo examples/c-record-overflow --witness-entry .shard/entry.sh
```
