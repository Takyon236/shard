# Example — a Python settings loader that evaluates its input

**What it demonstrates:** `output_marker`, the demonstration kind most languages reach for.

**The defect:** `settings.py` converts values with `eval` so that `retries = 3` arrives as an integer.
That also runs anything else the file contains.

## Run it by hand first

You do not need Shard, a key, or a model to check that this entry point is sound — and checking it is
the single most useful thing you can do before wiring one up in your own project.

```bash
cd examples/python-config-eval

bash .shard/entry.sh /dev/null                              # silent, exit 0   <- the baseline
bash .shard/entry.sh .shard/entry.sh.benign/ordinary.conf   # silent, exit 0
bash .shard/entry.sh .shard/entry.sh.benign/malformed.conf  # silent, exit 0

printf 'x = __import__("os")\n' > /tmp/attack.conf
bash .shard/entry.sh /tmp/attack.conf                       # SHARD_SETTINGS_ARBITRARY_CODE
```

**Those five lines are the whole contract.** An entry point that prints its marker on the first three
demonstrates nothing, because Shard's baseline run and its benign controls produce the same output —
and a finding built on it is refused rather than reported. Getting this right is what separates a
finding that fails a build from one that stays a hypothesis.

## Then point Shard at it

`survey` needs no key, no endpoint and no network:

```bash
shard survey --repo examples/python-config-eval --out-dir /tmp/shard-out
```

`preflight` tells you what a review would need and what it would cost, and — because this directory
declares an entry point — that something here can actually gate a build:

```bash
shard preflight --repo examples/python-config-eval --witness-entry .shard/entry.sh
```

A full `diff` review needs a model endpoint and a key. See the repository README.

## The two decisions worth copying

**The marker is not "eval ran".** `settings.load` evaluates every value, so an entry point watching for
evaluation would fire on `retries = 3` exactly as loudly as on an attack — and every benign input
beside it would reproduce the finding, so Shard would refuse it. `.shard/witness.py` watches for what
an attack ACHIEVES and ordinary settings never do: an import, a process, a socket.

**Nothing but the marker is printed.** The parsed settings are never echoed. An entry point that prints
what it was given will eventually "demonstrate" a defect that is only its own echo.
