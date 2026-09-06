# Examples

Five small projects, each with one real defect, each carrying the two files that decide whether
anything Shard finds can fail a build.

**Every command below runs with no API key, no model endpoint and no network.** That is deliberate:
the part of Shard people get wrong is the witness, and the witness can be checked entirely on your own
machine before any inference is involved.

| example | language | demonstrates | the defect |
|---|---|---|---|
| [`python-config-eval`](python-config-eval/) | Python | `output_marker` | a settings loader converts values with `eval` |
| [`node-path-traversal`](node-path-traversal/) | JavaScript | `output_marker` | `path.join` normalises `..`, it does not refuse it |
| [`ruby-yaml-deserialise`](ruby-yaml-deserialise/) | Ruby | `output_marker` | `YAML.unsafe_load` restores objects from untrusted text |
| [`php-template-include`](php-template-include/) | PHP | `output_marker` | `include` resolves `..`, so a template name executes a file |
| [`c-record-overflow`](c-record-overflow/) | C | `fatal_signal` | a heap buffer is sized from the file, filled from its header |

**An example skips rather than fails when its runtime is absent.** `tests/test_examples.py` checks
PATH per example, so a machine without `php` still gets a real result for the other four. The action's
container carries all five.

## What this build adjudicates

Two demonstration kinds, and picking one your build does not adjudicate is the quiet failure this
product exists to avoid:

| kind | what it means | when to reach for it |
|---|---|---|
| `output_marker` | your entry point prints a string you chose | almost always. It is the only route in most managed languages |
| `fatal_signal` | the program dies on SIGSEGV, SIGABRT, … | memory-safety work, and sanitiser builds that abort |

`nonzero_exit` and `unhandled_exception` have names in this codebase and are **deliberately not
offered**: both were measured, and each turned out to fire on programs that were simply rejecting
input as designed. If your failure mode is an exception or a non-zero exit, **print a marker on that
branch and use `output_marker`.** `shard preflight --entry-template` generates a skeleton listing
exactly what your build accepts, so it cannot drift from this table.

## Four of the five use `output_marker`, and that is the honest ratio

`fatal_signal` needs a program that dies, which in practice means memory-unsafe code or a sanitiser
build. Everywhere else you choose a marker and print it on the branch that proves the defect — so the
interesting question is never *which kind*, it is **what observation separates the defect from the
feature.** Each example answers that in its own README, and the answers are worth reading together:

| example | the naive observation that would be REFUSED | what it watches instead |
|---|---|---|
| `python-config-eval` | "eval ran" — it runs for `retries = 3` too | an import, a process, or a value that is not plain data |
| `node-path-traversal` | "the read succeeded" — that is the feature | content that exists only outside the notes directory |
| `ruby-yaml-deserialise` | "the document parsed" — every session does | an object was constructed where the format is plain data |
| `php-template-include` | "the include succeeded" — every page does | a file from outside the template root was EXECUTED |
| `c-record-overflow` | "it exited non-zero" — malformed input does that | the process died on a signal, under a sanitiser |

Every left-hand column fires on the benign inputs shipped beside it. Shard would reproduce the finding
against those controls and refuse it — which is the adjudicator working, and the single most common
reason a real entry point produces nothing that gates.

## The shape every one of them shares

```bash
bash .shard/entry.sh path/to/payload-file
```

One argument, a path to a file whose contents Shard supplies. Four rules, and the third is the one
that costs people a run:

1. **Read the payload.** A program that ignores its input cannot be evidence about it.
2. **Print nothing but the marker.** Echoing what you were given is how an entry point ends up
   demonstrating its own echo.
3. **An empty payload must take a quiet branch.** Shard runs a baseline on empty input and compares.
   An entry point that prints its marker or dies whatever it is given demonstrates nothing — the
   baseline does the same — and the run is refused. Every example here opens with the same three
   lines for exactly this reason.
4. **Declare benign inputs beside it**, in `<entry>.benign/`, one per branch your entry point can
   take. Every finding is then checked against them. Measured against a five-class Java target: with
   no benign inputs, **four fixtures containing no attack at all** produced gate-eligible findings at
   exit 0. With four declared, all four were refused and every honest finding survived.

## Starting from nothing in your own project

Use the non-overwriting creation sequence in [Getting started](../docs/getting-started.md#2-add-and-validate-a-witness).
It refuses existing and symlinked paths. After you edit the generated skeleton, check its empty input:

```bash
set -euo pipefail
bash -- .shard/entry.sh /dev/null     # must be silent and exit 0 before you go further
```

The template is a fixed skeleton with one invocation line chosen by your repository's primary
language. It is not generated from your code, and it is yours to commit — a witness the agent wrote
and is then graded against is not evidence, which is the whole reason this file is yours rather than
ours.
