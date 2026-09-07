# Witness entry points

A witness turns a model hypothesis into evidence. Shard supplies an input, runs your adapter and
compares the result with benign controls. The model cannot write or replace the witness it is graded
against.

This page describes the current v4 release candidate. See [Getting started](getting-started.md) for
availability and the exact source and Action revisions.

## Calling convention

Declare a repository-relative executable with `witness_entry`, usually `.shard/entry.sh`.

Shard invokes it from the repository root as:

```text
bash -- .shard/entry.sh <payload-file>
```

The payload is a file path in `$1`. Nothing is written to standard input. The witness must:

- read the file named by `$1`;
- exercise one stable target behavior;
- exit 0 and print nothing for an empty or ordinary input;
- print a precise marker for an exploitable behavior, or let a genuine fatal signal reach the process;
- avoid network access and dependence on Git metadata;
- finish within 60 seconds.

[Getting started](getting-started.md#2-add-and-validate-a-witness) includes a fail-closed creation
command that refuses to overwrite an existing entry point. The generated file is a skeleton, not an
adapter inferred from your application; edit it and test ordinary and known-failing inputs before
committing it.

## Minimal shape

```bash
#!/usr/bin/env bash
set -euo pipefail

payload="${1:?Shard passes the payload file as argument 1}"
if [[ ! -s "$payload" ]]; then
  exit 0
fi

exec python3 .shard/witness.py "$payload" 2>&1
```

The target program may use a different runtime. Keep the shell wrapper: it makes the invocation and
empty-input behavior explicit.

## Benign controls

Put one valid, non-malicious input at `<witness_entry>.benign`, or put several in a directory at that
path; the default is `.shard/entry.sh.benign`. Shard runs the candidate and controls through the same
adapter. If an ordinary input produces the same marker or failure, the candidate is refused.

At most eight controls run, selected in sorted path order. Additional files are reported but not
executed, so keep the directory at eight files or fewer and cover every normal branch you rely on.
Without a `.benign` file or directory, the only control is an empty file; that catches an adapter that
always fails, not one whose ordinary non-empty path matches the suspected defect.

## What counts as a demonstration

Shard accepts two observation classes:

- `output_marker`: a marker attributable to the candidate input and absent from benign controls;
- `fatal_signal`: the target terminates under a fatal signal attributable to the candidate input.

A plain non-zero exit is not evidence by itself. Programs routinely use non-zero exits for rejected
input. If your target exposes the defect as a handled exception or an error return, make the adapter
print a marker only on that branch.

For AddressSanitizer builds, set `export ASAN_OPTIONS=abort_on_error=1` inside `.shard/entry.sh`
immediately before it starts the target. The Action does not forward arbitrary workflow environment
variables into hostile execution. ASAN's default exit 1 is ordinary input rejection, while
`abort_on_error=1` turns a detected fault into the fatal signal Shard can evaluate.

## Build placement

See [Runtime support](reference.md#runtime-support) for what the image can run. Do not build an
unsupported target earlier in the secret-bearing Shard job: repository code can leave a process,
daemon, mount or writable descriptor alive across steps. Build in a separate no-secret job, start the
review on a fresh runner, and download—but do not execute—the expected product. The witness starts it
only after Shard establishes the execution boundary.

For `fail_on: new`, Shard runs the witness against tracked files extracted from the base revision.
Build products from an earlier workflow job are absent from that archive. A self-contained witness or
committed runnable fixture gives the strongest answer; otherwise Shard falls back to changed-line
attribution and records the limitation.

## Isolation and fidelity

Shard captures a regular-file-only source snapshot before analysis. Model-authored commands, witness
runs and controls use that snapshot inside private PID, mount, proc and network namespaces. The source
is read-only; scratch and `/tmp` are private; configured credentials and standard input are removed.
An incomplete boundary causes refusal rather than an uncontained run.

Git administration is deliberately absent. A witness whose behavior depends on `.git` is not currently
fidelity-supported. The snapshot is also not a secret scanner: credentials written into ordinary files
inside the checkout become source. Keep `.env`, `.npmrc` and similar job credentials outside the
workspace.

See [SECURITY.md](../SECURITY.md) for the complete boundary.

## Validate before a model run

Use the fail-closed sequence in
[Getting started](getting-started.md#2-add-and-validate-a-witness) to run preflight, the empty input and
every benign control. Every control must be quiet and exit 0. Then run a safe known positive and
require the intended marker or fatal signal to be stable.

Five complete adapters are in [`examples/`](../examples/): Python, Node.js, Ruby, PHP and C.

## Retain a demonstrated finding

`reproduced: true` records the originating run's contained adjudication. The retained bundle is not
independently replayable, so the documented v4 workflow remains report-only. Follow
[Finding bundles and replay](replay.md) for safe handling. Do not execute its `reproduce.sh`.
