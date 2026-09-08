# Reference

This reference describes the current v4 release candidate. See [Getting started](getting-started.md)
for availability and a first run; read [Witness entry points](witnesses.md) before configuring one.

## Commands

| Command | Inference | Purpose |
|---|---|---|
| `shard survey --repo PATH` | none | profile languages, build shape and likely blind spots |
| `shard preflight --repo PATH` | none by default | validate repository, witness, visibility and local runtime readiness |
| `shard preflight --entry-template` | none | print a witness skeleton to standard output |
| `shard preflight --probe-endpoint …` | one probe turn; retries possible | validate SSE framing, tool calls and served model identity |
| `shard diff --repo PATH --base-ref REF …` | yes | review the diff and adjudicate proposed findings |
| `shard action` | depends on `INPUT_MODE` | entry point used by the GitHub Action container |

Run `shard <command> --help` for the full CLI. The free image does not expose `deep`, `mirror` or
`fix`.

## GitHub Action inputs

Input names use underscores.

| Input | Default | Meaning |
|---|---|---|
| `mode` | `diff` | `survey` or `diff` in the free image |
| `model_endpoint` | unset → OpenRouter | OpenAI-compatible chat-completions base URL; refused by `survey` |
| `model` | `glm-5.2` | identifier; custom endpoints receive it unchanged |
| `api_key_env` | `OPENROUTER_API_KEY` | name of the environment variable containing the endpoint key |
| `max_spend_usd` | `10` | observed-cost ceiling; 0 disables it |
| `max_minutes` | `60` | wall-clock ceiling; 0 disables it |
| `max_tokens` | `0` | explicit token ceiling; 0 means no token ceiling in diff mode |
| `scan` | unset | budget profile (`initial` or `followup`), not scope |
| `max_steps` | `40` | maximum diff-review turns; 0 is invalid |
| `hunk_radius` | unset → `40` | attention window around changed lines; 0 uses whole changed files |
| `witness_entry` | unset | repository-relative executable used to demonstrate findings |
| `base_ref` | `HEAD~1` | revision the change is compared with |
| `state_repo` | unset | optional checked-out repository for cross-run state |
| `slug` | inferred | `owner/name` attributed in reports and delivery |
| `fail_on` | `none` | `none`, `reproduced` or `new` |
| `out_dir` | `shard-out` | fresh workspace-relative output directory; components use ASCII letters, digits, dot, underscore or hyphen; no traversal, symlinks or existing content; one directory per Shard step |
| `github_token` | unset | enables pull-request comments and SARIF delivery when permissions allow |

Inputs irrelevant to a mode are either refused or explicitly inert. In particular, `preflight` is a
CLI command, not a valid Action mode.

## Checkout and diff scope

Use `fetch-depth: 0` when passing a base revision. A depth-1 checkout cannot resolve `HEAD~1`; the
result is `no changed files in scope`, which is a successful process that reviewed nothing.

On a normal `pull_request` merge checkout, `github.event.pull_request.base.sha` is a valid base. On a
manually checked out head branch, prefer the merge base when the base branch may have moved:

```bash
set -euo pipefail
TARGET_BRANCH='replace-with-reviewed-target-branch'
git check-ref-format --branch "$TARGET_BRANCH" >/dev/null
git fetch --no-tags origin \
  "+refs/heads/${TARGET_BRANCH}:refs/remotes/origin/${TARGET_BRANCH}"
BASE_SHA="$(git merge-base "refs/remotes/origin/${TARGET_BRANCH}" HEAD)"
git cat-file -e "$BASE_SHA^{commit}"
```

Shard uses a three-dot diff and records any fallback or scope limitation in the result.

## Gate values

| `fail_on` | Build behavior |
|---|---|
| `none` | always report-only; findings cannot make the step exit 1 |
| `reproduced` | exit 1 when at least one finding has a demonstration |
| `new` | exit 1 when a demonstrated defect is attributed to this change |

During the originating run, `new` first tries the input against the base revision. If that base cannot
run, Shard falls back to changed-line attribution and records the reduced confidence. Hypotheses never
gate under any value.

These values describe engine behavior. The documented v4 candidate remains `fail_on: none` because no
trusted independent replay path ships; do not enable either gate from the release-candidate journey.

## Outputs and files

| Action output | File or value |
|---|---|
| `status` | `done`, `error`, `budget`, `maxsteps` or `repeat` |
| `findings` | number of findings emitted |
| `gate-eligible` | number of demonstrated findings; `new` attribution is recorded in the result |
| `sarif-path` | absolute path to the validated SARIF snapshot; empty for survey |
| `report-path` | absolute path to the validated Markdown snapshot |
| `bundle-path` | absolute path to validated finding bundles; empty when no bundle was written |
| `result-path` | absolute path to the validated machine result; empty for survey |
| `telemetry-path` | absolute path to validated telemetry, when written |
| `log-path` | absolute path to the validated run log, when written |

Action path outputs point into a private directory below the runner's temporary root and remain valid
for later job steps. The CLI also writes mutable copies under `out_dir`: diff writes the report, result,
SARIF, optional telemetry and log, and `bundles/`; survey writes the report and profile. Upload only the
named Action paths, never the whole checkout output directory.

### Source inspection

Every diff run reports which of the files in scope it actually read. The Markdown report carries a
**Source inspection** section and `shard-result.json` carries the same data under `inspection`.

The heading line reads `N of M scoped file(s) returned source; K with no source recorded`, followed by
a per-file table: the path, whether **full**, **partial** or **no** source was returned, the line
ranges that reached the model, the diff context ranges, and any other activity against that file.

In `shard-result.json`, `inspection` carries `scope_files`, `files_with_source`,
`files_fully_returned`, `files_partially_returned`, `files_without_source`, `observed_lines`, a
`files` array with `observed_ranges` per path, and counters including `read_calls`, `failed_reads`,
`clamped_reads`, `partial_line_reads`, `search_calls` and `unscoped_reads`.

Read it as an observation, not as coverage. The block carries its own `measurement` string saying so:
returned source is what reached the conversation, not proof the model analysed it; clamped reads
contribute no ranges, so the counts are lower bounds; and search results, shell output and directory
listings establish no line coverage at all. A run that read 1 of 3 scoped files and reported nothing
is a different result from one that read all three, and this block is how you tell them apart.

A bundle can hold either a demonstrated input or a refused candidate; read `reproduced` in
`metadata.json`. `done` is the only completed-review status. `budget`, `maxsteps` and `repeat` are
incomplete; `error` means the review failed.

Reports, results, SARIF and bundles can contain source-derived data. Telemetry and the run log contain
counts, timings and gaps without tool arguments, tool output, source or model prose. The private event
journal can contain model reasoning and source-derived tool results. Direct CLI users retain it only by
setting `shard diff --journal-path` to a private path outside `--out-dir`; otherwise Shard consumes it
for redacted outputs and deletes it on successful and error exits. The Action exposes no journal path.

## Limits and cost

Diff mode has four independent controls: `max_spend_usd`, `max_minutes`, `max_tokens` and `max_steps`.
Zero disables the first three; `max_steps` must be positive. When an endpoint reports no dollar price,
use `max_spend_usd: 0` and rely on time, steps and calibrated tokens.

A positive dollar cap follows endpoint-reported cost. It cannot predict the first request or a later
price change and is not provider-side hard enforcement. Request counts include every endpoint attempt;
`abandoned_requests` identifies attempts whose token and price totals could not be recovered, so the
reported totals remain a floor. Usage varies by endpoint, repository and run; start report-only and set
limits from your own completed reviews.

### What a run costs

You supply the model, so your model bill is the price. Every pull-request run this project has
metered:

| changed files | changed lines | size of files touched | cost | tokens |
|---|---|---|---|---|
| 1 | 12 | 2,800 | $0.022 | 21,184 |
| 1 | 1 | 2,900 | $0.026 | 50,547 |
| 3 | 48 | 120,000 | $0.030 | 97,852 |
| 3 | 48 | 120,000 | $0.045 | 131,410 |
| 3 | 82 | 190,000 | **$0.507** | 786,563 |

Five points is a small sample, quoted as a range rather than a formula. Cost tracks the size of the
files touched more closely than the size of the change: 82 lines cost seventeen times what 48 lines
did, against files 58% larger. Do not plan against the high end of that table — it is not the high
end that has happened.

**Read the dollar range as a FLOOR**, because those runs did not exercise command execution. Five
later runs widened the measured band to 21,184–1,544,464 tokens, a median 7.9x the earlier sample.
A first whole-repository survey is a different job again and measured far above this band. `shard preflight`
estimates against your own repository's file sizes before you spend anything, and says which of the
two jobs it is quoting. Your endpoint, repository and diff determine the actual result; size your
limits from your own completed report-only runs.

## Runtime support

| In the image | Not in the image |
|---|---|
| Python 3, Bash, Git, Node.js 22, Ruby and PHP CLI | Go, Rust and Swift |
| headless JRE | JDK |
| .NET 8 runtime | .NET SDK |
| GCC, G++ and libc headers | other unlisted toolchains |

Preflight reports the environment in which it runs: a local install reports local runtimes, while an
image run reports image runtimes. Action survey has no runtime inventory. Read
[Build placement](witnesses.md#build-placement) before supplying a generated product.

## CLI exit codes

| Code | Meaning |
|---|---|
| **0** | no configured gate matched; report-only and some incomplete runs also use 0, so inspect `status` |
| **1** | a demonstrated finding matched `--fail-on` |
| **2** | invalid configuration or failure to perform the requested review |

Exit 1 alone means a security gate matched. Under `fail_on: none`, a revoked key or unreachable
endpoint can return 0 with `status: error`; under `reproduced` or `new`, that failed review returns 2.
Always inspect `status` or `shard-result.json` before treating a run as complete.

No supported non-GitHub CI integration ships; see [Other CI systems](other-ci.md). An exit code does not
supply the missing CI identity, output or trust guarantees.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| API-key error, exit 2 | the variable named by `api_key_env` is empty | pass the secret through `env`, not `with` |
| `no changed files in scope` | the checkout lacks the base revision | use `fetch-depth: 0` and a resolvable base |
| findings but `gate-eligible: 0` | no witness or no stable demonstration | declare and validate a witness |
| ordinary inputs reproduce the marker | the witness is too broad | add benign controls and narrow the marker |
| endpoint probe is `unsupported`, including after HTTP 200 | stream, tool-call or model identity failed, or the model was substituted | inspect `why` and `observed`; correct the server or model |
| witness exits 127 | a runtime or build tool is absent | build earlier and run the artefact |
| status is `budget`, `maxsteps` or `repeat` | the review ended before completion | adjust the named limit only after checking telemetry |
| no comment or code-scanning alert | token/input/permission missing | pass `github_token`; grant `pull-requests: write` and `security-events: write` |

For a bug report, include the version, command or workflow with secrets removed, `shard-result.json`,
and `shard-run.log`. Inspect every file before sharing it because findings can contain source excerpts.
