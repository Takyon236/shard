# Shard

Security analysis that runs in your CI, on a model endpoint you control, and reports a finding only when
it can attach a reproducing input.

> **Licensed under [BUSL 1.1](LICENSE).** **Free forever on public repositories**, at any scale, for
> any organisation. On private repositories it is free while you are under **$5M revenue and 10
> contributing developers**; above either, a commercial licence applies. Your own code, config and
> findings are never covered by anything here. You supply your own model inference; this project
> operates no endpoint and receives none of your code.

## Quickstart — five minutes, no API key

Two of the three modes need no model, no endpoint, no secret and no network. Start there, because they
answer the two questions worth answering before you spend anything: *what is in this repository*, and
*could a finding here ever fail my build*.

```bash
git clone https://github.com/Takyon236/shard && cd shard
python3 -m venv .venv && . .venv/bin/activate
pip install -e .

shard --help
```

**Survey your own project.** No inference; it reads the tree and reports what it is and where the
attack surface sits.

```bash
shard survey --repo /path/to/your/project --out-dir ./shard-out
cat shard-out/shard-report.md
```

**Then ask what a review would need.** `preflight` profiles the repository, estimates what a run
costs, names any language runtime your entry point would need and this image does not carry, and —
the one that surprises people — says whether anything here could gate a build at all.

```bash
shard preflight --repo /path/to/your/project
shard preflight --repo /path/to/your/project --json | less
```

**Then write the file that makes findings provable.** Shard reports a defect it cannot demonstrate as
a hypothesis, and a hypothesis never fails a build. The demonstration runs an entry point *you*
declare, and the product will write you a correct skeleton for it:

```bash
cd /path/to/your/project
mkdir -p .shard
shard preflight --repo . --entry-template > .shard/entry.sh
bash .shard/entry.sh /dev/null        # must be SILENT and exit 0 before you go further
```

**Then see a finished one working**, with a real defect and real benign controls, in
[`examples/`](examples/) — five small projects that need no key either. Back in the Shard checkout:

```bash
cd examples/python-config-eval
bash .shard/entry.sh .shard/entry.sh.benign/ordinary.conf   # silent: an ordinary input
printf 'x = __import__("os")\n' > /tmp/attack.conf
bash .shard/entry.sh /tmp/attack.conf                       # SHARD_SETTINGS_ARBITRARY_CODE
```

A key is needed only for `diff` — the pull-request review — which is the [Usage](#usage) section
below. Everything above it is free in both senses.

## What makes it different

**It runs inside your perimeter.** A CI runner is your infrastructure. Your source code, your binaries
and your traffic do not leave it. There is no clause to read carefully, because there is no transfer to
describe.

**It runs on open weights you control.** A self-hosted vLLM, Ollama or TGI endpoint on your own
hardware, or a managed one in your own cloud account. You can inspect the model, pin it to a version,
and hold it there for as long as your validation requires. You supply the inference on every tier,
including this one — see [which endpoints work](#which-endpoints-work) for exactly what that means.

**Findings carry proof.** The agent proposes and an oracle adjudicates, independently of the model's
opinion — the declared entry point ran with the reported input and something observable happened, or it
did not. The agent cannot promote its own guess to a finding. Every reported finding ships a
reproduction bundle: the input, the exact command, and the revision it was produced against.

**The build never fails on an unreproduced finding**, whatever you configure. Hypotheses without a
reproduction are informational and cannot gate anything.

## The two files you declare

Both live beside each other, and the second is the one people skip.

| path | what it is |
|---|---|
| `.shard/entry.sh` | a runnable entry point. Shard gives it an input and observes what happens. Without it, nothing can gate — every finding stays informational |
| `.shard/entry.sh.benign/` | ordinary, non-malicious inputs — **one per branch your entry point can take.** Every finding is checked against them |

**Without an entry point, Shard reports and cannot prove.** This is the single largest determinant of
what you get out of a run, and it is worth being blunt about: on a repository that declared one, a real
run reported four findings, reproduced one by execution, and failed the build on it. On a repository
that declared none, the same analysis produced candidates that nothing could promote past a hypothesis.

**If you set `fail-on: new`, make the entry point self-contained.** To decide whether *this* pull
request introduced a defect, Shard extracts your repository as it was at the base revision and re-runs
the same reproducing input against it — the answer is about your program, not about your diff, so it
covers a silent exploit that produced no stack trace and a defect a deletion introduced, neither of
which appears anywhere in the diff. That extraction carries tracked files only, so an entry point
needing a binary an earlier step built cannot start there; Shard then falls back to the diff and says
so, rather than blaming the author for code they did not touch.

**Why the benign inputs matter more than they look.** Without them the only control is an *empty*
input, and an empty input takes a different branch through almost any program — so anything your
program prints on real input looks like something the finding caused. Measured against a five-class
Java target: **four fixtures containing no attack at all produced gate-eligible findings and exit 0.**
With four benign inputs declared, all four were refused and every honest finding survived.

A run made without a benign control says so in the finding itself, so this is a limit you can see
rather than one you have to already know about.

### What one actually looks like

Shard runs `bash -- .shard/entry.sh <payload-file>` and supplies the payload's contents. It never
writes this file: a witness the agent authored and is then graded against is not evidence, which is
why this is yours to commit.

```bash
#!/usr/bin/env bash
set -u
PAYLOAD="${1:-/dev/null}"

# THE BASELINE BRANCH, and it is the part people leave out. Shard runs your entry point on an empty
# payload and compares. A script that prints its marker or dies whatever it is given demonstrates
# nothing — the baseline does the same — and the finding is refused.
if [ ! -s "$PAYLOAD" ]; then
  exit 0
fi

exec python3 .shard/witness.py "$PAYLOAD" 2>&1
```

Four rules, and the third is the one that costs a run:

1. **Read the payload.** A program that ignores its input cannot be evidence about it.
2. **Print nothing but your marker.** Echoing what you were given is how an entry point ends up
   demonstrating its own echo.
3. **Empty input must be quiet** — the branch above.
4. **Put benign inputs in `.shard/entry.sh.benign/`**, one per branch your entry point can take.

**Two things happen to your entry point that are worth knowing before you write one.**

*Its output is scrubbed of our credentials before anything reads it.* The container hands your script
an environment with the API key and every `INPUT_*` value removed — but it runs as root beside us, so
`/proc/1/environ` still holds them, and its output is published back to whoever opened the pull
request. Any value we hold is therefore replaced with `[redacted]` in the captured text, on the
attack run and on every benign control alike. A marker that happens to contain one will not
demonstrate, which is the correct answer to a finding whose evidence is our own key.

*It may run without a network.* Where the kernel grants it — a self-hosted runner with
`CAP_SYS_ADMIN` — your entry point and its controls run inside a network namespace with no egress, the
same treatment the review agent's own shell has always had. On a standard GitHub-hosted runner Docker
grants no such capability, nothing is isolated, and the run says so in its report. **Build in an
earlier step**, which this page already advises for a different reason: an entry point that fetches
something at witness time is one whose behaviour depends on which runner you happen to be on.

**Two demonstration kinds are adjudicated**, and choosing one this build does not adjudicate is a
quiet failure rather than an error:

| kind | what it means | when to reach for it |
|---|---|---|
| `output_marker` | your entry point prints a string you chose | almost always; the only route in most managed languages |
| `fatal_signal` | the program dies on SIGSEGV, SIGABRT, … | memory safety, and sanitiser builds that abort |

`nonzero_exit` and `unhandled_exception` have names in this codebase and are **deliberately not
offered**: both were measured, and each fired on programs that were merely rejecting input as
designed. **If your failure mode is an exception or a non-zero exit, print a marker on that branch and
use `output_marker`.** The template `shard preflight --entry-template` generates lists exactly what
your build accepts, so it cannot drift from this table.

Five complete, runnable examples — covering both adjudicated kinds — are in
[`examples/`](examples/).

## What this image does

| mode | what it is for | inference |
|---|---|---|
| `survey` | what this codebase is and where the attack surface sits. The mode to run first | none — free to run |
| `diff` | review a pull request and gate on what it introduced | yes, on your endpoint |
| `preflight` | profile a repository and estimate what a run will cost, before you buy one | none |

Every run writes a human-readable report, and every mode writes the same `shard-report.md`, so a
workflow that consumes `report-path` does not branch on the mode. Reports open with a fixed header —
**verdict** first, **trust** second — because the two questions a reader arrives with are *was anything
found* and *did this run actually finish*. A run that was cut off at a ceiling says so there, rather
than rendering like a clean result.

### Which languages can be GATED, which is not the same as which can be read

Proving a finding means running your entry point, and that happens inside this image. A language whose
runtime is not here can be reviewed and can never fail a build, because a finding without a
demonstration never gates by design.

| | can be demonstrated here | ground truth |
|---|---|---|
| Python | **yes** — `python3` | `canary-py`, 4 of 4 planted classes gate |
| JavaScript · TypeScript | **yes** — `node` 22 | `canary-js`, 5 of 5 |
| Java · Kotlin · Scala | **yes** — a headless JRE | `canary-java`, 5 of 5 |
| Ruby | **yes** — `ruby` | `canary-ruby`, 3 of 3 |
| PHP | **yes** — `php-cli` | `canary-php`, 3 of 3 |
| C# | **yes** — the .NET 8 runtime | `canary-cs`, 3 of 3 |
| C · C++ | **yes** — `gcc` / `g++` | `canary`, 3 of 3, under AddressSanitizer |

Those are **26 of 26**: executions of this product's own adjudicator inside this image against planted
defects, not estimates. Before the runtimes were added the same measurement was **4 of 14** across the
three canaries that existed; the four new ones were written to make the rest of the claim testable at
all, because a runtime with no canary is a claim nobody has checked.

**The corpus these were measured against is NOT public, and that is stated here rather than left for a
reader to discover.** The seven canaries live in a separate reference harness that has not been
published, so the number above is reproducible by us and not yet by you. Publishing that harness is an
outward-facing decision nobody has taken; until it is, treat 26 of 26 as a vendor measurement with its
instrument named rather than as something you can check. What you can check today is your own
repository — `shard preflight` reports which of these runtimes your entry point needs and whether this
image carries them, before you spend anything.

**Two of them run an artefact your build produces, rather than compiling it.** The image carries the
**.NET runtime and a JRE**, not the SDK or a JDK — 69 MB against 564 for .NET alone — so a C# or Java
entry point should run the assembly your existing build step already emits, exactly as `canary-cs` runs
a committed DLL. C and C++ are the exception: `gcc` is here, so an entry point that compiles works too.

**`shard preflight` answers this for your repository before you spend anything**, and if it prints
nothing about runtimes, everything your repository needs was found.

**The image is 934 MB, and about 810 MB of that is those runtimes.** A deliberate trade: one layer pull
per runner against a language that could otherwise never fail a build.

## Usage

**A COMPLETE workflow, and completeness is the point.** Showing the scan step alone produces a run
whose findings nobody can see: the report and the reproduction bundles are written into a directory on
a runner that is destroyed when the job ends.

```yaml
name: shard
on: pull_request

# EVERY LINE OF THIS BLOCK IS LOAD-BEARING, and without it the run still works and still gates while
# producing nothing anybody sees. Each permission buys exactly one delivery surface, and Shard says
# in the log which one it could not use rather than skipping quietly.
permissions:
  contents: read             # actions/checkout
  security-events: write     # the SARIF becomes code-scanning alerts, in the Security tab
  pull-requests: write       # the report becomes ONE comment, edited in place on every push

jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      # THE CHECKOUT DEPTH IS PART OF THE CONFIGURATION, not boilerplate above it. `actions/checkout`
      # defaults to fetch-depth: 1 — one commit — so nothing Shard can be asked to diff against
      # exists, and the run reports "no changed files in scope" and exits 0. That is a GREEN CHECK
      # THAT REVIEWED NOTHING, and a green check is what most people look at.
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0    # `2` also works, but ONLY with base_ref left at its default `HEAD~1`:
                            # a `pull_request.base.sha` that has moved is outside a shallow window

      - uses: Takyon236/shard@v2
        env:
          # THE SECRET ITSELF, and the only place it appears. Shard never takes it as an input, so it
          # cannot reach an argv, a log line or the action manifest.
          OPENROUTER_API_KEY: ${{ secrets.OPENROUTER_API_KEY }}
        with:
          mode: diff
          # What turns a finished run into something a human sees. Leave it out and the run is still
          # correct and still gates — it simply produces no alerts and no comment, and says so.
          github_token: ${{ secrets.GITHUB_TOKEN }}
          api_key_env: OPENROUTER_API_KEY   # only the NAME of the variable, and this is the default
          model_endpoint: https://vllm.internal/v1   # an OpenAI-compatible URL
          max_spend_usd: 10
          fail_on: none                # gating is opt-in

      # THE REPRODUCTION BUNDLE IS THE DISTINGUISHING ARTEFACT and it dies with the runner unless
      # something keeps it. `if: always()` because the run you most want the input from is the one
      # that just failed your build.
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: shard-evidence
          path: shard-out/
          if-no-files-found: warn
```

**If you would rather upload the SARIF yourself**, leave `github_token` out and pass the action's
`sarif-path` output to `github/codeql-action/upload-sarif`. It is the same API; the built-in upload
exists so that installing Shard stays one step.

Every run also writes its report to `$GITHUB_STEP_SUMMARY`, which needs **no** token and no
permission — so even a workflow with none of the above is legible on the job page.

Store the secret once under **Settings → Secrets and variables → Actions**. GitHub injects a step's
`env:` into the container, and Shard looks the name up in its environment.

### Reviewing a pull request from a fork

**On a fork's pull request there is no secret**, and that is GitHub's rule rather than ours: secrets are
withheld from `pull_request` runs originating in a fork. Stated as a product fact rather than a
footnote: **out of the box, this tier cannot review outside contributions to an open-source project.**
It works on branch pull requests from people who already have write access — and a maintainer catching
a drive-by contribution from a stranger, the case with the most security value, is precisely the
excluded one.

There is no fully clean answer. There are two honest partial ones, and **`workflow_run` is the one to
reach for.** Pick one deliberately rather than discovering the gap on the pull request that mattered.

**Recommended — `workflow_run`.** A second workflow triggered by the completion of the pull request's
own build. It runs in the **base** repository's context, so the secret is available, and the fork's
code is analysed as data rather than executed as a trusted step. Two things it needs, neither optional:

**Shard writes this file for you**, because three lines in it are load-bearing and a copy-paste error
in any of the three produces a green check that reviewed nothing rather than an error:

```bash
shard preflight --fork-workflow > .github/workflows/shard-fork.yml
```

```yaml
name: shard-fork
on:
  workflow_run:
    workflows: [ci]          # the fork-triggered build whose completion this waits for
    types: [completed]

permissions:
  contents: read
  security-events: write
  pull-requests: write

jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      # CHECK OUT THE FORK'S HEAD EXPLICITLY. `workflow_run` starts on the BASE branch, so without a
      # ref this reviews your own code and reports a clean result for a pull request nobody read —
      # the green-check-that-reviewed-nothing this product refuses everywhere else.
      - uses: actions/checkout@v4
        with:
          repository: ${{ github.event.workflow_run.head_repository.full_name }}
          ref: ${{ github.event.workflow_run.head_sha }}
          fetch-depth: 0
          persist-credentials: false

      - uses: Takyon236/shard@v2
        env:
          OPENROUTER_API_KEY: ${{ secrets.OPENROUTER_API_KEY }}
        with:
          mode: diff
          github_token: ${{ secrets.GITHUB_TOKEN }}
          base_ref: ${{ github.event.workflow_run.head_branch }}
          # THE TARGET IS THE FORK. Without this the report and the alerts name YOUR repository for a
          # review of somebody else's code — which is why the SARIF upload refuses outright when the
          # reviewed repository is not the token's.
          slug: ${{ github.event.workflow_run.head_repository.full_name }}
```

**The care this needs, stated plainly:** a witness entry point *does* execute code from the fork. That
is true of Shard on any input, but a `workflow_run` job holds a token the `pull_request` job did not —
so treat `witness_entry` on fork pull requests as a decision, not a default.

**The alternative — `pull_request_target`.** It runs with secrets against the base repository while a
fork controls the code under review. It is the pattern the ecosystem uses and it is a genuine footgun
without both of these: `permissions:` locked to the minimum, and a required-approval environment gate
so a maintainer sees the diff before anything runs.

See [`action.yml`](action.yml) for the full interface. It sits at the repository root beside the
[`Dockerfile`](Dockerfile) deliberately — **this repository is the action**, and GitHub resolves a
container action's image and build context relative to the metadata file, so neither may move into a
subdirectory. Point `model_endpoint` at an OpenAI-compatible base URL — see
[which endpoints work](#which-endpoints-work).

## Which endpoints work

**One rule: an OpenAI-compatible `/chat/completions` that supports native tool calling.** That is not
a preference — the agent proposes findings through tool calls, and an endpoint without them completes
a run and finds nothing. `shard preflight --probe-endpoint` spends one request establishing this and
refuses a bad endpoint rather than letting you pay for an empty review.

| endpoint | works | what to know |
|---|---|---|
| **vLLM, Ollama, TGI, llama.cpp** | yes | the guaranteed-residency path: your hardware, your weights, no third party in the request |
| **OpenRouter** | yes | the default `api_key_env`. Verified end to end on `glm-5.3` |
| **Google Vertex AI** | yes, via its OpenAI-compatible path | `…/endpoints/openapi/chat/completions`. The bearer token is a short-lived OAuth token, so mint it in the step before the scan |
| **Azure OpenAI / SageMaker** | yes, shape-wise | both expose OpenAI-compatible routes; SageMaker does so when serving through vLLM or TGI |
| **AWS Bedrock, natively** | **no** | Bedrock speaks SigV4 and its own request shape, not OpenAI's. Put a gateway in front of it — LiteLLM or the Bedrock Access Gateway — and point `model_endpoint` at that |

**`model_endpoint: bedrock` and `model_endpoint: vertex` are refused by name**, deliberately: those
are adapter names for work that has not landed, and accepting them would produce a confusing failure
instead of a configuration error. Pass a URL.

**Only the first two rows have been executed by us.** The rest are the same OpenAI-compatible contract
and are expected to work, and expected is not measured — so they are listed as a shape rather than as
a result. If you run one, a note in an issue is genuinely useful.

## Running it outside GitHub Actions

`action.yml` is GitHub-specific. **The product is not.** It is a container with a command-line
interface, and the action is a thin mapping from `INPUT_*` environment variables onto that CLI — so any
CI that can run a container can run Shard, and the only GitHub-specific parts are the two delivery
surfaces (code-scanning alerts and the pull-request comment), which such a run simply does not use.

The image is published for each release. Pull it rather than building it:

```bash
docker pull ghcr.io/takyon236/shard:v2
```

Then drive the CLI directly. Nothing below needs a GitHub token:

```bash
docker run --rm \
  -v "$PWD:/src" -w /src \
  -e OPENROUTER_API_KEY \
  ghcr.io/takyon236/shard:v2 \
    diff --repo /src --base-ref "$BASE_SHA" \
         --witness-entry .shard/entry.sh \
         --model-endpoint https://your-endpoint/v1 \
         --fail-on reproduced \
         --out-dir /src/shard-out
```

The exit code is the gate: **0** passes, **non-zero** means a demonstrated finding matched your
`--fail-on` rule. That is the whole integration contract — everything else is reading `shard-out/`.

| platform | what to know |
|---|---|
| **GitLab CI** | run it as the job `image:`, or `docker run` in a `script:`. `CI_MERGE_REQUEST_DIFF_BASE_SHA` is your `--base-ref`. Fetch depth matters here too: set `GIT_DEPTH: 0` |
| **Jenkins** | `docker.image('ghcr.io/takyon236/shard:v2').inside { … }`, or a plain `sh 'docker run …'`. Archive `shard-out/` as a build artefact |
| **AWS CodeBuild** | works in a standard Linux image with privileged mode off — Shard runs your entry point, it does not build containers. Pull from ghcr; no ECR mirror is needed unless your policy requires one |
| **Google Cloud Build** | a `name: ghcr.io/takyon236/shard:v2` step with `args:` as above. Cloud Build mounts `/workspace`, so use `--repo /workspace` |
| **anything else** | if it runs a container and can set an environment variable, it works. The CLI is the whole surface |

**Two things a non-GitHub run does not get, and it is better to know now**: the SARIF is still written
to `shard-out/`, but nothing uploads it to a code-scanning UI, and there is no pull-request comment.
Both are GitHub APIs. The report, the SARIF and the reproduction bundles are ordinary files — publish
them wherever your platform keeps artefacts.

## What a run costs

You supply the inference, so your model bill *is* the price. Every pull-request run this project has
metered:

| changed files | changed lines | bytes in the files touched | cost | tokens |
|---|---|---|---|---|
| 1 | 12 | 2,800 | $0.022 | 21,184 |
| 1 | 1 | 2,900 | $0.026 | 50,547 |
| 3 | 48 | 120,000 | $0.030 | 97,852 |
| 3 | 48 | 120,000 | $0.045 | 131,410 |
| 3 | 82 | 190,000 | **$0.507** | 786,563 |

**Five points is a small sample, not a corpus**, and it is quoted as a range rather than a formula
because a regression on five points would be two decimal places of false precision on the one number
you plan against. Plan against the high end: it is the one that has happened.

**Cost does not track the size of the change.** 82 lines of markdown cost seventeen times what 48
lines of a real library diff cost. What separates them is the size of the *files* the change touches —
the agent reads changed files, and context accumulates across turns, so a large file read early is
paid for again in every turn after it. Stated as the leading hypothesis rather than a model.

Wall clock is minutes to about fifteen on a small diff; 15m14s measured on a 3-file, 71-line change.

**`shard preflight` prints this band placed against your own repository**, using your median source
file size to say which end you resemble. It costs nothing to run.

**The table covers pull-request runs only.** A first whole-repository pass is a different job and was
measured far above this band — 13 chunks of one 1,960-file repository spent 16.6M tokens. `preflight`
says so rather than quoting the pull-request number for it.

`max_spend_usd` is a ceiling, not an estimate: the run stops before a model call it cannot afford at
the highest price it has already paid. Two cases can still cross it by at most one call — the first
call of a run has no observed price behind it, and any call can be priced above every call before it.

## When something does not work

Every row is a behaviour of this build, with the symptom you actually see.

| what you see | what it is | what to do |
|---|---|---|
| `exit 2` and a line about an API key | the key's environment variable is unset. A configuration error, deliberately not reported as a finding | set the variable named by `api_key_env` — the default is `OPENROUTER_API_KEY`. Pass the secret through `env:`, never through `with:` |
| a green check, and "no changed files in scope" | `actions/checkout` defaults to `fetch-depth: 1`, so there is no base commit to diff against. **A green check that reviewed nothing** | `fetch-depth: 0` in the checkout step |
| findings appear, but `gate-eligible` is 0 and nothing fails | no entry point, so nothing could be demonstrated. Working as designed — a hypothesis never gates | declare `witness_entry`. Start with `shard preflight --entry-template` |
| an entry point exists, and findings still cannot gate | the entry point prints its marker, or dies, on empty input — so the baseline reproduces it | `bash .shard/entry.sh /dev/null` must be silent and exit 0 |
| a defect you know is real is refused | a benign control reproduced it, so the observation was not attributable to the input | correct: it is the adjudicator working. Narrow the marker to something only the defect produces |
| the run finds nothing and looks clean | the endpoint may not support native tool calling, which this product requires | `shard preflight --probe-endpoint` — one request, and it refuses a bad endpoint rather than producing a bad run |
| `deep mode is not present in this build` | deep mode is a separate, commercially licensed image | use `mode: diff`, `survey` or `preflight` |
| a C or C++ entry point demonstrates nothing under a sanitiser | ASAN's default is to print its report and `exit(1)`, which is indistinguishable from your program rejecting the input | `export ASAN_OPTIONS=abort_on_error=1` so the fault becomes a fatal signal |
| `exit 127` inside your entry point | it invoked a runtime this image does not carry | `shard preflight` names it. There is no JDK and no .NET SDK here — a JRE and the .NET runtime, so build in an earlier step |
| the run ends `error` with no findings | the report names the cause — a revoked key, an exhausted balance, a rate limit, a mistyped model name, a provider outage | read the cause line. That run's counts are a floor, and its silence is not a statement about your code |
| the SARIF or the comment did not appear | the job lacked `security-events: write` or `pull-requests: write`, or `github_token` was not passed | see the permissions block under [Usage](#usage). Shard names the surface it could not use in the log |

Two things that are **not** faults. A finding without a reproduction is informational by design and
cannot fail your build whatever `fail_on` says. And a review that altered the files under review
reports everything as informational — the checkout is digested before and after, and a run that
modified what it was judging cannot gate. **That digest covers your benign controls as well as the
changed files and the entry point**, so a run that deleted them refuses to gate rather than quietly
adjudicating without the differential they provide.

A third that reads like one and is a ceiling doing its job: **`not adjudicated and cannot gate`**.
Executing a witness costs a real run of your entry point — up to ten of them per claim, and ten more
at the base revision under `fail_on: new` — so the phase after the review carries a wall-clock ceiling
and a claim backstop. A claim past either is still reported in full; it just has no execution behind
it. The backstop sits five times above the largest number of findings any measured run has produced,
so meeting it is a signal about the run rather than about your repository.

## What this image does not do, and what does

**Deep mode is not in this build**, and selecting `mode: deep` fails with *"deep mode is not present in
this build"* rather than doing something unexpected. It is a different product on a different image,
and the difference is not a feature flag:

| | this image — pull-request review | deep mode |
|---|---|---|
| Scope | the diff and what it reaches | the whole repository |
| Finds | source vulnerabilities, proven by executing your entry point | memory-safety defects, with the crashing input **constructed** rather than waited for |
| Proof | your declared entry point reproduced it | a sanitiser caught it, and the bundle replays outside the product |
| Takes | minutes | hours |
| Needs | a standard hosted runner | a sanitiser toolchain, a container runtime and real CPU |

The honest summary of the boundary: **this tier proves what your entry point can be made to do; deep
mode goes and finds the crash.** It ships as a separate image on a separate base because a hosted
runner cannot supply what it needs, and bundling the two would put that dependency weight into an
image most people run on every pull request.

## Licence

[`LICENSE`](LICENSE) is the terms; this is the shape of them, and where the two disagree the file wins.

**Two doors, and you only need one of them.**

| | |
|---|---|
| **Public repositories** | **free, always.** Any number of repositories, pipeline runs, findings or contributors, and **no limit on the size of your organisation.** A trillion-dollar company reviewing its open-source projects needs nothing from us |
| **Private repositories** | free while your group is under **both** USD $5M annual revenue **and** 10 developers contributing to the private repositories Shard reviews |
| **Whose code** | yours or a client's. A consultancy, contractor or MSP is treated exactly like anyone else — **the line is size, not client relationship** |
| **Modifications** | change Shard and run the changed version in production, and you either publish those changes under this licence within 90 days **or** take a commercial licence and keep them private. **Your** source, config, entry points and findings are never covered — reviewing your code with Shard never obliges you to publish it |
| **Not permitted** | offering Shard *itself* to third parties as a hosted, managed or embedded service. Using Shard to do your own work is not that |
| **Above the line** | or to keep modifications private — <licensing@reyse.ai>, and we answer |
| **Eventually** | each version converts to Apache 2.0 on 2030-08-22, or four years after that version was first published, whichever comes first |

Revenue is measured **across your group** — parent and affiliates included — so a small team inside a
large organisation is measured by that organisation. The developer count is of contributors to the
**repositories reviewed**, not your own headcount: pointing Shard at a large private codebase exceeds
it whoever you are, which is what keeps the consultancy rule honest without a special case for it.

## Security

Shard is offensive tooling. Run it only against systems you are authorised to test. See
[`SECURITY.md`](SECURITY.md) for the reporting process and for what is and is not confined today.
