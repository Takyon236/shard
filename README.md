# Shard

Security analysis that runs in your CI, on a model endpoint you control, and reports a finding only when
it can attach a reproducing input.

- **It runs inside your perimeter.** A CI runner is your infrastructure. Your source, your binaries and
  your traffic do not leave it. There is no transfer to describe.
- **It runs on open weights you control.** A self-hosted vLLM, Ollama or TGI endpoint on your own
  hardware, or a managed one in your own cloud account. You can inspect the model, pin it to a version,
  and hold it there for as long as your validation requires.
- **A finding carries the input that produced it.** The agent proposes and an oracle adjudicates,
  independently of the model's opinion: an entry point you declared ran with the reported input and
  something observable happened, or it did not. The agent cannot promote its own guess to a finding.
  Every reported finding ships the input, the exact command, and the revision it was produced against.
- **The build never fails on an unreproduced finding**, whatever you configure. A defect Shard cannot
  demonstrate is informational, and informational findings cannot gate anything.

You need a CI that can run a container and an OpenAI-compatible model endpoint. Do not expect a list of
everything the product suspects.

> **Licensed under [BUSL 1.1](LICENSE).** **Free forever on public repositories**, at any scale, for
> any organisation. On private repositories it is free while you are under **$5M revenue and 10
> contributing developers**; above either, a commercial licence applies. Your own code, config and
> findings are never covered by anything here. You supply your own model inference; this project
> operates no endpoint and receives none of your code.

## Quickstart — five minutes, no API key

`survey` and `preflight` need no model, no endpoint, no secret and no network. Start there: they answer
the two questions worth answering before you spend anything — *what is in this repository*, and *could a
finding here ever fail my build*.

```bash
git clone https://github.com/Takyon236/shard && cd shard
python3 -m venv .venv && . .venv/bin/activate
pip install -e .

shard --help
```

**1. Survey your own project.** No inference. It reads the tree and reports what it is and where the
attack surface sits.

```bash
shard survey --repo /path/to/your/project --out-dir ./shard-out
cat shard-out/shard-report.md
```

**2. Ask what a review would need.** `preflight` profiles the repository, estimates what a run costs,
names any language runtime your entry point would need and this image does not carry and says whether anything here could gate a build at all.

```bash
shard preflight --repo /path/to/your/project
shard preflight --repo /path/to/your/project --json | less
```

**3. Write the file that makes findings provable.** Shard reports a defect it cannot demonstrate as a
hypothesis, and a hypothesis never fails a build. The demonstration runs an entry point *you* declare,
and `preflight` writes you a correct skeleton for it:

```bash
cd /path/to/your/project
mkdir -p .shard
shard preflight --repo . --entry-template > .shard/entry.sh
bash .shard/entry.sh /dev/null        # must be SILENT and exit 0 before you go further
```

**4. See a finished one working.** [`examples/`](examples/) holds five small projects with a real defect
and real benign controls. They need no key either. From the Shard checkout:

```bash
cd examples/python-config-eval
bash .shard/entry.sh .shard/entry.sh.benign/ordinary.conf   # silent: an ordinary input
printf 'x = __import__("os")\n' > /tmp/attack.conf
bash .shard/entry.sh /tmp/attack.conf                       # SHARD_SETTINGS_ARBITRARY_CODE
```

A key is needed only for `diff`, the pull-request review.

| command | valid as `mode:` | what it is for | inference |
|---|---|---|---|
| `survey` | yes | what this codebase is and where the attack surface sits. The one to run first | none — free to run |
| `diff` | yes | review a pull request and gate on what it introduced | yes, on your endpoint |
| `preflight` | **no — CLI only** | profile a repository and estimate what a run will cost, before you buy one | none |

`preflight` takes no `--out-dir`, writes no files and prints to stdout; putting it in a `with:` block is
refused with exit 2. Both modes write the same `shard-report.md`, so a workflow reading `report-path`
does not branch on the mode. A report opens with **verdict** first and **trust** second, because the two
questions a reader arrives with are *was anything found* and *did this run actually finish* — a run cut
short at a ceiling says so there rather than rendering like a clean result.

## The entry point you declare

Two files, side by side.

| path | what it is |
|---|---|
| `.shard/entry.sh` | a runnable entry point. Shard gives it an input and observes what happens. Without it, nothing can gate — every finding stays informational |
| `.shard/entry.sh.benign/` | ordinary, non-malicious inputs — **one per branch your entry point can take.** Every finding is checked against them |

**Without an entry point, Shard reports and cannot prove**, and this is the single largest determinant
of what a run gives you. On a repository that declared one, a real run reported four findings,
reproduced one by execution, and failed the build on it. On a repository that declared none, the same
analysis produced candidates that nothing could promote past a hypothesis.

Shard runs `bash -- .shard/entry.sh <payload-file>` and supplies the payload's contents. It never writes
this file: a witness the agent authored and is then graded against is not evidence, which is why this is
yours to commit.

```bash
#!/usr/bin/env bash
set -u
PAYLOAD="${1:-/dev/null}"

if [ ! -s "$PAYLOAD" ]; then
  exit 0
fi

exec python3 .shard/witness.py "$PAYLOAD" 2>&1
```

Read the payload, print nothing but a marker you chose, and keep that empty-input branch: Shard runs the
same script on an empty payload and compares, so an entry point that prints its marker or dies whatever
it is given demonstrates nothing — the baseline does the same — and the finding is refused. Two
demonstration kinds are adjudicated, `output_marker` and `fatal_signal`; if your failure mode is an
exception or a plain non-zero exit, print a marker on that branch and use `output_marker`.
[`examples/`](examples/) has the full contract and five working entry points, and it is the thing to
read next.

**Declare benign inputs.** Without them the only control is an *empty* input, and an empty input takes a
different branch through almost any program — so anything your program prints on real input looks like
something the finding caused. Measured against a five-class Java target: **four fixtures containing no
attack at all produced gate-eligible findings**, each program running to a clean exit of its own and
being adjudicated as a demonstration anyway. With four benign inputs declared, all four were refused and
every honest finding survived. A run made without a benign control says so in the finding itself, so
this is a limit you can see rather than one you have to already know about.

**If you set `fail_on: new`, make the entry point self-contained.** To decide whether *this* pull
request introduced a defect, Shard extracts your repository as it was at the base revision and re-runs
the same reproducing input against it — the answer is about your program, not about your diff, so it
covers a silent exploit that produced no stack trace and a defect a deletion introduced, neither of
which appears anywhere in the diff. That extraction carries tracked files only, so an entry point
needing a binary an earlier step built cannot start there; Shard falls back to the diff and says so,
rather than blaming the author for code they did not touch.

### Two things that happen to your entry point

**Its output is scrubbed of our credentials before anything reads it.** The container hands your script
an environment with the API key and every `INPUT_*` value removed — but it runs as root beside us, so
`/proc/1/environ` still holds them, and its output is published back to whoever opened the pull request.
Any value we hold is replaced with `[redacted]` in the captured text, on the attack run and on every
benign control alike, so a marker that happens to contain one will not demonstrate.

**It may run without a network.** Where the kernel grants it — a self-hosted runner with
`CAP_SYS_ADMIN` — your entry point and its controls run inside a network namespace with no egress, the
same treatment the review agent's own shell has always had. On a standard GitHub-hosted runner Docker
grants no such capability, nothing is isolated, and the run says so in its report. Build in an earlier
step: an entry point that fetches something at witness time behaves differently depending on which
runner it lands on.

## Add it to a pull request

A complete workflow. Showing the scan step alone produces a run whose
findings nobody can see: the report and the reproduction bundles are written into a directory on a
runner that is destroyed when the job ends.

```yaml
name: shard
on: pull_request

permissions:
  contents: read             # actions/checkout
  security-events: write     # the SARIF becomes code-scanning alerts, in the Security tab
  pull-requests: write       # the report becomes ONE comment, edited in place on every push

jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: Takyon236/shard@v3
        env:
          OPENROUTER_API_KEY: ${{ secrets.OPENROUTER_API_KEY }}
        with:
          mode: diff
          github_token: ${{ secrets.GITHUB_TOKEN }}
          api_key_env: OPENROUTER_API_KEY           # only the NAME of the variable; this is the default
          model_endpoint: https://vllm.internal/v1  # an OpenAI-compatible URL
          max_spend_usd: 10
          fail_on: none                             # gating is opt-in

      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: shard-evidence
          path: shard-out/
          if-no-files-found: warn
```

Four parts of that block are easy to leave out, and each one costs something:

| leave out | and |
|---|---|
| `fetch-depth: 0` | `actions/checkout` fetches one commit, so there is nothing to diff against. The run reports "no changed files in scope" and exits 0 — a green check that reviewed nothing. `2` also works, but only with `base_ref` left at its default `HEAD~1`: a `pull_request.base.sha` that has moved is outside a shallow window |
| a `permissions:` line | each one buys exactly one delivery surface. The run still works and still gates, and produces nothing anybody sees. Shard says in the log which surface it could not use |
| `github_token` | no alerts and no comment. The run is still correct and still gates |
| `if: always()` on the upload | the reproduction bundles die with the runner, and the run you most want the input from is the one that just failed your build |

The secret goes in `env:` and never in `with:`. Shard never takes the key as an input, so it cannot
reach an argv, a log line or the action manifest; it looks up the variable named by `api_key_env` in its
own environment. Store it once under **Settings → Secrets and variables → Actions**.

Every run also writes its report to `$GITHUB_STEP_SUMMARY`, which needs **no** token and no permission,
so even a workflow with none of the above is legible on the job page. **If you would rather upload the
SARIF yourself**, leave `github_token` out and pass the action's `sarif-path` output to
`github/codeql-action/upload-sarif`; the built-in upload exists so that installing Shard stays one step.

[`action.yml`](action.yml) is the full interface, and `model_endpoint` takes an OpenAI-compatible base
URL — see [which endpoints work](#which-endpoints-work). `action.yml` sits at the repository root beside
the [`Dockerfile`](Dockerfile) deliberately: **this repository is the action**, and GitHub resolves a
container action's image and build context relative to the metadata file, so neither may move into a
subdirectory.

### Reviewing a pull request from a fork

**On a fork's pull request there is no secret**, and that is GitHub's rule rather than ours: secrets are
withheld from `pull_request` runs originating in a fork. So, stated as a product fact rather than a
footnote: **out of the box, this tier cannot review outside contributions to an open-source project.**
It works on branch pull requests from people who already have write access — and a maintainer catching a
drive-by contribution from a stranger, the case with the most security value, is precisely the excluded
one.

There is no fully clean answer, only two partial ones. Pick one deliberately rather than discovering the
gap on the pull request that mattered.

**Recommended — `workflow_run`.** A second workflow triggered by the completion of the pull request's
own build. It runs in the **base** repository's context, so the secret is available, and the fork's code
is analysed as data rather than executed as a trusted step.

```yaml
name: shard-fork
on:
  workflow_run:
    workflows: [ci]          # the fork-triggered build whose completion this waits for
    types: [completed]

permissions:
  contents: read             # actions/checkout, and the only permission this trigger can use

jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      # `workflow_run` starts on the BASE branch. Without an explicit ref this reviews your own code
      # and reports a clean result for a pull request nobody read.
      - uses: actions/checkout@v4
        with:
          repository: ${{ github.event.workflow_run.head_repository.full_name }}
          ref: ${{ github.event.workflow_run.head_sha }}
          fetch-depth: 0
          persist-credentials: false

      - uses: Takyon236/shard@v3
        env:
          OPENROUTER_API_KEY: ${{ secrets.OPENROUTER_API_KEY }}
        with:
          mode: diff
          # No `github_token`: both surfaces it would buy are unreachable on this trigger, so passing
          # it puts a credential in a container running a stranger's code for nothing.
          base_ref: ${{ github.event.workflow_run.head_branch }}
          # The target is the FORK. Without this the report and the alerts name YOUR repository.
          slug: ${{ github.event.workflow_run.head_repository.full_name }}

      # The only place the reproduction bundles survive on this trigger.
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: shard-out
          path: shard-out/
```

**Two of the three delivery surfaces cannot fire here, and no permission recovers either.** The comment
needs a pull-request number: `workflow_run` runs on a BRANCH ref, and GitHub leaves
`workflow_run.pull_requests` empty whenever the head is a fork — which is every case this section is
about. The alerts need the reviewed repository to be the token's, and `slug` names the fork on purpose,
which is why the SARIF upload refuses outright. **So the report is delivered by the job summary and the
uploaded `shard-out/` artifact**, and Shard prints both refusals by name rather than skipping quietly.
Granting `security-events: write` or `pull-requests: write` in this workflow buys nothing.

**The care this needs, stated plainly:** a witness entry point *does* execute code from the fork. That
is true of Shard on any input, but a `workflow_run` job holds a token the `pull_request` job did not —
so treat `witness_entry` on fork pull requests as a decision, not a default.

**The alternative — `pull_request_target`.** It runs with secrets against the base repository while a
fork controls the code under review. It is the pattern the ecosystem uses and it is a genuine footgun
without both of these: `permissions:` locked to the minimum, and a required-approval environment gate so
a maintainer sees the diff before anything runs.

## Which endpoints work

**One rule: an OpenAI-compatible `/chat/completions` that supports native tool calling.** That is not a
preference — the agent proposes findings through tool calls, and an endpoint without them completes a
run and finds nothing. `shard preflight --probe-endpoint` spends one request establishing this and
refuses a bad endpoint rather than letting you pay for an empty review.

| endpoint | works | what to know |
|---|---|---|
| **vLLM, Ollama, TGI, llama.cpp** | yes | the guaranteed-residency path: your hardware, your weights, no third party in the request |
| **OpenRouter** | yes | the default `api_key_env`. Verified end to end on `glm-5.3` |
| **Google Vertex AI** | yes, via its OpenAI-compatible path | `…/endpoints/openapi/chat/completions`. The bearer token is a short-lived OAuth token, so mint it in the step before the scan |
| **Azure OpenAI / SageMaker** | yes, shape-wise | both expose OpenAI-compatible routes; SageMaker does so when serving through vLLM or TGI |
| **AWS Bedrock, natively** | **no** | Bedrock speaks SigV4 and its own request shape, not OpenAI's. Put a gateway in front of it — LiteLLM or the Bedrock Access Gateway — and point `model_endpoint` at that |

**Only the first two rows have been executed by us.** The rest are the same OpenAI-compatible contract
and are expected to work, and expected is not measured — so they are listed as a shape rather than as a
result. If you run one, a note in an issue is genuinely useful.

**`model_endpoint: bedrock` and `model_endpoint: vertex` are refused by name**, deliberately: those are
adapter names for work that has not landed, and accepting them would produce a confusing failure instead
of a configuration error. Pass a URL.

## What it can gate, and what it can only read

Proving a finding means running your entry point, and that happens inside this image. A language whose
runtime is not here can be reviewed and can never fail a build, because a finding without a
demonstration never gates by design.

| language | can be demonstrated here | ground truth |
|---|---|---|
| Python | **yes** — `python3` | `canary-py`, 4 of 4 planted classes gate |
| JavaScript · TypeScript | **yes** — `node` 22 | `canary-js`, 5 of 5 |
| Java · Kotlin · Scala | **yes** — a headless JRE | `canary-java`, 5 of 5 |
| Ruby | **yes** — `ruby` | `canary-ruby`, 3 of 3 |
| PHP | **yes** — `php-cli` | `canary-php`, 3 of 3 |
| C# | **yes** — the .NET 8 runtime | `canary-cs`, 3 of 3 |
| C · C++ | **yes** — `gcc` / `g++` | `canary`, 3 of 3, under AddressSanitizer |

Those are **26 of 26**: executions of this product's own adjudicator inside this image against planted
defects, not estimates. Four of the seven canaries were written for this measurement
at all, because a runtime with no canary is a claim nobody has checked.

**The corpus these were measured against is not public.** The seven canaries live in a separate
reference harness that has not been published, so treat 26 of 26 as a vendor measurement with its
instrument named. What you can check today is your own repository: `shard preflight` reports which of
these runtimes your entry point needs and whether this image carries them, before you spend anything,
and if it prints nothing about runtimes then everything your repository needs was found.

**Two of them run an artefact your build produces, rather than compiling it.** The image carries the
**.NET runtime and a JRE**, not the SDK or a JDK — 69 MB against 564 for .NET alone — so a C# or Java
entry point should run the assembly your existing build step already emits, exactly as `canary-cs` runs
a committed DLL. C and C++ are the exception: `gcc` is here, so an entry point that compiles works too.

**The image is 934 MB, and about 810 MB of that is those runtimes.** A deliberate trade: one layer pull
per runner against a language that could otherwise never fail a build.

## What a run costs

You supply the inference, so your model bill *is* the price. Every pull-request run this project has
PRICED:

| changed files | changed lines | bytes in the files touched | cost | tokens |
|---|---|---|---|---|
| 1 | 12 | 2,800 | $0.022 | 21,184 |
| 1 | 1 | 2,900 | $0.026 | 50,547 |
| 3 | 48 | 120,000 | $0.030 | 97,852 |
| 3 | 48 | 120,000 | $0.045 | 131,410 |
| 3 | 82 | 190,000 | **$0.507** | 786,563 |

**Five points is a small sample, not a corpus**, and it is quoted as a range rather than a formula
because five points cannot support the precision a formula would imply on the one number you
plan against.

**Read the dollars as a floor, not as a range, and the high end of the table is not the high end that has happened.** Every priced row above was metered on 2026-08-12/13.
This agent gained the ability to execute code in your checkout on 2026-08-19, and what it runs enters
the transcript and is re-sent on every turn after; nothing has re-priced it since. Five pull-request
runs of the shipped artefact against real third-party repositories on 2026-08-25 used a **median 7.9x
the tokens** of the priced sample, two of them above its maximum; they ran on an endpoint that reports
no price, so they widen the TOKEN band and cannot correct the dollar one. Across both samples a run has
spent **21,184 to 1,544,464 tokens**, and that band is the one measured since the product could execute.

**Cost does not track the size of the change.** 82 lines of markdown cost seventeen times what 48 lines
of a real library diff cost. What separates them is the size of the *files* the change touches — the
agent reads changed files, and context accumulates across turns, so a large file read early is paid for
again in every turn after it. Stated as the leading hypothesis rather than as a model. Wall clock is
minutes to about fifteen on a small diff; 15m14s measured on a 3-file, 71-line change.

**The table covers pull-request runs only.** A first whole-repository pass is a different job and was
measured far above this band — 13 chunks of one 1,960-file repository spent 16.6M tokens. `preflight`
says so rather than quoting the pull-request number for it.

`max_spend_usd` is a ceiling, not an estimate: the run stops before a model call it cannot afford at the
highest price it has already paid. Two cases can still cross it by at most one call — the first call of
a run has no observed price behind it, and any call can be priced above every call before it.

**`shard preflight` prints this band placed against your own repository**, using your median source file
size to say which end you resemble, and it costs nothing to run.

## Running it outside GitHub Actions

`action.yml` is GitHub-specific. **The product is not.** It is a container with a command-line
interface, and the action is a thin mapping from `INPUT_*` environment variables onto that CLI — so any
CI that can run a container can run Shard, and the only GitHub-specific parts are the two delivery
surfaces (code-scanning alerts and the pull-request comment), which such a run simply does not use.

The image is published for each release. Pull it rather than building it:

```bash
docker pull ghcr.io/takyon236/shard:v3
```

Then drive the CLI directly. Nothing below needs a GitHub token:

```bash
docker run --rm \
  -v "$PWD:/src" -w /src \
  -e OPENROUTER_API_KEY \
  ghcr.io/takyon236/shard:v3 \
    diff --repo /src --base-ref "$BASE_SHA" \
         --witness-entry .shard/entry.sh \
         --model-endpoint https://your-endpoint/v1 \
         --fail-on reproduced \
         --out-dir /src/shard-out
```

### The exit code is the gate

It has **three** values rather than two. `shard/gate.py` decides every one of them, and nothing else
does:

| code | what it means |
|---|---|
| **0** | nothing gated. `--fail-on none` always lands here; so does a run that matched nothing you asked to gate on, and so does a run a ceiling cut short — `budget`, `maxsteps`, `repeat` |
| **1** | **the only code that means a finding.** A demonstrated finding matched your `--fail-on` rule: a reproduction exists under `reproduced`, and under `new` it also sits on something this change introduced |
| **2** | Shard could not do what you asked. A bad argument, a repository it cannot read, an unset key variable — and, under `--fail-on reproduced` or `new`, a review that ended `status: error`, because a review that never happened must not clear a gate you asked for |

**Branch on `1`, never on "non-zero".** A revoked key, an exhausted balance and an unreachable endpoint
all exit **2**, and so does a review that ended `status: error` under a gate you asked for — measured: a
dead endpoint under `--fail-on reproduced` exits 2 with `status error` and nothing adjudicated. A
pipeline that treats every non-zero code as a demonstrated vulnerability sends the team hunting one that
was never reported, or teaches them to ignore the exit code. Under the default `--fail-on none` a **1**
is unreachable, so a non-zero exit there is always a **2**.

That is the whole integration contract; everything else is reading `shard-out/`.

### Per platform

| platform | what to know |
|---|---|
| **GitLab CI** | run it as the job `image:`, or `docker run` in a `script:`. `CI_MERGE_REQUEST_DIFF_BASE_SHA` is your `--base-ref`. Fetch depth matters here too: set `GIT_DEPTH: 0` |
| **Jenkins** | `docker.image('ghcr.io/takyon236/shard:v3').inside { … }`, or a plain `sh 'docker run …'`. Archive `shard-out/` as a build artefact |
| **AWS CodeBuild** | works in a standard Linux image with privileged mode off — Shard runs your entry point, it does not build containers. Pull from ghcr; no ECR mirror is needed unless your policy requires one |
| **Google Cloud Build** | a `name: ghcr.io/takyon236/shard:v3` step with `args:` as above. Cloud Build mounts `/workspace`, so use `--repo /workspace` |
| **anything else** | if it runs a container and can set an environment variable, it works. The CLI is the whole surface |

**Two things a non-GitHub run does not get**: the SARIF is still written to `shard-out/`, but nothing
uploads it to a code-scanning UI, and there is no pull-request comment. Both are GitHub APIs. The
report, the SARIF and the reproduction bundles are ordinary files — publish them wherever your platform
keeps artefacts.

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
| `mode must be one of ['survey', 'diff'], not 'deep'` | deep mode is a separate, commercially licensed image and this one does not carry it | use `mode: diff` or `mode: survey`. `preflight` is a CLI command, not a mode |
| `mode must be one of ['survey', 'diff'], not '...'` for any other value | `mode:` takes exactly the two names above | the same two. Every other `shard` command — `preflight` included — runs from the CLI, not from `with:` |
| a C or C++ entry point demonstrates nothing under a sanitiser | ASAN's default is to print its report and `exit(1)`, which is indistinguishable from your program rejecting the input | `export ASAN_OPTIONS=abort_on_error=1` so the fault becomes a fatal signal |
| `exit 127` inside your entry point | it invoked a runtime this image does not carry | `shard preflight` names it. There is no JDK and no .NET SDK here — a JRE and the .NET runtime, so build in an earlier step |
| the run ends `error` with no findings | the report names the cause — a revoked key, an exhausted balance, a rate limit, a mistyped model name, a provider outage | read the cause line. That run's counts are a floor, and its silence is not a statement about your code. Under `fail_on: reproduced` or `new` this **exits 2, not 1**: a review that never happened cannot clear a gate, and it is not a finding either |
| the SARIF or the comment did not appear | the job lacked `security-events: write` or `pull-requests: write`, or `github_token` was not passed — or the trigger is `workflow_run`, where neither can fire whatever you grant | see the workflow under [Add it to a pull request](#add-it-to-a-pull-request) and [Reviewing a pull request from a fork](#reviewing-a-pull-request-from-a-fork). Shard names each surface it could not use in the log |

Two things that are **not** faults. A finding without a reproduction is informational by design and
cannot fail your build whatever `fail_on` says. And a review that altered the files under review reports
everything as informational — the checkout is digested before and after, and a run that modified what it
was judging cannot gate. **That digest covers your benign controls as well as the changed files and the
entry point**, so a run that deleted them refuses to gate rather than quietly adjudicating without the
differential they provide.

A third that reads like a fault and is a ceiling doing its job: **`not adjudicated and cannot gate`**.
Executing a witness costs a real run of your entry point — up to ten of them per claim, and ten more at
the base revision under `fail_on: new` — so the phase after the review carries a wall-clock ceiling and
a claim backstop. A claim past either is still reported in full; it just has no execution behind it. The
backstop sits five times above the largest number of findings any measured run has produced, so meeting
it is a signal about the run rather than about your repository.

## What this image does not carry

**Deep mode is not in this build**, and this artefact does not offer the mode at all: `mode: deep` fails
at input validation with *"mode must be one of ['survey', 'diff'], not 'deep'"*, exit 2, rather than
doing something unexpected. It is a different product on a different image, and the difference is not a
feature flag:

| | this image — pull-request review | deep mode |
|---|---|---|
| Scope | the diff and what it reaches | the whole repository |
| Finds | source vulnerabilities, proven by executing your entry point | memory-safety defects, with the crashing input **constructed** rather than waited for |
| Proof | your declared entry point reproduced it | a sanitiser caught it, and the bundle replays outside the product |
| Takes | minutes | hours |
| Needs | a standard hosted runner | a sanitiser toolchain, a container runtime and real CPU |

The boundary in one line: **this tier proves what your entry point can be made to do; deep mode goes and
finds the crash.** It ships as a separate image on a separate base because a hosted runner cannot supply
what it needs, and bundling the two would put that dependency weight into an image most people run on
every pull request.

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
**repositories reviewed**, not your own headcount: pointing Shard at a large private codebase exceeds it
whoever you are, which is what keeps the consultancy rule honest without a special case for it.

## Security

Shard is offensive tooling. Run it only against systems you are authorised to test. See
[`SECURITY.md`](SECURITY.md) for the reporting process and for what is and is not confined today.
