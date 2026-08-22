# Shard

Security analysis that runs in your CI, on a model endpoint you control, and reports a finding only when
it can attach a reproducing input.

> **Licensed under [BUSL 1.1](LICENSE).** Free to use in your own pipelines, on your own
> repositories, at any scale — including production. You supply your own model inference; this project
> operates no endpoint and receives none of your code.

## What makes it different

**It runs inside your perimeter.** A CI runner is your infrastructure. Your source code, your binaries
and your traffic do not leave it. There is no clause to read carefully, because there is no transfer to
describe.

**It runs on open weights you control.** Bedrock or Vertex in your own cloud account, or a self-hosted
vLLM endpoint on your own hardware. You can inspect the model, pin it to a version, and hold it there
for as long as your validation requires. You supply the inference on every tier, including this one.

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

**The image is 890 MB, and about 680 MB of that is those runtimes.** A deliberate trade: one layer pull
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

      - uses: Takyon236/shard@v1
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

      - uses: Takyon236/shard@v1
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
subdirectory. Point `model_endpoint` at an OpenAI-compatible base URL; `bedrock` and `vertex` are
refused by name until their adapters land, so you get a configuration error rather than a bad run.

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

See [`LICENSE`](LICENSE).

## Security

Shard is offensive tooling. Run it only against systems you are authorised to test. See
[`SECURITY.md`](SECURITY.md) for the reporting process and for what is and is not confined today.
