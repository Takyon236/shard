# Shard
<place to put image logo later>

## What Shard is

Shard is a security reviewer for all your pull requests and it runs inside your build system and it runs on a model endpoint you supply and pay for. Most importantly **it only reports a probelm when it attaches and input that makes the problem happen on demand**.

Other tools like CodeRabbit etc. guess through your code and hand you a list, half full of false positives and unbased suggestions with no clear solution. Shard runs your program and uses an input that it custom-crafted and watches what happens, reporting what it actually saw.

*Speaking truth, not a clean response designed to make you happy*. 

## The idea behind it all

Prove it, or it didn't happen. The model says so, a heuristic checker proves it, by just running your program. The model cannot promote a guess to a real finding just because it "thinks so". 

Each real finding comes with a bundle (labelled with the input and the exact command and the version of your code it was produced against) you can reproduce it with. *If the bundle doesn't work and it can't prove it, it didn't exist.*

The build never fails on a an unproven finding, no matter what you do. Guesses are for reference only

The code stays yours. Code analysis runs on your own machine, analysed by your AI. Your source code, your binaries and your information never leave your own machine. There is no privacy clause because your information is your information and this project runs no model service of it's own and never sees your code.

## The three modes
| mode | what it does | needs a model? |
|---|---|---|
| `survey` | reads your repository and reports what it is and where attackers would look. Run this first | no — free |
| `preflight` | profiles your repository, estimates what a review would cost, and tells you which language runtimes your entry point needs that the container doesn't carry | no — free |
| `diff` | reviews a pull request and can fail the build on what the pull request introduced | yes, on your endpoint |

There is a fourth hidden one called action. You never type it and it is what the GitHub Action runs, reading its settings from the environment that GitHub builds for it.

Two modes need no model and no API key no secret and nothing other than the code. You can start there and answer these two questions for yourself. 

What is in this repository and couild a finding here fail my build?

## Try it in 5 minutes

```bash
git clone https://github.com/Takyon236/shard && cd shard
python3 -m venv .venv && . .venv/bin/activate
pip install -e .

shard --help
```

You can look around and then estimate

```bash
shard survey --repo /path/to/your/project --out-dir ./shard-out
cat shard-out/shard-report.md

shard preflight --repo /path/to/your/project
```

This creates the file that makes the findings provable and when you want to see a finished one look at examples/ with 5 small projects with no real defects in them that also need no key.

```bash
cd examples/python-config-eval
bash .shard/entry.sh .shard/entry.sh.benign/ordinary.conf   # silent: an ordinary input
printf 'x = __import__("os")\n' > /tmp/attack.conf
bash .shard/entry.sh /tmp/attack.conf       
```

An API key is needed only for the diff function which is the pull request review.

## The two files you write

These decide whether anything Shard finds can fail your build and they live sid by side. 

| path | what it is |
|---|---|
| `.shard/entry.sh` | a small runnable script you commit. Shard hands it an input file and watches what happens. Without it, nothing can gate — every finding stays a warning |
| `.shard/entry.sh.benign/` | ordinary, harmless inputs — **one for each path your script can take.** Every finding is checked against them |

**Why the script must be yours:** Shard never writes it. A witness the model wrote and is then
graded against is not evidence. The product will, however, write you a correct skeleton:

```bash
cd /path/to/your/project
mkdir -p .shard
shard preflight --entry-template > .shard/entry.sh
bash .shard/entry.sh /dev/null        # must be SILENT and exit 0 before you go further
```

## Rules of a good entry script

Shard runs 'bash -- .shard/entry.sh <payload file>' and supplies the payload's contents.

1. **Read the payload.**: A  program that ignores it's outputs cannot be evidence without it.
2. **Print nothing but your marker.**: Echoing back what you were given demonstrastes your echo.
3. **Empty input must be quiet**: Shard runs the script on an emptypayload as a baseline and compares, A script that prints its marker or die is pointless, the baseline does the same thing, and the finding is refused. This is a waste of time.
4. **Put safe inputs beside it**: one per branch. Without them the only comparison is an empty input. Whatever your program prints on real input loosk like it was caused by the attack

A run made without controls says so in the finding. A limit you can see rather than one you already know about.

## Two kinds of proof

Your script proves a defect in one of two ways. Asking for a type in this build does not judge is a quiet failure and not an error.

| kind | what it means | when to use it |
|---|---|---|
| `output_marker` | your script prints a string you chose | almost always; the only route in most languages |
| `fatal_signal` | the program dies on a crash signal | memory bugs, and builds that abort on detection |

Two other kinds exist in the code and were deliberately switched off. Both were measured and both fired on programs tht were merely rejecting bad input, as designed. If you failure mode is an exception or a non-zero exit, print a marker on that path and then use `output-marker`. The generated skeleton lists only what this build accepts, so it cannot drift away from this.

It can run without a network. Where the build machine allows it, your script and its controls run in a network space with no way out which is the same treatment the reviewers own shell has always had. On a standard GitHub runner this is not possible and nothing is isolated and the report says so. Regardless, a script that download something at proff time behaves differently depending on which machine it lands on.

## What languages can fail a build

Proving a finding means running your script, and that happens inside the container this product
ships. A language whose runtime is not there can be reviewed but can never fail a build, because
an unproven finding never gates by design.

| | runs in the container | tested against planted defects |
|---|---|---|
| Python | **yes** | 4 of 4 |
| JavaScript · TypeScript | **yes** — node 22 | 5 of 5 |
| Java · Kotlin · Scala | **yes** — a headless JRE | 5 of 5 |
| Ruby | **yes** | 3 of 3 |
| PHP | **yes** | 3 of 3 |
| C# | **yes** — the .NET 8 runtime | 3 of 3 |
| C · C++ | **yes** — `gcc` / `g++` | 3 of 3, under AddressSanitizer |

That is 26 of 26, this product's own checker run against deliberately planted defects, not an
estimate. **The corpus is not public**, which is stated here rather than left for you to discover:
treat 26 of 26 as our measurement with its instrument named, not something you can re-run today.
What you can check for free is your own repository — `shard preflight` names any runtime your
script needs that the container lacks.

Two of them run an artefact your build produces rather than compiling it. The container
carries a .NET runtime and a JRE, not the full SDKs — 69 MB against 564 for .NET alone — so a C#
or Java entry script should run the assembly your build step already emits. C and C++ are the
exception: a compiler is present, so a script that compiles works as well.

Absent on purpose: Go, Rust, Swift and every other toolchain. A script calling one exits with
"command not found" (127) and `preflight` will have told you so first. This is on purpose and is a technical decision

The image is 934 MB, and about 810 MB of that is the runtimes. An intendd trade: one
download per machine against languages that could otherwise never fail a build.

## Every setting, and what it does

These are the GitHub Action inputs; each corresponds to a flag with the same meaning
(underscores, not hyphens; hyphens are a real GitHub quirk that once silently switched most of
these off). Defaults are what you get if you say nothing.

| input | default | what it does |
|---|---|---|
| `mode` | `diff` | which of the three modes runs |
| `model_endpoint` | — | the web address of your model service. `bedrock` and `vertex` are refused by name — pass a real URL instead |
| `model` | `glm-5.2` | which model to ask for |
| `api_key_env` | `OPENROUTER_API_KEY` | the **name** of the environment variable holding your key — never the key itself |
| `max_spend_usd` | `10` | hard ceiling on model spend for this run. `0` means no limit. The run stops *before* a call it cannot afford; the first call and a suddenly-pricier call can still cross it by one call |
| `max_minutes` | `60` | hard ceiling on wall-clock time, checked between steps. `0` means no limit |
| `max_tokens` | `0` | ceiling on total model words. `0` means no limit |
| `scan` | — | `initial` (a first look at a repository — budgets for coverage) or `followup` (the baseline exists — pay for the change). Sets budgets, never scope: the review always covers exactly the diff |
| `max_steps` | `40` | how many turns the hunt may take. `0` is refused — zero steps is no review at all, which would be a green check that reviewed nothing. To let a run go longer, raise the money ceiling |
| `hunk_radius` | `40` | lines of context either side of a changed line. `0` means whole files. Measured on a one-line change in a 6,895-line file: it cut tokens by 40% and cost by 42% at the same step count, and a defect planted 69 lines outside the window was still found, 3 times of 3 |
| `witness_entry` | — | path to your entry script, e.g. `.shard/entry.sh`. Without it nothing can gate |
| `base_ref` | `HEAD~1` | what the pull request is measured against. See the checkout-depth rules below — this is the setting behind the most common silent failure |
| `state_repo` | — | path to a separate checked-out repository where Shard keeps what it learns between runs. It never writes to the repository under review, and a state problem never fails the build |
| `slug` | — | `<owner>/<name>` of the repository under review |
| `fail_on` | `none` | when the build goes red: `none` (report only), `reproduced` (any proven finding), `new` (only what this pull request introduced) |
| `out_dir` | `shard-out` | where the output files are written |
| `github_token` | — | pass `secrets.GITHUB_TOKEN` to publish findings as alerts in the Security tab and as a pull-request comment. Without it the run still works and still gates — it just produces nothing anybody sees, and says so |


The CLI takes the same knobs with dashes: `shard diff --repo . --max-spend-usd 5 …`.

### What each `fail_on` value actually does

Every row below is a finding Shard proved by running your script:


| the finding | `none` | `reproduced` | `new` |
|---|---|---|---|
| defect on a line this pull request added | pass | **fail** | **fail** |
| defect whose exploit was silent (no crash, no error) | pass | **fail** | **fail** |
| defect introduced by a line this pull request *deleted* | pass | **fail** | **fail** |
| defect that was already there, untouched | pass | **fail** | pass |


How `new` answers the middle two rows, when neither is visible in the diff: it takes your
repository as it was **before the pull request** and re-runs the same reproducing input against it.
Reproduces there — the defect was already there. Doesn't — this change introduced it. The answer
is about your program, not your diff. The cost is one archive extraction per run and one extra run
of your entry script per proven finding, and only under `new`. When the base copy cannot run —
it carries only the files git tracks, so a binary built in an earlier step is missing — `new`
falls back to line numbers and says so, rather than blaming the author for code they did not touch.

## What the run hands back

Outputs that you can read in a workflow after the step:

| output | what it is |
|---|---|
| `status` | whether the run finished: `done` or `audited` mean yes; `error`, `budget` or `maxsteps` mean it stopped early and "no findings" is not a clean result. The check stays green either way — installing Shard does not break your build — so this is where a workflow reads what actually happened |
| `findings` | how many findings were emitted |
| `gate-eligible` | how many carry proof — the only ones that may fail a build |
| `sarif-path` | the findings in the standard alert format GitHub's Security tab reads |
| `report-path` | the short human report |
| `bundle-path` | the reproduction bundles: the crashing input and the command that produced it |
| `result-path` | the whole result as one versioned JSON document — findings split into `reproduced` and `hypotheses` as separate lists, plus a `limits` array naming in codes what this run does not establish. The output to give another tool |
| `telemetry-path` | how the run went, as JSON — timings, turns, tool calls, context growth. Holds no source and none of the model's prose, so it is safe to forward |
| `log-path` | the same story, human-readable, in order. About the run; the report is about the *code* |

## Exit codes

Three numbers can define it all:

| exit code | meaning |
|---|---|
| **0** | pass. Either nothing was found, or nothing matched your `fail_on` rule |
| **1** | a proven finding matched your `fail_on` rule — the review worked and this is its verdict |
| **2** | a configuration problem: a missing key, a bad setting. Deliberately distinct, so an internal error can never masquerade as a security finding |

## The files a run leaves behind

All in `out_dir` (default `shard-out/`):

| file | what it is |
|---|---|
| `shard-report.md` | the human report. Every mode writes this same filename, so a workflow consuming it does not branch on the mode |
| `shard.sarif` | the findings in the standard alert format |
| `shard-result.json` | the whole result, versioned, for other tools |
| `shard-telemetry.json` | how the run went, for other tools |
| `bundles/` | one folder per finding: the input that triggers it and the exact command |
| `shard-survey.json` | survey mode's machine-readable output |

Every run also writes its report to the job's step summary, which needs no tokens and no
permission so even a minimal workflow is visible on the job page.

### The report's fixed header

Every report opens the same way, because the two questions a reader arrives with are was anything
found and did this run actually finish: verdict first, trust second, then what was
reviewed, the gate decision, whether a witness was declared, whether the agent executed things in
your checkout, and the cost. A run cut off by a ceiling says so there, rather than rendering like a
clean result. A fact the run does not know omits its row rather than printing a zero.

## Setting it up in GitHub Actions

A complete workflow, and completeness is the whole point, the scan step alone produces a run whose
findings nobody sees, because the output lives on a machine that is destroyed when the job ends:

```yaml
name: shard
on: pull_request

permissions:
  contents: read             # the checkout
  security-events: write     # findings become alerts in the Security tab
  pull-requests: write       # the report becomes ONE comment, edited in place on every push

jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      # THE DEPTH IS PART OF THE CONFIGURATION. The checkout step's default grabs ONE commit,
      # so there is nothing to compare against; the run then reports "no changed files in scope"
      # and exits 0 — a GREEN CHECK THAT REVIEWED NOTHING.
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: Takyon236/shard@v2
        env:
          OPENROUTER_API_KEY: ${{ secrets.OPENROUTER_API_KEY }}   # the secret itself, and the
                                                                  # only place it appears
        with:
          mode: diff
          github_token: ${{ secrets.GITHUB_TOKEN }}
          model_endpoint: https://vllm.internal/v1
          max_spend_usd: 10
          fail_on: none                # gating is opt-in

      # The reproduction bundle is the thing worth keeping, and it dies with the machine unless
      # something keeps it — most urgently on the run that just failed your build.
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: shard-evidence
          path: shard-out/
          if-no-files-found: warn
```

Store the model key once under **Settings → Secrets and variables → Actions**. Shard never takes
it as an input, so it cannot reach a command line, a log or the action's manifest — it looks the
variable name up in its environment.

If you would rather upload the alert file yourself, leave `github_token` out and pass the step's
`sarif-path` output to the standard upload action. Same result, one more step.

### Checkout depth and the base commit, the rules in one place

This is the setting behind the most common silent failure — a green check that reviewed nothing —
so it gets its own paragraph:

- **Saying nothing is safest**: the default base is `HEAD~1`, the commit before this one, and a
  one-commit-deep checkout can resolve it.
- **`fetch-depth: 2` plus the default base** also works.
- **Any explicit `base_ref` deserves `fetch-depth: 0`.** The pull request's official base commit
  is the branch tip *as of the last sync*, not the true fork point — on a pull request open
  longer than the branch is quiet it has moved, and a moved commit outside a shallow window makes
  git answer "bad object", the scope come back empty, and the run exit 0 looking green.
- Where the base has moved, the review falls back to the true fork point — the right causal
  answer to "what did this change add" — and says so in its output. On a head-branch checkout
  (a fork, a manual run) prefer the fork point yourself.

## Pull requests from strangers

On a pull request opened from a fork there is no secret, and that is GitHub's rule rather than
ours. Stated as a product fact: out of the box, this tier cannot review outside contributions —
precisely the case where a security tool has the most value. Pick an answer deliberately rather
than discovering the gap on the pull request that mattered.

**Recommended — a second workflow that waits for the build.** Trigger it on the completion of the
pull request's own CI. It runs in your repository's context — so the key is available — and the
stranger's code is read as data, never run as a trusted step. Two things it must do: check out
the fork's head explicitly (without this it reviews your own code and reports a clean result
nobody earned), and name the fork as the target so the alerts land on the right repository.

**The alternative is the pattern everyone uses**: running with your secrets
against code the fork controls. If you take it, lock the permissions to the minimum and require a
maintainer's approval before anything runs.

**And the plain warning that applies to both:** a witness entry script does execute code from
the fork — that is its job on any input. Treat declaring one on fork pull requests as a decision,
not a default.

## Which model services work

One rule: a service that is OpenAI-compatible and supports native tool
calling. That is not a preference — the reviewer proposes findings *through* tool calls, and a
service without them completes its run and finds nothing. `shard preflight --probe-endpoint`
spends one request confirming this and refuses a bad endpoint rather than letting you pay for an
empty review.

| service | works | what to know |
|---|---|---|
| **vLLM, Ollama, TGI, llama.cpp** | yes | your hardware, your weights, nobody else in the request |
| **OpenRouter** | yes | the default key name. Verified end to end |
| **Google Vertex AI** | yes, via its OpenAI-compatible path | its token is short-lived, so mint it in the step before the scan |
| **Azure OpenAI / SageMaker** | yes, shape-wise | expected rather than measured — a note in an issue is genuinely useful if you run one |
| **AWS Bedrock, natively** | **no** | it speaks its own protocol. Put a translating gateway in front and point `model_endpoint` at that |

Only the first two rows have been executed by us; the rest are the same contract and are listed as
a shape rather than a result.

## Running it outside GitHub Actions

The action wrapper is GitHub-specific; the product is not. It is a container with a command line,
and any CI that can run a container can run it. Pull the published image rather than building it:

```bash
docker pull ghcr.io/takyon236/shard:v2

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

The exit code is the whole gate contract — everything else is reading `shard-out/`. GitLab,
Jenkins, AWS CodeBuild and Google Cloud Build all work (fetch full history on GitLab too). Two
things such a run does not get: the alert upload and the pull-request comment, both of which are
GitHub features. The report, the alert file and the bundles are ordinary files — publish them
wherever your platform keeps build artefacts.

## What a run costs

You supply the model, so your model bill is the price. Every pull-request run this project has
metered:

| changed files | changed lines | size of files touched | cost | model words used |
|---|---|---|---|---|
| 1 | 12 | 2,800 | $0.022 | 21,184 |
| 1 | 1 | 2,900 | $0.026 | 50,547 |
| 3 | 48 | 120,000 | $0.030 | 97,852 |
| 3 | 48 | 120,000 | $0.045 | 131,410 |
| 3 | 82 | 190,000 | **$0.507** | 786,563 |

Five points is a small sample, quoted as a range rather than a formula. **Cost tracks the size of
the files touched, not the size of the change** — 82 lines of documentation cost seventeen times
what 48 lines of real code did. Plan against the high end: it is the one that has happened.

Wall clock is minutes to about fifteen on a small change.

**The cost estimate prints before you spend anything** (`shard preflight`), placed against your own
repository's file sizes — and it is honest about being a floor: later runs with code execution
available used a median 7.9× the words of the original calibration sample.

**A first whole-repository pass is a different job** and measured far above this band — one pass
over 13 chunks of a 1,960-file repository spent 16.6M words. `preflight` says so rather than
quoting the pull-request number at you.

## When something goes wrong

Every row is a behaviour of this build, with the symptom you actually see:

| what you see | what it is | what to do |
|---|---|---|
| exit 2 and a line about an API key | the key's variable is unset. A configuration error, deliberately not reported as a finding | set the variable named by `api_key_env`. Pass the secret through `env:`, never through `with:` |
| a green check, and "no changed files in scope" | the checkout was one commit deep, so there was nothing to compare against. **A green check that reviewed nothing** | `fetch-depth: 0` in the checkout step |
| findings appear, but `gate-eligible` is 0 | no entry script, so nothing could be proven. Working as designed | declare `witness_entry`; start from `shard preflight --entry-template` |
| an entry script exists and findings still cannot gate | the script prints its marker, or dies, on empty input — the baseline reproduces it | `bash .shard/entry.sh /dev/null` must be silent and exit 0 |
| a defect you know is real was refused | a benign input reproduced it, so the observation was not caused by the attack | correct — that is the checker working. Narrow the marker to something only the defect produces |
| the run finds nothing and looks clean | the model service may not support tool calling | `shard preflight --probe-endpoint` — one request, and it refuses a bad endpoint |
| "deep mode is not present in this build" | deep mode is a separate, commercially licensed product | use `diff`, `survey` or `preflight` |
| a C or C++ script demonstrates nothing under a sanitiser | the sanitiser's default exit code is indistinguishable from your program rejecting input | `export ASAN_OPTIONS=abort_on_error=1` so the fault becomes a crash signal |
| exit 127 inside your script | it called a runtime the container does not carry | `shard preflight` names it. No JDK or .NET SDK here — build in an earlier step |
| the run ends `error` with no findings | the report names the cause: a revoked key, an exhausted balance, a rate limit, a mistyped model name, a provider outage | read the cause line. That run's silence is not a statement about your code |
| the alerts or the comment did not appear | the job lacked the write permissions, or no token was passed | see the permissions block above. The log names what it could not use |

**Three things that look like faults and are not.** A finding without a reproduction is
informational by design and cannot fail your build. A review that altered the files it was judging
reports everything as informational — the checkout is fingerprinted before and after, and a run
that modified what it was judging cannot gate; that fingerprint covers your benign controls too,
so a run that deleted them loses its gate rather than quietly judging without them. And
"not adjudicated and cannot gate" is a ceiling doing its job: proving a claim costs real runs of
your script — up to ten per claim, ten more at the base under `fail_on: new` — so the proving
phase carries time and claim limits. A claim past either is still reported in full; it just has no
execution behind it.

## The safety promises, and their limits

**The analysis cannot read outside the folder it was given**, including the code that grades its
own findings — checked at image build time, not promised in prose.

**A repository under review cannot impersonate the product.** The action runs with its working
directory inside your checkout, and without a guard a repository containing a look-alike package
would be loaded and run *as the product*, with full privileges and your key in the environment.
The image switches on the Python safety path that blocks this, and proves it during its own build
with a decoy.

**The build opens no network connections except to the model service you configure.** Anything
beyond that is a reportable defect, not a configuration question.

**The limits, stated as plainly as the promises.** A witness entry script executes code from the
repository under review — that is what turns a guess into a reproduction, and on a fork pull
request it means running a stranger's code with whatever the job holds. And where the runner's
kernel refuses the network-isolation arrangement, your script runs without it and the report says
so. A safety property you believe in that nothing enforces is a defect in itself; both halves are
here for that reason.

Shard is offensive security tooling. Run it only against systems you are authorised to test.
Report problems in Shard itself privately (see [SECURITY.md](SECURITY.md)); escaping the folder it
was pointed at is treated as the most serious class of report, however contrived the setup.

## Deep mode — the other product

Deep mode is **not in this build**, and asking for it fails with a clear message rather than
something unexpected. It is a separate product on a separate image, and the difference is not a
switch:

| | this build — pull-request review | deep mode |
|---|---|---|
| looks at | the change and what it reaches | the whole repository |
| finds | source-code weaknesses, proven by running your script | memory bugs, with the crashing input **constructed rather than waited for** |
| proof | your declared script reproduced it | a sanitiser caught it, and the bundle replays outside the product |
| takes | minutes | hours |
| needs | a standard build machine | a sanitiser toolchain, a container runtime and real CPU |

The honest summary of the boundary: **this build proves what your script can be made to do; deep
mode goes and finds the crash.**

## The licence, in plain words

The full terms are the [LICENSE](LICENSE); this is the shape of them, and where the two disagree
the file wins. **Two doors, and you only need one of them:**

- Public repositories: free, always. Any number of repositories, runs, findings or
  contributors, and no limit on the size of your organisation. A trillion-dollar company
  reviewing its open-source projects needs nothing from us.
- Private repositories: free while your group is under both $5M annual revenue and 10 people
  contributing to the private repositories reviewed. Revenue counts across parent and affiliate
  companies together, so a small team inside a large company is measured by that company. The
  contributor count is of people contributing to the *repositories reviewed*, not your headcount.
  Whether the code is yours or a client's makes no difference — the line is size, not client
  relationship.
- Change Shard itself and run the changed version, and one of two things follows: publish your
  changes under the same licence within 90 days, or buy a commercial licence and keep them
  private. Your own source, configuration, entry scripts and findings are never covered** —
  reviewing your code with Shard never obliges you to publish it.
- Not permitted: offering Shard itself to others as a hosted, managed or embedded service.
  Using it to do your own work is not that.
- Eventually: each version converts to a fully open licence (Apache 2.0) on 2030-08-22, or
  four years after that version was first published, whichever comes first.
- Questions and commercial terms: <licensing@reyse.ai>, and we answer.

## Helping out, and where your work lands

Contributions are welcome, and [CONTRIBUTING.md](CONTRIBUTING.md) is honest about the bar. The
short version:

1. Open an issue first for anything larger than a bug fix.
2. Sign the contributor agreement when the bot asks — one click, once, and you keep your
   copyright. It exists because the free and commercial editions share code, so a fix may need to
   ship in both.
3. Every change needs a **deterministic test** — no network, no model calls. The suite runs with
   no API key at all; use the scripted fakes the existing tests use.
4. Run `python -m pytest -q` and `python -m ruff check shard/` before you push.

**The one fact worth knowing before you spend an evening: this repository is generated.** It is
built from a private development tree by a release job. Your pull request is reviewed here and
**ported upstream** — a maintainer applies it to the development tree, and it reaches you in the
next release as part of a regenerated tree. Your authorship is preserved in the changelog and the
upstream history; what you will not see is your commit sitting on this repository's `main`. The
release also refuses to publish if it finds a commit here it did not generate — work that never
reached the development tree would be destroyed by the next regeneration, so the job stops rather
than let that happen.

**What will be declined**, stated rather than discovered: new configuration options nobody asked
for; speculative abstraction; unrelated reformatting riding on a fix; and the one line that will
not move — **changes that make a run report findings it cannot reproduce**.

**Reporting a false positive is one of the most useful things you can send** — include the report
and, if you can, the reproduction bundle, because the finding's own evidence is what separates a
broken checker from a real defect you did not expect.

## How this project checks itself

- **The core has zero dependencies.** It runs entirely on Python's standard library — every
  dependency would be one more thing inherited by everyone whose build pipeline this runs inside.
  Python 3.11 or newer.
- **The test suite runs with no key and no network**, on every pull request including forks — so a
  stranger's first contribution gets a real green check without a maintainer approving a run that
  could read credentials.
- **CI tests three Python versions** (the floor is the one the shipped image carries; the ceiling
  catches a deprecation before a runner upgrade does), **then builds the container and drives it
  the way GitHub does** — because every input-mapping defect this project has had lived in the gap
  between the source passing tests and the container reading its settings. The build even retries
  on transient registry outages, and still fails if the image is genuinely broken.
- **The published action pins the image by exact digest** — one specific artefact, not a tag
  somebody could move. The Dockerfile still ships: it is what you audit, and what you build if you
  would rather run your own.
- **The image proves its own claims while building**: every language runtime listed above is
  asserted to actually run; the sanitiser is proven by compiling a deliberate memory bug and
  requiring its report; the look-alike-package decoy is proven to lose. A claim nobody has checked
  is not shipped as a claim.
- **Versioning carries one local rule, stricter than the usual:** a change that can turn a green
  build red is a major version, even when it is a bug fix. A customer who pinned a major and
  merged on a Friday is entitled to the same answer on Monday. The changelog records every change
  that can alter a verdict, a gate decision, or an artefact a customer parses.

## What changed, release by release

Full detail in [CHANGELOG.md](CHANGELOG.md); the shape of it:

| version | date | the headline |
|---|---|---|
| 1.0.0 | 2026-08-22 | first published release: the free tier, findings delivered (alerts, comment, step summary), benign-input directory, licence, open contributions, testable package |
| 1.1.0 | 2026-08-24 | action pulls a published image instead of building 934 MB on every job; the `v1` pin resolves; plain-language docs for other CI systems; examples cover five languages; entry templates stop advertising switched-off proof kinds |
| 2.0.0 | 2026-08-24 | a red-team audit of the ceilings, the perimeter and the tamper controls — 23 findings, 4 rated fatal; the fixes: retries billed as turns, atomic spend guard, time ceilings that actually bound, tamper watch extended to the benign controls, secrets scrubbed from output by value, the entry script network-isolated like the reviewer's shell |
| 2.1.x | 2026-08-25 | the two-door licence (public free always; private free under the size line); honest preflight costs (a stated floor, words re-measured); the report says what the review actually ran; generated-repository fixes |
| 2.2.0 | 2026-08-27 | `shard-result.json` — the whole run as one versioned document with a `limits` array; deep mode gains generated C harnesses and tooling |
| 2.3.0 | 2026-08-31 | findings carry a weakness class and a severity a dashboard can rank; alert identity stabilised on the crash state so alerts stop churning and losing their triage state |

Before the first release: 263 commits with no tags, not reconstructable here.

## Where the authoritative words live

| question | the file that decides |
|---|---|
| the terms | [LICENSE](LICENSE) |
| every input and output, exactly | [action.yml](action.yml) |
| what changed and when | [CHANGELOG.md](CHANGELOG.md) |
| how to contribute | [CONTRIBUTING.md](CONTRIBUTING.md) |
| reporting a security problem | [SECURITY.md](SECURITY.md) |
| worked examples | [examples/](examples/) |
| the code | [shard/](shard/) — one reading order: `cli.py` in, `gate.py` for the verdict rules, `witness.py` for how proof is checked |



