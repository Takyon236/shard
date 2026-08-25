# Changelog

**Why this file exists, stated once.** Shard can fail a build, and a security gate whose behaviour
changes under an unpinned ref is not something a regulated buyer will install — so every change that
can alter a **verdict**, a **gate decision** or an **artefact a customer parses** belongs here, and the
ones that cannot are not padding to add.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning: semantic, with one
local rule that is stricter than semver and exists because of what this product does —

> **A change that can turn a green build red is MAJOR, even when it is a bug fix.** Widening what
> gates is not a patch. A customer who pinned `v1` and merged on a Friday is entitled to the same
> answer on Monday.

## [2.1.0] — 2026-08-25

**Nothing here widens what gates.** Three of the four changes are about what the product TELLS you —
what a review ran, what it will cost, and what the package says about itself — and the fourth is a
file that keeps a contributor's checkout tidy. No demonstration kind was added or withdrawn, no
action input changed, and `@v2` continues to resolve.

### Added

- **A `.gitignore`, so following this repository's own instructions leaves a clean tree.**
  `CONTRIBUTING.md` invites pull requests and `README.md` promises `pip install -e ".[dev]" && pytest`
  works from a clean clone. Both were true and neither was tidy: the suite compiles the C example and
  Python writes bytecode, so a contributor's first `git status` listed files they did not create — and
  `git add -A` before a pull request would have committed a 31 KB binary into a repository that ships
  source.

### Fixed

- **The published package named the private development repository.** Three comments carried it —
  the action entry point named it outright, and a measurement tally and the cost-calibration table
  each mentioned it once — and it has been in the distribution since 1.0.0. The sibling name for the
  paid tree had been substituted since that table was written; this one was in neither the
  substitution list nor the check that is supposed to catch a miss. It grants nobody access, and that
  is not the point: an artefact of this kind should not tell a reader where the unpublished half
  lives, any more than it should name the runs it was measured on.

- **`preflight`'s cost estimate was taken before the product could execute code, and it reads as a
  range rather than as a floor.** Every priced run behind the band was metered on 2026-08-12/13; the
  agent gained the ability to run things in your checkout on 2026-08-19, and observations enter the
  transcript and are re-sent on every turn after — the same mechanism the band's own `what drives it`
  line names for file reads. Nothing re-measured it. Five runs of the shipped artefact on real
  third-party repositories used a **median 7.9x the tokens** of the calibration sample, two of them
  above its maximum. The dollar figure cannot be corrected from an endpoint that reports no price, so
  it now says plainly that it is a floor and by how much — and the **token** band, which those runs
  can correct, is re-measured and printed. That last part is also the first cost number available at
  all to a customer on a self-hosted vLLM or a subscription, where dollars are never reported.

- **The report now says what the review actually RAN.** The header stated `witness | none declared —
  nothing in this run could be proven by execution`, which is true of *adjudication* and reads as a
  claim about the run — while the agent had been executing code in your checkout since 2026-08-19 and
  no artefact said so. Measured across five reviews of real public-sector repositories: every run
  executed, 30 to 36 commands apiece, and one report carried a finding whose own text read *"I
  reproduced this by executing the exact helper …: it throws"* two paragraphs below the line saying
  nothing could be proven by execution. Both sentences were correct and the artefact contradicted
  itself on one screen. A new `observed` row sits directly under `witness` and prints both. A run that
  COULD execute and never did says that too — it is the fact a reader weighing an unverified finding
  needs most, and it was previously invisible.

## [2.0.0] — 2026-08-24

**A red-team audit of the ceilings, the perimeter and the tamper controls**, run against this tree on
2026-08-24. Twenty-three findings; six defences held and are recorded as holding; four were rated FATAL
and three NEAR-FATAL. This section is the fixes.

**If you are upgrading from `v1`, this is the whole of what can behave differently for you.** Every
change below either narrows what gates or bills you more honestly for what you already spent. One does
neither, and it is why the number moved:

> **BY THIS FILE'S OWN STRICTER RULE THIS IS A MAJOR RELEASE, and the reason is one line of it.** The
> transport's absolute ceiling now bounds a whole retry ladder rather than each attempt in it, so a run
> whose provider stalls for a quarter of an hour per turn now ends `error` where it previously ground
> on and ended `budget` when the wall-clock ceiling caught it between steps. `error` is `EXIT_CONFIG`
> under `fail-on: reproduced` or `new`, and `budget` is `EXIT_OK` — a green build can become a red one.
> Everything else here NARROWS what gates, which is never breaking. This one does not, so the rule
> applies.

**What that costs you if you pinned `@v1`, said plainly rather than left to be discovered.** The major
alias is what makes a pin mean *"get fixes without editing your workflow"*, and it only ever moves
inside a major. `@v1` therefore stays on 1.1.0 and does **not** receive any of this — including the
metering fixes, which are the ones that were quietly costing money. Move the pin to `@v2` to get them.
The two files you declare (`.shard/entry.sh` and `.shard/entry.sh.benign/`) are unchanged, no action
input was renamed or removed, and no demonstration kind was added or withdrawn: `offered_expectations()`
returns the same two it returned in 1.0.0. The edit is the pin and nothing else.

### Fixed

- **The dollar ceiling was crossed by every retry the provider billed for.** `chat` makes up to five
  requests per turn and returned only the last, so a refusal that burned 9,003 prompt tokens, an empty
  completion, and every attempt aborted mid-stream entered the meter at **$0 and zero tokens** — while
  the provider charged for all of them. Worse than a wrong number: `--max-spend-usd` reserves the price
  of the most expensive call the run has made, so the guard was calibrated on the same understated
  figures and under-reserved by exactly the factor by which it was under-billed. A turn is now billed as
  a turn. What still cannot be priced — a stream aborted before any usage arrived — is COUNTED, so a
  figure that is a floor can say so instead of reading as a total.
- **One step could make two provider calls and be charged for one.** A forced `tool_choice` a provider
  rejects is answered, read and billed; the degrade-safe retry then overwrote the result.
- **The spend guard was a read, and the governor is shared.** Deep mode fans sub-loops out over one
  governor on a thread pool, and each read the same headroom, each concluded it could afford a call, and
  each made it — so the cap was crossed by as many calls as there were loops, not by the one call the
  documented residual accounts for. Headroom is now claimed atomically and released on every exit.
- **`max_minutes` bounded the run between steps and nothing inside one.** The transport's 900-second
  absolute ceiling applied to each attempt of a five-rung retry ladder, so a single step could run for
  over an hour against a ceiling of sixty minutes. It is now the ceiling on a turn.
- **Adjudication ran outside every ceiling in the product.** Tokens and dollars are bounded by the
  governor, the loop by `max_steps`, each execution by its own timeout, the agent's executions by their
  own budget — and the number of claims by nothing, while each surviving claim buys up to ten executions
  of your entry point and ten more at the base revision. A wall-clock ceiling and a claim backstop now
  bound the phase. A claim past either is still reported; it becomes a hypothesis, which is what a claim
  nobody executed is.
- **Deleting the benign controls mid-run was invisible.** They are the differential that makes an
  `output_marker` finding sound, and they were in neither tamper digest — so one `rm -rf` restored the
  configuration measured in 2026-08-12's audit to forge four demonstrations out of four, and left the
  check that watches the entry point and the changed files perfectly quiet. The digest now covers the
  witness contract: the entry point and the controls it declares.
- **Stripping our credentials from the entry point's environment was never enough.** It runs as root in
  the same container as the reviewer, so `/proc/1/environ` still holds the block the kernel copied at
  exec time whatever we do to the child's own environment — and its output is published back to whoever
  opened the pull request. Credentials are now removed from captured output **by value**, before
  adjudication rather than only before reporting, so a marker built on our own key cannot demonstrate
  anything either.
- **The customer's entry point was the one thing never network-isolated.** The model's shell has been
  wrapped in a network namespace since it existed, and the attacker-authored script it is graded on was
  not — on a runner where the kernel grants it, the weaker half of the perimeter was protecting the
  stronger one. Both now take the same prefix, along with every benign control, so the differential
  stays a comparison of one program with itself. Where the kernel refuses — a stock GitHub-hosted runner
  — nothing changes and the run says so, as it always has.

## [1.1.0] — 2026-08-24

**Nothing here widens what gates**, which is why it is a minor release under this file's own stricter
rule. The adjudicator offers the same two demonstration kinds it offered in 1.0.0; what changed is
what the product *tells you* about them, how the image reaches your runner, and how much of the
product you can try before spending anything.

### Added

- **The action runs a published image instead of building one on your runner.** `runs.image` named
  `Dockerfile`, so GitHub built 934 MB at the start of **every job**, for every customer. The release
  now publishes the image and pins the manifest to it **by digest** — one exact artefact, not a tag
  somebody can move. The `Dockerfile` still ships: it is what you read to audit what executes in your
  pipeline, and what you build if you would rather run your own.
- **`uses: Takyon236/shard@v1` resolves.** It did not. The published repository carried `main` and
  `v1.0.0` and no `v1`, while every documented example named `@v1` — so the first line anybody copies
  failed with *"Unable to find version v1"*. The release now publishes the exact version and moves a
  major alias, which is what makes pinning a major mean "get fixes without editing your workflow".
- **Running it outside GitHub Actions is documented.** The product never was GitHub-specific: it is a
  container with a command-line interface, and the action is a thin mapping from `INPUT_*` onto it.
  GitLab, Jenkins, CodeBuild and Cloud Build, with the exit code as the whole gate contract — and an
  honest note that the code-scanning upload and the pull-request comment are GitHub APIs such a run
  does not get.
- **Which endpoints actually work**, in one place. The headline promised *"Bedrock or Vertex in your
  own cloud account"* while a later paragraph refused both by name. Vertex works through its
  OpenAI-compatible path; **Bedrock does not** — it speaks SigV4 and needs a gateway in front. The two
  rows we have executed ourselves are marked as the only measured ones.

### Changed

- **`.shard/entry.sh` templates now list only the demonstration kinds this build adjudicates.**
  `shard preflight --entry-template` printed four — `fatal_signal`, `output_marker`, `nonzero_exit`
  and `unhandled_exception` — against an adjudicator that offers the first two. The other two are
  measured and deliberately off, so an entry point built around either produced a witness nothing
  could claim: the run completed, every finding stayed a hypothesis, and nothing gated. No error was
  raised at any point, which is what made it expensive. The template is now rendered from the offered
  set at call time, so a lever cannot be advertised while it is off.
- **The generated entry point for a Go repository names a built binary rather than `go run`.** There
  is no Go toolchain in this image, so the line as generated exited 127 inside the container. Go now
  has the arrangement Rust, Java and C# already had: run the artefact your build step produced.
- **The manifest said this container carried "python and bash and NOTHING ELSE — no gcc, no clang, no
  make."** It carries node 22, a headless JRE, ruby, php, the .NET 8 runtime and gcc/g++, and asserts
  at build time that each one runs. `witness_entry`'s guidance now matches the image, including the
  part that survives the correction: your build belongs in an earlier step, because no JDK and no
  .NET SDK are here.
- **`examples/` covers five languages** — Python, JavaScript, Ruby, PHP and C — each a self-contained
  project with one real defect, a real entry point and real benign controls, and each executed by the
  test suite in both directions rather than only read. That is five of the seven languages this image
  can gate. An example whose runtime is absent skips by name instead of failing.
- **`README.md` gained a quickstart, worked examples and a troubleshooting section.** Everything the
  free tier could do without a key, a secret or a repository — `survey`, `preflight`,
  `--entry-template` — was reachable only from `CONTRIBUTING.md`, which is addressed to people who
  want to change Shard rather than use it.

### Fixed

- **AddressSanitizer is now asserted in the image build.** The README claims C and C++ are
  ground-truthed under ASAN and the manifest tells you how to arrange one; nothing checked that
  `-fsanitize=address` could link here. The build now compiles a deliberate heap overflow and
  requires ASAN's own report, because a toolchain that accepts the flag and detects nothing would
  pass a plain compile-and-run check and leave every C finding undemonstrable.
- **The changelog named a workflow that does not exist in this repository**, and the release build's
  own reference check could not see it: the rule resolves paths, and a bare filename is not one.
- **A contribution merged into the published repository would have been destroyed.** Every release
  replaced that repository's history wholesale, so anyone who had cloned it could no longer pull and
  any commit on it — a merged pull request included — vanished at the next publish. The release now
  extends the published history, refuses when it finds commits it did not generate, and
  `CONTRIBUTING.md` states the one mechanical fact that decides what you see happen to your work:
  a pull request is reviewed there and **ported upstream**, arriving in the next release as part of a
  regenerated tree rather than as your merge commit.
- **The image is 934 MB, not the 890 the documentation claimed**, and about 810 MB of that is the
  language runtimes rather than 680.

## [1.0.0] — 2026-08-22

**The first published release.** `uses: Takyon236/shard@v1` resolves from this tag onward.

What is being published is the FREE tier: `survey`, `preflight` and `diff` — a pull-request review that
reports a finding only when it can attach an input that reproduces it. Deep mode is a separate,
commercially licensed image and is excluded from this artefact by construction; the build fails rather
than emitting a tree that contains it.

### Added

- **The findings have somewhere to go.** `$GITHUB_STEP_SUMMARY` on every run (no token needed),
  a code-scanning SARIF upload and a pull-request comment behind a new `github_token` input, and a
  complete workflow in `README.md`. Until this, the SARIF, the report and the reproduction bundles
  were written to a directory on a runner that is destroyed when the job ends — measured on a run
  that gated a build, where the only way anybody read the finding was `gh run download`.
- **A human-readable artefact for `survey` mode.** It wrote JSON and nothing a person reads, and
  survey is the mode a customer meets first. Same `shard-report.md` filename diff mode uses, so a
  workflow consuming `report-path` does not branch on the mode.
- **`.shard/entry.sh.benign/`** — a directory of your own benign inputs, one per branch the entry
  point can take. Any demonstration a benign input also reproduces is refused.
- **A licence.** Business Source License 1.1, with an Additional Use Grant that permits production use
  inside your own pipelines, on your own repositories, at any scale — and forbids offering Shard to
  third parties as a service. It converts to Apache 2.0 on 2030-08-22. The grant is written the way it
  is because a bare BUSL forbids production use, which would forbid the only thing this product is for.
- **Contributions are open.** `CONTRIBUTING.md`, a bot-enforced CLA, a code of conduct, issue templates
  for bug reports and false positives, and a CI workflow that runs on every pull request including
  from forks — with no secret in it, so an outside contributor gets a real green check without a
  maintainer approving a run that could read credentials.
- **The published package is testable.** A test suite over the shipped surface — the gate's exit
  codes, diff scoping, adjudication and its benign control, the report and SARIF contract, and an
  end-to-end run of the CLI — plus a `pyproject.toml`, so `pip install -e ".[dev]" && pytest` works
  from a clean clone.

### Changed

- **Every report opens with a fixed header** — verdict, trust, reviewed, gate, witness, cost — because
  four real runs could not be told apart by reading the artefact. A fact the run does not know omits
  its row rather than printing a zero.
- **`Finding.message` is rendered as a blockquote.** The model may format its own paragraph and may
  not emit block structure that belongs to the document — an unbalanced fence in the first finding's
  prose used to put every finding after it inside a code block.
- **`--max-spend-usd` is a ceiling rather than an estimate.** The run now stops BEFORE a model call it
  cannot afford at the highest price it has already paid, instead of noticing afterwards that a cap was
  crossed. Measured before the change: a $2.50 cap billed $2.5866. Two cases still cross it by at most
  one call and both are now stated in the flag's own help — the first call of a run has no observed
  price behind it, and any call can be priced above every call before it.
- **`alexandria` and `alexandria_mirror` are renamed `library` and `library_mirror`** (action inputs
  and CLI flags). They named an internal codename that means nothing to a reader of this repository.
  Renaming is free before the first tag and a breaking change after it.
- **`LUCENT_LOG` is now `SHARD_LOG`.** Same env var, correct name.

### Removed

- **The `scope_file` input.** It was declared and read by nothing, honestly labelled as such, and a
  security product shipping a security control that never executes is a review liability the honesty
  does not remove. The module behind it is unchanged; the input returns in the commit that wires it.

### Fixed

- **The report named the wrong repository** when the scanner and the target differ. `--slug` reaches
  all three modes; the SARIF upload and the comment now refuse outright when the reviewed repository
  is not the one the token belongs to.
- **`gate_eligible` was forgeable with one byte.** Replaced by seven independent payload readings.
- **The diff was taken against the working tree** rather than `base_ref...HEAD`.
- **A filename could write its own paragraph into the system message.**
- **A run that ends `error` now says WHY.** A revoked key, an exhausted balance, a rate limit, a
  mistyped model name and a provider outage all reported the same bare word, and the first four are
  things you fix in a minute. The report now names the cause and what to do about it — and says
  plainly that the run's silence is not a statement about your code.
- **Every model request announced a private repository.** `HTTP-Referer` and `X-Title` carried an
  internal project name to the provider on every call, from your runner. They now name this
  repository and this product.
- **Two error messages cited documents that do not exist in this distribution**, so the one
  instruction they gave was unfollowable.

## Before this file

263 commits with no tags. Behaviour before the first release is not reconstructable from this file, and
nothing here should be read as describing it.
