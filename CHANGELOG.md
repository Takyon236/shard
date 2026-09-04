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

**AND THE MAJOR TAG FLOATS, which is what gives that rule its teeth.** Alongside each `vX.Y.Z` this
repository carries a moving `vX`, and `README.md`'s own examples say `uses: Takyon236/shard@v2`. So a
release lands on every customer pinned to the major tag automatically, with no opt-in and no review —
**the major number is the only thing that holds a change back from an installed customer.**

That is stated here because the rule above is unreadable without it. Deciding MAJOR against MINOR is
deciding whether a change reaches installed customers tonight, and until 2026-08-31 the rule was
written as a principle with the mechanism that makes it consequential recorded nowhere.

## [Unreleased]

## [3.0.2] — 2026-09-04

**Documentation only. No code changed.**

The published README was written in this project's own maintainer voice — block capitals inside the
workflow you are meant to copy, a comment in the sample entry point telling you which step people
skip, two sections sharing a title, and the reasoning behind a decision placed ahead of the decision
itself. It now opens with what Shard does, who it is for and what it costs, then a five-minute run
that needs no API key, then the Action in one clean block.

**No factual claim moved.** Every number, limit, refusal and negative result is carried across: the
26-of-26 canary count, the unpublished corpus behind it, the languages that can be read but not
gated, the exit-code contract, and the cost table. Checked by an independent read of the built
distribution rather than of the source.

Three real defects were found while rewriting, and fixed:

- the README wrote `fail-on:` in one place, a spelling neither the Action input (`fail_on`) nor the
  CLI flag (`--fail-on`) accepts, so a customer copying it would have been ignored in silence
- the cost table said to read the dollars as a floor but had dropped the clause explaining that the
  top of the table is not the top of what has happened — the only place the rewrite understated a
  caveat, restored
- the issue template told you to run `shard preflight` to check whether your endpoint qualifies;
  the command that answers that is `shard preflight --probe-endpoint`

`SECURITY.md` is reordered around what a security team needs to decide whether to run this: what
executes where, what leaves the runner and to whom, and what you control. Its network claims are
unchanged and remain pinned to what the code imports.

## [3.0.1] — 2026-09-04

**PATCH. Nothing that decides a verdict or a gate changed** — both fixes correct what a run TELLS you
about itself, and neither can turn a green build red.

### A run that spent its whole execution budget said it was complete

Measured on a live review of a real repository: every one of the 24 allowed executions was used, the
model's own final turn opened *"I have no tool budget left"* at turn 20 of an allowed 40, and the
report's trust row said `complete run`, the result document said `"complete": true`, and the run log
said the ceiling "refused nothing, so no claim here was cut short by it".

The signal everything read was whether a call had been REFUSED. It never is: the model is told how
many executions remain, so it stops asking rather than being denied, and the ceiling binds silently.
A spent budget is now reported as its own state on all three surfaces, distinct both from a refusal
(which proves the run was cut off) and from a run that simply finished. **If you see it, raise
`--max-steps`.**

### The exit code, for everyone not on GitHub Actions

The README told you `0` passes and non-zero means a demonstrated finding, and called that "the whole
integration contract". The code has always said otherwise, and the difference matters most to the
people this section is for, who have no `status` output to read:

    0   nothing gated — including a review a ceiling cut short
    1   the ONLY code that means a finding matched your --fail-on rule
    2   Shard could not do what you asked — a bad argument, an unreadable repository,
        an unset key variable, or a review that ended in `error` under --fail-on reproduced/new

**Branch on `1`, never on "non-zero".** Following the old sentence, a revoked key or an unreachable
endpoint was indistinguishable from a vulnerability. Under the default `--fail-on none` a `1` is
unreachable, so a non-zero exit there is always a `2`.

## [3.0.0] — 2026-09-03

**MAJOR, AND ONE CHANGE DECIDES IT.** `mode: survey` now REFUSES five inputs it used to accept and
silently discard. A workflow that sets any of them on a survey job exits 2 where it exited 0:

    survey + model_endpoint    the survey makes no inference call
    survey + scan              the survey has no budget for a profile to size
    survey + max_steps         the survey takes no turns
    survey + hunk_radius       the survey reads no diff
    survey + state_repo        the survey writes no state

Under this file's own rule a change that can turn a green build red is MAJOR even when it is a bug
fix, and the major tag floats — so this reaches every customer pinned to it with no opt-in. **Pin
`@v3` when you are ready to take it.** A sixth refusal, `survey` + `fail_on`, was written and then
withdrawn before release: a reusable workflow sets `fail_on` once for both jobs, so refusing it
would fail a build for a setting that is merely vacuous on that mode rather than wrong.

Nothing else widens what gates. The gate's own decision is untouched, and both free-tier adjudication
paths only ever REMOVE a way a finding could be reported.

### The reproduction bundle now reproduces

The artefact this product is built around did not work. `reproduce.sh` mixed a repo-root-relative
entry point with a bundle-relative input, so **from the repository root it printed nothing and exited
0** — indistinguishable from "no finding was made" — and from the bundle directory it exited 127. The
reproduction itself was real the whole time; only the command that shipped could not reach it.

It now resolves both halves from its own location, enters the directory the verdict was reached in,
shell-quotes the entry path (an entry named `.shard/x;touch OWNED` previously ran `touch`), refuses
loudly with a sentence naming what is missing instead of exiting 0, and records the revision it was
produced against so a replay on a moved tree says so. Verified from eight working directories,
including a path containing a space and a bundle unpacked outside the checkout. Deep-mode bundles
carried the identical defect and are fixed with it.

### The survey report names files and lines

It counted and named nothing: 744 candidates on one repository in 1,690 bytes of totals, with no path
and no line anywhere in it. It now lists candidates with their locations, ordered so that any prefix
holds each directory in proportion to its size — sliced alphabetically, the first twenty were all
vendored test code and none of the 415 candidates in the repository's own source. It states plainly
when the list is a sample rather than a ranking, and the JSON says so too.

### What a failed run tells you

A run ending `error` carried an empty `error_kind` and an empty `error_advice`, and the only copy of
the cause was in a journal that contains excerpts of your source and so cannot be forwarded. The
cause now reaches the report. The model that actually answered is read off the response and recorded,
which matters on any endpoint that substitutes one model for another.

`model` is no longer rewritten to a provider-specific slug on endpoints that are not that provider —
the documented self-hosted example previously died at HTTP 400 before reading a file.

### Corrections to the shipped documents

`SECURITY.md` said the build has no network capability beyond the model endpoint. It does: the
recommended workflow posts to the GitHub API, and state runs `git push`. Both are now described.
`CONTRIBUTING.md` told you to run tools the documented install never installs. The action manifest
now states the witness entry point's calling convention — the payload is a file and its path is
`$1` — because getting it wrong completes the run, reports findings and gates nothing.

## [2.4.1] — 2026-09-02

**No code changed.** The 2.4.0 and 2.4.1 distributions were built and diffed, file for file: three
files differ, and two of them by one line each — the version string. The third is this entry. Nothing
that decides a verdict, a gate or an artefact you parse is different.

This entry exists because 2.4.0 was cut, tagged and never published, and the reason is worth keeping.

The release path refuses when the published repository carries a commit this project's build did not
generate — a real guard, because that repository is GENERATED and a release regenerates it, so a
contributor's merged work would vanish without a word. It refused correctly on a contributor's ignore
rule. The content had already been carried into the source the build reads, so regenerating over it
lost nothing, and yet the commit stays in the published history for good: the same refusal would have
fired on every release afterwards. The only way past it discards published commits.

**So shipping meant using the discard flag as routine — the exact event the guard exists to prevent,
performed as procedure.** The refusal now clears once a commit is recorded as absorbed, by full hash
and by nothing else, and recording one costs a test that proves the content really is in the tree. An
unrecorded commit still refuses, and an abbreviated hash is a hard error rather than a quiet
exemption, because a prefix is a pattern and a pattern can match something nobody read.

## [2.4.0] — 2026-09-02

**THIS IS A MINOR RELEASE, and the one change in it that can turn a green build red is why that had
to be argued rather than assumed.** A generated harness refused for never firing exits 2, and
`--fail-on none` does not suppress it: `none` decides whether a FINDING fails your build, and a
refusal to produce a result at all is not a finding. Under this file's own stricter rule that is the
shape of a MAJOR.

It is MINOR because of where that change can land, and only that. The refusal exists in deep mode
alone; deep mode ships as a separate image pinned per version, with no alias that moves; and taking a
new deep version is an edit you make to your own workflow. **Nothing that rides the floating `@v2`
tag widens what gates** — the free tier's new memory ceiling is handed to the model as an observation
and never reaches the exit code, and both free-tier adjudication fixes below REMOVE a way a finding
could be reported rather than adding one.

**One leg of that argument used to be `--fail-on none`, and that leg is false.** It is written down
here rather than re-derived at the next cut, and it does not survive a moving major tag on the deep
image: the day that alias exists, this same change is MAJOR.

### Changed

- **A model-authored command now runs under a memory ceiling, and it can be killed by it.** The shell
  the review hands the model is bounded at 4,096 MB resident across the whole process tree, and a
  command that exceeds it is killed and reported as having been killed rather than as having failed.
  Raise or remove it with `SHARD_MEM_CAP_MB`.

  This is a **free-tier behaviour change** and it reaches you on `@v2` with no opt-in, which is why
  it is here rather than in a commit message. It was written after model-authored code exhausted the
  memory of the machine running it four times. A command that legitimately needs more than 4 GB —
  a large build, a fuzzer with a big corpus in memory — will now stop where it previously did not.

- **A generated harness that cannot be shown to read your input is refused**, and the run exits 2
  rather than reporting a clean result. `--fail-on none` does not suppress it: `none` governs whether
  a FINDING fails the build, and this is a refusal to produce a result at all. A harness that never
  fires reports "no defects" for a reason that has nothing to do with your code, and this product
  will not do that quietly.

  Deep mode only, and deep mode ships as a separate image pinned per version.

### Fixed

- **A program that rejects malformed input by exiting non-zero is no longer read as a crash.** On
  your own code — as opposed to a benchmark build known to carry a defect — a fault is a signal or a
  sanitiser report, and an ordinary rejection is neither. Three of the four places that asked the
  question were using the benchmark rule, so the shape `if corrupt: return 1` was reported as a
  crash, and one of them could withdraw an already-clean result over it.

- **A finding can no longer be manufactured out of the filename we stage your input under.** The run
  under review and the control runs it is checked against now execute a byte-identical command line.
  They previously differed in the last argument, so a marker overlapping that path was present for
  the run and absent for every control by construction — a differential built out of our staging
  convention rather than out of your program. **Free tier, and it decides whether a build fails.**

- **Your credentials survive one more class of accident.** Output published back to a pull request is
  scrubbed of secret values in several encodings rather than only verbatim, so a value that was
  base64-encoded or hex-dumped on its way out no longer passes through. This is a cost increase, not
  a closed channel, and `SECURITY.md` now says which residuals remain.

- **A program that prints without stopping can no longer exhaust the reviewing process.** Output from
  code under review is captured up to a ceiling and says so when it truncates, instead of being
  accumulated whole.

- **The published action manifest reads as prose again.** Removing the paid-mode paragraphs used to
  cut individual lines out of the middle of a description, leaving sentence fragments; `max_steps`
  had lost the sentence that says what it is and `fail_on` was left stating the opposite of its own
  paragraph. The build now refuses a manifest whose description is empty or ends mid-sentence.

- **`from shard import *` works in the published package.** Its export table named four symbols the
  distribution does not carry, including two belonging to modules removed from the build on purpose.
  The table is narrowed to what ships and the build refuses to emit one that is not.

- **`SECURITY.md` no longer claims this build makes no network requests.** It does, on the default
  configuration: the GitHub API when you pass a token, your git remote with `--state-repo`, and
  whatever the agent's shell can reach on a runner whose kernel refuses a network namespace — which
  is every stock GitHub-hosted runner. The file now says so and tells you what to allowlist.


- **A build failure now tells you which symbol is missing and which of your files defines it.** When
  Shard generates a harness and the link fails, it used to report the last line the toolchain
  printed — which for a link failure is always `collect2: error: ld returned 1 exit status`. That
  names nothing and suggests nothing.

  On a real library this was the whole difference between a refusal and a working harness: every
  named source compiled, one symbol was undefined, and the file defining it was one Shard could have
  found by looking. It now says so, and says that this is a `sources` problem rather than an `entry`
  problem, so the fix is one field rather than a new guess at the function.

  Compiler output is also read and reported in a fixed language now. `ld` translates its
  diagnostics, so the text of a refusal previously depended on the locale of the machine that ran
  the scan.

### Added

- **Deep mode can now generate a harness for a decompressor.** Shard writes the fuzzing body itself
  when your repository ships no fuzz target, and it could only ever call two shapes of function: one
  taking a string, and one taking a pointer and a length. Across eleven open-source C projects
  **3.1% of declarations fit either** — and six of the eleven failed for that reason alone, because
  the library's real entry point decompresses or decodes into a buffer the caller supplies.

  The new shape covers `f(void *dst, size_t dstCapacity, const void *src, size_t srcSize)` — the
  form `ZSTD_decompress` and its equivalents take. Both buffers are allocated at exactly the size
  the function is told it has, so a write past the capacity it was granted, or a read past the
  declared length, lands outside the allocation where the sanitiser sees it rather than in slack.

  Nothing changes about what Shard will call: the shape is inferred from your header's own
  declaration, a `const` destination is refused rather than guessed at, and the generated harness
  must still show that your input reaches code that reads it before it is accepted.

- **And for a library that hands you a context object first.** The commonest shape of C parser API
  is not a free function — it is *make a parser, feed it bytes, destroy it*, and Shard could not call
  one. It now finds the constructor and destructor in your own headers, including when they are
  wrapped in an export macro, which is where most libraries put them. Across 28 open-source
  checkouts this reaches **125 entry points in 10 projects** that were previously uncallable,
  including libexpat's `XML_Parse`.

  You still name only the entry point. The constructor, the destructor and the context type are
  found mechanically from your headers, never chosen by a model, and each is checked against a strict
  whitelist before it is written into the generated harness — a name that is not a plain identifier,
  or a type that is not a plain type, is refused rather than compiled.

  Output parameters after the input are given a real buffer rather than a null pointer. That sounds
  like a detail and is not: a decoder handed nowhere to write validates, returns an error, and never
  looks at your input — producing a harness that runs clean forever and finds nothing.

### Fixed

- **Deep mode refused repositories it can in fact analyse, because of which eight files it happened
  to look at.** To decide whether it can generate a harness for your project, Shard picks a sample of
  your C and C++ sources and checks whether any of them compile on their own. That sample was filled
  in whatever order the filesystem returned, so on a repository with several source directories it
  came entirely from the first one — and if those particular files needed a header your build
  generates, the whole repository was declined.

  Measured across twelve open-source C projects: **six of the twelve** drew the entire sample from a
  single subtree. On one of them the sample was taken from a command-line tool's test directory while
  the library itself was never examined. The sample is now drawn across directories, and deep mode is
  offered on **7 of the 12** rather than 5 — with no change to how many of your files are checked.

- **The same repository could get two different answers on two machines.** Directory order from the
  filesystem also reached the language tally on large repositories, where the scan stops at a file
  limit: which directories it reached decided which languages were reported, and that is what decides
  whether deep mode applies at all. Two checkouts of one project could disagree about whether it
  contains memory-unsafe code. The scan is now ordered, so a verdict you dispute is a verdict you can
  reproduce.

### Added

- **A generated harness that never fires is now refused instead of run.** When Shard writes the
  harness body itself, "it compiled and the control inputs came back clean" was the entire
  acceptance test — and a function that takes your bytes and ignores them passes it perfectly. It
  links, it returns 0 on an empty file and on random bytes, and it then fuzzes nothing for the whole
  budget while the run looks healthy.

  Before accepting a generated harness, Shard rebuilds it once with instrumentation and feeds it
  seven structurally different inputs of identical length, reading two things: how much distinct code
  each input reaches, and whether the input's own bytes ever arrive at a comparison. Only when
  neither moves across all seven is the harness refused — with the per-input numbers attached, so you
  can see the reading rather than take the verdict. The measurement is written beside the harness on
  every run, including the ones that pass.

  Two signals rather than one, because coverage alone is not enough to refuse on: a parser guarded by
  a magic prefix runs exactly the same code on every input that lacks the prefix, and refusing it
  would reject a working harness for one of the most common shapes a file format has. Watching the
  comparisons catches that the bytes did arrive.

  **It refuses; it does not certify.** Passing this check is not a promise that the harness can find
  anything — a function that only checks a magic number passes it too — so nothing is accepted
  *because* of it, only rejected. A refusal names both of its possible causes: the entry point may
  ignore its input, or the generated body may not be delivering it. And when the instrumented rebuild
  itself fails, the result is *unknown* and nothing is refused: the harness has already compiled once
  by that point, so a second build failing is a compiler-flag interaction, not evidence about your
  code.

  This only affects deep mode on repositories with no fuzz target of their own. A run that would
  previously have completed with no finding may now stop early and say why.

## [2.3.0] — 2026-08-31

### Added

- **A finding now carries its weakness: a CWE, a severity a dashboard can rank, and a crash state.**
  A Shard rule reached GitHub code scanning with a level and nothing else, so an estate could
  neither sort it by severity nor slice it by weakness. On a product whose position is that GitHub
  *is* the control plane, that left the reporting surface half empty. The SARIF rule now carries
  `security-severity`, `tags` including `external/cwe/cwe-NNN`, `problem.severity` and `precision`;
  `shard-result.json` carries the same values in a new `weakness` object, derived from the same
  place so the two artefacts cannot disagree; the report names the crash state and the CWE.

  `weakness` is **null**, and the SARIF fields absent, when the observed output was not a sanitiser
  report. There is no default severity and no fallback CWE. A finding that says how a defect was
  *demonstrated* is not a finding that says what class it is, and Shard does not invent a defect
  class.

  The severity bands are ClusterFuzz's, adopted unchanged including its cap: a `WRITE` bumps one
  band, and nothing reaches `critical` from a crash type alone. How confident Shard is that the
  alert is real is a different axis and rides on `precision`, which is `very-high` only for a
  finding carrying a replayed reproducing input.

- **Deep mode proposes which function to fuzz, on a repository that ships no fuzz target.** When
  Shard generates the harness body itself, it previously showed the model a list of header paths and
  asked it to name an entry point. On a well-known project that works; on your code it was a guess,
  and a wrong guess fuzzes the wrong thing and quietly finds nothing. Discovery now offers a ranked
  shortlist built from your own headers, each row carrying the evidence for its rank — what the name
  suggests, whether the signature is length-delimited, and whether the header is public.

  It is a hint, not a constraint: the model may still name a function the ranking missed, and the
  probe compile remains the only hard gate. Nothing about the witness rule changes — Shard picks a
  function and a byte shape from enumerated sets, and writes no C.

- **Deep mode proposes the seed corpus too, and says when to leave it blank.** Every harness kind
  takes a `corpus`, and nothing helped fill it — the field said *"if there is one"* and never where.
  A seed corpus is the single largest lever on fuzzing coverage; OSS-Fuzz puts it at an order of
  magnitude. Discovery now ranks the directories in your repository that actually look like sample
  inputs, and shows what it measured about each: how many of the files are data rather than source,
  and the median size.

  The discriminator is **the contents, not the name**. A test directory full of `.c` files is a
  test suite, and copying it as a corpus starts the fuzzer from source text; the `testdata`
  directory beside it is the thing worth having. A corpus nested one level under a
  conventionally-named parent is recognised through that parent.

  It also says **leave the field empty** when it finds nothing, and that is the safe direction
  rather than the timid one: a corpus path that is not a directory fails the whole acquisition, so
  an unhelped guess costs the run.

### Fixed

- **The field that exists to stop alerts churning was causing it.** Code scanning matches alerts
  across runs on `partialFingerprints`, and Shard's value was a hash of the whole harness output.
  Measured on one cJSON `heap-buffer-overflow` reported six ways that differ only as two ordinary
  runs differ — build directory, process id, ASLR addresses, a source line moved by an unrelated
  edit, the sanitiser's own interceptor frames — that value produced **4 distinct identities for 1
  defect**. So an alert closed and re-opened on almost every push, losing its triage state and its
  assignee. The fingerprint is now the crash state: the defect class plus the top three frames of
  your code, with sanitiser and fuzzing-engine frames filtered out. Same six runs, **1 identity**.

### Changed

- **Alert identity changes once, for the overflow classes.** `shard/heap-buffer-overflow` becomes
  `shard/heap-buffer-overflow-read` or `shard/heap-buffer-overflow-write`. This is forced rather
  than chosen: a SARIF rule's properties describe every alert under that rule, and an out-of-bounds
  READ is CWE-125 at medium severity while a WRITE is CWE-787 at high. One rule cannot state both
  without mislabelling half its alerts. Existing alerts of those classes close and new ones open,
  once, on the first run after upgrading. Classes with no read/write distinction — use-after-free,
  leaks, integer overflow, and the neutral `shard/reproducing-input` — keep the id they have.

## [2.2.0] — 2026-08-27

### Added

- **`shard-result.json` — the whole result of a scan, as one versioned document.** Written beside the
  SARIF and the report, and declared as the `result-path` action output. Until now a tool consuming a
  Shard run had five places to look and no complete one among them: the SARIF carries none of the run
  facts, `bundles/<fp>/metadata.json` has no run context, `shard-telemetry.json` has no findings, and
  `--json` was stdout-only, unversioned, and spelled its keys differently on `diff` and `deep`. **The
  only artefact carrying the whole result was `shard-report.md`, which is prose.**

  The document splits findings into `reproduced` and `hypotheses` as **separate arrays**, because a
  consumer looping a flat list with a boolean it forgot to check rebuilds the triage queue this
  product exists to eliminate. `gate_eligible`, `level`, and whether `reproduction` is `null` are
  three views of one fact and cannot disagree.

  It carries a **`limits` array**: fourteen codes naming what the run does *not* establish — an
  unfinished run, a ceiling that bound, a walk that truncated, an alert anchored on the entry point
  rather than the fault, a run with no baseline. `no_coverage_statement` is present on **every** run,
  including a clean one: Shard reports what it found and does not report what it covered. A dashboard
  cannot read a careful sentence; it can read a code.

  `schema` is an integer and bumps only when a consumer would misread an older file.

- **`synthesized_c`: deep mode on a repository that fuzzes nothing.** Three harness kinds were
  registered and every one needed something you had already done — a `test_poc.sh` you wrote, or a
  repository that already fuzzes. Two mainstream C projects were measured reporting *"no harness kind
  applies"* for exactly that reason.

  Shard now **generates** the libFuzzer body. You name a function your own header declares and how
  bytes reach it; Shard writes the code, compiles it against your sources with AddressSanitizer, and
  the sanitiser decides. No model writes C, and the generated body has no verdict of its own — the
  same property that has always made the `cargo_fuzz` and `libfuzzer_c` harnesses sound.

  Registered last, so a repository that ships its own fuzz target still wins: your target is stronger
  evidence than one we generated.

- **`gdb` and the docker client in the deep image** (+81.7 MB). Four registered tools previously
  failed 100% of their calls on any workdir that could have used them. A client, never a daemon.

### Fixed

- **The markdown report ignored its own reporting cap.** Measured on 505 findings: it rendered all 505
  and printed *"5 further finding(s) were ranked below the reporting cap and omitted"* underneath
  them. The SARIF capped correctly, so the human artefact described a larger set than the machine one.
  No effect on gating.

- **The egress ledger claimed to list every request the container made, and could not know it.** The
  solver holds an unrestricted shell; one measured run fetched four upstream source revisions while
  the ledger reported none. The claim is now scoped to what it can actually see.

- **A read-only source mount silently disabled the `libfuzzer_c` kind.** Its build probe wrote into
  the checkout, so mounting your source `:ro` — the careful thing to do — produced *"no harness kind
  applies"*, indistinguishable from a genuine build failure. It builds in a temporary directory now.

- **A run that shelled outside the workdir left no trace.** Deep mode copies your checkout and strips
  its VCS metadata so a finding has to be constructed rather than looked up; a `--repo` mount let a
  run reach the original anyway. That now records a journal event naming what happened. It records;
  it does not block.

## [2.1.3] — 2026-08-26

### Changed

- **Free forever on public repositories; a size line on private ones.** The Additional Use Grant
  permitted production use *"at any scale"*, so a 50,000-engineer organisation had exactly the grant a
  two-person startup had, and nothing in the terms ever converted internal use into a conversation.
  There are now two doors and you need only one of them.

  **Public repositories are free without qualification** — no limit on repositories, pipeline runs,
  findings or contributors, and **no limit on the size of your organisation.** A trillion-dollar
  company reviewing its open-source projects needs nothing from us. Repository visibility is a fact
  rather than a self-assessment, which is what makes this door both generous and unarguable.

  **Private repositories** are free while your group is under **both** USD $5,000,000 annual revenue
  **and** 10 individuals contributing to the private repositories Shard reviews. Revenue is counted
  across parents and affiliates, so a small team inside a large organisation is measured by that
  organisation. The contributor limb counts contributors **to the repositories reviewed**, not your
  own headcount — pointing Shard at a large private codebase exceeds it whoever you are, which is what
  keeps the consultancy rule below honest without a special case for it.

  **Whose code you review is no longer part of the test.** A consultancy, contractor or managed
  service provider is treated exactly like anyone else: the line is size, not client relationship.
  That also removes a contradiction the previous text carried, in which one paragraph permitted work
  on code you were *"contractually engaged to … secure"* and a later one forbade performing
  *"vulnerability-discovery services to third parties"* with it. The not-as-a-service prohibition now
  says what it always meant — you may not offer **Shard itself** to others to run.

  **And modifications to Shard come back — or you buy the right to keep them.** Run a modified version
  in production and you either publish those modifications under the same licence within 90 days, or
  take a commercial licence, which permits you to keep them private. Publishing asks nothing else of
  you: not a pull request, not a contribution to us, not support for what you publish. **Your own
  source, configuration, entry points and findings are never covered** — reviewing your code with
  Shard has never obliged you to publish that code and still does not.

## [2.1.2] — 2026-08-25

### Fixed

- **The CLA check was red on the release itself.** Every generated commit in the published repository
  is authored `shard-release` — the whole distribution is regenerated on each release — and there is
  no person behind that identity to sign anything, so the check failed on the release pull request
  while every build and test job passed. A check that is red on every release trains a maintainer to
  merge past a red check, which is the cost the retry above was landed to avoid. `dependabot[bot]` and
  `github-actions[bot]` were already exempt; this identity was the one that was missing.

## [2.1.1] — 2026-08-25

### Fixed

- **A pull request no longer goes red because a registry had a bad minute.** The image job's
  `docker build` failed on `main` in 36 seconds with `failed to fetch oauth token: … 500 Internal
  Server Error` from Docker Hub — both base images, before a single layer was built — while the
  identical commit had passed on a pull request thirteen seconds earlier. These are anonymous pulls,
  and they are rate-limited per IP while hosted runners share addresses, so it is a recurring failure
  mode belonging to the network rather than to the change under test. The build now makes three
  attempts with widening gaps and **still fails at the end**: a genuinely broken image fails exactly as
  it did before. Contributions are invited here and this is the check a contributor sees; a red tick
  they cannot explain and did not cause teaches them to ignore it.

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
- **The two mirror inputs are named `library` and `library_mirror`** (action inputs and CLI flags).
  They previously carried an internal codename that means nothing to a reader of this repository.
  Renaming is free before the first tag and a breaking change after it.
- **The log-level environment variable is `SHARD_LOG`.** Same variable and same values; it previously
  carried the predecessor project's name.

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
