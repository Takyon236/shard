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

## [1.0.0] — 2026-08-22

**The first published release.** `uses: Takyon236/shard@v1` resolves from this tag onward.

What is being published is the FREE tier: `survey`, `preflight` and `diff` — a pull-request review that
reports a finding only when it can attach an input that reproduces it. Deep mode is a separate,
commercially licensed image and is excluded from this artefact by construction; the build fails rather
than emitting a tree that contains it.

### Added

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

- **`--max-spend-usd` is a ceiling rather than an estimate.** The run now stops BEFORE a model call it
  cannot afford at the highest price it has already paid, instead of noticing afterwards that a cap was
  crossed. Measured before the change: a $2.50 cap billed $2.5866. Two cases still cross it by at most
  one call and both are now stated in the flag's own help — the first call of a run has no observed
  price behind it, and any call can be priced above every call before it.
- **`alexandria` and `alexandria_mirror` are renamed `library` and `library_mirror`** (action inputs
  and CLI flags). They named an internal codename that means nothing to a reader of this repository.
  Renaming is free before the first tag and a breaking change after it.
- **`LUCENT_LOG` is now `SHARD_LOG`.** Same env var, correct name.

### Fixed

- **A run that ends `error` now says WHY.** A revoked key, an exhausted balance, a rate limit, a
  mistyped model name and a provider outage all reported the same bare word, and the first four are
  things you fix in a minute. The report now names the cause and what to do about it — and says
  plainly that the run's silence is not a statement about your code.
- **Every model request announced a private repository.** `HTTP-Referer` and `X-Title` carried an
  internal project name to the provider on every call, from your runner. They now name this
  repository and this product.
- **Two error messages cited documents that do not exist in this distribution**, so the one
  instruction they gave was unfollowable.

## [Unreleased]

### Added

- **The findings have somewhere to go.** `$GITHUB_STEP_SUMMARY` on every run (no token needed),
  a code-scanning SARIF upload and a pull-request comment behind a new `github_token` input, and a
  complete workflow in `README.md`. Until this, the SARIF, the report and the reproduction bundles
  were written to a directory on a runner that is destroyed when the job ends — measured on a run
  that gated a build, where the only way anybody read the finding was `gh run download`.
- **A human-readable artefact for `survey` mode.** It wrote JSON and nothing a person reads, and
  survey is the mode a customer meets first. Same `shard-report.md` filename diff mode uses, so a
  workflow consuming `report-path` does not branch on the mode.
- **`.shard/entry.sh.benign/`** — a directory of the customer's own benign inputs, one per branch
  the entry point can take. Any demonstration a benign input also reproduces is refused.
- **`jobs: free | all`** on `runner-proof.yml`, so the free half can be dispatched without buying the
  metered review.

### Changed

- **`Finding.message` is rendered as a blockquote.** The model may format its own paragraph and may
  not emit block structure that belongs to the document — an unbalanced fence in the first finding's
  prose used to put every finding after it inside a code block.
- **Every report opens with a fixed header** — verdict, trust, reviewed, gate, witness, cost — because
  four real runs could not be told apart by reading the artefact. A fact the run does not know omits
  its row rather than printing a zero.

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

## Before this file

263 commits with no tags. Behaviour before the first release is not reconstructable from this file, and
nothing here should be read as describing it.
