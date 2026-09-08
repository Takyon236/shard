# Changelog

This file records customer-visible changes to Shard.

Shard follows semantic versioning with one stricter rule: a change that can turn a green build red is
**MAJOR**, even when it fixes a bug. A moving `vX` Action tag advances only within that major line. Pin
an exact version or commit when updates need review.

## [Unreleased]

## [4.0.7] — 2026-09-08

### Changed

- **The published Python carries no comments or docstrings.** The free distribution is now built the
  way the commercial image already was: every docstring and comment is removed from the emitted
  `shard/` package. Measured on the artefact this replaces — 44 files, 25,998 lines, of which 11,648
  were prose (44.8%); the package falls from 1,527,188 to 595,024 bytes. The code itself is unchanged.
  The build proves, per file, that the emitted module's syntax tree equals the original's with its
  docstrings removed, and refuses to publish if it does not. The CLI's help text, the report format,
  `shard-result.json` and every documented interface are unaffected.
- **`__doc__` is now `None` on shipped modules.** Anything that calls `help()` on an installed module,
  or reads `Module.__doc__`, gets a different answer than it did in 4.0.6. Nothing in the product
  reads a docstring at runtime and no documented interface exposes one, so no Action input, output or
  report field changes — but it is observable from outside, and it is the one thing here to check if
  you have tooling that introspects an installed Shard module.
- **Line numbers in the published files move.** A traceback still matches the source at the tag it
  came from, because the published repository is the stripped tree — but anything pinned to a line
  number in an earlier release's file needs re-reading against the new one.
- **Only the `shard/` package is stripped.** The test files, the examples, `README.md`,
  `CHANGELOG.md`, `SECURITY.md`, `CONTRIBUTING.md` and the documentation ship exactly as written,
  comments and all — the shipped tests are meant to be read, and they are the best description of
  what the package promises. `CONTRIBUTING.md` now says which tree the missing comments are in, and
  that their absence is a build step rather than the house style, so a contributor does not open a
  pull request to restore them.

## [4.0.6] — 2026-09-08

### Changed

- The Action's manifest name is now **Shard Security Review**. GitHub refuses a Marketplace listing
  whose name matches an existing user or organisation, and `Shard` is one. This is a display string:
  it titles the listing and labels the step in a run log. The `uses:` reference resolves by
  repository path and is unchanged, so no workflow needs editing, and the SARIF tool driver is still
  `Shard` so code-scanning alert continuity is unaffected.


## [4.0.5] — 2026-09-08

### Added

- **The source-inspection block is documented.** Every diff run already reports which of the files in
  scope it actually read — a `Source inspection` section in the report and an `inspection` object in
  `shard-result.json`, with per-file line ranges — and no customer document had ever mentioned it. A
  contributor reading the distribution concluded the capability was missing and began rebuilding it,
  which is how the gap surfaced. [Reference](docs/reference.md) now describes the block, its fields,
  and what it does and does not claim.
- The licence summary in the README states the shape of the terms in plain words: source-available
  under BUSL 1.1, free for public repositories without limit, a small-organisation grant for private
  ones, your own code never covered, and what the Apache 2.0 conversion depends on. The thresholds
  stay in the licence, which is the only place they can be read without drifting.
- The measured per-run cost figures are shown as the table they were measured as, alongside the
  existing floor caveat.
- `action.yml` declares `branding`, which GitHub requires before an Action can be listed on the
  Marketplace. It is presentation metadata and changes no behaviour.

## [4.0.4] — 2026-09-07

**No behavioural change.** Apart from the version string, the package's code is identical to 4.0.3 —
verified by parsing both emitted trees and comparing them with every comment and docstring removed.
Everything below is prose: the comments the source ships and the documents shipped beside them.

### Fixed

- **Twenty-three references in the shipped source pointed at something a reader cannot reach.**
  Fourteen named a Python file: seven a module of this project that the distribution does not carry,
  five a module that exists in no version of Shard at all, and two a script in a different
  repository. Each was written as a bare filename, which every reference rule missed because each
  one expected a directory in front of it. The other nine had been rewritten as far as the path and
  left a symbol name dangling off the end, so the sentence named a private symbol immediately after
  saying its file cannot be reached.
- **Comment paragraphs explaining functionality this package does not include have been removed.**
  Twenty-one names — the functions and options behind it — survived in five shipped modules, with
  the prose around them explaining what each was for. The rule that removes such paragraphs was
  matching three literal names where the build's own tables hold eleven; it is now derived from
  those tables, so a name added to either is covered by the commit that adds it. The package carries
  76 fewer non-blank lines as a result.
- **The security policy told a v4 reader to treat the controls it documents as unavailable.** That
  paragraph was written for the v3 line and was never updated; v4 is published, installs
  anonymously, and does establish the immutable source snapshot, execution boundary and Action
  handoff the page describes. The README and the bug-report template also still warned that the
  source repository needed granted access, and the template told a reporter that the workflow ref it
  had just given them does not resolve.
- Twenty-six mangled possessives (`the design notes's`) across twelve modules, and twenty-three
  sentences that began in lower case where a rewritten reference opened a sentence whose full stop
  sat underneath its own markup or on the line above it.

## [4.0.3] — 2026-09-07

**Upgrade from 4.0.2. It could not demonstrate anything.** Measured against the published 4.0.2 image
under the Action's own flags: the execution boundary probe returned nothing, so every witness refused
and `reproduced: true` was unreachable.

### Fixed

- **The Action could not execute a witness, so no finding could ever gate a build.** The review
  container was launched with `SYS_ADMIN` alone; the trusted namespace initializer also needs
  `DAC_OVERRIDE` to mount the private writable trial and `SETPCAP` to lock securebits before the
  entry point starts. Without them the execution boundary could not be established, and every
  demonstration was correctly refused and reported as an unproven hypothesis. All three capabilities
  are now granted to the initializer, which then drops them before repository code runs. Measured
  inside the image, one capability at a time; the published CI now runs a real witness in the
  container under exactly these flags on every push and pull request.
- Adjudication tests that require the execution boundary now skip, naming the missing capability,
  on a runner that cannot provide it — instead of failing on a hosted runner, and instead of
  passing without having observed anything.

## [4.0.2] — 2026-09-06

`Takyon236/shard` is public. Anonymous source installs and `uses: Takyon236/shard@v4.0.2` work; the
earlier entries in this file were written while the repository was private and said so.

**No customer-visible change to the distribution.** The emitted tree is byte-identical to 4.0.0. This
is the version that actually publishes: 4.0.0 and 4.0.1 were tagged and never published, each stopped
by a release gate that had been added without ever being dispatched — a tag-object check the runner
could not answer, and a durable-root rule no first publish could satisfy. Both are fixed here.

## [4.0.1] — 2026-09-06

**No customer-visible change.** The emitted distribution is byte-identical to 4.0.0, verified by
building both trees and diffing them. This version exists because 4.0.0's release workflow could not
run: its tag-object check asked the runner a question only the repository can answer, and refused
every release including a correct one. The fix is in this repository's own CI and ships nothing.

## [4.0.0] — 2026-09-05

### Breaking changes

- Incomplete or contradictory model responses, unavailable execution isolation, unsafe source or
  output paths, and a failed required-result handoff now end the review with exit 2 instead of
  appearing successful.
- Shard reviews an immutable source snapshot and refuses to run when it cannot establish the documented
  process, filesystem, and network boundary.
- A model turn has one bounded deadline covering request preparation, connection, response, and
  retries, and capped response, error, and tool-output sizes.
- Built-in file and search tools stay inside that snapshot and stop at byte, file, depth, fanout,
  memory, and time limits.
- The Action requires a fresh output directory and validates every result before publishing it.
- The Action no longer forwards the variable named by `api_key_env` into the review container: it
  copies that value into one fixed internal carrier. A name reserved for an Action credential,
  including `GITHUB_TOKEN` and any name beginning `ACTIONS_`, is refused.
- Raw journals are retained only when a direct CLI run explicitly sets `--journal-path` to a path
  outside `--out-dir`.

### Fixed

- Retry decisions no longer read provider-supplied error text. Only an outcome measured by Shard's own
  transport can buy another attempt.
- A bundle name that would be unsafe, or that repeats within one run, becomes a distinct visible path
  instead of overwriting another finding's evidence or addressing content outside the output directory.

### Documentation

- Rebuilt the public docs around one short, report-only GitHub Actions onboarding path, and corrected
  its first-run workflow so it declares the witness, exact endpoint model and coherent key variable.
- Split witness design, endpoint setup, command reference, security, and finding-bundle guidance into
  focused pages.
- Removed unverified fork and non-GitHub CI recipes. Same-repository GitHub pull requests are the
  supported v4 CI integration, and automatic fork review remains unsupported until a tested design can
  prove both revisions and protect the restored model credential.
- Clarified that a finding bundle is an audit record, not independently verified replay evidence. The
  v4 release has no trusted acquisition and replay helper, so onboarding does not enable gates.

## [3.0.2] — 2026-09-04

### Fixed

- Corrected the documented Action input spelling to `fail_on` and the endpoint-check command to
  `preflight --probe-endpoint`.
- Clarified that post-execution cost figures are a floor and that self-hosted endpoints may not report
  dollar cost.
- Reordered the public security guidance around actual data flow and runner controls.

## [3.0.1] — 2026-09-04

### Fixed

- A run that used its full execution allowance is now reported as incomplete instead of complete.
- Documented the three CLI exit codes: only 1 means a demonstrated finding matched the gate; 2 means
  Shard could not perform the requested review.

## [3.0.0] — 2026-09-03

### Breaking

- Survey mode now rejects `model_endpoint`, `scan`, `max_steps`, `hunk_radius` and `state_repo` instead
  of silently discarding them. Remove those inputs from survey jobs.

### Fixed

- Reproduction scripts now resolve their own bundle paths, quote the witness and record the source
  revision.
- Survey reports now name sampled candidate locations.
- Failed reviews now carry a machine-readable error kind and actionable cause.
- Provider-specific model aliases are no longer applied to unrelated endpoints.

## [2.4.1] — 2026-09-02

- Release-only correction. Runtime and gate behavior are identical to 2.4.0.

## [2.4.0] — 2026-09-02

### Changed

- Model-authored commands are bounded by a process-tree memory ceiling.
- Generated harnesses that cannot be shown to consume the supplied input are refused instead of
  producing an apparently clean review.

### Fixed

- Ordinary non-zero input rejection is no longer treated as a crash on customer code.
- Candidate and control runs now use identical staged input paths.
- Captured output is bounded and credential values are redacted in additional encodings.
- The public Action manifest and package exports are verified after the free-tier cut.

## [2.3.0] — 2026-08-31

### Added

- Findings now carry CWE, severity and crash-state fields in SARIF and `shard-result.json`.

### Fixed

- Alert identity is stable across wording changes while preserving distinct findings.

## [2.2.0] — 2026-08-27

### Added

- Added the versioned `shard-result.json` machine-readable result.

### Fixed

- Markdown reports now enforce their finding cap.
- Network and state destinations are reported without claiming to observe runner traffic Shard cannot
  see.
- Source copies exclude Git administration and refuse paths outside the declared work area.

## [2.1.3] — 2026-08-26

- Public repositories became free without an organisation-size limit; private use retained the
  revenue and contributing-developer thresholds in `LICENSE`.

## [2.1.2] — 2026-08-25

- Generated release commits no longer fail their own contributor licence check.

## [2.1.1] — 2026-08-25

- Public CI retries transient container-registry failures while preserving a final hard failure.

## [2.1.0] — 2026-08-25

### Added

- Added a clean public-source checkout experience, executable examples and preflight guidance.

### Fixed

- Removed private development references from the generated distribution.
- Corrected the cost estimate and made the report state what the witness actually executed.

## [2.0.0] — 2026-08-24

### Security

- Provider retries and multi-call turns now settle against one spend governor.
- Time limits cover stalled model requests and adjudication has its own execution ceiling.
- Witness controls are integrity-checked and credentials are removed from child environments.

## [1.1.0] — 2026-08-24

### Added

- The Action now pulls a published image and the moving major ref resolves.
- Added non-GitHub container guidance, endpoint compatibility guidance and five runnable examples.
- Added the runtimes needed to demonstrate findings in Python, Node.js, Java, Ruby, PHP, .NET and C/C++.

## [1.0.0] — 2026-08-22

### Added

- Added job-summary, pull-request comment, SARIF and reproduction-bundle delivery.
- Added benign witness controls and a human-readable survey report.
- Added the source licence, contributor policy, public test suite and generated free distribution.

### Security

- Gate eligibility is derived from independent evidence fields rather than trusted from a serialized
  boolean.
