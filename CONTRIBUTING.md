# Contributing to Shard

Contributions are welcome. This page says what will and will not be merged, so you do not spend an
evening on something we then decline.

## Before you start

1. **Open an issue** for anything larger than a bug fix.
2. **Sign the CLA** when the bot asks. One click, once, covers everything you send.
3. **Write a deterministic test** — no network, no model calls.

## Running things

```bash
pip install -e ".[dev]"         # pytest and ruff. The README's `pip install -e .` installs neither
python -m pytest                # the whole suite. No API key needed, no network
python -m ruff check shard/     # lint
```

Do not add a quiet flag to that pytest line. `pyproject.toml` already sets `-q`, and a second one
makes it `-qq`, which suppresses the count line — and you want that line, because a skip renders as
a dot just like a pass. The same holds however you spell it: `-q`, `--quiet` and `-qq` are one
option counted twice, and so is the cluster `-xq`. **Nothing in this repository's suite checks
that.** The guard that reads every documented command and refuses the repeat lives in the
development tree this repository is generated from, so a doubled flag passes everything you can run
here and is caught when your change is ported.

To try Shard against a repository locally:

```bash
shard survey --repo /path/to/repo --out-dir ./out     # or: python -m shard survey ...
shard preflight --repo /path/to/repo
```

`survey` and `preflight` need no model endpoint, no key and no network. `diff` needs all three — set
the environment variable named by your `api_key_env` input, and see the README for the supported
providers.

The fastest way to see the whole loop is [`examples/`](examples/): five small projects with a real
defect, a real entry point and real benign controls. They run with no key, and
`tests/test_examples.py` executes every one of them, so a change that breaks a sample turns this
repository's CI red rather than being discovered by a reader.

## Where your pull request goes

**This repository is generated.** A release job builds it from a private development tree, which is
why every file here is self-contained and why there is no `docs/` directory of design notes.

**Your pull request is reviewed here and ported upstream — it is not merged here.** A maintainer
applies it to the development tree, and it reaches you in the next release as part of a regenerated
tree rather than as your merge commit. Your authorship is preserved in the changelog and in the
upstream history. What you will not see is your commit on this repository's `main`.

That is also why the release refuses to publish if it finds a commit here it did not generate: work
that never reached the development tree would be destroyed by the next regeneration, so the job
stops instead.

**A fix to a shared module ships in both editions**, which is what [the CLA](#the-cla) is for. None
of this changes what makes a good contribution. It changes where it lands.

## The bar for a change

Shard reports a finding **only when it can attach an input that reproduces it**. That clause is the
product, and it is the standard every contribution is measured against. A change that makes Shard
report more things is not automatically an improvement. A change that makes it report the same
things with a reproduction attached, or report fewer things that were never real, usually is.

**Ground every claim in something that was executed.** If your pull request says a change is faster,
safer or more accurate, put the number or the failing case in the description. "This should be
better" is not reviewable, and we will ask you to measure it — which is slower for you than
measuring it first.

**Write a deterministic test.** The suite runs with no API key and no network. Use the scripted
backends and in-memory fakes the existing tests use; look at any file in `tests/` for the pattern. A
change whose only evidence is a run against a live endpoint cannot be re-checked by anyone else,
including you in six months.

**A test that cannot fail is worse than no test.** Before you open the pull request, break your own
fix and confirm the test goes red. If it stays green, the test is measuring something other than
what you think.

**Keep the core dependency-free.** `budget`, `journal` and the policy layer import nothing
third-party, and the suite runs without any optional dependency installed. If your change needs a
library, say so in the issue before you write it. The answer is sometimes yes, but it is a decision
rather than a detail.

## What we will probably decline

- **A new configuration option nobody has asked for.** Every option is a branch that has to be
  tested and explained forever. If a setting has one sensible value, that value should be the
  behaviour.
- **Speculative abstraction.** An interface with one implementation is harder to read than the
  implementation.
- **Reformatting, renaming or restructuring unrelated code** in the same pull request as a fix. Send
  it separately and we will look at it on its own merits.
- **Changes that make a run report findings it cannot reproduce.** This is the one line that will
  not move.

## Reporting a false positive

This is one of the most useful things you can send, and it has [its own issue
template](.github/ISSUE_TEMPLATE/false_positive.md). Please include the report Shard produced and,
if you can, the reproduction bundle — the finding's own evidence is what lets us tell a broken
adjudicator from a real defect you did not expect.

## Security issues

**Do not open a public issue.** See [SECURITY.md](SECURITY.md).

## The CLA

Shard is published under the [Business Source License 1.1](LICENSE), and there is also a commercial
edition that is not public. The two share code, so a fix to a shared module may need to ship in
both. The [CLA](CLA.md) is the grant that makes that lawful. It does **not** ask you to assign your
copyright — you keep it.

A bot will comment on your first pull request with a link. One click.

Your contribution is licensed under the terms of the CLA. The published project remains under BUSL
1.1, which converts to Apache 2.0 on the Change Date stated in the licence file.
