# Contributing to Shard

Contributions are welcome, and this page tries to be honest about what will and
will not be merged, so you do not spend an evening on something we then decline.

## The short version

1. Open an issue first for anything larger than a bug fix.
2. Sign the CLA when the bot asks. One click, once, covers everything you send.
3. Every change needs a **deterministic test** — no network, no model calls.
4. Run `python -m pytest -q` and `python -m ruff check shard/` before you push.

## Where your pull request actually goes

**This repository is generated.** It is built from a private development tree by
a release job, which is why every file here is complete and self-contained and
why there is no `docs/` directory full of design notes. That has one consequence
worth knowing before you spend an evening, and it is not obvious from the outside:

**Your pull request is reviewed here and ported upstream — it is not merged
here.** A maintainer applies it to the development tree, and it reaches you in
the next release as part of a regenerated tree rather than as your merge commit.
Your authorship is preserved in the changelog and in the upstream history; what
you will *not* see is your commit sitting on this repository's `main`.

That is also why the release refuses to publish if it finds a commit here it did
not generate: work that never reached the development tree would be destroyed by
the next regeneration, so the job stops instead.

**A fix to a shared module ships in both editions**, and that is what the CLA is
for — see [The CLA](#the-cla). It is one grant, once, and it is the difference
between a fix that can be used and one that has to be reimplemented.

None of this changes what makes a good contribution. It changes where it lands.

## What this project is

Shard is a security agent that runs inside your CI pipeline, on a model endpoint
you control, and reports a finding **only when it can attach an input that
reproduces it**. That last clause is the product. It is also the standard every
contribution is measured against.

A change that makes Shard report more things is not automatically an improvement.
A change that makes it report the same things with a reproduction attached, or
report fewer things that were never real, usually is.

## The bar for a change

**Ground every claim in something that was executed.** If your pull request says
a change is faster, safer or more accurate, the number or the failing case goes
in the description. "This should be better" is not reviewable and we will ask you
to measure it, which is slower for you than measuring it first.

**Write a deterministic test.** The suite runs with no API key and no network.
Use the scripted backends and in-memory fakes the existing tests use — look at
any file in `tests/` for the pattern. A change whose only evidence is a run
against a live endpoint cannot be re-checked by anyone else, including you in six
months.

**A test that cannot fail is worse than no test.** Before you open the pull
request, break your own fix and confirm the test goes red. If it stays green, the
test is measuring something other than what you think.

**Keep the core dependency-free.** `budget`, `journal` and the policy layer
import nothing third-party, and the suite runs without any optional dependency
installed. If your change needs a library, say so in the issue before you write
it — the answer is sometimes yes, but it is a decision rather than a detail.

## What we will probably decline

Not to be discouraging — these come up often enough to be worth stating:

- **Adding a new configuration option nobody has asked for.** Every option is a
  branch that has to be tested and explained forever. If a setting has one
  sensible value, that value should be the behaviour.
- **Speculative abstraction.** An interface with one implementation is harder to
  read than the implementation.
- **Reformatting, renaming or restructuring unrelated code** in the same pull
  request as a fix. Send it separately and we will look at it on its own merits.
- **Changes that make a run report findings it cannot reproduce.** This is the
  one line that will not move.

## Running things

```bash
python -m pytest -q             # the whole suite. No API key needed, no network.
python -m ruff check shard/     # lint
```

To try it against a repository locally:

```bash
shard survey --repo /path/to/repo --out-dir ./out     # or: python -m shard survey ...
shard preflight --repo /path/to/repo
```

`survey` and `preflight` need no model endpoint, no key and no network. `diff`
needs all three — set the environment variable named by your `api_key_env` input
and see the README for the supported providers.

The fastest way to see the whole loop is [`examples/`](examples/): three small
projects with a real defect, a real entry point and real benign controls. They
run with no key, and `tests/test_examples.py` executes every one of them, so a
change that breaks a sample turns this repository's CI red rather than being
discovered by a reader.

## Reporting a false positive

This is one of the most useful things you can send, and it has [its own issue
template](.github/ISSUE_TEMPLATE/false_positive.md). Please include the report
Shard produced and, if you can, the reproduction bundle — the finding's own
evidence is what lets us tell a broken adjudicator from a real defect you did not
expect.

## Security issues

**Do not open a public issue.** See [SECURITY.md](SECURITY.md).

## The CLA

Shard is published under the [Business Source License 1.1](LICENSE), and there is
also a commercial edition that is not public. The two share code, so a fix to a
shared module may need to ship in both. The [CLA](CLA.md) is the grant that makes
that lawful. It explains itself in its first paragraph, and it does **not** ask
you to assign your copyright — you keep it.

A bot will comment on your first pull request with a link. One click.

## Licence of contributions

Your contribution is licensed under the terms of the CLA. The published project
remains under BUSL 1.1, which converts to Apache 2.0 on the Change Date stated in
the licence file.
