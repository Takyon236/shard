# Contributing to Shard

Contributions are welcome. Open an issue before a large change; focused bug fixes may go straight to a
pull request.

## Set up a clean checkout

You need Python 3.11 or newer, Git, Bash and Docker for the image check.

```bash
set -euo pipefail
git clone https://github.com/Takyon236/shard
cd shard
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"

python -m pytest
python -m ruff check shard/
```

`pyproject.toml` already supplies pytest's quiet/reporting options. Do not add `-q`, `--quiet` or
`-qq` to the command.

The suite makes no model call and needs no API key. The five small projects under
[`examples/`](examples/) are the fastest way to see a witness, benign controls and a known defect
together.

## What a change needs

- A deterministic test with no network or live model dependency.
- Evidence from an executed failing case, not “this should work.”
- A narrow diff that does not reformat or rename unrelated code.
- A check that the new test fails when the fix is removed.
- No new third-party dependency in the core policy modules.

Shard separates hypotheses from demonstrated findings. A change that reports more hypotheses is not
automatically an improvement; a change that attaches valid reproductions or removes false evidence is.

We will normally decline speculative abstractions, unused configuration, unrelated cleanup and any
change that lets an unreproduced hypothesis gate a build.

## Generated repository

This public repository is generated from a private full-stack development tree. Accepted pull requests
are ported upstream by a maintainer, with authorship preserved, and the next release regenerates this
tree. They are not merged directly into generated `main`, because the following release would
overwrite them.

Changes to shared modules may ship in both free and commercial distributions. The
[`CLA`](CLA.md) grants that right without assigning your copyright; the bot asks for it once on your
first pull request.

### Why `shard/` has no comments or docstrings

They are removed from the `shard/` package when this tree is generated. The development tree they come
from requires a comment to record a constraint, a measurement or a rejected alternative, and that
reasoning is what the commercial distribution is built on, so neither published tree carries it.
**This is a build step, not the style we write in, and not something to fix.** A pull request that adds
explanation to a module under `shard/` is work we cannot port: the next release regenerates the file
without it.

**Only `shard/` is stripped.** `tests/`, `examples/`, this file and every other document ship exactly
as written, comments and all — the tests in `tests/` are meant to be read, and they are the best
description of what the package promises. Prose you contribute there survives a release.

So read the code as the code — names, types, the tests and the [`docs/`](docs/) directory are the
intended explanation. When behaviour is unclear, open an issue rather than inferring intent from a
stripped module; a question answered there reaches the tree that keeps the answer.

## Useful local checks

```bash
set -euo pipefail
shard survey --repo .
shard preflight --repo . --visibility public
```

Endpoint probing spends one model turn, may retry transient HTTP failures, and needs explicit endpoint,
model and key configuration. See
[`docs/model-endpoints.md`](docs/model-endpoints.md).

## Reports

- Bugs: use the [bug template](.github/ISSUE_TEMPLATE/bug_report.md).
- False positives: include `shard-report.md` and the finding bundle when you may share them.
- Security vulnerabilities: do not open a public issue; follow [`SECURITY.md`](SECURITY.md).

Do not post credentials, proprietary source or a finding bundle you have not reviewed.
