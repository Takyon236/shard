# Shard

Shard reviews code changes inside your CI. The model proposes hypotheses; Shard reports a finding as
demonstrated only when a contained execution, separate from the model, can attach a reproducing input.

The Action runs on your Linux runner and sends diffs, selected source, and tool results to the model
endpoint you configure. Shard operates no inference or storage service. Contained model and witness
execution runs without network or configured Shard credentials; [Security](SECURITY.md) defines the
complete boundary.

> **Version:** These pages document `v4.0.3`. Existing v3 users should use the
> [v3.0.2 documentation](https://github.com/Takyon236/shard/tree/v3.0.2).

## Start here

- [Install a same-repository pull-request review](docs/getting-started.md)
- [Design and test a witness](docs/witnesses.md)
- [Connect a model endpoint](docs/model-endpoints.md)
- [Look up commands, outputs, limits, and runtimes](docs/reference.md)

## Quick survey

After `v4.0.3` is published, this profiles the Shard checkout without a model call or API key:

```bash
set -euo pipefail
demo_dir='shard-v4.0.3'
test ! -e "$demo_dir"
git clone --branch v4.0.3 --depth 1 https://github.com/Takyon236/shard "$demo_dir"
cd "$demo_dir"
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
shard survey --repo .
shard preflight --repo . --visibility public
```

Run the full onboarding from the repository you want Shard to review.

## Contract

- The model proposes; a separate execution step decides whether the evidence is real.
- A demonstrated finding must distinguish its candidate input from an empty input and benign controls.
- Start and remain at `fail_on: none`: the current candidate ships no trusted independent replay helper.
- Only `status: done` is complete. A partial or failed review is never presented as clean.

The free Action supports `survey` and `diff`; `preflight` is a local CLI command.

## Limits

- Automatic fork and Dependabot reviews are not supported. Never restore secrets with
  `pull_request_target`; review those changes manually.
- The Action requires Linux/amd64 and Docker. The endpoint must stream OpenAI-compatible chat
  completions with native tool calls; see the [runtime table](docs/reference.md#runtime-support).
- A clean report means only that this run found no demonstrated finding. It is not proof that the
  repository is vulnerability-free.

## Results, security, and licence

- [Outputs and files](docs/reference.md#outputs-and-files) lists the report, JSON, SARIF, telemetry, log,
  and finding bundles, with their privacy boundaries.
- [Security](SECURITY.md) covers data flow, source snapshots, containment, and vulnerability reporting.
  No public disclosure channel is active before launch; do not post credentials or a vulnerability in
  a public issue.
- [LICENSE](LICENSE) is authoritative. Public-repository use is free; private use has a limited
  small-organisation grant, and commercial licensing is available at <licensing@reyse.ai>.
- Read the [Changelog](CHANGELOG.md) for versioned behavior and [Contributing](CONTRIBUTING.md) before
  proposing a change.
