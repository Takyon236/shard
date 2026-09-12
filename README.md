# Shard

Shard reviews code changes inside your CI. The model proposes hypotheses; Shard reports a finding as
demonstrated only when a contained execution, separate from the model, can attach a reproducing input.

The Action runs on your Linux runner and sends diffs, selected source, and tool results to the model
endpoint you configure. Shard operates no inference or storage service. Contained model and witness
execution runs without network or configured Shard credentials; [Security](SECURITY.md) defines the
complete boundary.

> **Version:** These pages document `v5.0.0`. Existing v4 users should use the
> [v4.0.7 documentation](https://github.com/Takyon236/shard/tree/v4.0.7).

## Start here

- [Install a same-repository pull-request review](docs/getting-started.md)
- [Design and test a witness](docs/witnesses.md)
- [Connect a model endpoint](docs/model-endpoints.md)
- [Look up commands, outputs, limits, and runtimes](docs/reference.md)

## Quick survey

This profiles the Shard checkout without a model call or API key:

```bash
set -euo pipefail
demo_dir='shard-v5.0.0'
test ! -e "$demo_dir"
git clone --branch v5.0.0 --depth 1 https://github.com/Takyon236/shard "$demo_dir"
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
- [LICENSE](LICENSE) is authoritative, and this is the shape of it rather than a second copy of
  its terms. Shard is under the Business Source License 1.1: source-available, not open source.
  **Two doors, and you only need one of them.** Public-repository use is free, always — no limit on
  repositories, runs, findings, contributors, or the size of your organisation. Private repositories
  are covered by a small-organisation grant, whose revenue and contributor thresholds the licence
  states. Your own source, configuration, entry scripts and findings are never covered: reviewing
  your code with Shard never obliges you to publish it. Offering Shard itself to others as a hosted,
  managed or embedded service is not permitted; using it to do your own work, including for clients,
  is. Each version converts to Apache 2.0 four years after it is first published, or on the licence's
  change date, whichever comes first. Commercial terms: <licensing@reyse.ai>.
- Read the [Changelog](CHANGELOG.md) for versioned behavior and [Contributing](CONTRIBUTING.md) before
  proposing a change.
