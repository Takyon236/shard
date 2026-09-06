---
name: Bug report
about: Shard did something wrong, crashed, or would not run
title: ''
labels: bug
assignees: ''
---

<!--
Two things this template is NOT for:

  - A SECURITY issue in Shard itself. Do not open an issue — a public one discloses it to
    everyone immediately. See SECURITY.md.
  - A finding that is not real. Use the "False positive" template; it asks for different things.

This template describes v4. `v4.0.2` is published and needs granted access to install, and the build
is not anonymously installable or pullable. Report the exact source and Action revisions you were
given; existing v3 users should follow the documentation at their v3 tag.
-->

## What happened

<!-- Paste the error, the exit code, or the output that was wrong. -->

## What you expected

## How to reproduce

<!--
The supported v4 candidate path is GitHub Actions in report-only mode. Local container and non-GitHub
CI experiments are diagnostics, not supported integrations. Paste your exact workflow revision with
secrets removed. The intended release ref below does not resolve during the release candidate:

    - uses: Takyon236/shard@v4.0.2
      with:
        mode: diff
        fail_on: none
-->

```yaml
```

## The run's own output

<!--
Attach only the public evidence files you need: `shard-report.md`, `shard-result.json`, `shard.sarif`,
`shard-telemetry.json`, `shard-run.log`, and the relevant finding bundle under `bundles/`. Inspect each
file for source-derived details before sharing it. A bundle is an audit record, not an independently
replayable proof; do not execute its `reproduce.sh`.

`shard-telemetry.json` and `shard-run.log` are the two worth attaching first. They describe the run
— where the seconds and tokens went, which tools fired and which failed — rather than your code,
and are designed to omit source and model prose. Inspect them anyway. Never attach
`shard_journal.jsonl`; it can contain model reasoning, tool results, and source excerpts.

If you paste only one thing, make it the report's summary table. It gives the verdict, how complete
the scan was, and what limited it.
-->

```
```

## Environment

- Shard source commit and exact Action ref (`v4.0.2`, or the commit you pinned):
- Action mode (`survey` or `diff`), or CLI command (`preflight`):
- Runner (GitHub-hosted `ubuntu-latest` or fresh self-hosted Linux GitHub Actions runner):
- Model endpoint URL and exact model identifier:

<!--
The model matters more than it might seem. Shard requires native tool calling and fails closed when
the endpoint cannot provide it. Probe before a review so the incompatibility is reported immediately:

    shard preflight --probe-endpoint --model-endpoint URL --model ID --api-key-env KEY_VARIABLE

The probe spends one model turn establishing whether your endpoint qualifies, may retry transient HTTP
failures, and refuses an unsupported endpoint before a review.
-->
