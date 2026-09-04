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
-->

## What happened

<!-- Paste the error, the exit code, or the output that was wrong. -->

## What you expected

## How to reproduce

<!--
Your workflow step or command line, with secrets removed. For example:

    - uses: Takyon236/shard@v3
      with:
        mode: diff
        fail-on: gate-eligible
-->

```yaml
```

## The run's own output

<!--
Attach whatever your output directory holds, or paste the useful part.

`shard-telemetry.json` and `shard-run.log` are the two worth attaching first. They describe the run
— where the seconds and tokens went, which tools fired and which failed — rather than your code,
and they are redacted by design, so they are safe to forward.

If you paste only one thing, make it the report's summary table. It gives the verdict, how complete
the scan was, and what limited it.
-->

```
```

## Environment

- Shard version or ref (e.g. `v3.0.1`):
- Mode (`survey`, `diff`, `preflight`):
- Runner (GitHub-hosted `ubuntu-latest`, self-hosted, local `docker run`):
- Model endpoint and model (OpenRouter, Bedrock, Vertex, self-hosted vLLM):

<!--
The model matters more than it might seem. Shard requires native tool calling, and an endpoint
without it produces a run that finds nothing and looks like a clean repository.

    shard preflight --probe-endpoint

spends one request establishing whether your endpoint qualifies, and refuses a bad one rather than
producing a bad run.
-->
