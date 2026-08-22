---
name: Bug report
about: Shard did something wrong, crashed, or would not run
title: ''
labels: bug
assignees: ''
---

<!--
Before you start: if this is a SECURITY issue in Shard itself, do not open an
issue. See SECURITY.md — a public issue discloses it to everyone immediately.

If Shard reported a finding that is not real, please use the "False positive"
template instead. It asks for different things.
-->

## What happened

<!-- What did Shard do? Paste the error, the exit code, or the wrong output. -->

## What you expected

## How to reproduce

<!--
The workflow step or command line, with secrets removed. For example:

    - uses: Takyon236/shard@v1
      with:
        mode: diff
        fail-on: gate-eligible
-->

```yaml
```

## The run's own output

<!--
Shard writes `shard-telemetry.json` and `shard-run.log` to the output directory,
and both are redacted for publication by design. If you have them, they answer
most of the questions we would otherwise have to ask.

The report's summary table is the single most useful thing: it names what stopped
the run and which ceiling or failure bound it.
-->

```
```

## Environment

- Shard version / ref (e.g. `v1.0.0`):
- Mode (`survey`, `diff`, `preflight`):
- Runner (GitHub-hosted `ubuntu-latest`, self-hosted, local `docker run`):
- Model endpoint and model (OpenRouter, Bedrock, Vertex, self-hosted vLLM):

<!--
The model matters more than it might seem. Shard requires native tool calling,
and an endpoint that does not support it will produce a run that finds nothing
and looks like a clean repository. `python -m shard preflight` reports whether
your endpoint qualifies.
-->
