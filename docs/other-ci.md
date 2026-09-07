# Other CI systems

This page describes the current v4 release candidate. See [Getting started](getting-started.md) for
availability and the exact supported GitHub Action revision.

GitHub Actions is the only supported CI integration. Shard does not publish a tested GitLab CI,
Jenkins, AWS CodeBuild, Google Cloud Build or generic container recipe.

The CLI can be used locally, but its exit code is only the result of that process. Shard has no
supported non-GitHub wrapper that verifies the CI run identity, reviewed head and base, output handoff,
ownership cleanup, or secret and fork trust boundary. A finding bundle also has no trusted independent
replay path; see [Finding bundles and replay](replay.md).

Do not adapt the Action or an image invocation and present the result as a supported Shard gate.
Experiments under separately granted access must remain report-only. Treat their outputs as diagnostics,
not evidence authenticated by a Shard-supported producer contract.

The command exit codes remain documented in [Reference](reference.md#cli-exit-codes). They do not add
the missing CI guarantees.
