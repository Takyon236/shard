# Finding bundles and replay

This page describes the current v4 release candidate. See [Getting started](getting-started.md) for
availability and the exact source and Action revisions.

## What a bundle proves

Shard adjudicates a candidate during the originating review. It runs the candidate and benign controls
through the declared witness in fresh contained source trees. `metadata.json` records
`reproduced: true` only when that in-run adjudication accepts the observation. A hypothesis or refused
candidate can also have a bundle; its metadata says `reproduced: false`.

Depending on the finding, a bundle can contain:

- `metadata.json` — the finding, adjudication summary and revision when available;
- `input` — the candidate bytes supplied to the witness;
- `output.txt` — captured source-derived output; and
- `reproduce.sh` — the command recorded for the finding.

The engine computes gate eligibility in the originating run. The documented v4 candidate deliberately
uses `fail_on: none`: without a trusted independent replay path, it remains report-only. A retained
bundle is an audit record, not a second gate.

## Independent replay is unavailable

Shard does not currently ship a trusted acquisition or replay command. The bundle alone cannot
independently authenticate its GitHub workflow, Action bytes, reviewed source, build products or
transfer. It also does not carry the exact source tree, benign-control bytes, required-product bytes or
a complete runtime description needed to recreate the original trials.

`reproduce.sh` is evidence content, not a verifier. It relies on repository-relative paths in the
checkout around it and does not recreate Shard's immutable snapshot, fresh tree per trial, control
comparison or execution boundary. Do not execute it. In particular, never run it on a workstation,
credentialed CI runner or persistent self-hosted runner.

A checksum made after download can detect later changes to those downloaded bytes. It does not prove
who produced them or supply the missing source and runtime.

## Retain and inspect safely

- Retain bundles only through the documented workflow's named `bundle-path`; do not publish the whole
  checkout output directory.
- Keep the bundle attached to its original workflow run. If it is copied, record the run URL, head and
  base revisions, Action reference and a checksum beside it. This improves traceability but is not
  independent verification.
- Treat `input`, `output.txt`, metadata and reports as sensitive source-derived data. Review every file
  before sharing it.
- Inspect bundle files as data only, preferably in an offline disposable environment.
- To check a fix or another revision, run Shard again against that revision instead of executing the old
  bundle script.

See [Witness entry points](witnesses.md) for in-run adjudication,
[Reference](reference.md#outputs-and-files) for output paths, and
[Security](../SECURITY.md) for the containment and data boundaries.
