# Getting started

This path adds Shard to a same-repository pull request in report-only mode. It verifies the repository,
witness, endpoint, CI connection, and public outputs without turning findings into a merge gate.

> **Version:** These pages document `v4.0.5`. Existing v3 users should use the
> [v3.0.2 docs](https://github.com/Takyon236/shard/tree/v3.0.2).

## Before you start

You need Linux/amd64 with Docker (`ubuntu-latest` works), Python 3.11 or newer, Git, Bash, an
[OpenAI-compatible endpoint](model-endpoints.md), and permission to add Actions settings and a workflow.
This path supports same-repository pull requests only; forks and Dependabot do not receive the model key.

## 1. Install and inspect

Run these commands from the repository you want Shard to review; basic survey and preflight make no model request:

```bash
set -euo pipefail
onboarding_env="$(mktemp -d)/venv"
python3 -m venv "$onboarding_env"
. "$onboarding_env/bin/activate"
python -m pip install 'git+https://github.com/Takyon236/shard.git@v4.0.5'

repository_visibility='public' # change to private when appropriate
shard survey --repo .
shard preflight --repo . --visibility "$repository_visibility"
```

Before a witness exists, `can gate NO` is expected; local runtime rows describe this machine, not the Action image.

## 2. Add and validate a witness

A witness proves one target behavior. Generate its skeleton without overwriting a path or following a
symlinked `.shard` parent:

```bash
set -euo pipefail
test ! -L .shard
mkdir -p .shard
test -d .shard
test ! -e .shard/entry.sh
test ! -L .shard/entry.sh
entry_template="$(mktemp .shard/.entry.sh.XXXXXX)"
trap 'rm -f -- "$entry_template"' EXIT
shard preflight --repo . --entry-template > "$entry_template"
test -s "$entry_template"
chmod 0755 "$entry_template"
ln -- "$entry_template" .shard/entry.sh
rm -f -- "$entry_template"
trap - EXIT
```

Edit the skeleton to run the target on the payload path in `$1`. Add real, non-malicious fixtures under
`.shard/entry.sh.benign/`, then validate the declared entry and every control:

```bash
set -euo pipefail
shard preflight --repo . --witness-entry .shard/entry.sh
shopt -s nullglob
controls=(.shard/entry.sh.benign/*)
((${#controls[@]} > 0))
bash -- .shard/entry.sh /dev/null
for control in "${controls[@]}"; do
  bash -- .shard/entry.sh "$control"
done
```

Require `can gate YES`; the empty input and controls must be quiet and exit 0. Test one safe controlled
positive for its exact marker or fatal signal, but do not commit that payload. See [Witness entry points](witnesses.md).

## 3. Verify the endpoint

Run the [endpoint probe](model-endpoints.md#run-the-probe) and continue only for `validated` or
`compatible`. A workstation probe does not replace the first Action run from the CI container.

Under **Settings → Secrets and variables → Actions**, add:

| Kind | Name | Value |
|---|---|---|
| Variable | `SHARD_MODEL_ENDPOINT` | the base URL you probed |
| Variable | `SHARD_MODEL` | the exact served model identifier |
| Secret | `SHARD_MODEL_API_KEY` | the endpoint credential |

## 4. Add the report-only workflow

Save this as `.github/workflows/shard.yml` with the witness. It runs no repository build before the
secret-bearing step; generated products need the separate no-secret job in [Build placement](witnesses.md#build-placement).

```yaml
name: shard

on:
  pull_request:

permissions:
  contents: read
  pull-requests: write
  security-events: write

jobs:
  review:
    if: github.event.pull_request.head.repo.full_name == github.repository && github.actor != 'dependabot[bot]'
    runs-on: ubuntu-latest
    timeout-minutes: 90
    steps:
      - name: Check out the pull request
        uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0
        with:
          fetch-depth: 0
          persist-credentials: false

      - name: Review the change with Shard
        id: shard
        uses: Takyon236/shard@v4.0.5
        env:
          SHARD_MODEL_API_KEY: ${{ secrets.SHARD_MODEL_API_KEY }}
        with:
          mode: diff
          model_endpoint: ${{ vars.SHARD_MODEL_ENDPOINT }}
          model: ${{ vars.SHARD_MODEL }}
          api_key_env: SHARD_MODEL_API_KEY
          base_ref: ${{ github.event.pull_request.base.sha }}
          slug: ${{ github.repository }}
          witness_entry: .shard/entry.sh
          github_token: ${{ secrets.GITHUB_TOKEN }}
          max_spend_usd: 0
          max_minutes: 60
          max_steps: 40
          fail_on: none

      - name: Retain Shard's public outputs
        if: always()
        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2
        with:
          name: shard-evidence
          path: |
            ${{ steps.shard.outputs.report-path }}
            ${{ steps.shard.outputs.result-path }}
            ${{ steps.shard.outputs.sarif-path }}
            ${{ steps.shard.outputs.telemetry-path }}
            ${{ steps.shard.outputs.log-path }}
            ${{ steps.shard.outputs.bundle-path }}
          if-no-files-found: warn

      - name: Require a complete Shard review
        if: always()
        env:
          SHARD_STATUS: ${{ steps.shard.outputs.status }}
          SHARD_REPORT: ${{ steps.shard.outputs.report-path }}
          SHARD_RESULT: ${{ steps.shard.outputs.result-path }}
        run: |
          set -euo pipefail
          if [[ "$SHARD_STATUS" != done ]]; then
            echo "Shard did not complete: status=${SHARD_STATUS:-missing}" >&2
            exit 1
          fi
          for output in "$SHARD_REPORT" "$SHARD_RESULT"; do
            [[ -n "$output" && -r "$output" ]] || {
              echo "Shard did not emit a readable report and result" >&2
              exit 1
            }
          done
```

`max_spend_usd: 0` disables an unenforceable dollar cap when no price is reported. The 60-minute,
40-turn, and 90-minute job ceilings leave room for bounded adjudication and output delivery; see
[Limits and cost](reference.md#limits-and-cost).

## 5. Accept the first run

Open a same-repository PR with the workflow, witness, and controls. Accept it only when all five checks hold:

1. **Require a complete Shard review** passes and the report says `status: done`.
2. The report scopes the expected changed files and does not say `no changed files in scope`.
3. The endpoint request succeeds from the Action container.
4. The job summary and pull-request comment appear; code scanning succeeds when enabled, or the SARIF
   file opens from the artifact when it is not.
5. `shard-evidence` contains readable report and result files and only the named public outputs.

`budget`, `maxsteps`, `repeat`, and `error` are incomplete results. A clean result means only that this
run found no demonstrated finding.

> **Stop at report-only.** Keep `fail_on: none`. The current candidate ships no trusted independent
> replay helper, so a downloaded bundle is not safe evidence for a CI gate. Do not execute bundles on
> a developer workstation. Enable gating only in a later version that ships matching acquisition and
> contained, class-specific replay commands.
