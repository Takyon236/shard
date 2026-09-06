# Security policy

Shard analyzes untrusted source, lets a model choose bounded shell commands and can run a repository
witness. This page defines the data flow and containment boundary for teams deciding whether to install it.

## Version and availability

This policy describes the current v4 release candidate, not an earlier release. See [Getting
started](docs/getting-started.md) for availability and exact source and Action revisions.

## Version scope

This page describes the current `[Unreleased]` source tree. The intended v3.0.2 release bytes and its
`@v3` major alias do not provide the immutable source snapshot, complete execution boundary, or Action
handoff described below. The runnable v3.0.2 onboarding journey has its own narrower acceptance checks;
a green v3.0.2 run is not evidence for any guarantee on this page. Treat these controls as unavailable
to an installed Action until public availability is witnessed and a later major switches the install, Action and
matching documentation together.

## At a glance

| Question | Answer |
|---|---|
| Where does Shard run? | In a container on a Linux CI runner you provide. |
| Where does inference run? | At an endpoint you configure. Shard operates none. |
| Does source leave the runner? | Source excerpts, diffs and tool results are sent to that endpoint. Optional delivery and state operations are listed below. |
| Does repository code execute? | Yes. Diff mode offers a bounded shell; a declared witness also runs candidate and control inputs. |
| Does that code have credentials or network? | It has no network and configured Shard credentials are removed. Do not place unrelated secrets in the Shard step. |

## Network and data flow

| Destination | When contacted | Data sent |
|---|---|---|
| Configured model endpoint | Diff reviews | prompts containing the diff, selected source excerpts, tool results and prior model turns |
| Configured model endpoint | opt-in `preflight --probe-endpoint` | a fixed tool-call probe and requested model identity; no repository source |
| `api.github.com` or `GITHUB_API_URL` | only when `github_token` is supplied | report text, SARIF, repository/run identity and pull-request comment operations |
| GitHub Actions artifact service | only when a later workflow step uses `upload-artifact` | the named report, result, SARIF, telemetry, log and finding bundles; reports, results, SARIF and bundles can contain source-derived data |
| Configured state Git remote | only with `state_repo` | Shard's state commits through `git fetch` and `git push` operations |

Basic `survey` and basic `preflight` make no model request. Shard operates no inference or storage
service. Configure egress for the trusted Shard process and separately for artifact upload. The model
shell, witness, controls and compiler helpers have no network interface; if that namespace cannot be
created, their execution is refused.

## Source boundary

Before the model can read or execute repository content, Shard captures one immutable source view:

- regular files must have one link;
- `.git` is omitted at every depth;
- symlinks must resolve inside the checkout; and
- sockets, FIFOs and device nodes are refused.

`read_file`, `grep`, directory traversal, and every hostile execution use this snapshot rather than
the live checkout. Capture failure stops the review instead of silently omitting or crossing the
problematic path. The current structural outline tool is the recorded exception to this guarantee.

`SourceSnapshot.capture` has no internal entry-count, directory-depth, per-file-byte or aggregate-byte
ceiling. Only the CI job or runner's memory, storage and time limits bound it; configure those limits
before reviewing an untrusted repository shape.

The snapshot is not a secret classifier. A regular credential file written under the checkout becomes
source and can reach the model endpoint, so keep `.env`, `.npmrc` and job credentials outside the
workspace. The snapshot omits `.git`; witnesses whose behavior depends on Git administration are not
supported.

## Execution boundary

The outer Action container retains only `SYS_ADMIN` so a trusted initializer can create the boundary.
Before any model-authored or repository-provided code starts, the initializer:

- creates private PID, mount, proc and network namespaces;
- exposes only read-only source and required runtimes, one writable scratch directory, private `/tmp`
  and minimal devices;
- omits the host root, container control sockets and GitHub command files;
- removes the configured model and GitHub credentials, all `INPUT_*` values, credential-shaped names,
  and control-socket variables;
- closes ambient standard input;
- clears effective, permitted, inheritable, ambient and bounding capability sets;
- applies `no_new_privs`.

Shard has no raw subprocess or PID-only fallback. If the complete boundary is unavailable, the run
records a containment refusal and cannot turn that observation into a demonstrated finding.

The analysis container retains `SYS_ADMIN` only for the trusted namespace initializer. After that
container exits, the Action uses a separate helper with `no_new_privs`, no network, and only `CHOWN` to
validate file types and link counts and return output/publication ownership to the runner. That helper
does not execute repository code.

The job's own CPU, memory and time limits remain important. Untrusted code can consume resources within
those outer limits. Side channels in the shared kernel and hardware are not claimed to be eliminated.

The environment scrub is a denylist, not proof that every arbitrary variable is harmless. A secret
with an unrelated, non-credential-looking name can remain available to repository code. Give the Shard
step only the model key and GitHub token it needs.

## Pull-request trust cases

The documented workflow supports branches in the same repository. GitHub does not provide repository
secrets to fork-originated `pull_request` jobs.

Shard does not currently ship an automatic privileged fork workflow. Do not use `pull_request_target`
or a standalone `workflow_run` recipe as a shortcut: restoring a model credential while processing an
attacker-controlled change requires a separately reviewed, maintainer-approved protocol that proves
both revisions and pull-request identity.

## Reporting a vulnerability in Shard

Do not open a public issue or include live credentials. GitHub private vulnerability reporting is not
enabled, and no disclosure address or response-time commitment is active before launch. Wait for this
page to name an active private channel before sending a vulnerability report.

Include the affected version, environment, boundary crossed and a reproducing input or workflow.
Containment escapes, credential exposure, source-boundary bypasses, forged gate evidence and
release-integrity failures are in scope.

## Authorized use

Shard is offensive security tooling. Run it only against systems you are authorised to test.
