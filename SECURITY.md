# Security policy

Shard runs inside your CI pipeline as a container action. It reads the checkout it is given, runs
shell commands, and — when you declare a witness entry point — executes code from the repository
under review.

This page is for the person deciding whether to allow that. It says what runs where, what leaves the
runner, what this image enforces, and what it does not.

## Can I run this?

| Question | Answer |
|---|---|
| Where does the agent run? | In a container, on a CI runner you provide. |
| Where does inference run? | On an endpoint you provide. We operate none. |
| What leaves the runner? | Your model endpoint, and three destinations beyond it. All four are listed below. |
| Does it execute code from the repository under review? | Only if you declare a witness entry point. |
| What confines it? | One control asserted in this image, plus whatever you impose around the container. |

## Where it runs, and what leaves the runner

### The network, and the allowlist to write

**This build makes network requests beyond your model endpoint, on the default configuration
documented in its own README.** Each destination is listed with the condition that produces it.
Only one of them — your git remote — is something you opt into:

| Destination | When | What it carries |
|---|---|---|
| Your model endpoint | Every run | Inference. |
| `https://api.github.com`, or `GITHUB_API_URL` | Only with `github_token` set — which the README's recommended workflow does | Pull-request comments, read and written, and the SARIF upload to code scanning. Two surfaces, separate requests, separate permissions. |
| Your git remote | Only with `--state-repo` | `git push`, and `git pull --rebase` when another workflow pushed first — so it reads that remote as well as writing to it. |
| Whatever the agent's shell reaches | Every run that reviews a diff | The `run` tool executes inside a network namespace where the kernel allows one. **On a stock GitHub-hosted runner the kernel refuses**, and the run reports `network: unrestricted` rather than pretending otherwise. Where that happens, the shell has the runner's network. |

**So write a network policy.** Allowlist your model endpoint, `api.github.com` if you pass
`github_token`, and your git remote if you use `--state-repo`. Egress beyond those is worth
reporting; egress to those is this product working as documented.

### What confines this build

**One control is asserted in the image at build time.**

- **The image cannot be shadowed by the repository under review.** A container action runs with its
  working directory set to the checkout, and Python puts that directory at the front of the module
  search path. A repository containing a top-level `shard/` package would otherwise be imported and
  executed *as the product*, as root, with your inference key in the environment. The image sets
  `PYTHONSAFEPATH` to remove that entry, and proves during its own build that a decoy loses.

- **Read confinement is a design property of the tools, not a control in this image.** The modules
  that implement an explicit scope manifest are excluded from this build. The analysis reads the
  checkout because that is what the tools are pointed at, and nothing in this artefact would stop
  code that read elsewhere. Treat "confined to the checkout" as the intent of the design, not as
  something this image proves.

**The strongest containment available here is the one you impose around the container**, not one
this image imposes on itself. A safety property you believe in and nothing enforces is a defect
class of its own, so it is stated rather than implied.

### Executing code from the repository under review

**A witness entry point executes code from the repository under review**, by design — that is what
turns a hypothesis into a reproduction.

On a pull request from a fork, this means executing a stranger's code with whatever the job holds.
Treat declaring an entry point there as a decision rather than a default.

## Reporting a vulnerability in Shard

Report privately rather than in a public issue. Email <security@reyse.ai>, or use GitHub's private
vulnerability reporting on this repository. Expect an acknowledgement within 72 hours.

Please include a reproducing input where you can. It is what we ask of our own tool.

**In scope:** the agent, the CI action, the report and reproduction-bundle generation, and anything
that would let Shard act outside the boundary it was pointed at — the checkout it was given and the
entry point the repository declared.

**Containment bypasses are the highest severity class in this project.** Reading or writing outside
the checkout, or executing anything the repository did not declare, is treated as critical
regardless of how contrived the setup.

## Using Shard

Shard is offensive security tooling. It holds real capability. Run it only against systems you are
authorised to test.
