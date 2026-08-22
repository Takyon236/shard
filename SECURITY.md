# Security policy

Shard is offensive security tooling. It holds real capability and it is designed to be run against
systems the operator is authorised to test.

## Reporting a vulnerability in Shard itself

Report privately rather than in a public issue, to <security@reyse.ai>, or use GitHub's private
vulnerability reporting on this
repository. Expect an acknowledgement within 72 hours.

Please include a reproducing input where you can. It is what we ask of our own tool.

## Scope

In scope: the agent, the CI action, the report and reproduction-bundle generation, and anything that
would let Shard act outside the boundary it was pointed at — the checkout it was given and the entry
point the repository declared.

**Containment bypasses are the highest severity class in this project.** Reading or writing outside
the checkout, or executing anything the repository did not declare, is treated as critical regardless
of how contrived the setup.

### What confines this build, stated exactly

Two controls carry it, and both are asserted in the image at build time rather than documented as
intent:

- **The analysis is confined to the checkout it is given.** The agent's read roots are the checkout,
  and nothing else — including the code that grades its own findings, which it must not be able to
  read.
- **The image cannot be shadowed by the repository under review.** A container action runs with its
  working directory set to the checkout, and Python puts that directory at the front of the module
  search path. A repository containing a top-level `shard/` package would otherwise be imported and
  executed *as the product*, as root, with the operator's inference key in the environment. The image
  sets `PYTHONSAFEPATH` to remove that entry and proves during its own build that a decoy loses.

**There is no network capability in this build.** No mode in this image opens a network connection to
anything but the model endpoint you configure. There is consequently no network policy to describe
here, and any egress beyond that endpoint is a reportable defect rather than a configuration question.

**A witness entry point executes code from the repository under review**, by design — that is what
turns a hypothesis into a reproduction. On a pull request from a fork this means executing a stranger's
code with whatever the job holds, so treat declaring one there as a decision rather than a default.

Stated plainly because the alternative is worse: a safety property a user believes in and nothing
enforces is a defect class in its own right, and it would be an odd thing to correct everywhere except
the file where we ask other people to report ours.

## Using Shard

Run it only against systems you are authorised to test.
