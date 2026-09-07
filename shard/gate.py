"""THE GATE — what CI is told, and the rule that decides it.

This is the product's contract with a pull request. Three exit codes, the vocabulary of `fail-on`, and
the two predicates that turn a set of findings into a pass or a fail. Everything a customer's pipeline
acts on is decided here and nowhere else.

## Why it is its own module

It was inside `shard/cli.py`, and that made the CLI the only place the contract existed. Two things
followed, both of them visible in the tree before this module was written:

- **`shard/action.py` had to import the entry point to read an exit code.** It reached back into `cli`
  from inside a function body, with a comment explaining that it had to — a workaround for a layering
  inversion rather than a fix for one. The GitHub Action is a *caller* of the CLI; it should not have to
  re-enter it to learn what a 1 means. That edge is now an import of this module at action's own module
  scope.

  **The `cli → action → cli` cycle still exists and is meant to**, which is why it is worth naming here
  rather than claiming a fix. `cli._cmd_action` imports `action`, and `action.run` calls `cli.main` with
  an argv built from the environment: `shard action` is a *re-entry* into the entry point, and that is
  the design. What moved out of the cycle is the part that was never delegation — looking up two
  integers. Measured after the move: one cycle, on the `main` edge alone.
- **Two core modules documented this behaviour in prose because there was nowhere to point.**
  `agentloop.py` describes when the gate refuses to pass a build and `report.py` describes what escapes
  into `EXIT_CONFIG`. A rule that three modules describe and none can import is a rule that drifts.

A maintenance script had already named this surface: its rows are grouped under `"gate"`, and there were a
dozen of them scoring a module that did not exist. The group came first; this is the module catching up.

## The layer

Above `diffscope` and `witness`, which it reads; below `cli` and `action`, which read it. It imports
neither at module scope — `is_new_finding` resolves them inside the call so that importing the contract
does not drag in the machinery that produces findings. `action.py` imports this module and gets three
integers and two functions, which is what a caller of a CLI should need.
"""

from __future__ import annotations

#: What a customer's pipeline sees. `EXIT_GATED` is the ONLY code that means "the review found something
#: and you asked me to stop the build for it"; every other failure is `EXIT_CONFIG`, because an internal
#: error reported as 1 would be indistinguishable from a reproduced finding.
EXIT_OK, EXIT_GATED, EXIT_CONFIG = 0, 1, 2


class ConfigError(Exception):
    """A problem with the invocation or the target — never a security finding. Exits `EXIT_CONFIG`.

    **It lives here for this module's own founding reason.** `shard/action.py` had to re-enter the
    entry point to learn what a 1 means, and the fix was to put the contract where a caller can read
    it. This is what a 2 means, expressed as an exception, and it had exactly the same problem one
    layer in: it was defined in `shard/cli.py`, so every module the CLI is being decomposed into
    would have had to import the dispatcher to refuse an argument — a cycle, and the cycle that
    passing handlers into `cliargs.build_parser` was arranged to avoid.

    Raised from twenty-one sites and caught in exactly one, `cli.main`, which turns it into
    `EXIT_CONFIG` and a message with no traceback. That asymmetry is the design: a customer whose
    repository cannot be acquired has a setup problem, and reporting it as a security finding would
    be a false positive of the most annoying kind.

    Public where `cli._ConfigError` was private, because a name three modules import is not private
    to any of them.
    """


#: `new` needs NO baseline storage. It asks whether THIS change introduced the demonstrated defect,
#: and since 2026-08-12 it asks CAUSALLY where it can: `diffscope.base_tree` extracts the repository as
#: it was and `witness.attribute` re-runs the reproducing input against it, so a silent exploit with no
#: location and a defect a DELETION introduced are both reachable — the two rows the line test could not
#: see (an internal audit item 7, owner decision). Where it cannot, it falls back to the
#: line test over the diff already in hand. The alert-history design the integration guide sketched is
#: GitHub-only and therefore fails the maintainers' notes' GitLab requirement; the diff-derived rule generalises
#: unchanged and builds none of the storage the maintainers' notes closes against. It is a NARROWING of
#: `reproduced`, never a widening: new ⇒ demonstrated ∧ introduced-by-this-diff, so a hypothesis still
#: cannot gate whatever this is set to.
FAIL_ON_CHOICES = ("none", "reproduced", "new")

DEEP_FAIL_ON_CHOICES = ("none", "reproduced")


def is_new_finding(finding, introduced) -> bool:
    """Did THIS change introduce this demonstrated defect? The whole of what `fail-on: new` reads.

    A MODULE-LEVEL function rather than the closure it was for one afternoon, because
    a maintenance script scores this rule and a bench that re-implements the rule scores a COPY.
    The maintainers' notes' trap 3 — copies of one value in files that cannot import each other WILL
    drift — arrived here immediately: the bench was measured against a MUTATED `_cmd_diff` and did not
    notice, because it was grading its own transcription of the rule rather than the rule.

    Ordering is the decision. `gate_eligible` first: a hypothesis can never gate, whatever anything else
    says. Then the CAUSAL verdict, which supersedes the line test in BOTH directions — a defect the base
    revision also has is not new however new the line looks, and one it does not have is new even with
    no line to point at. The line test is the fallback for when the counterfactual could not run at all.

    The two imports stay INSIDE the call. This module is what `action.py` reads to learn what an exit
    code means, and a contract whose import pulls in the witness machinery is a contract that costs more
    to consult than to re-implement — which is how the copies in trap 3 get written.
    """
    from shard.diffscope import is_in_diff
    from shard.witness import INHERITED, INTRODUCED

    if not finding.gate_eligible:
        return False
    if finding.attribution in (INTRODUCED, INHERITED):
        return finding.attribution == INTRODUCED
    return is_in_diff(introduced, finding.location, finding.line)


def exit_code(solved: bool, fail_on: str, *, new: bool = False, status: str = "done") -> int:
    """`solved` is `verdict is not None and verdict.reproduced` — there is no other way to set it.

    So the "never fails on an unreproduced finding" rule is not implemented here as a check that could
    be forgotten; it is inherited from `SolveResult.solved` having exactly one source. A hypothesis
    cannot reach this function in a state that gates.

    `new` is `fail-on: new`'s second conjunct: a demonstrated finding sits on a line this change
    introduced. It is `solved and new`, never `new` alone, so the anti-slop guarantee survives a caller
    that mislabels a hypothesis as new — the narrowing is structural here as well as at the call site,
    because a guard that exists in one place is a guard one refactor from gone.

    ## A RUN THAT COULD NOT RUN DOES NOT PASS A GATE

    **Measured 2026-08-21, on a real endpoint failure.** The Z.ai subscription quota was exhausted, so
    every model request returned 429 and the loop produced `status=error` with ZERO requests. Under
    `--fail-on new` this function returned `EXIT_OK`. In CI that is a green check over a review that
    never happened, and it is general rather than an artefact of that provider — a connection refused
    to a dead port does the same.

    `SimpleRun`'s docstring records that the STATUS field was added precisely because *"a run whose
    model refused the prompt, whose budget ran out, or whose backend died therefore reported `done`,
    `findings: 0` and exit 0 — indistinguishable from a clean review"*. The status now travels and the
    report states it honestly. **The gate never read it**, so the fix had landed halfway: the artefact
    told the truth and the exit code — the only part CI acts on — did not.

    `EXIT_CONFIG`, NOT `EXIT_GATED`: an internal error reported as 1 would be indistinguishable from a
    reproduced finding, so it reports as `EXIT_CONFIG` because that is what an internal failure is from
    the customer's side. The doctrine already existed for exceptions; this routes the loop's own failure
    to the same place.

    ONLY WHEN A GATE WAS ASKED FOR. Under `--fail-on none` the customer has said report-only, and a
    failed run exiting 0 is then the correct answer to the question they asked. The change is scoped to
    the case where they made the build depend on the review.

    ONLY `error`, DELIBERATELY. `maxsteps` and `budget` are also outside `COMPLETED_STATUSES`, and they
    are NOT treated this way: those runs reviewed something and their counts are an honest floor, which
    `RunFacts` already states. Failing a build because a deliberately small ceiling was reached would
    make the cheap incremental scan unusable. `error` is the case where nothing was concluded at all.
    That is a judgement, and it is written here so the next reader finds a decision rather than a gap.
    """
    if fail_on in ("reproduced", "new") and status == "error":
        return EXIT_CONFIG
    if fail_on == "reproduced" and solved:
        return EXIT_GATED
    if fail_on == "new" and solved and new:
        return EXIT_GATED
    return EXIT_OK
