"""Order one tied block so that any prefix of it holds each subtree in proportion to its size.

ONE JOB, AND IT IS NOT RANKING. This module claims nothing about which candidate is likelier to be
a defect and prefers no directory by name — `src`, `lib` and `deps` are all just strings here. It
answers a sampling question: given a block the ranker could not separate at all, and an artefact
that shows only the first N of it, which N?

It lives apart from `shard/survey.py` because the size ratchet said so and the seam was already
there. `survey.py` went 371 to 415 code lines against a 400 ceiling when this landed inside it, and
the gate's own instruction is "put the new code in a new module". The responsibility genuinely
changes at this line: everything else in `survey.py` decides what a candidate IS, and this decides
only what order a set of them comes out in.

It takes `(path, item)` pairs rather than the survey's own row type, which keeps the dependency
pointing one way — `survey` imports this, this imports nothing from `shard` — and lets the whole
rule be tested with plain strings.
"""

from __future__ import annotations

from typing import TypeVar

_T = TypeVar("_T")


def spread(rows: list[tuple[str, _T]], depth: int = 0) -> list[_T]:
    """Order one TIED block so that any prefix of it holds each subtree in proportion to its size.

    **A SAMPLING RULE, NOT A RANKING.** It claims nothing about which candidate is likelier to be a
    defect, and it prefers no directory by name — `src`, `lib` and `deps` are all just strings here.
    It exists because both artefacts are CAPPED (20 rows in `shard-report.md`, 200 in
    `shard-survey.json`) while `_rank_spread` keeps reporting that the rank did not discriminate at
    all, and the head of an alphabetical list is a report about whichever directory sorts first.

    Measured 2026-09-03 on three checkouts, counting rows in the repository's OWN library source:

        libgit2   744 candidates, 415 under src/   report 20:  0 -> 12   json 200:   0 -> 118
        zstd      515 candidates, 148 under lib/   report 20:  0 ->  9   json 200:  91 ->  83
        libyaml    38 candidates,  15 under src/   report 20: 15 -> 15   json 200:  15 ->  15

    Before, libgit2's twenty were `benchmarks/` (4), `ci/` (2) and `deps/clar/` (14) — flamegraph
    scripts and a vendored test framework — because `benchmarks` < `ci` < `deps` < … < `src`. zstd's
    twenty were twenty rows of `contrib/`, from five files. libyaml's own source already held every
    slot, because a tree that small has nothing to interleave. zstd's json-200 falling 91 -> 83 is the
    trade, stated rather than buried: 91 was the accident of `contrib`, `doc` and `examples` running
    out before the cap did, and 83 is what proportion says — `lib` holds 148 of the 358 candidates in
    that block, 41.3%, and 41.3% of 200 is 83. libgit2's 118 is the same arithmetic on 415 of 702.

    THE KEY IS `(2i+1)/2n` WITHIN EACH BUCKET, which spaces a group of n evenly across the unit
    interval, so any prefix takes each bucket in proportion to its size. Applied at EVERY path
    component, the filename INCLUDED, which is worth one line of its own: interleaving directories
    alone still let one file take a directory's whole slice, and adding the filename level took the
    twenty rows from ten distinct files to twenty on libgit2 and from eleven to nineteen on zstd —
    which is what "a map of where to look" has to mean. Ties on the fraction fall back to the
    component name, and that is the only place alphabetical order survives.

    Nothing is pruned and nothing is dropped — `_provenance`'s rule. The same rows, in another order.
    """
    tree: dict[str, list[tuple[str, _T]]] = {}
    for path, item in rows:
        # The slice is EMPTY past the last component, so the join is the base-case key: rows that have
        # run out of path share one bucket that is never recursed into, and the recursion terminates.
        tree.setdefault("".join(path.split("/")[depth:depth + 1]), []).append((path, item))
    sub = {name: [i for _, i in rs] if name == "" else spread(rs, depth + 1)
           for name, rs in tree.items()}
    keyed = [((2 * i + 1) / (2 * len(rs)), name, r) for name, rs in sub.items() for i, r in enumerate(rs)]
    return [t[2] for t in sorted(keyed, key=lambda t: t[:2])]
