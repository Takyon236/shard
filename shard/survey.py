"""The survey — what this codebase is, and what we might look for in it.

The design notes. This is **not** `preflight`, and conflating them would lose both.
`preflight` answers *"can we run here and what will it cost"*. The survey answers *"what is this
codebase, and what might we look for"*, and by owner requirement it exists **on the free tier too** —
it is what makes a first interaction useful on a repository where nothing is yet provable.

## Two halves, deliberately separate

    survey_repo()   OBSERVATION   pure static scan. What the code contains
    assess()        JUDGEMENT     given what Shard can actually do here, what could be proven

The split is not tidiness. The observation is the same on every tier; the judgement changes with the
build, the harness dictionary and what the customer declared. Keeping them apart means a free-tier
survey and a paid one see the same code and differ only where they genuinely differ, and it keeps this
module simple-safe — `assess` takes the capability facts as ARGUMENTS rather than importing
the separate package, exactly as `cli._mode_verdict` already does.

## Ranked by demonstrability, which is what stops it being a wish list

| Rank | Means | Decided by |
|---|---|---|
| `deep` | a reproducing input could be attached here | a harness kind applies AND the surface is memory-unsafe |
| `witness` | a demonstration could be executed here | the customer declared a runnable entry point |
| `hypothesis` | we could reason about it and prove nothing | neither of the above |

Every other tool in this market produces a ranked list of things to worry about. The distinguishing
claim is proof, so the ranking is by **whether proof is reachable**, and it is computed from the
capabilities this repository already has rather than from a severity table.

## Blind spots are an output, not an omission

`Assessment.blind_spots` states what the survey CANNOT check. Same discipline as `report_no_finding`'s
`not_reached` field: the honest counterweight to a green result is a named list of what was never looked
at. A survey that only lists what it found reads as coverage it does not have.

## No precision claim is made, and this is the important paragraph

What a line has to look like to become a candidate lives in `shard/surveymarkers.py`, which carries
the corpus measurement behind every row and the rule a new one has to pass. What matters HERE is what
this module is forbidden to do with the answer: a candidate surface is **not a finding**, and nothing
this file produces may be reported as a defect. The table's accuracy is **unmeasured** — it is wrong
in both directions, `memcpy` appears in safe code constantly and a defect can sit somewhere no marker
fires — so the consequences are held in the code: surfaces never become `report.Finding`s, `assess`
never emits a severity, and `summarise` says "candidate" everywhere it says anything.
"""

from __future__ import annotations

import os
import pathlib
import re
from dataclasses import dataclass

from shard.ignorefile import IgnoreIndex
from shard.spread import spread
from shard.surveymarkers import MARKER_LANGUAGES, kind_of
from shard.target import EXT_LANGUAGE
from shard.tools import _VCS_DIRS

#: Reading is what makes the survey more expensive than `profile_repo`, so it is bounded on three axes
#: and every cap is REPORTED. The design notes: a truncated scan that found nothing
#: reads as absence.
MAX_SURVEY_FILES = 4000
MAX_FILE_BYTES = 262_144
MAX_HITS_PER_FILE = 20

MEMORY_UNSAFE = frozenset({"c", "c++", "asm", "zig"})

#: **OFF until measured — ships EMPTY.** A per-kind gate for MANAGED-LANGUAGE proof-bearing, read at
#: call time by `_rank_one` (same discipline as `witness.DIFFERENTIAL_NONZERO_EXIT`: a lever is a
#: decision, not an import order).
#:
#: `MEMORY_UNSAFE` answers one question — *can bytes into a built binary produce an UNFORGEABLE crash?*
#: — and the answer is a property of C/C++/asm/zig. Python has no fatal signal, so it is deliberately
#: NOT extended: adding `python` to `MEMORY_UNSAFE` would silently promote Python surfaces to RANK_DEEP
#: on a crash mechanism that is measured false for the language. Proof-bearing for a managed language is
#: a **(kind × language)** property, which a set of languages cannot express and a set of kinds can: a
#: Python `command_exec` surface CAN carry a reproducing input once P1.0's witness lever is measured ON
#: — an injected command whose output the agent did not supply (`id` -> `uid=`) is unforgeable via the
#: existing `output_marker` route — while a Python `parser` or `input_boundary` surface cannot.
#:
#: Candidates for the flip (from the W9 P1.2 recon): `command_exec`, `deserialiser`, `sql_injection`.
#: The flip is ONE reviewable line — populate this set — in the commit that carries the measurement.
#: The standing rule: a lever lands OFF because a default is a claim.
#:
#: **STILL EMPTY, and as of W9 P2 the blocker has CHANGED — do not read "awaiting P1.3" here.** P1.3
#: reported, and what it found does not license the flip: `command_exec` is proof-bearing only through
#: `output_marker`, which is already on, so populating this set would buy nothing for that kind. The
#: kinds it WOULD promote — `deserialiser`, `sql_injection` — reach a witness only through
#: `nonzero_exit`, and W9 P2 measured that route's lever unsound and left it off
#: (`shard/witness.py`, "the baseline is NECESSARY AND NOT SUFFICIENT"). A correct program rejecting
#: malformed input still adjudicates as a demonstration.
#:
#: So the order is: fix or replace the `nonzero_exit` route FIRST, then revisit this set. Populating it
#: while that route is unsound would promote a surface to gate-eligible on an observation that a
#: defect-free program produces. Measured 2026-08-11, and it applies to every managed language rather
#: than to JavaScript alone.
WITNESSABLE_KINDS: frozenset[str] = frozenset()

#: Extension -> language. Every entry is a SPELLING of a language already claimed here; this table
#: decides what gets READ, so a missing spelling is not a smaller survey, it is a survey that reports
#: `files_read` for a repository it did not open. Measured 2026-08-11 on two real targets before the
#: module spellings were added: a Next.js site read **4 of its 24** TypeScript/JavaScript files and
#: reported that count without qualification, and an EPUB toolchain read 175 of 188. The surface yield
#: was small (+1 and +3) and is not the reason — a false coverage number is.
#:
#: `.mjs`/`.cjs` and `.mts`/`.cts` are Node's ESM/CommonJS spellings; `.jsx`/`.tsx` are JSX, a syntax
#: extension rather than a language. None of them adds a language the table did not already claim,
#: which is what keeps this a spelling fix rather than a coverage decision needing its own corpus.
#: **ONE TABLE, IMPORTED — this used to be a second copy and the two were each blind to what the other
#: saw.** `shard/target.py`'s `EXT_LANGUAGE` holds the reasoning and the measurement: the copy that lived
#: here could never see `.kt`, `.swift`, `.scala`, `.s`, `.asm` or `.hxx`, so a Kotlin or Swift repository
#: had **every source file skipped** — and two rows in `shard/surveymarkers.py` are language-AGNOSTIC,
#: `parser` among them, so that was lost coverage and not merely a lost count.
_EXT_LANG = EXT_LANGUAGE

RANK_DEEP, RANK_WITNESS, RANK_HYPOTHESIS = "deep", "witness", "hypothesis"

#: Descending. `ranked()` sorts on this, so "what could we actually prove" is what a reader sees first.
_RANK_ORDER = {RANK_DEEP: 0, RANK_WITNESS: 1, RANK_HYPOTHESIS: 2}

#: Tie-break WITHIN a rank: the target's own source, then its tests, then generated files.
#:
#: **THE RANK ANSWERS "COULD WE PROVE IT HERE", WHICH IS A PROPERTY OF THE BUILD AND NOT OF THE
#: CANDIDATE.** On a repository with no harness and no entry point every candidate is equally
#: unprovable, so one label is the CORRECT answer and `_rank_spread` says so. What was wrong is what
#: happened next: the tie-break was `(path, line)` alone, i.e. alphabetical, so a test fixture or a
#: minified bundle sorted above the target's own source whenever its path did.
#:
#: Measured 2026-08-18 over four real repositories — the ranked list interleaves on three of them:
#:
#:     suitenumerique/docs   101 candidates   first test at index 24, LAST source at index 100
#:     huggingface_hub       200 shown        first generated at index 20
#:     mistralai/client-py   200 shown        first generated at index 28
#:
#: **And the cap turns that into lost coverage.** `client-python` has 735 candidates and the report
#: shows 200: **36 of those slots went to `generated`** — files the same report calls unusable, *"a
#: line over 500 chars; the location is not usable"* — while 492 of the target's own source candidates
#: were omitted. Ordering costs nothing, uses a field already measured and already printed, and it
#: claims only what `_provenance` claims: not that one candidate is likelier to be a defect, but that
#: unusable and non-target code should not be interleaved with code the customer actually owns.
#:
#: Still NEVER PRUNED — everything is reported, in a better order.
_PROVENANCE_ORDER = {"source": 0, "test": 1, "generated": 2}


@dataclass(frozen=True)
class Surface:
    """One candidate area. NOT a finding — see the module docstring."""

    path: str
    line: int
    kind: str
    language: str
    evidence: str                      # the matched source line, trimmed
    #: Whose code this is: the target's own `source`, its `test` fixtures, or something `generated`.
    #: Reported, never pruned — see `_provenance`. Defaults to `source` so a `Surface` built by hand
    #: in a test means what it says.
    provenance: str = "source"


@dataclass(frozen=True)
class Survey:
    """The observation half. Identical on every tier, because the code is."""

    surfaces: tuple[Surface, ...]
    files_read: int
    truncated: bool = False
    #: How many GENERATED directories the walk skipped. Reported, never absorbed: a project that keeps
    #: real source under `build/` exists, and a survey that silently did not look there would read as
    #: "we looked and found nothing" — the failure mode this whole module's blind-spot list exists for.
    pruned_dirs: int = 0
    #: How many directories `.gitignore` excluded. SEPARATE from `pruned_dirs` because the two answer
    #: different questions: a generated directory might hold source, whereas an ignored one is the
    #: customer's own statement that it is not part of the repository. Counted and reported for the
    #: same reason everything else here is — a measured run.1 is what a walk that
    #: silently read 139 MB of ignored agent worktrees produced.
    ignored_dirs: int = 0
    #: WHICH QUESTION THE IGNORE DECISIONS ANSWERED. `IgnoreIndex.tracked_basis`: a sentence naming the
    #: git index when one was readable, and empty when the walk had only the patterns. Those are not the
    #: same claim — `.gitignore` does not apply to a file git already tracks — so a report that states
    #: one while having measured the other is the kind of confident wrong number this module's blind-spot
    #: list exists for.
    ignore_basis: str = ""
    #: And WHY there is no basis, when there is none — `IgnoreIndex.tracked_refusal`. Named rather than
    #: generic: *"your .git/index is version 4, which this walk does not read"* is actionable, where
    #: *"no git index was readable"* is vaguer AND false in that case. It is also what makes the guards
    #: in `_read_git_index` killable by a test at all; see `_GitIndex`.
    ignore_refusal: str = ""
    #: How many paths matched an ignore rule and were surveyed ANYWAY, because git tracks them. A
    #: non-zero count is a fact about the customer's repository worth telling them: it is committed code
    #: that a pattern claims is not part of the project.
    ignored_but_tracked: int = 0
    #: HOW MANY FILES THE WALK DID NOT READ TO THE END. `truncated` covers the 4,000-FILE ceiling and
    #: nothing covered the two PER-FILE ones, so until 2026-09-02 both were silent in every artefact.
    #:
    #: `MAX_HITS_PER_FILE`: one `.c` file with 25 marker lines yields 20 surfaces and the payload said
    #: `truncated: False`, `omitted: 0`, counts summing to 20 — a consumer could not tell 20 real hits
    #: from 25 truncated to 20, and the `candidates_cap` invariant beside it balanced on a total that
    #: was itself a sample.
    #:
    #: `MAX_FILE_BYTES` is the same defect and it lies harder. Measured on a 306,014-byte `.c` file
    #: whose one `strcpy(` sits past 262,144: the survey reported ZERO candidates, `truncated: False`,
    #: and the blind spot *"no candidate surface was detected anywhere; treat this as the marker
    #: table's limit"* — an attribution to the table for a file the walk never opened the end of.
    #:
    #: ONE COUNTER FOR BOTH, because they make one claim: this file's counts are a floor. Which
    #: ceiling stopped it is recoverable from the two the payload states beside this number, and
    #: splitting the counter would buy a distinction no consumer acts on differently. Counted as FILES
    #: rather than as dropped hits: knowing how many were dropped means reading the rest of the file,
    #: which is the cost both caps exist to refuse.
    files_read_in_part: int = 0
    #: THE SAME COUNT PER LANGUAGE, because the sentence that reads it is a per-language ATTRIBUTION.
    #: `_blind_spots` answers a language with no candidates by saying *"those files WERE read and
    #: nothing in the marker table matched, so this is that table's limit"* — a claim about a file the
    #: walk opened the END of. Measured 2026-09-03 on one 300,102-byte `.c` whose only `strcpy(` sits
    #: past `MAX_FILE_BYTES`: the artefact printed that sentence and the true one about the same file
    #: four lines apart, and the false one is the one phrased as a conclusion. The count above cannot
    #: separate them, because a language whose files were all read to the end is still owed the
    #: stronger wording. Only languages with a partly-read file appear; a zero would read as
    #: "measured, none".
    languages_read_in_part: tuple[tuple[str, int], ...] = ()
    #: FILES ACTUALLY READ, per language, descending by count. A tuple of pairs because this record is
    #: frozen and a dict is not hashable.
    #:
    #: It exists to replace a HEDGE with a fact. `_blind_spots` used to answer a language with no
    #: candidates by saying *"this may mean there is none, or that the marker table does not cover it"* —
    #: and the walk knows which. Reading four thousand Kotlin files and matching nothing is a statement
    #: about the marker table; never opening one is a statement about the walk. They call for opposite
    #: actions and that sentence covered both.
    languages_read: tuple[tuple[str, int], ...] = ()

    def by_kind(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for s in self.surfaces:
            counts[s.kind] = counts.get(s.kind, 0) + 1
        return dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))

    def by_provenance(self) -> dict[str, int]:
        """How much of this surface is the target's own source. ALWAYS all three keys, including the
        zeroes: an absent key reads as "not measured", and the maintainers' notes is that a zero
        you cannot distinguish from an unknown is a lie with a number on it."""
        counts = {"source": 0, "test": 0, "generated": 0}
        for s in self.surfaces:
            counts[s.provenance] = counts.get(s.provenance, 0) + 1
        return counts


@dataclass(frozen=True)
class RankedSurface:
    surface: Surface
    rank: str
    why: str


@dataclass(frozen=True)
class Assessment:
    """The judgement half. Depends on what Shard can do HERE, so it differs by build and by customer."""

    ranked: tuple[RankedSurface, ...]
    blind_spots: tuple[str, ...]

    def counts(self) -> dict[str, int]:
        out = {RANK_DEEP: 0, RANK_WITNESS: 0, RANK_HYPOTHESIS: 0}
        for r in self.ranked:
            out[r.rank] += 1
        return out


#: `_VCS_DIRS` was already pruned and nothing pruned these. The count of what this removed is REPORTED
#: as a blind spot rather than absorbed, because a project that genuinely keeps source under `build/`
#: exists and would otherwise be silently unsurveyed.
GENERATED_DIRS = frozenset({
    "build", "_build", "cmake-build-debug", "cmake-build-release", "out", "dist",
    "node_modules", "vendor", "third_party", "target", ".tox", ".venv", "venv", "__pycache__",
})


def survey_repo(root, *, max_files: int = MAX_SURVEY_FILES) -> Survey:
    """Scan a checkout for candidate surfaces. Static only — no inference, no network, no subprocess."""
    root = pathlib.Path(root)
    surfaces: list[Surface] = []
    files_read = 0
    truncated = False
    pruned = 0
    ignored = 0
    per_language: dict[str, int] = {}
    per_part: dict[str, int] = {}
    # Ignored paths are resolved as the walk descends, so nothing is parsed twice and an ignored
    # directory is never entered. See `shard/ignorefile.py` for what this cost to find.
    index = IgnoreIndex(root)

    for dirpath, dirnames, filenames in os.walk(root, onerror=lambda _e: None):
        here = pathlib.Path(dirpath)
        rel_dir = here.relative_to(root).as_posix()
        rel_dir = "" if rel_dir == "." else rel_dir
        index.load(rel_dir)

        # `GENERATED_DIRS` DOES NOT YIELD TO TRACKING, and that asymmetry is deliberate. The two prunes
        # make different claims. An ignore rule says *this is not part of my project*, which tracking
        # directly refutes, so tracking overrides it. This list says *this directory conventionally holds
        # build output*, which is weaker, already caveated in `_blind_spots`, and is the mechanism that
        # protects the 200-candidate cap: `node_modules` is on it, some repositories COMMIT
        # `node_modules`, and letting tracking override here would spend the whole cap on vendored
        # dependencies — a measured run.1 with the cause changed and the symptom
        # identical.
        keep = [d for d in dirnames if d not in _VCS_DIRS and d not in GENERATED_DIRS]
        pruned += len(dirnames) - len(keep) - sum(1 for d in dirnames if d in _VCS_DIRS)
        after_ignore = [d for d in keep
                        if not index.ignored(f"{rel_dir}/{d}".lstrip("/"), is_dir=True)]
        ignored += len(keep) - len(after_ignore)
        dirnames[:] = after_ignore

        for name in sorted(filenames):
            language = _EXT_LANG.get(pathlib.PurePath(name).suffix.lower())
            if language is None:
                continue
            if index.ignored(f"{rel_dir}/{name}".lstrip("/"), is_dir=False):
                continue
            if files_read >= max_files:
                truncated = True
                break
            files_read += 1
            # PER LANGUAGE, so a report can say "read 4,102 kotlin files and matched nothing" instead of
            # "this may mean there is none, or that the table does not cover it". See `languages_read`.
            per_language[language] = per_language.get(language, 0) + 1
            hits, in_part = _scan_file(here / name, root, language)
            surfaces.extend(hits)
            per_part[language] = per_part.get(language, 0) + in_part
        if truncated:
            break

    return Survey(surfaces=tuple(surfaces), files_read=files_read, truncated=truncated,
                  files_read_in_part=sum(per_part.values()), pruned_dirs=pruned, ignored_dirs=ignored,
                  # WHAT THE IGNORE DECISIONS RESTED ON, and how many the index overruled. Reported
                  # rather than assumed: with no readable index the walk answers a weaker question, and
                  # `_blind_spots` has to be able to say which one it answered.
                  ignore_basis=index.tracked_basis, ignore_refusal=index.tracked_refusal,
                  ignored_but_tracked=index.rescued,
                  languages_read_in_part=tuple((k, n) for k, n in sorted(per_part.items()) if n),
                  languages_read=tuple(sorted(per_language.items(), key=lambda kv: (-kv[1], kv[0]))))


#: Directory components that name a TEST tree. Conventions, not guesses — but only `test` and `tests`
#: fired in the six-repository corpus this was measured on, so every other entry is exercised by its
#: own case in the maintainers' suite instead. An entry nothing kills is untested, and a list that
#: reads as thorough while three-sevenths of it is unexercised is a defect this project has already
#: paid for once (`witness.payload_readings`).
#:
#: `examples` is deliberately ABSENT though it measured 7 candidates: a demo is not a test, and a
#: label that is convenient and wrong is worse than one gap. So are `integration`, `benchmarks` and
#: `regression`, each of which is an ordinary product-module name in some repository.
TEST_DIRS = frozenset({
    "test", "tests", "testing", "spec", "specs", "__tests__", "fixtures", "testdata", "test_data",
    "e2e",
})

#: `test_x.py`, `x_test.go`, `x.test.js`, `x.spec.ts`, `conftest.py`.
_TEST_FILE = re.compile(r"(^test[_-].*|.*[_-]test\.[^.]+$|.*\.(test|spec)\.[^.]+$|^conftest\.py$)")

#: A line longer than any human writes is the signature of a GENERATED file, and this is a CONTENT
#: property rather than a name list because the name list was measured and lost. Over six repositories
#: (601 candidates), `*.min.js`-style names caught 107 and this caught 127 — every one of the name
#: rule's hits plus twenty it missed, including `npm/lib/jsrsasign.js` whose longest line is 47,978
#: characters and `sample/js/moment-2.2.1.js` at 32,912. Neither has "min" anywhere in its name.
#:
#: 500 is generous by design: black caps at 88 and prettier at 80, so nothing hand-written is near it.
#:
#: WHY THIS MATTERS MORE THAN THE COUNT. A minified file is generated FROM source that is usually also
#: in the checkout, so the candidate is a duplicate of one already reported — and it is frequently a
#: single enormous line, which makes the `path:line` this product anchors every alert on meaningless.
GENERATED_LINE_CHARS = 500


def _provenance(rel: str, longest_line: int) -> str:
    """Whose code this is. REPORTED, NEVER PRUNED, and the measurement is why.

    The fraction that is not the target's own source ranges from 0% to 77% across six repositories —
    urllib3 60.2%, express 77.4%, jsrsasign 0% test but 63.5% generated, goawk 12.2%. A rule that
    dropped any class would be right for one of those repositories and wrong for the next, and
    dropping a candidate silently is how a survey reports a smaller attack surface than it found.
    Naming the split lets the reader do the arithmetic this function must not do for them.

    Generated is checked FIRST: a minified test bundle is generated, and that is the more useful
    thing to say about it.
    """
    if longest_line > GENERATED_LINE_CHARS:
        return "generated"
    parts = pathlib.PurePosixPath(rel).parts
    if any(part.lower() in TEST_DIRS for part in parts[:-1]):
        return "test"
    return "test" if _TEST_FILE.match(parts[-1].lower()) else "source"


def _scan_file(path: pathlib.Path, root: pathlib.Path,
               language: str) -> tuple[list[Surface], bool]:
    """Match the marker table against one file. Capped per file so one generated blob cannot dominate.

    Returns the surfaces AND whether this file was read only in PART — by `MAX_FILE_BYTES` at the
    read or by `MAX_HITS_PER_FILE` in the loop — because a cap nobody reports reads as absence, which
    is the rule `truncated` already exists for one level up.
    """
    # REGULAR FILES ONLY, and the `except OSError` below is exactly why this needs its own check rather
    # than relying on the guard. Opening a FIFO BLOCKS until a writer appears — it does not raise, so no
    # exception handler can rescue it, and there is no timeout anywhere in the scan. Measured: one
    # `src/pipe.c` FIFO made `survey_repo` hang until an external kill at 60s. A character device is the
    # quieter half: `/dev/zero` opens and reads MAX_FILE_BYTES of nothing, at whatever cost.
    #
    # Git cannot store a FIFO, so a plain `actions/checkout` tree has none. It arrives from a preceding
    # workflow step, self-hosted-runner leftovers, or a PREPARED WORKDIR — which customer harness
    # scripts build and which `profile_repo` is explicitly pointed at.
    if not path.is_file():                                # False for FIFOs, sockets, devices, dirs
        return [], False
    try:
        with open(path, "rb") as fh:
            # ONE BYTE PAST THE CEILING, and that byte is the whole point: `read(MAX_FILE_BYTES)`
            # returns the same length for a file that is exactly the cap and one that is a gigabyte,
            # so the truncation cannot be told from a complete read. Measured on a 306,014-byte `.c`
            # file whose only `strcpy(` sits past the cap — the survey reported zero candidates and
            # blamed the marker table.
            raw = fh.read(MAX_FILE_BYTES + 1)
    except OSError:
        return [], False

    in_part = len(raw) > MAX_FILE_BYTES
    text = raw[:MAX_FILE_BYTES].decode("utf-8", errors="replace")
    rel = str(path.relative_to(root))
    lines = text.splitlines()
    # Free: this file is already read and already being walked line by line.
    provenance = _provenance(rel, max((len(ln) for ln in lines), default=0))
    found: list[Surface] = []
    for number, line in enumerate(lines, start=1):
        if len(found) >= MAX_HITS_PER_FILE:
            # A LINE REMAINED AND THIS FILE WAS NOT READ TO THE END. Set here rather than derived from
            # `len(found) == MAX_HITS_PER_FILE` at the return, because a file whose LAST line produced
            # the twentieth hit was read completely and its count is a total, not a floor.
            in_part = True
            break
        stripped = line.strip()
        # A ROW'S SHAPE IS NOT KNOWN HERE, which is why `surveymarkers` exports `kind_of` and not the
        # table. This loop used to unpack `(kind, langs, pattern)` itself; across a module boundary
        # that layout becomes a contract two files have to agree on, and the scan has no use for it —
        # it wants a kind or nothing, and the language filter is the table's business.
        if (kind := kind_of(line, stripped, language)) is not None:
            found.append(Surface(path=rel, line=number, kind=kind, language=language,
                                 evidence=stripped[:160], provenance=provenance))
    return found, in_part


def assess(survey: Survey, *, harness_kinds=(), witness_entry: str | None = None,
           deep_available: bool = True, languages=None) -> Assessment:
    """Rank each surface by whether Shard could attach proof there, and name what it cannot check.

    Capability facts arrive as ARGUMENTS. That is what keeps this module simple-safe: the harness
    dictionary lives behind the separate package and the free image does not contain it, so the caller resolves
    what it can and passes the answer in.
    """
    deep_reachable = bool(deep_available and harness_kinds)
    witness_reachable = witness_entry is not None

    # RANK, THEN PROVENANCE, THEN A SPREAD — `path` is no longer the tie-break, and `_spread` records
    # what that cost a customer. `.get(..., 1)` rather than `[...]`: a future provenance value must not
    # raise here, and the middle of the order is the honest place for an unknown one — ahead of what is
    # known to be unusable, behind what is known to be the customer's own code.
    blocks: dict[tuple[int, int], list[RankedSurface]] = {}
    for r in (_rank_one(s, deep_reachable, witness_reachable, witness_entry) for s in survey.surfaces):
        blocks.setdefault((_RANK_ORDER[r.rank], _PROVENANCE_ORDER.get(r.surface.provenance, 1)), []).append(r)
    ranked = tuple(row for key in sorted(blocks)
                   for row in spread([(r.surface.path, r) for r in
                                     sorted(blocks[key],
                                            key=lambda r: (r.surface.path, r.surface.line))]))

    return Assessment(ranked=ranked,
                      blind_spots=_blind_spots(survey, ranked, deep_reachable, witness_reachable,
                                               deep_available, languages))


def _rank_one(s: Surface, deep_reachable: bool, witness_reachable: bool,
              witness_entry: str | None) -> RankedSurface:
    if deep_reachable and s.language in MEMORY_UNSAFE:
        return RankedSurface(s, RANK_DEEP,
                             "a harness kind applies and this is memory-unsafe source, so a crashing "
                             "input could be attached")
    if witness_reachable and s.kind in WITNESSABLE_KINDS:
        # OFF today: `WITNESSABLE_KINDS` is empty, so `s.kind in WITNESSABLE_KINDS` is always False,
        # this branch never fires, and the two ranks below are byte-identical to what they were before
        # the gate existed. When P1.0's witness lever is measured ON and the set is populated, a
        # managed-language surface of a witnessable kind carries a reproducing input the same way
        # memory-unsafe source does — for `command_exec`, measured unforgeable via `output_marker`
        # (inject `id`, observe `uid=` the agent did not supply). It requires a declared entry point
        # because that route IS the witness: without one there is nothing to re-execute the payload.
        return RankedSurface(s, RANK_DEEP,
                             f"a runnable entry point is declared and a {s.kind} finding here carries a "
                             f"reproducing input the runner can re-execute, so proof is attachable")
    if witness_reachable:
        return RankedSurface(s, RANK_WITNESS,
                             f"{witness_entry} is declared, so a demonstration could be executed here")
    return RankedSurface(s, RANK_HYPOTHESIS,
                         "nothing here could carry proof: no harness kind applies and no runnable "
                         "entry point is declared")


def _blind_spots(survey: Survey, ranked, deep_reachable: bool, witness_reachable: bool,
                 deep_available: bool, languages) -> tuple[str, ...]:
    """What the survey cannot check. Named, because silence about a gap reads as coverage."""
    out: list[str] = []

    if survey.truncated:
        out.append(f"the scan stopped at {survey.files_read} files; every count is a floor, not a total")

    # THE SECOND CAP, and it was silent until 2026-09-02. The one above is the FILE ceiling; this is
    # the per-file HIT ceiling, which fires on exactly the file a reader most wants the total for —
    # the one with twenty-odd marker lines in it. Without this sentence the artefact says
    # `truncated: False` over a count that is a sample, which is the "we looked and found nothing"
    # failure the whole blind-spot list exists to refuse.
    if survey.files_read_in_part:
        out.append(f"{survey.files_read_in_part} file(s) were read only in part — past "
                   f"{MAX_FILE_BYTES:,} bytes or past {MAX_HITS_PER_FILE} candidates the scan stops "
                   f"— so every count above is a floor for them, and a marker beyond either ceiling "
                   f"was never reached rather than absent")

    if not deep_available:
        out.append("deep capability is not present in this build, so nothing here can carry a "
                   "reproducing input")
    elif not deep_reachable:
        out.append("no harness kind applies, so no candidate can be raised to a reproducing input. "
                   "Declare a harness at .shard/test_poc.sh")

    if not witness_reachable:
        out.append("no runnable entry point is declared, so simple mode cannot demonstrate anything "
                   "and every candidate below stays a hypothesis")

    if hypotheses := sum(1 for r in ranked if r.rank == RANK_HYPOTHESIS):
        out.append(f"{hypotheses} candidate(s) can be reasoned about but not proven in this configuration")

    # A LANGUAGE WITH NO CANDIDATES: two facts wearing one sentence until 2026-08-17.
    #
    # This used to answer every such language with *"this may mean there is none, or that the marker
    # table does not cover it"* — a hedge over something the walk MEASURED. The two halves call for
    # opposite actions: files read and nothing matched is a limit of the marker table, and no file read
    # at all is a limit of the walk, which the customer can often fix (the cap, an ignore rule, a
    # directory on `GENERATED_DIRS`). Splitting them cost nothing but the count.
    read = dict(survey.languages_read)
    part = dict(survey.languages_read_in_part)
    unseen = sorted(set(languages or ()) - {s.language for s in survey.surfaces})
    whole = [lang for lang in unseen if read.get(lang) and not part.get(lang)]
    partly = [lang for lang in unseen if read.get(lang) and part.get(lang)]
    unread = [lang for lang in unseen if not read.get(lang)]
    if whole:
        out.append("no candidate surface was detected in: "
                   + ", ".join(f"{lang} ({read[lang]} file(s) read)" for lang in whole)
                   + " — those files WERE read and nothing in the marker table matched, so this is that "
                     "table's limit rather than a clean bill of health")
    if partly:
        out.append("no candidate surface was detected in: "
                   + ", ".join(f"{lang} ({read[lang]} read, {part[lang]} NOT to the end)" for lang in partly)
                   + " — the scan stopped inside those files at a per-file ceiling, so that is a FLOOR "
                     "for the language and NOT a statement about the marker table")
    if unread:
        out.append("NOT ONE FILE was read in: " + ", ".join(unread)
                   + " — preflight found that language in this repository and the survey opened none of "
                     "it, so nothing here is a statement about that code. Every such file sat behind the "
                     "file cap, an ignore rule or a generated directory named above")

    # WHICH LANGUAGES THE TABLE ACTUALLY KNOWS SOMETHING ABOUT. Two of its rows are language-agnostic —
    # `parser` is one, and it is the highest-volume kind measured — so a language with no row of its own
    # still produces candidates, and its coverage is thinner in a way no count reveals. A Kotlin project
    # getting `parser` hits and nothing else should be told that is all there was to get.
    if thin := sorted(lang for lang, n in survey.languages_read if n and lang not in MARKER_LANGUAGES):
        out.append("the marker table has NO language-specific rows for: " + ", ".join(thin)
                   + " — only its language-agnostic ones applied there, so coverage of those files is "
                     "thinner than for a language the table names, however many candidates it produced")

    if survey.pruned_dirs:
        out.append(f"{survey.pruned_dirs} generated/build directory(ies) were not surveyed "
                   f"({', '.join(sorted(GENERATED_DIRS)[:6])}, …) — deep mode needs a built tree, so "
                   f"they are normally artefacts, but a project that keeps source there was not read")

    if survey.ignored_dirs:
        # THE BASIS IS PART OF THE CLAIM. With an index, "git does not track it" is measured and the
        # sentence is a fact. Without one, the walk has only the patterns — and `.gitignore` does not
        # apply to a file git already tracks, so an untracked-looking skip may have been committed source.
        # Stating that is `_mode_verdict`'s rule: answer `unknown` rather than guessing.
        basis = (f", checked against the {survey.ignore_basis}" if survey.ignore_basis else
                 f" — and this rests on the PATTERNS ALONE, because {survey.ignore_refusal}. A file that "
                 f"git tracks despite matching a rule would have been skipped here")
        out.append(f"{survey.ignored_dirs} directory(ies) were not surveyed because this repository's "
                   f".gitignore excludes them{basis}")

    if survey.ignored_but_tracked:
        out.append(f"{survey.ignored_but_tracked} path(s) match a .gitignore rule but are TRACKED by "
                   f"git, so they were surveyed anyway — committed code a pattern claims is not part of "
                   f"the project. Worth knowing about; it usually means a file was committed before the "
                   f"rule that now covers it")

    if not survey.surfaces:
        # THE SAME ATTRIBUTION, REPOSITORY-WIDE, and it is a claim about a scan that FINISHED. Either
        # ceiling falsifies it: the 300,102-byte `.c` above produced `candidates 0` and this sentence,
        # and a walk stopped at `MAX_SURVEY_FILES` produces it over files nobody opened. Both counts
        # are already named above, so this one only has to stop claiming a cause it cannot know.
        out.append("no candidate surface was detected anywhere" + (
            ", and the scan did not finish — so this is a FLOOR and NOT the marker table's limit: a "
            "marker past one of the ceilings above was never reached rather than absent"
            if survey.truncated or survey.files_read_in_part else
            "; treat this as the marker table's limit rather than as a clean bill of health"))
    return tuple(out)


#: WHY the rank came out uniform, keyed on the rank that came out uniform. Three sentences and not one,
#: because the single hardcoded clause "because nothing here could carry proof" was true of exactly one
#: of them and `_rank_spread` printed it under all three.
#:
#: Measured 2026-09-02 on libyaml with `--witness-entry .shard/entry.sh`, which is the remediation the
#: report itself asks for: the route line read `0 in reach of a reproducing input, 37 in reach of an
#: executed demonstration` and the very next line said nothing here could carry proof. The JSON, the
#: ranks and every per-candidate `why` were correct and agreed with the route line — only this clause
#: disagreed, so a customer who had just done the work was told in the same breath that it achieved
#: nothing. The uniformity claim in front of the clause was true throughout; the cause was not.
_SPREAD_CAUSE = {
    RANK_DEEP: "because a harness kind and a memory-unsafe language are facts about the REPOSITORY, "
               "which every candidate in it inherits",
    RANK_WITNESS: "because the one declared entry point reaches all of them equally",
    RANK_HYPOTHESIS: "because nothing here could carry proof",
}

#: AND THE HEAD OF A TIED LIST IS A SAMPLE, which no reader can tell from a cap. `report.py` prints
#: *"the 20 highest-ranked candidates"* over a rank this sentence has just called uniform, and both
#: artefacts are a PREFIX of `assessment.ranked` — so what the cap actually selects is `_spread`'s
#: sample. Said once here rather than in both branches below, and only where the rank went uniform,
#: because that is the only case where a prefix is not a top-N.
_SAMPLED = (" Where a cap cuts this list, its head is a PROPORTIONAL SAMPLE across the tree rather "
            "than its first directory alphabetically.")


def _rank_spread(assessment: Assessment) -> str | None:
    """Say so when the rank did not discriminate. Returns None when it did, or when there is nothing.

    The design notes calls a rank that never discriminates *"a wish list with a rank column"* —
    the specific outcome the design notes says the ranking exists to prevent. The
    honest instrument does not hide that: when one label and one reason cover nearly everything, the
    survey reports the fact rather than presenting a flat list as an ordering.

    This is a statement about THIS survey's output, not a precision claim about the marker table, so it
    needs no measurement to be true. Making the rank actually predictive does, and that stays open.
    """
    total = len(assessment.ranked)
    if total < 2:
        return None
    reasons = {r.why for r in assessment.ranked}
    top_rank, top = max(assessment.counts().items(), key=lambda kv: kv[1])
    if len(reasons) > 1 and top < total:
        return None
    # THE LIST IS ORDERED EVEN WHEN THE RANK IS NOT, since 2026-08-18. The old sentence ended "read the
    # list as a map of where to look, not as an ordering", which was true of a rank that cannot
    # discriminate and false about the list, because it is now sorted with the target's own source
    # ahead of its tests and of generated files. Saying there is no ordering when there is sends a
    # reader to the bottom of a list whose top is the part they own.
    provenances = {r.surface.provenance for r in assessment.ranked}
    if len(provenances) > 1:
        return (f"this rank did not discriminate: {top} of {total} candidates share one label and one "
                f"reason, {_SPREAD_CAUSE[top_rank]} — that is a fact about this configuration, not "
                f"about the code. The list is still ORDERED: the target's own source first, then test "
                f"paths, then generated files.{_SAMPLED}")
    return (f"this rank did not discriminate: {top} of {total} candidates share one label and one "
            f"reason, so read the list as a map of where to look, not as an ordering.{_SAMPLED}")


def _provenance_line(survey: Survey) -> str:
    """`74 in the target's own source, 112 in test paths` — and the zeroes are omitted HERE, unlike in
    the payload, because a human reading "0 generated" learns nothing while a machine diffing two runs
    needs the key to exist."""
    counts = survey.by_provenance()
    parts = [f"{counts['source']} in the target's own source"]
    if counts["test"]:
        parts.append(f"{counts['test']} in test paths")
    if counts["generated"]:
        parts.append(f"{counts['generated']} in generated files (a line over "
                     f"{GENERATED_LINE_CHARS} chars; the location is not usable)")
    return ", ".join(parts)


def summarise(survey: Survey, assessment: Assessment) -> str:
    """The human summary. Says "candidate" everywhere it says anything, on purpose."""
    counts = assessment.counts()
    lines = [
        f"scanned      {survey.files_read} source file(s)"
        + ("  (TRUNCATED — counts are a floor)" if survey.truncated else ""),
        f"candidates   {len(assessment.ranked)}"
        + (f"  ({', '.join(f'{k}={v}' for k, v in survey.by_kind().items())})"
           if survey.surfaces else ""),
        # WHOSE CODE, on the line under the count, because the count alone has been misleading on every
        # repository measured: 60% test fixtures on urllib3, 63% minified bundles on jsrsasign, 12% on
        # goawk. Stated rather than pruned — see `_provenance`.
        *([f"             {_provenance_line(survey)}"] if survey.surfaces else []),
        f"route        {counts[RANK_DEEP]} in reach of a reproducing input, "
        f"{counts[RANK_WITNESS]} in reach of an executed demonstration, "
        f"{counts[RANK_HYPOTHESIS]} in reach of neither",
    ]
    if (spread := _rank_spread(assessment)) is not None:
        lines.append(f"             {spread}")
    if assessment.blind_spots:
        lines.append("blind spots")
        lines += [f"             {b}" for b in assessment.blind_spots]
    return "\n".join(lines)


try:
    from shard._markers_version import MARKERS_PACK_VERSION as _MARKERS_PACK_VERSION
except ImportError:
    _MARKERS_PACK_VERSION = "unstamped"


def to_payload(survey: Survey, assessment: Assessment, *, limit: int = 200) -> dict:
    """JSON for the state repository and the action outputs.

    Capped, and the cap is reported for the same reason every other cap here is.

    THREE DESTINATIONS, enumerated 2026-09-02 because a guard was written against one of them and
    the one it missed is the product's only deployment:

      1. `shard-survey.json`, written by `shard/cli.py:_cmd_survey`.
      2. the `--json` print in that same function — which `shard/action.py` captures with
         `contextlib.redirect_stdout` and `json.loads`, and echoes verbatim into the step log. Every
         GitHub Action run learns its status and its artefact paths from this string and from
         nothing else; `argv_for` appends `--json` to every survey argv.
      3. `shard/clidiff.py:_survey_for_diff`, into the state repository.

    Sites 1 and 2 are ONE document plus `written` and `artefacts`, and
    `test_the_PRINTED_document_is_the_WRITTEN_one_plus_two_NAMED_KEYS` is what holds them together —
    `shard/cli.py` legitimately mutates this dict five times between the return and the print, so one
    more edit in that window is the same shape as the edits already there. Site 3 has no artefact to
    compare against and is not covered by it. `shard-report.md` is a fourth ARTEFACT and not a fourth
    destination:
    `build_survey_markdown` is handed `summarise()` and `assessment.ranked`, never this payload,
    which is why it carries its own smaller cap.
    """
    kept = assessment.ranked[:limit]
    return {
        "files_read": survey.files_read,
        "truncated": survey.truncated,
        "kinds": survey.by_kind(),
        "counts": assessment.counts(),
        # WHOSE CODE THE COUNT ABOVE IS ABOUT. A headline of "186 candidates" was 60% test fixtures on
        # urllib3 and 63% minified bundles on jsrsasign, and the artefact said neither.
        "provenance": survey.by_provenance(),
        # THE ARRAY AND THE THREE AGGREGATES ABOVE DESCRIBE DIFFERENT SETS, and until 2026-09-02 no
        # field in the document said so. Measured on libgit2: `provenance` read
        # `{source: 702, test: 30, generated: 12}` over all 744 while grouping the 200-row
        # `candidates` array gave `{source: 200}` — one scan, two breakdowns, and nothing to tell a
        # consumer which was which. `omitted` was present and correct; what it never said is that it
        # is omitted FROM THE ARRAY. With the ceiling beside it,
        # `len(candidates) + omitted == sum(counts.values())` is checkable from the document alone,
        # and a COMPLETE array is provable (`len(candidates) < candidates_cap`) instead of assumed.
        #
        # ADDED rather than narrowing the aggregates to the kept rows: `summarise()` prints the
        # whole-scan numbers into `shard-report.md` in the same `--out-dir`, so narrowing would trade
        # an internal disagreement for a cross-artefact one. The markdown says the same thing in
        # prose (`report.build_survey_markdown`'s `where` row) and a dashboard never reads it.
        #
        # AND THE INVARIANT IS ABOUT THE ARRAY, NOT ABOUT THE REPOSITORY — the three fields below are
        # what makes that difference statable. `truncated` and `files_read_in_part` bound the SCAN
        # that produced `counts`; `candidates_cap` and `omitted` bound the ARRAY cut out of it.
        # Measured 2026-09-02: one `.c` file with 25 marker lines emitted `truncated: False`,
        # `omitted: 0`, `candidates_cap: 200` and counts summing to 20, so every array-side check
        # passed while five hits had been dropped before anything counted them. A consumer wanting
        # "this is the whole population" needs BOTH halves:
        # `len(candidates) + omitted == sum(counts.values())` with `truncated` false AND
        # `files_read_in_part` zero.
        "candidates_cap": limit,
        "hits_per_file_cap": MAX_HITS_PER_FILE,
        "bytes_per_file_cap": MAX_FILE_BYTES,
        "files_read_in_part": survey.files_read_in_part,
        "omitted": max(0, len(assessment.ranked) - len(kept)),
        "blind_spots": list(assessment.blind_spots),
        "markers_pack_version": _MARKERS_PACK_VERSION,
        "candidates": [{
            "path": r.surface.path, "line": r.surface.line, "kind": r.surface.kind,
            "language": r.surface.language, "evidence": r.surface.evidence,
            "rank": r.rank, "why": r.why, "provenance": r.surface.provenance,
        } for r in kept],
    }


__all__ = [
    "MAX_FILE_BYTES", "MAX_HITS_PER_FILE", "MAX_SURVEY_FILES", "MEMORY_UNSAFE", "WITNESSABLE_KINDS",
    "RANK_DEEP", "RANK_HYPOTHESIS", "RANK_WITNESS",
    "Assessment", "RankedSurface", "Surface", "Survey",
    "assess", "summarise", "survey_repo", "to_payload",
]
