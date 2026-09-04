"""Target acquisition — what a repository IS, and whether a workdir can be adjudicated.

The layer above the solver. The design notes is the decision record; this module is its
first half.

## The gap this closes

The design notes, still open at the time of writing: *"no workdir-preparation code
exists in this repository at all."* `replay.py` runs `bash test_poc.sh <poc>` in a workdir, the benchmark
hands that workdir over pre-built, and a customer hands over a git checkout. Every one of the 770
measured tasks satisfied the workdir contract by construction, so no measurement could have surfaced
this.

Audit §1 is sharper still, and it is the reason `validate_workdir` exists at all. The `__EXIT__`
contract *"is documented — to the model, not to the customer."* `prompts.py` tells the AGENT to read the
marker line. Nothing told the human writing the harness, and **nothing checked**. A marker-less harness
used to adjudicate as "did not crash" on every replay, whatever the target actually did. That specific
false negative is closed in the oracle (`_effective_exit`), but the diagnosis still belongs BEFORE the
run, where it costs nothing, rather than inside it, where it costs a whole budget.

## Two jobs, and why they are one module

* `profile_repo` — the static facts. This is preflight (the integration guide): what the
  repository is, which modes it can support, and what a run would cost. No inference, no network, no
  subprocess, so it is nearly free and completely deterministic.
* `validate_workdir` — the contract check, run after a harness entry has materialised a workdir and
  before the solver is started.

They are the input and the output of the same pipeline stage, and both are read by the same caller.


**Simple-safe.** the maintainers' suite lists this module's peers. Profiling and contract validation
are commodity: the design notes puts CI glue and format work explicitly in the leave-in-Python
column, and preflight is a product feature on the free tier as much as the paid one. Nothing here may
ever import the separate package.

## What this module may never do

**It may not repair a harness.** the separate package holds `test_poc.sh` read-only against `write_poc` and
`apply_patch`, because a writable harness is how an agent forges its own verdict — `write_poc(
path="./test_poc.sh", text="echo __EXIT__=1\\n")` was once an accepted tool call that made every replay
report a reliable 5/5 crash. This module REPORTS. Preparation happens in a harness entry, before the
solver starts and before the digest is taken, and nothing downstream may write to the file.

Trading a silent false negative for a false positive would also be strictly worse for a tool whose whole
value is that a finding is real, so every verdict below fails toward *"say less"*, never toward
*"assume it works"*.
"""

from __future__ import annotations

import dataclasses
import os
import pathlib
import re
from dataclasses import dataclass

# The one place the VCS metadata set is stated. `tools._grep` excludes the same directories before its
# file cap, and a second copy here is exactly the drift the separate package was created to end: two sites
# asking the same capability question and answering it differently. Private by name, shared by intent.
from shard.ignorefile import IgnoreIndex
from shard.tools import _VCS_DIRS
# `shard/witness.py` imports nothing from this package — it is a leaf — so this is a plain module-scope
# import and not a cycle. The FUNCTION is imported rather than the tuple behind it, deliberately: its
# own docstring is *"read AT CALL TIME so a lever is a decision and not an import order"*, and binding
# the value here would reintroduce exactly the drift `_EXPECTATION_HELP` below exists to end.
from shard.witness import offered_expectations

# --- the workdir contract ---------------------------------------------------------------------------

#: The harness. `replay.py` runs exactly `["bash", "test_poc.sh", poc]` and nothing else in the chain
#: reads any other file to decide ground truth.
HARNESS_NAME = "test_poc.sh"

#: The marker `oracle._parse_exit` recovers the target's own status from. Stated once, here, and
#: asserted against the oracle's own literal in the maintainers' suite — a validator that reported
#: "conforming" for a string the oracle cannot read would be worse than no validator.
EXIT_MARKER = "__EXIT__="

#: The one-line fix, quoted verbatim to the customer when the marker is missing. It is the last line of
#: a conforming harness, and `$?` must be the TARGET's status, so nothing may run between them.
#:
#: **DERIVED FROM `EXIT_MARKER`, because the two drifting apart is silent and total.** A harness that
#: prints a marker the oracle cannot parse yields no inner exit code at all — every replay reads as
#: whatever the container returned, and the adjudication is about the wrong program. Until 2026-08-21
#: this was an independent literal: the maintainers' suite pinned `EXIT_MARKER` against the oracle's
#: own copy and nothing pinned this one, so changing it to `echo __WRONG__=$?` broke NOTHING that the
#: suite could see — measured.
#:
#: It matters more now than it did then. `instrument`, `deep/triage` and `deep/registry` build their
#: in-container shell commands from these two constants rather than from copies of the string, so a
#: drift here would put the wrong marker in three executors at once.
EXIT_MARKER_FIX = f'echo {EXIT_MARKER}$?'


def harness_prints_exit_marker(workdir) -> bool | None:
    """Does the workdir's ``test_poc.sh`` print the ``__EXIT__=<n>`` line the oracle reads?

    ``None`` means there was no harness to inspect — the deterministic suite's own shape, and the same
    state ``harness_digest`` reports as ``None``. It is not a failure and it is not a "no".

    Never raises. This is a DIAGNOSTIC: a run that dies because a status line could not be computed
    would be strictly worse than a run that says nothing.

    **Moved down from `the separate package`**, which now re-exports it under its old private name. Same
    reasoning as `the separate package`: the check was needed by a module that must not import the protected
    side, and a leaf cannot reach mid-stack. Behaviour is unchanged, deliberately —
    `the maintainers' suite` pins all four of its answers through ``Solve`` and those
    assertions were not touched.

    **A static read of the script text, and the honest limit is worth stating.** ``_parse_exit`` reads
    the runtime OUTPUT. A harness that prints the marker through a variable is a false negative here and
    the oracle will still read it correctly; a harness carrying the literal inside a comment is a false
    positive. Both are rare and both fail toward the safe direction, because the report is advisory and
    `the separate package` deliberately does NOT make conformance a condition of accepting a finding.
    """
    text = _harness_text(workdir)
    return None if text is None else EXIT_MARKER in text


def _harness_text(workdir) -> str | None:
    """The harness source, or ``None`` when there is nothing to read. Never raises."""
    try:
        return (pathlib.Path(workdir) / HARNESS_NAME).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


@dataclass(frozen=True)
class WorkdirReport:
    """Whether a workdir can be adjudicated, and what it costs the run if not.

    ``verdict`` uses the product vocabulary already fixed in `the integration guide` §6b —
    ``supported`` / ``degraded`` / ``unsupported`` — rather than inventing a third set of words for the
    same three states.
    """

    workdir: str
    harness: bool                       # test_poc.sh is present and readable
    harness_empty: bool                 # present, but with no content at all — cannot adjudicate
    exit_marker: bool | None            # None iff there is no harness to inspect
    corpus: bool                        # ./corpus or a *_seed_corpus.zip — `use_corpus` has a base
    repo_tree: bool                     # ./repo — `code_query` has a tree to search
    description: bool                   # ./description.txt — asserts a KNOWN, published defect
    vcs_in_repo: bool                   # ./repo still carries VCS metadata (see §5 of the audit)
    reasons: tuple[str, ...] = ()

    #: Did the harness call a BENIGN control input a crash? ``None`` means nobody asked — which is what
    #: this module always answers, because deciding it needs a subprocess and nothing here runs one.
    #: `the separate package` `acquire` is where it is answered, and the tri-state is the same idiom
    #: ``exit_marker`` already uses: not-checked and checked-and-clean are different facts, and
    #: collapsing them to ``False`` would let a workdir nobody controlled read as a workdir that
    #: passed. `preflight --workdir` therefore reports ``None`` and says less, deliberately.
    control_crashed: bool | None = None

    @property
    def verdict(self) -> str:
        """``unsupported`` when nothing can be adjudicated; ``degraded`` when the unambiguous arm is
        missing; ``supported`` otherwise.

        No harness is the only hard stop. Without one there is no path from a candidate input to a
        verdict at all, so a run would burn its whole budget and report ``audited`` — a clean bill of
        health from a target that was never actually tested. That is the single most expensive way this
        product can be wrong, and it is worth refusing before any inference is paid for.

        **A harness that calls a benign input a crash is the second hard stop**, and it is the one the
        first real run found (the design notes, "Found by the FIRST REAL RUN" §4). `CRASH_OK` is
        ``{0, 300}``, so every other status the harness reports is a crash — and a fuzz driver that
        exits non-zero for an input it merely REJECTED is an ordinary thing to write. Demonstrated
        against cJSON v1.7.10's own shipped `fuzzing/afl.c`: a one-byte PoC containing ``x``
        adjudicated ``reproduced 5/5`` with no sanitizer report at all, which downstream is a SARIF
        alert, a reproduction bundle and a broken build.

        Refused rather than degraded because such a harness cannot produce a real finding either: every
        verdict it gives is unfalsifiable, so a run against it costs a whole budget and can only end in
        a false positive or a meaningless clean. The customer's fix is one line in their harness and
        the reason quotes it.
        """
        if not self.harness or self.harness_empty:
            return "unsupported"
        if self.control_crashed:
            return "unsupported"
        return "supported" if self.exit_marker else "degraded"

    @property
    def known_bug(self) -> bool:
        """Does this workdir assert that a defect is already known to be here?

        The benchmark's framing and the customer's are opposites, and `_TargetCaps.known_bug` carries
        the same claim from the other signal (a masked `:vul` image). Both must agree, because
        the design notes records what asserting a known bug on a customer commit costs:
        the agent is told the harness is trustworthy and is structurally forbidden from suspecting it.
        """
        return self.description


def validate_workdir(workdir) -> WorkdirReport:
    """Check a materialised workdir against the contract, before the solver is started.

    Cheap, pure, and it never raises: an unreadable workdir is reported as ``unsupported``, which is the
    same answer an empty one gets and the correct one in both cases.
    """
    root = pathlib.Path(workdir)
    text = _harness_text(root)
    marker = None if text is None else EXIT_MARKER in text
    harness = text is not None
    # Whitespace-only, and NOTHING more clever than that. A placeholder somebody `touch`ed costs a
    # whole budget to discover at run time and nothing to catch here. The line is drawn at "has no
    # content" deliberately: whether a script that DOES have content exercises the right target is not
    # statically decidable, and a validator that guessed would start refusing working harnesses —
    # strictly worse for a tool whose value is that its findings are real.
    harness_empty = harness and not text.strip()

    repo_tree = _is_dir(root / "repo")
    reasons: list[str] = []

    if not harness:
        reasons.append(
            f"no {HARNESS_NAME}: there is no path from a candidate input to a verdict, so a run would "
            f"report 'audited' on a target it never tested")
    elif harness_empty:
        reasons.append(
            f"{HARNESS_NAME} is empty: it cannot exercise the target, so every replay is clean and the "
            f"run would report 'audited' on a target it never tested")
    elif not marker:
        reasons.append(
            f"{HARNESS_NAME} does not print {EXIT_MARKER}<n>: the oracle falls back to a sanitizer "
            f"report or a fatal signal, which recovers most crashes but not a target that dies quietly. "
            f"Add `{EXIT_MARKER_FIX}` as the last line, with nothing between it and the target")

    vcs_in_repo = repo_tree and any(_is_dir(root / "repo" / d) for d in sorted(_VCS_DIRS))
    if vcs_in_repo:
        # Measured on this repository: 68.7% of walked files are under `.git`. `_grep` now excludes them
        # before its file cap, so this is no longer a capability kill — but it is still the customer's
        # source control sitting inside an offensive agent's read roots, and stripping it is free.
        reasons.append("./repo carries VCS metadata; strip it during preparation")

    return WorkdirReport(
        workdir=str(root),
        harness=harness,
        harness_empty=harness_empty,
        exit_marker=marker,
        corpus=_is_dir(root / "corpus") or bool(_glob_one(root, "*_seed_corpus.zip")),
        repo_tree=repo_tree,
        description=(root / "description.txt").is_file(),
        vcs_in_repo=vcs_in_repo,
        reasons=tuple(reasons),
    )


# --- the static profile -----------------------------------------------------------------------------

# A ceiling so a pathological tree cannot hang preflight. `truncated` is reported rather than absorbed:
# the design notes records what a silent cap costs — a truncated scan that found
# nothing reads as absence of the bug.
MAX_WALK_FILES = 200_000

# --- THE one extension → language map -----------------------------------------------------------------
#
# **There were TWO of these and each was blind to what the other saw.** `survey._EXT_LANG` and this table
# both answered "what language is this file", disagreed about six extensions in one direction and four in
# the other, and nothing compared them. Measured 2026-08-17:
#
#   the survey could never see  .kt .swift .scala .s .asm .hxx   -> kotlin, swift, scala, asm, and C++
#                                                                   HEADERS, whose language IS covered
#   preflight could never see   .mjs .cjs .mts .cts              -> modern JavaScript and TypeScript
#
# Both directions are a silent drop, and both were visible in one number without anyone reading it: on
# a real repository's checkout preflight reported **269 source files and the survey read 276** for the same
# repository, on the same commit, in the same run. That gap IS this defect, and it sat in the artefact.
#
# The consequence differed by direction and neither was cosmetic. A Kotlin or Swift repository had **every
# one of its source files skipped by the survey** — and two marker rows are language-AGNOSTIC, including
# `parser`, which produced 353 of the 413 candidates on a real repository, so those repositories lost real coverage
# rather than merely a count. In the other direction every cost estimate keyed off `source_bytes`
# understated a modern JavaScript project, which is the direction that quotes a customer too low.
#
# The separate package exists because two sites asking one capability question answered it differently. This is
# that, about the most basic question either walk asks. ONE table now, imported by both.
EXT_LANGUAGE: dict[str, str] = {
    ".c": "c", ".h": "c",
    ".cc": "c++", ".cpp": "c++", ".cxx": "c++", ".hpp": "c++", ".hh": "c++", ".hxx": "c++",
    ".rs": "rust", ".go": "go", ".zig": "zig",
    ".py": "python", ".js": "javascript", ".ts": "typescript", ".jsx": "javascript",
    ".tsx": "typescript", ".java": "java", ".rb": "ruby", ".php": "php", ".cs": "c#",
    ".swift": "swift", ".kt": "kotlin", ".scala": "scala", ".s": "asm", ".asm": "asm",
    # ES modules and CommonJS, and the TypeScript equivalents. Held only by the survey until 2026-08-17,
    # so preflight counted an `.mjs`-heavy repository as if those files were not source at all.
    ".mjs": "javascript", ".cjs": "javascript", ".mts": "typescript", ".cts": "typescript",
}

# Languages with no memory safety by default. `deep` mode's whole capability — sanitiser builds, the
# fuzz ladder, crash classification — is aimed at these, so their presence is what makes the mode
# plausible rather than merely permitted.
_MEMORY_UNSAFE = frozenset({"c", "c++", "asm", "zig"})

# Extensions that DECLARE rather than execute. Counted for display like any other file — a customer
# reading `c=1` should see the file they have — but not on their own evidence that there is anything
# here to build and run. See `TargetProfile.memory_unsafe`, which is where the distinction is spent.
_HEADER_EXTS = frozenset({".h", ".hh", ".hpp", ".hxx"})

_MAX_NATIVE_SAMPLE = 8

#: How many native sources are kept PER DIRECTORY while walking, before the sample is drawn. Equal to
#: `_MAX_NATIVE_SAMPLE` so a repository whose sources sit in one directory still fills the sample;
#: the spread happens in `_spread_sample`, not here. Bounds the memory: 8 strings per directory
#: holding native code, against every native path in the tree.
_PER_DIR_NATIVE = _MAX_NATIVE_SAMPLE


def _spread_sample(by_dir: dict[str, list[str]], limit: int) -> list[str]:
    """Draw `limit` paths ACROSS directories, round-robin over sorted directories.

    **THE GATE SAMPLED EIGHT FILES FROM WHICHEVER DIRECTORY THE WALK ENTERED FIRST, and that decided
    whether the separate capability was offered at all.** `native_sources` is not only a name for a refusal to
    print: `deep/harness._synth_applies` calls `synth.compilable_sources` on it, so a repository whose
    eight sampled files happen not to compile standalone is REFUSED, however much of it does.

    Measured 2026-08-31 over twelve cloned C repositories, before this function existed:

        libarchive   all 8 from `cat/` and `cat/test/`      the bsdcat TOOL's tests; `libarchive/` never seen
        libcbor      all 8 from `src/` and `src/cbor/`
        cmark        all 8 from `src/`
        jansson      all 8 from `src/`
        tidy-html5   all 8 from `src/`
        lz4          all 8 from `tests/`

    Six of twelve drew the whole sample from one subtree. libarchive has 718 native sources across 19
    directories and the gate saw two of those directories, neither of them the library.

    Round-robin and not a score: which directory a source sits in says nothing this repository has
    measured about whether it compiles standalone, and a `src`-over-`tests` preference would be the
    unmeasured name heuristic that `deep/fuzzable` had to retract. Spread is structural. It makes the
    sample REPRESENTATIVE without claiming to make it good.

    **What it buys, on the same twelve repositories, through `_synth_applies` itself:**

        _synth_applies      5 of 12  ->  7 of 12
        compilable sources     18    ->     18

    The TOTAL DID NOT MOVE, and that is the finding rather than a caveat. The same eighteen
    compilable sources were there before; fourteen of them were piled into libpng and zlib, which
    already qualified, and the gate is per-repository. cmark went 0 -> 1 and libarchive 0 -> 3, so two
    repositories the separate capability refused outright are now offered. A sample concentrated in one directory
    buys nothing on a repository that was already going to pass.

    **A uniform STRIDE through the sorted directory list was measured and rejected.** Taking every
    `ndirs // limit`-th directory rather than the first `limit` reaches deeper into the alphabet —
    libarchive 3 -> 4 compilable, libpng 3 -> 4, total 18 -> 20 — and changes no verdict, 7 of 12
    either way. Two more compilable sources do not earn the extra concept; "earn its place" applies
    to a selection rule as much as to a module.
    """
    picked: list[str] = []
    for depth in range(max((len(v) for v in by_dir.values()), default=0)):
        for name in sorted(by_dir):
            if len(picked) >= limit:
                return picked
            if depth < len(by_dir[name]):
                picked.append(by_dir[name][depth])
    return picked

# Marker filename → build system. Matched on the FILE NAME at any depth, because a monorepo's real build
# root is rarely the checkout root.
_BUILD_MARKERS: dict[str, str] = {
    "CMakeLists.txt": "cmake", "configure.ac": "autotools", "configure.in": "autotools",
    "Makefile.am": "autotools", "meson.build": "meson", "Cargo.toml": "cargo",
    "go.mod": "go", "build.gradle": "gradle", "pom.xml": "maven", "BUILD.bazel": "bazel",
    "WORKSPACE": "bazel", "setup.py": "setuptools", "pyproject.toml": "python",
    "package.json": "npm", "Makefile": "make", "GNUmakefile": "make",
}

#: **THE library SEAM, and it is one function.** the library design: a pack is knowledge we
#: keep and lend, and the tables above are the `markers` pack — the three of them, measured, not
#: re-typed (a maintenance script).
#:
#: The floor is the table in this file, which is what makes the whole design safe to depend on: with no
#: pack, with a refused pack, with no network, with no subscription, `_with_markers(None)` returns
#: exactly what this module has always used and every caller behaves exactly as it does today. A pack
#: can only WIDEN recognition, because these tables carry no behaviour — an extension nobody knows is an
#: extension nobody counts, and that is the one failure mode a per-release cadence produces and a weekly
#: one does not.
#:
#: `dict(baked, **fresh)` and not the other way round: the library is newer than the image by
#: construction, so where both name a key the library wins. `library_pin` is how a customer freezes
#: that, and the ledger records which version ran either way.
def _with_markers(markers: dict | None) -> tuple[dict, dict, dict]:
    """`(ext_language, build_markers, language_runtime)`, overlaid with a `markers` pack if there is one."""
    if not markers:
        return EXT_LANGUAGE, _BUILD_MARKERS, LANGUAGE_RUNTIME

    def merged(baked: dict, key: str) -> dict:
        fresh = markers.get(key)
        if not isinstance(fresh, dict):
            return baked
        # str -> str only. A pack is signed, so a wrong type here is our bug rather than an attack, and
        # the right response to our bug is still the baked-in value rather than a TypeError inside a
        # customer's scan.
        return {**baked, **{k: v for k, v in fresh.items()
                            if isinstance(k, str) and isinstance(v, str)}}

    return (merged(EXT_LANGUAGE, "ext_language"), merged(_BUILD_MARKERS, "build_markers"),
            merged(LANGUAGE_RUNTIME, "language_runtime"))


# Directories whose contents are candidate fuzz harnesses regardless of file name.
_FUZZ_DIRS = frozenset({"fuzz", "fuzzing", "fuzzers", "oss-fuzz", "ossfuzz", "test_fuzz"})

# The entry points a fuzzing build actually links. libFuzzer's C/C++ hook, Rust's `cargo-fuzz` macro,
# and Go's native harness signature. A file carrying one of these IS a harness; a file merely named
# `fuzz_something.c` is a candidate until it is read.
_FUZZ_ENTRY = re.compile(
    r"LLVMFuzzerTestOneInput|fuzz_target!\s*\(|func\s+Fuzz[A-Z_]\w*\s*\(\s*\w+\s+\*testing\.F")

# Reading is the only expensive thing this module does, so it is bounded on both axes. A harness entry
# point is at the top of its file in every convention.
_MAX_PROBE_FILES = 400
_MAX_PROBE_BYTES = 65_536

# Where a repository may declare a harness it has already prepared, in preference order. `.shard/` is
# our convention and is checked first; a bare `test_poc.sh` at the root is what a benchmark-shaped
# workdir and a hand-written one both look like, and recognising it is what lets the benchmark and the
# product run the same acquisition path.
PREPARED_HARNESS_PATHS: tuple[str, ...] = (f".shard/{HARNESS_NAME}", HARNESS_NAME)


@dataclass(frozen=True)
class TargetProfile:
    """The static facts about a repository. No inference produced any of them.

    This is preflight's input and the discovery step's input, and it is deliberately small: every field
    is read by something today. The integration guide names further measurements — pull-request
    frequency, monorepo detection — and they are not here because nothing consumes them yet. The maintainers' notes's
    "earn its place" rule applies to a profile field exactly as it applies to a knob.
    """

    root: str
    files: int                              # source files counted, after VCS pruning
    source_bytes: int                       # their total size — what a run's cost scales with
    languages: dict[str, int]               # language → file count, descending by count
    build_systems: tuple[str, ...]
    fuzz_harnesses: tuple[str, ...]         # repo-relative paths that carry a fuzzing entry point
    oss_fuzz: bool                          # an OSS-Fuzz / ClusterFuzzLite integration is checked in
    truncated: bool                         # the walk hit MAX_WALK_FILES; every count below is a floor
    prepared_harness: str | None = None     # a test_poc.sh the repository already carries, if any
    #: Of `languages`, how many were HEADERS. A subset of those counts, never additional to them, so
    #: `languages` remains the whole truth about what was found and this only says which part declares
    #: rather than executes. Defaulted so a literal `TargetProfile(...)` in a test still constructs —
    #: an absent entry reads as "none of them were headers", which is the pre-2026-08-21 behaviour.
    header_files: dict[str, int] = dataclasses.field(default_factory=dict)
    native_sources: tuple[str, ...] = ()

    @property
    def primary_language(self) -> str | None:
        """The most-represented language, or None for a repository with no recognised source."""
        return next(iter(self.languages), None)

    @property
    def memory_unsafe(self) -> bool:
        """Is there anything here that that capability's capability is actually aimed at?

        A language qualifies only when it has at least one file that is NOT a header — `n > headers`.
        **A header declares; it does not execute.** Measured on PentHertz/a real repository 2026-08-21: 159 Rust
        files, ZERO `.c`, and exactly one `.h` — a 26-line bindgen shim of `#define`/`#include` with an
        `__has_include` chain, no executable code, and macOS-only, so unreachable on the Linux runner
        reviewing it. `_LANG_BY_EXT` mapped it to `c`, that made this property true, and a 159-file Rust
        workspace was told the separate capability was `supported` rather than `degraded`. The $2.69 audit that
        followed qualified on that one file.

        The cut is header-versus-source and NOT a count, deliberately: a genuine single-file C core is
        exactly the target this mode is for and must still qualify on its one `.c`.

        **The named consequence, so it is a decision and not a surprise:** a HEADER-ONLY C++ library now
        reports False. That is the honest answer for this property rather than a regression — the
        question is whether there is something to build and run, and a tree with no translation unit has
        nothing the separate capability can adjudicate. The harness gate would refuse it one step later anyway; this
        just stops the customer being told `supported` first.
        """
        return any(count > self.header_files.get(lang, 0)
                   for lang, count in self.languages.items() if lang in _MEMORY_UNSAFE)


def profile_repo(root, *, max_files: int = MAX_WALK_FILES, markers: dict | None = None) -> TargetProfile:
    """Scan a checkout and report what it is. Static only — no inference, no network, no subprocess.

    VCS directories are pruned during the walk rather than filtered after it, which is the difference
    between skipping `.git` and descending into it: measured on this repository, 68.7% of walked files
    are git objects.

    `.gitignore` is honoured for the same reason and it is not a refinement. This walk pruned VCS
    directories ONLY — not even `node_modules` — so on a real working checkout it reported **28,674
    files and 305 MB against a truth of 260 files and 6.5 MB**, and named seven languages the
    repository does not contain. Every cost estimate keyed off `source_bytes` was wrong by 46x, in the
    direction that overstates. A measured run.1.
    """
    root = pathlib.Path(root)
    ext_language, build_markers, _ = _with_markers(markers)
    counts: dict[str, int] = {}
    headers: dict[str, int] = {}
    native: dict[str, list[str]] = {}
    build: set[str] = set()
    candidates: list[pathlib.Path] = []
    files = 0
    source_bytes = 0
    oss_fuzz = False
    truncated = False
    index = IgnoreIndex(root)

    for dirpath, dirnames, filenames in os.walk(root, onerror=lambda _e: None):
        here = pathlib.Path(dirpath)
        rel_dir = here.relative_to(root).as_posix()
        rel_dir = "" if rel_dir == "." else rel_dir
        index.load(rel_dir)
        # Prune in place. `os.walk` honours mutation of `dirnames`, so this is what stops the descent
        # rather than merely hiding the results.
        # SORTED, and it is not cosmetic. `os.walk` yields whatever order `os.scandir` gives, which on
        # ext4 is hash order — stable for one checkout and different after a re-clone.
        #
        # WHAT THIS FIXES IS NOT WHAT `_spread_sample` FIXES, and the first version of this comment
        # merged them. It claimed the four verdicts that flipped across two runs of fifteen
        # repositories were "half" this and half the sample. Checked against that run's own record:
        # c-ares, jq and libjpeg-turbo all still reported `c`, so `memory_unsafe` held and they
        # failed later, at `compilable_sources` — the SAMPLE, not the tally. The two instabilities
        # are independent and the merged explanation was the one that sounded better.
        dirnames[:] = sorted(d for d in dirnames
                             if d not in _VCS_DIRS
                             and not index.ignored(f"{rel_dir}/{d}".lstrip("/"), is_dir=True))
        filenames = sorted(filenames)
        if here.name in {".clusterfuzzlite"} or "oss-fuzz" in here.name:
            oss_fuzz = True

        # ANY path component, not just the immediate parent. `cargo-fuzz`'s canonical layout is
        # `fuzz/fuzz_targets/*.rs`, where the harness sits one level below the fuzz directory and its
        # own filename carries no hint at all — a parent-only check misses every Rust target there is.
        # Same for `tests/fuzz/`. Caught by `test_rust_and_go_harness_entry_points_are_recognised`.
        in_fuzz_dir = any(part.lower() in _FUZZ_DIRS for part in _relative_parts(here, root))
        for name in filenames:
            if name in build_markers:
                build.add(build_markers[name])
            if name in {"build.sh", "Dockerfile"} and in_fuzz_dir:
                oss_fuzz = True

            suffix = pathlib.PurePath(name).suffix.lower()
            # AN EXTENSION IS ONLY A LANGUAGE IF THE FILENAME IS A FILENAME. Measured on
            # NousResearch/hermes-agent 2026-08-21: `contributors/emails/` holds 702 files each NAMED
            # for a contributor's email address, and two of them end in a country code that collides
            # with a source extension — `d@rko.rs` (Serbia) counted as Rust, `github.commits@widow.cc`
            # (Cocos Islands) as C++. That second one was the repository's ENTIRE `c++` tally, so a
            # tree with no C++ whatsoever reported some, and `memory_unsafe` would have been satisfied
            # by an email address alone had there been no real C beside it — `.h` one week, `.cc` the
            # next, the same defect wearing a different extension.
            #
            # `@` is the cut because it is the defining character of an address and is not legal in a
            # C, C++ or Rust identifier; all 702 carry one and no source file in any tree measured here
            # does. Narrow ON PURPOSE — the alternative is reading file CONTENT, which would cost the
            # walk its "static, no-subprocess, nearly free" contract for a rarer class of mistake.
            lang = None if "@" in name else ext_language.get(suffix)
            if lang is None:
                continue
            if index.ignored(f"{rel_dir}/{name}".lstrip("/"), is_dir=False):
                continue
            if files >= max_files:
                truncated = True
                break
            files += 1
            counts[lang] = counts.get(lang, 0) + 1
            # Tallied HERE rather than re-derived from the counts later, because by then the extension
            # is gone: `counts` knows only `c=1` and cannot tell a `.c` from a `.h`.
            if suffix in _HEADER_EXTS:
                headers[lang] = headers.get(lang, 0) + 1
            elif lang in _MEMORY_UNSAFE and len(native.setdefault(rel_dir, [])) < _PER_DIR_NATIVE:
                native[rel_dir].append(f"{rel_dir}/{name}".lstrip("/"))
            path = here / name
            source_bytes += _size(path)
            if len(candidates) < _MAX_PROBE_FILES and (in_fuzz_dir or "fuzz" in name.lower()):
                candidates.append(path)
        if truncated:
            break

    return TargetProfile(
        root=str(root),
        files=files,
        source_bytes=source_bytes,
        languages=dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))),
        build_systems=tuple(sorted(build)),
        fuzz_harnesses=tuple(sorted(_probe_harnesses(root, candidates))),
        oss_fuzz=oss_fuzz,
        header_files=dict(sorted(headers.items())),
        native_sources=tuple(_spread_sample(native, _MAX_NATIVE_SAMPLE)),
        truncated=truncated,
        prepared_harness=next((rel for rel in PREPARED_HARNESS_PATHS if (root / rel).is_file()), None),
    )


def _probe_harnesses(root: pathlib.Path, candidates: list[pathlib.Path]) -> list[str]:
    """Which candidates actually carry a fuzzing entry point.

    A file NAMED for fuzzing is not a harness — `fuzz_test_helpers.c` is a real filename — and the
    difference decides whether the separate capability reports supported or degraded. Reading is what settles it.
    """
    found: list[str] = []
    for path in candidates:
        # Regular files only — see the same guard in `survey._scan_file`. Opening a FIFO blocks forever
        # rather than raising, so the `except OSError` here cannot save it: measured, a fuzz-named FIFO
        # hung `profile_repo` until an external kill. This walk runs against PREPARED WORKDIRS, which
        # are built by customer harness scripts rather than by git, so a non-regular file is reachable
        # here in a way it is not in a plain checkout.
        if not path.is_file():
            continue
        try:
            with open(path, "rb") as fh:
                head = fh.read(_MAX_PROBE_BYTES)
        except OSError:
            continue
        if _FUZZ_ENTRY.search(head.decode("utf-8", errors="replace")):
            found.append(str(path.relative_to(root)))
    return found


# --- cargo-fuzz: the repository's own fuzz targets, and whether each is BUILT ------------------------
#
# cargo-fuzz has a fixed, published layout, and that is the whole reason a harness can be DERIVED from
# it rather than written by hand: the target SOURCE is `<fuzz>/fuzz_targets/<name>.rs` carrying
# `fuzz_target!(...)`, and `cargo +nightly fuzz build <name>` produces a native ELF at
# `<fuzz>/target/<triple>/release/<name>`. The triple is the host's by default, so the binary is found
# by GLOBBING `*/release/<name>` rather than assuming one — cargo-fuzz always passes `--target`, so the
# plain host `target/release/` is never where the fuzz binary lands and the glob deliberately excludes
# it (it has one path component too few to match).
_CARGO_FUZZ_TARGETS_DIR = "fuzz_targets"


@dataclass(frozen=True)
class CargoFuzzTarget:
    """One cargo-fuzz target of the repository, tagged with its built binary if there is one.

    ``binary`` is ``None`` until ``cargo +nightly fuzz build <name>`` has run — which is the state a
    fresh clone is in, and the state preflight announces as *one build command away* rather than
    refusing. ``source`` is the customer's ``fuzz_target!`` file; a derived harness adds only the
    invocation around it, which is why deriving it is not the agent authoring its own witness.
    """

    name: str                 # the target name — `header_parse`
    source: str               # repo-relative .rs source — `fuzz/fuzz_targets/header_parse.rs`
    binary: str | None        # repo-relative built ELF, or None when it has not been built


def cargo_fuzz_targets(profile: TargetProfile) -> tuple[CargoFuzzTarget, ...]:
    """The repository's cargo-fuzz targets, each tagged with its built binary if one is on disk.

    Derived from ``profile.fuzz_harnesses``, which discovery has already parsed: a harness whose path
    is ``<fuzz>/fuzz_targets/<name>.rs`` IS a cargo-fuzz target by that convention's fixed layout. No
    model and no judgement — a deterministic transformation of files the customer committed.

    Reads the filesystem to answer ``binary``, so it is not free like a field access; but it is still
    deterministic, subprocess-free and network-free, which is the contract ``profile_repo`` holds and
    the reason this can back a free-tier preflight answer.
    """
    root = pathlib.Path(profile.root)
    out: list[CargoFuzzTarget] = []
    for rel in profile.fuzz_harnesses:
        p = pathlib.PurePosixPath(rel)
        if p.suffix != ".rs" or p.parent.name != _CARGO_FUZZ_TARGETS_DIR:
            continue
        fuzz_root = p.parent.parent                    # `<fuzz>/fuzz_targets/x.rs` -> `<fuzz>`
        out.append(CargoFuzzTarget(name=p.stem, source=rel,
                                   binary=_cargo_fuzz_binary(root, fuzz_root, p.stem)))
    return tuple(out)


# --- libFuzzer C/C++: the entry points discovery already found, narrowed to the ones we can drive ----
_LIBFUZZER_EXTS = frozenset({".c", ".cc", ".cpp", ".cxx"})


def libfuzzer_targets(profile: TargetProfile) -> tuple[str, ...]:
    """The repository's libFuzzer C/C++ entry points, repo-relative.

    Selected by EXTENSION from harnesses already discovered, because `_FUZZ_ENTRY` matches three
    conventions at once — `LLVMFuzzerTestOneInput`, Rust's `fuzz_target!` and Go's `FuzzXxx` — and only
    the C/C++ one can be driven by a gcc standalone driver. A `.rs` match belongs to `cargo_fuzz`.

    Pure: a field read and a suffix test, no filesystem access at all, so preflight pays nothing.
    """
    return tuple(rel for rel in profile.fuzz_harnesses
                 if pathlib.PurePosixPath(rel).suffix.lower() in _LIBFUZZER_EXTS)


def _cargo_fuzz_binary(root: pathlib.Path, fuzz_root: pathlib.PurePosixPath, name: str) -> str | None:
    """Repo-relative path to the built cargo-fuzz binary for ``name``, or None when it is not built.

    Globs ``<fuzz>/target/*/release/<name>`` — the ``*`` is the target triple, which varies by host and
    is matched rather than assumed. Only a regular EXECUTABLE file counts: a stale ``<name>.d`` depfile,
    or a directory that happens to share the name, is not a runnable harness.
    """
    target_dir = root / fuzz_root.as_posix() / "target"
    try:
        for cand in sorted(target_dir.glob(f"*/release/{name}")):
            if _is_executable_file(cand):
                return cand.relative_to(root).as_posix()
    except OSError:
        return None
    return None


def _is_executable_file(path: pathlib.Path) -> bool:
    try:
        return path.is_file() and os.access(path, os.X_OK)
    except OSError:
        return False


# --- filesystem helpers, each swallowing the error a scan must survive -------------------------------

def _relative_parts(here: pathlib.Path, root: pathlib.Path) -> tuple[str, ...]:
    """Path components of `here` beneath `root`, or `()` when it is not beneath it.

    `os.walk` derives every `dirpath` from `root`, so the fallback is unreachable in practice. It is
    here because a scan helper that raises would take preflight down over a symlink or a mount, and
    reporting nothing is the correct degradation for a directory we cannot place.
    """
    try:
        return here.relative_to(root).parts
    except ValueError:
        return ()


def _is_dir(path: pathlib.Path) -> bool:
    try:
        return path.is_dir()
    except OSError:
        return False


def _size(path: pathlib.Path) -> int:
    try:
        return path.stat().st_size
    except OSError:
        return 0


def _glob_one(root: pathlib.Path, pattern: str) -> bool:
    try:
        return next(root.glob(pattern), None) is not None
    except OSError:
        return False


# --- whether ANYTHING this repository produces could gate a build ------------------------------------

#: Where a customer conventionally declares the runnable entry point simple mode grades against.
#: `action.yml`'s `witness_entry` input takes an arbitrary repo-relative path, so this is a
#: CONVENTION and not the rule — a repository declaring `tools/fuzz.sh` in its workflow is correctly
#: configured and matches nothing here. `demonstrability` therefore reports what it FOUND and takes a
#: declared path when one is supplied; it never says "you have no entry point", only "none at the
#: conventional paths, and none was named".
ENTRY_CANDIDATES: tuple[str, ...] = (".shard/entry.sh", ".shard/run.sh", ".shard/witness.sh")

#: Runnable, input-consuming entry points a repository may ALREADY carry under another convention.
#: A prepared harness takes one argument and exercises the target with it — the same contract
#: `.shard/entry.sh` has — so a repository carrying one can gate today and was being told it could not.
PREPARED_ENTRY_CANDIDATES: tuple[str, ...] = PREPARED_HARNESS_PATHS


def demonstrability(root, declared: str = "") -> dict:
    """Could a run on this repository produce a finding that FAILS A BUILD? Answered before it is paid for.

    **THE PRODUCT'S CENTRAL CLAIM HAS A PRECONDITION AND `preflight` DID NOT CHECK IT.** Shard reports
    findings "only when it can attach a reproducing input"; a reproducing input is one the adjudicator
    can send to an entry point *the agent did not write* (`shard/witness.py` — a witness the agent both
    authors and is graded on is not evidence). `action.yml` states the consequence in its own
    `witness_entry` description: *"WITHOUT ONE, nothing diff mode reports can gate the build — every
    finding stays informational."*

    `preflight` is the instrument the integration guide designates to answer *"will this work
    for me"* for free, before anybody pays. It reported languages, runtimes, the separate capability fitness, a
    machine profile and a cost band — and never this. So a customer could be told that every runtime
    they need is present and what a run costs, and still get nothing that can gate, and only discover
    it afterwards.

    **Measured, on the first real customer engagement.** a measured run: 13 chunks,
    24 findings, and `gate_eligible = 0` on all thirteen, *because the target declares no entry point*.
    Every finding shipped informational. Nothing was wrong with the run; the precondition was absent
    and no surface had said so.

    Three states, never two. `declared` names a path the caller has configured (the workflow's
    `witness_entry`); an empty string means the caller did not name one, which is NOT the same as
    naming one that is missing — the second is a misconfiguration and the first is a repository that
    has simply never been set up.
    """
    base = pathlib.Path(root)

    def _runnable(rel: str) -> dict | None:
        """A repo-relative path that exists, is a file, and is not empty.

        Containment matters because `declared` arrives from the WORKFLOW, and `resolve_entry`'s
        docstring records both escape shapes reaching `demonstrated=True` on an empty repository —
        the absolute one working because `pathlib.Path(repo) / "/abs/x"` discards `repo` entirely.

        **`relative_to` IS THE GUARD; the `is_absolute` test above it is redundant and was measured
        to be.** A mutation sweep removed the absolute check and no test could be made to fail,
        including one asserting `/etc/passwd` directly — `resolve()` then lands outside the root and
        `relative_to` raises. It is kept as belt and braces, the same posture `resolve_entry` states
        for its own pair, and it is recorded as redundant here so that nobody deletes the
        containment check believing this one covers it. That direction would be a real hole.
        """
        raw = (rel or "").strip()
        if not raw or pathlib.PurePath(raw).is_absolute():
            return None
        try:
            root_real = base.resolve()
            target = (root_real / raw).resolve()
            target.relative_to(root_real)
        except (OSError, ValueError):
            return None
        if not target.is_file():
            return None
        try:
            size = target.stat().st_size
        except OSError:
            return None
        # AN EMPTY ENTRY POINT IS NOT ONE. `target.py`'s own harness check already refuses an empty
        # `test_poc.sh` on the ground that "it cannot exercise the target, so every replay is clean";
        # the same reasoning applies here, and an empty file is the likeliest shape of a placeholder
        # somebody committed intending to fill in.
        return {"path": raw, "bytes": size} if size > 0 else None

    if declared:
        found = _runnable(declared)
        if found:
            return {"can_gate": True, "entry": found["path"], "source": "declared",
                    "why": f"`{found['path']}` is declared and runnable, so a finding this run "
                           f"reproduces can fail the build"}
        return {"can_gate": False, "entry": "", "source": "declared-missing",
                "why": f"`{declared}` is declared but is not a non-empty file inside the checkout, so "
                       f"NOTHING this run reports can fail a build — every finding stays "
                       f"informational. This is a misconfiguration rather than a limit: fix the path."}

    for candidate in ENTRY_CANDIDATES:
        found = _runnable(candidate)
        if found:
            return {"can_gate": True, "entry": found["path"], "source": "convention",
                    "why": f"`{found['path']}` exists and is runnable; pass it as `witness_entry` so "
                           f"a reproduced finding can fail the build"}

    # A HARNESS THE REPOSITORY ALREADY CARRIES UNDER THE OTHER CONVENTION. Same contract — one
    # argument, an input file — so it can grade today. Reported second because `.shard/entry.sh` is
    # what the documentation tells people to write, and a repository with both should be told about
    # the one it was asked for.
    for candidate in PREPARED_ENTRY_CANDIDATES:
        found = _runnable(candidate)
        if found:
            return {"can_gate": True, "entry": found["path"], "source": "prepared-harness",
                    "why": f"`{found['path']}` is a prepared harness and takes one input argument, "
                           f"so it can grade as-is; pass it as `witness_entry`. You do not need to "
                           f"write a second entry point"}

    return {"can_gate": False, "entry": "", "source": "none",
            "why": "no runnable entry point is declared or present at a conventional path, so NOTHING "
                   "a run reports here can fail a build — every finding will be informational. Add a "
                   "script that takes ONE argument, an input file, and exercises your code with it; "
                   "declare it as `witness_entry`. Shard supplies the data and never writes that "
                   "script: a witness the agent authors and is graded on is not evidence."}


#: How each language's runtime is invoked on one input file, for the entry-point template. Keyed the
#: same way `LANGUAGE_RUNTIME` is, and deliberately a SEPARATE table: that one answers "can this box
#: execute the language at all", this one answers "what would the first line look like". A language
#: absent here still gets a template — with a `#` placeholder — because a customer whose language we
#: cannot spell still needs the CONTRACT, which is the part they get wrong.
_ENTRY_INVOCATION: dict[str, str] = {
    "python": 'exec python3 .shard/witness.py "$PAYLOAD" 2>&1',
    "javascript": 'exec node .shard/witness.js "$PAYLOAD" 2>&1',
    "typescript": 'exec node .shard/witness.js "$PAYLOAD" 2>&1',
    "ruby": 'exec ruby .shard/witness.rb "$PAYLOAD" 2>&1',
    "php": 'exec php .shard/witness.php "$PAYLOAD" 2>&1',
    "java": 'exec java -cp build/classes Witness "$PAYLOAD" 2>&1',
    # **GO AND RUST NAME A BUILT BINARY, NEVER A TOOLCHAIN, and that is the rule this table now obeys.**
    # `go` read `go run ./.shard/witness.go` until 2026-08-24, and there is no Go toolchain in this
    # image — `LANGUAGE_RUNTIME` below says so itself, mapping `go` to `go`, which `probe_runtimes`
    # would report absent. So one table in this module handed a Go repository a line that exits 127
    # inside the container while the other table, forty lines down, knew it would.
    #
    # The generated line may only name something the image can run. A prebuilt artefact always
    # qualifies, because building it is the customer's earlier workflow step and not ours — which is
    # the same arrangement `java` uses (a JRE, no javac) and the reason `rust` was already correct.
    "go": 'exec ./witness "$PAYLOAD" 2>&1',
    "c": 'exec ./build/witness "$PAYLOAD" 2>&1',
    "c++": 'exec ./build/witness "$PAYLOAD" 2>&1',
    "rust": 'exec ./target/debug/witness "$PAYLOAD" 2>&1',
}

#: Every demonstration kind this product has a name for, and the one line a customer needs in order to
#: choose between them. **The TABLE is exhaustive; the TEMPLATE is not.** `entry_template` renders only
#: what `witness.offered_expectations()` returns at call time, so a lever that is off cannot be
#: advertised.
#:
#: That distinction is the whole point, and it is here because the alternative shipped. The template
#: listed four kinds for as long as the adjudicator offered two: `witness.EXPECTATIONS` is
#: `("fatal_signal", "output_marker")`, with `DIFFERENTIAL_NONZERO_EXIT` and `UNHANDLED_EXCEPTION`
#: both deliberately off and both carrying the measurement that keeps them off. The two it advertised
#: and could not honour — `nonzero_exit` and `unhandled_exception` — are precisely the two a Python,
#: Ruby or PHP customer reaches for first.
#:
#: **Nothing errored, which is what made it expensive.** A customer who built their entry point around
#: `unhandled_exception` got a witness the model was never told it could claim: the run completed,
#: every finding stayed a hypothesis, and nothing gated. `witness.py` records the cost from the other
#: side — with that lever off, the model chose `fatal_signal` for a Python traceback in 4 of 5 canary
#: samples, because it is the only exception-shaped route offered.
#:
#: A name here that `offered_expectations()` never returns is dead help text and costs nothing; the
#: entries for the two off levers are kept so that turning one on needs no edit here. A name it returns
#: that is NOT here would print bare, which is why the two vocabularies are pinned together by a test
#: rather than by an intention to keep this table current.
_EXPECTATION_HELP: dict[str, str] = {
    "fatal_signal": "the program dies on a signal (SIGSEGV, SIGABRT, ...)",
    "output_marker": "this script prints a marker string you choose",
    "nonzero_exit": "this script exits non-zero",
    "unhandled_exception": "the program dies on an uncaught exception / traceback",
}


def _expectation_lines() -> str:
    """The demonstration kinds a customer may actually build against, as template comment lines.

    Rendered from `offered_expectations()` and never from a copy of it. The column is aligned to the
    longest name that is actually offered, so removing a lever does not leave the table indented for a
    word nobody can see.
    """
    offered = offered_expectations()
    width = max((len(name) for name in offered), default=0)
    return "\n".join(f"#   {name:<{width}}   {_EXPECTATION_HELP.get(name, '')}".rstrip()
                     for name in offered)


def entry_template(language: str | None = None) -> str:
    """A ready-to-commit `.shard/entry.sh` skeleton for a repository that has none.

    **THE BLANK PAGE IS THE REAL BARRIER, not the concept.** `preflight` can now tell a customer that
    nothing they get will gate without an entry point; that turns an invisible limit into a visible
    one and leaves them to guess the contract. The contract is small and every part of it is load-
    bearing, and two of the parts are not obvious from the outside:

    * **One argument, a PATH to an input file.** Shard runs `bash -- <entry> <payload>`. The agent
      supplies the payload's CONTENT; it never writes this script. That asymmetry is the soundness
      argument (`shard/witness.py`) and it is why this is a template a human commits rather than
      something the model produces at run time.
    * **An empty payload must take a QUIET branch.** `adjudicate` runs a baseline on an empty input
      and compares. An entry point that prints its marker or exits non-zero regardless of input
      demonstrates nothing, because the baseline does it too — and the adjudicator will correctly
      refuse it. `${1:-/dev/null}` plus an early exit is how the shipped example handles it.

    * **It advertises only what this build adjudicates.** The demonstration kinds come from
      `offered_expectations()` at call time rather than from a list maintained beside it. Until
      2026-08-24 they were a hard-coded four against an adjudicator that offered two, and the two it
      could not honour were the two a Python, Ruby or PHP customer picks first — so the template's
      own reader was being pointed at a witness nothing would ever claim. See `_EXPECTATION_HELP`.

    Not generated by a model and not customised per repository: it is a fixed skeleton, with one
    invocation line chosen by language and one list chosen by what the shipped levers allow. A
    template that guessed at the customer's code would be a guess wearing a checker's clothes, and
    `preflight` is the command that must not do that.
    """
    invoke = _ENTRY_INVOCATION.get((language or "").lower())
    if invoke is None:
        invoke = ('# TODO: exec your program here, passing "$PAYLOAD" as its input.\n'
                  '# It must READ that file. A program that ignores it cannot be evidence about it.\n'
                  'exec false')
    return f'''#!/usr/bin/env bash
# Shard witness entry point. Declare this file as `witness_entry` in your workflow.
#
# THE CONTRACT
#   Shard runs:  bash -- .shard/entry.sh <payload-file>
#   Shard supplies the payload's CONTENT. It never writes this file — a witness the agent
#   authors and is graded on is not evidence, which is why this is yours to commit.
#
# WHAT COUNTS AS A DEMONSTRATION — pick ONE and make it mean something.
# THIS LIST IS WHAT THIS BUILD ACTUALLY ADJUDICATES, not everything the product has a name for:
{_expectation_lines()}
#
# If your program's failure mode is an uncaught exception or a plain non-zero exit, print a
# marker on that branch and use output_marker. Those two kinds are measured and deliberately
# not offered — see the levers in the witness module — so an entry point built around either
# would be one nothing can claim, and every finding would stay an ungating hypothesis.
#
# THE ONE THING PEOPLE GET WRONG
#   An EMPTY payload must take a quiet branch. Shard runs a baseline on empty input and
#   compares; if this script exits non-zero or prints the marker no matter what it is given,
#   the baseline does it too, nothing is demonstrated, and the run is refused. Test it:
#       bash -- .shard/entry.sh /dev/null   # must be silent and exit 0
set -u
PAYLOAD="${{1:-/dev/null}}"

# The baseline branch. Keep it: it is what makes a real observation mean something.
if [ ! -s "$PAYLOAD" ]; then
  exit 0
fi

{invoke}
'''


# --- what a run will cost the customer, an internal audit P6 ---------------------------------------------

#: **EVERY LIVE DIFF RUN THIS PROJECT HAS METERED, and the calibration set is exactly this small.**
#: the integration guide designates preflight the pricing instrument and preflight said nothing
#: about money; the audit's instruction is to ship an estimate *"labelled as calibrated on a small
#: sample with a wide band, and narrow it as runs accumulate"*, because a wide honest band beats no
#: number. Adding a row here is how it narrows — in the commit that takes the measurement.
#:
#: (run id, changed files, changed lines, bytes of the files touched, usd, tokens)
CALIBRATION = (
    ("31687294640", 1, 12, 2_800, 0.022426, 21_184),      # canary-py, one hunk in a 95-line file
    ("31693159403", 1, 1, 2_900, 0.026376, 50_547),       # canary-py, a one-line docstring
    ("31676495998", 3, 48, 120_000, 0.030164, 97_852),    # urllib3, a real third-party diff
    ("31675518894", 3, 48, 120_000, 0.044588, 131_410),   # urllib3, the same diff, a second run
    ("31692946989", 3, 82, 190_000, 0.507274, 786_563),   # The development tree DOCS: 82 lines, $0.51
)

#: **EVERY ROW ABOVE PREDATES THE AGENT BEING ABLE TO RUN ANYTHING, and the gap that opens is not
#: small.** They were all metered on 2026-08-12/13. `shard/sandbox.py` landed on 2026-08-19 and gave
#: simple mode a shell — observations enter the transcript and are re-sent on every turn after, which
#: is the mechanism `COST_DRIVER` below already names for file reads. Nothing re-measured the band
#: afterwards, which is the same staleness that had every published recall figure predating the single
#: biggest capability change until it was caught on 2026-08-24.
#:
#: These are five PULL-REQUEST runs of the shipped 2.0.0 artefact on real public-sector repositories,
#: 2026-08-25, `glm-5.3`. They are TOKENS ONLY and kept in their own table on purpose: the endpoint was
#: a subscription, which reports no price, so folding a zero into the dollar band would understate it
#: exactly where it is already understated. The token band is what they are allowed to widen.
#:
#:     (label, changed files, changed lines, tokens)
CALIBRATION_TOKENS_ONLY = (
    ("dinum/docs, an auth-path SQL rewrite", 4, 144, 646_756),
    ("dinum/docs, the CPU follow-up", 5, 65, 866_609),
    ("etalab company directory, mismatch detection", 2, 223, 703_357),
    ("a ministry site, 30 files of contributions", 30, 825, 1_544_464),
    ("an Urssaf simulator, a navigation refactor", 7, 100, 774_078),
)

#: What the two tables say TOGETHER, and it is the sentence a customer sizing a bill needs first.
#:
#:     priced sample, 2026-08-12/13     21,184 –   786,563 tokens, median    97,852
#:     token sample,  2026-08-25       646,756 – 1,544,464 tokens, median   774,078
#:
#: **The measured median is 7.9x the calibrated median, and 2 of 5 runs exceed the calibrated maximum**
#: — the largest by 1.96x. Every one of the five is above the priced sample's median by at least 6.6x.
#: So the dollar band is not merely small, it is a FLOOR taken before the product could execute, and
#: `estimate_diff_cost` now says so in the basis a customer reads rather than leaving it to be
#: discovered from an invoice.
#:
#: It is NOT converted into a dollar figure here. The two samples ran on different endpoints and
#: different models, so their tokenisers differ and a price-per-token multiplication across them would
#: be false precision on the one number this module exists to keep honest. What can be said from the
#: measurement is the token range, and that is what is said.
TOKENS_ONLY_BASIS = ("the token range also covers 5 runs of the shipped artefact on real third-party "
                     "repositories, 2026-08-25 — those ran on an endpoint that reports no price, so "
                     "they widen the TOKEN band and cannot correct the dollar one")

#: What the numbers above say, and it is not what anybody assumed. **Cost does not track the size of
#: the CHANGE.** 82 added lines of markdown cost seventeen times what 48 lines of urllib3 cost. What
#: separates them is the size of the FILES the change touches — the agent reads changed files, and
#: context accumulates across turns, so a large file read early is paid for again in every turn after
#: it. Stated as the leading HYPOTHESIS rather than as a fitted model: five points cannot support a
#: formula, and a fitted curve would be false precision on the one number a customer plans against.
COST_DRIVER = ("the size of the FILES a change touches, not the size of the change — 82 lines of "
               "markdown in large files cost $0.51 while 48 lines of urllib3 cost $0.03")


def estimate_diff_cost(profile: TargetProfile) -> dict:
    """What a pull-request run may cost the CUSTOMER, with the band it is actually known to.

    **COGS ≈ 0 is true and irrelevant to the buyer.** The customer supplies inference on every tier, so
    their inference bill IS the price of the product, and it appeared nowhere in the pricing model.
    Measured: one repository at ~100 pull-request runs a month is somewhere between $2 and $50 of their
    own inference — a range wider than a flat per-repository licence, which is the point. The customer
    cost of an "unlimited pull-request mode" is not flat, whatever the licence beside it is.

    (The licence figure that argument was first written against is deliberately not quoted here. This
    module ships in the public package, and an unannounced commercial term is not something a build
    should publish as a side effect of explaining a cost estimate.)

    **THE BAND IS THE OBSERVED RANGE, NOT A FITTED CURVE**, and that is the honest form at N=5. A
    regression on five points would produce a number with two decimal places and no support; the range
    plus the driver lets a customer place themselves, which is what they actually need. `high` is the
    number to plan against — it is the one that has happened.

    Never raises, and never returns a false zero: an unprofiled repository gets the same band with
    `basis` saying so.
    """
    usd = sorted(row[4] for row in CALIBRATION)
    # THE TOKEN BAND TAKES BOTH TABLES, the dollar band only the priced one. See
    # `CALIBRATION_TOKENS_ONLY`: an unpriced endpoint cannot correct a dollar figure, and folding its
    # zero in would understate the number exactly where it is already understated.
    tokens = sorted([row[5] for row in CALIBRATION] +
                    [row[3] for row in CALIBRATION_TOKENS_ONLY])
    # Where THIS repository sits, by the one property the calibration says matters. The median file is
    # the unit because a change touches files, not repositories.
    typical = profile.source_bytes // max(profile.files, 1)
    return {
        "usd_low": usd[0], "usd_high": usd[-1], "usd_median": usd[len(usd) // 2],
        "tokens_low": tokens[0], "tokens_high": tokens[-1],
        "per_month_at_100_runs": {"low": round(usd[0] * 100, 2), "high": round(usd[-1] * 100, 2)},
        # THE MODE IS PART OF THE BASIS, and leaving it out mis-sold the number. Every row in
        # `CALIBRATION` is a PULL-REQUEST run; the band was printed unqualified, so a customer sizing
        # a first full scan read a figure measured on follow-ups. Measured 2026-08-20
        # (a measured run): 13 `--scan initial` chunks on one 1,960-file
        # repository spent 16,637,927 tokens — four orders of magnitude off the top of this band —
        # and one 54-file chunk cost 8.6x a 110-file one, so even the DRIVER above does not hold
        # there. Naming the mode is the cheap half of the fix; an `initial` band needs its own
        # calibration rows and this sample cannot supply them.
        # **THE DOLLAR FIGURE IS A FLOOR, and saying so is the whole of this string's job.** Every
        # priced row predates `shard/sandbox.py` (2026-08-19), which let the agent execute — and
        # 2026-08-25's five runs of the shipped artefact came in at a MEDIAN 7.9x the priced sample's
        # median, with 2 of 5 above its maximum. The dollars cannot be corrected from an unpriced
        # endpoint; the understatement can be named, and a customer planning against the number is
        # owed the name.
        "basis": f"{len(CALIBRATION)} live PULL-REQUEST runs, 2026-08-12/13 — a SMALL SAMPLE, not a "
                 f"corpus, and taken BEFORE this product could execute code (2026-08-19), so read the "
                 f"dollars as a FLOOR: {len(CALIBRATION_TOKENS_ONLY)} runs since then used a median "
                 f"7.9x the tokens. It does NOT cover `--scan initial`, which is a different job and "
                 f"was measured far above this band",
        "tokens_basis": TOKENS_ONLY_BASIS,
        # THE UNDERSTATEMENT AS A NUMBER, so a customer can multiply rather than guess at what "floor"
        # buys them. Derived, never restated: a second hand-maintained copy of a ratio is the drift
        # this file has recorded before.
        "tokens_median_ratio": round(
            (sorted(row[3] for row in CALIBRATION_TOKENS_ONLY)[len(CALIBRATION_TOKENS_ONLY) // 2])
            / max(sorted(row[5] for row in CALIBRATION)[len(CALIBRATION) // 2], 1), 1),
        "covers": "pull-request runs only",
        "driver": COST_DRIVER,
        "mean_source_file_bytes": typical,
        # NOT a prediction. It says which end of the observed band this repository resembles, which is
        # a claim the sample can support; "this run will cost $X" is not.
        "resembles": ("the expensive end — large source files" if typical > 20_000 else
                      "the cheap end — small source files" if typical < 6_000 else
                      "the middle of the observed band"),
        "wall_clock": "minutes to ~15 on a small diff; measured 15m14s on a 3-file, 71-line change",
    }


#: Language → the command something written in it needs on PATH before it can be EXECUTED. Not a claim
#: about any particular entry point: a `.shard/entry.sh` may run a prebuilt binary, a shell script, or
#: nothing at all. It is the command such a project needs *if* it runs its own code, which is what a
#: demonstration is.
#:
#: **`python` IS here even though the free image is a Python image.** Leaving it out was the first
#: version, on the reasoning that a row which can never fire is a row nobody reads — and it made a
#: PYTHON repository report `not looked up for: python`, which reads as a gap in the one language that is
#: guaranteed to work. A probe's silence is not neutral. `bash` has no row because it is not a language
#: any of these tables detect.
LANGUAGE_RUNTIME: dict[str, str] = {
    "python": "python3",
    "javascript": "node", "typescript": "node",
    "java": "java", "kotlin": "java", "scala": "java",       # all three run on the JVM
    "ruby": "ruby", "php": "php", "c#": "dotnet", "go": "go", "rust": "cargo",
    "swift": "swift", "zig": "zig",
    # C, C++ and assembly need a COMPILER rather than a runtime, which is why they are grouped apart:
    # `cc` and `c++` are what an entry point that BUILDS its own witness needs on PATH. The free image
    # carries both (`gcc`, `g++`, `libc6-dev`) and asserts during its own build that each compiles and
    # runs a program — the comment here said the opposite, unswept, for as long as that was true of an
    # earlier image.
    "c": "cc", "c++": "c++", "asm": "cc",
}


def probe_runtimes(languages) -> dict:
    """Which of this repository's languages could be EXECUTED on this machine. Probed, never assumed.

    ## Why this is preflight's job and not the witness's

    `witness._missing_runtime` already catches this — a `.shard/entry.sh` that `exec`s a runtime the
    image does not carry exits 127, and since 2026-08-13 that is a REFUSAL rather than a quiet
    "nothing demonstrated". That fix is sound and it arrives **after the customer has paid for a
    review**: the model reads the diff, proposes a finding, and only then does anything discover that
    the box cannot run their language. The integration guide makes preflight the instrument that
    answers *"will this work for me"* for free, and `_cmd_preflight` already answers exactly this shape
    of question for that capability's Docker levers — *"answered where a customer asks BEFORE paying for a run
    rather than only in the run's own account afterwards"*. The free tier, which is every customer's
    first contact, had no equivalent.

    **This probe is about the MACHINE, and the machine is not always the shipped image.** When it was
    written the free image was `python:3.12-slim` plus `git`, so node, java, ruby, php, dotnet and every
    C compiler were absent and the probe's answer was almost always "no". They have since been added
    and are asserted at image build time, so a run inside the shipped container now finds them — while
    the same code on a developer's laptop, a self-hosted runner or a custom image finds whatever is
    there. That is the reason this is probed rather than declared: a constant would have had to be
    rewritten twice already and would be wrong off the runner in either version.

    ## The wording rule this obeys, and what it cost to learn

    **A statement about THIS machine, never about the product.** the maintainers' notes records a probe
    whose first wording said *"4 levers could not fire"*, which reads as *your runner cost you these
    tools* — and it was wrong, because the gate was the workdir's rather than the machine's. Telling a
    customer their machine cost them something it did not is a confident wrong number, so this reports
    what it looked for, where, and nothing more. A self-hosted runner or a custom image may carry any of
    these, and a project may not need its runtime at all.

    **REPORTS, never gates.** Nothing branches on this. `shutil.which` is a PATH lookup and not a
    subprocess, so `profile_repo`'s *"no subprocess"* contract is untouched.
    """
    import shutil

    probed, absent, unknown = [], [], []
    for language in languages or ():
        command = LANGUAGE_RUNTIME.get(language)
        if command is None:
            unknown.append(language)
            continue
        path = shutil.which(command)
        probed.append({"language": language, "command": command, "present": path is not None,
                       "path": path or ""})
        if path is None:
            absent.append(language)

    return {
        "probed": probed,
        # The languages whose runtime is NOT here, which is the whole point of the call.
        "absent": absent,
        # And the ones nothing was looked up for, reported rather than counted as fine. `_mode_verdict`'s
        # vocabulary: answer `unknown` instead of guessing.
        "unknown": unknown,
        "note": (f"{', '.join(absent)}: no runtime for this on the machine running preflight, so an "
                 f"entry point that executes it cannot demonstrate anything HERE — and a finding "
                 f"without a demonstration can never fail a build. A self-hosted runner or a custom "
                 f"image may carry it; a project that runs a prebuilt binary may not need it."
                 if absent else ""),
    }


def free_tier_verdict(profile: TargetProfile, *, visibility: str = "") -> dict:
    """Does this repository fit the free tier — the integration guide's price list, as a verdict.

    **The rule is public + simple.** Every row that bills is "deep, scheduled". So the honest answer
    turns on two facts, and preflight can only see one of them locally: `visibility` comes from the
    caller because a checkout does not know whether its origin is public, and GUESSING it would put a
    licence claim on a guess.

    `unknown` is a first-class answer here rather than a default to "fits". A pricing instrument that
    resolves ambiguity in our own favour is the kind of thing a customer finds out about later.
    """
    if visibility not in ("public", "private"):
        return {"verdict": "unknown",
                "why": "repository visibility was not supplied, and it is half the rule — public "
                       "plus simple mode is the free tier. Pass --visibility to get an answer.",
                "needs": []}
    if visibility == "public":
        return {"verdict": "fits",
                "why": "public repository, pull-request mode: free, with no repository count against "
                       "any band.",
                "needs": []}
    needs = ["a licence — private repositories are not on the free tier"]
    if profile.memory_unsafe:
        needs.append("a self-hosted or larger runner IF you want deep mode: sanitisers, a Docker "
                     "socket and real CPU are beyond a standard hosted runner")
    return {"verdict": "needs a licence", "why": "private repository", "needs": needs}


__all__ = [
    "CALIBRATION", "COST_DRIVER", "ENTRY_CANDIDATES", "EXT_LANGUAGE", "HARNESS_NAME", "EXIT_MARKER",
    "EXIT_MARKER_FIX", "LANGUAGE_RUNTIME", "PREPARED_ENTRY_CANDIDATES",
    "CargoFuzzTarget", "TargetProfile", "WorkdirReport",
    "cargo_fuzz_targets", "demonstrability", "entry_template", "estimate_diff_cost",
    "libfuzzer_targets",
    "free_tier_verdict", "harness_prints_exit_marker", "probe_runtimes", "profile_repo",
    "validate_workdir",
]
