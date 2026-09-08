
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

MAX_SURVEY_FILES = 4000
MAX_FILE_BYTES = 262_144
MAX_HITS_PER_FILE = 20

MEMORY_UNSAFE = frozenset({"c", "c++", "asm", "zig"})

WITNESSABLE_KINDS: frozenset[str] = frozenset()

_EXT_LANG = EXT_LANGUAGE

RANK_DEEP, RANK_WITNESS, RANK_HYPOTHESIS = "deep", "witness", "hypothesis"

_RANK_ORDER = {RANK_DEEP: 0, RANK_WITNESS: 1, RANK_HYPOTHESIS: 2}

_PROVENANCE_ORDER = {"source": 0, "test": 1, "generated": 2}


@dataclass(frozen=True)
class Surface:

    path: str
    line: int
    kind: str
    language: str
    evidence: str
    provenance: str = "source"


@dataclass(frozen=True)
class Survey:

    surfaces: tuple[Surface, ...]
    files_read: int
    truncated: bool = False
    pruned_dirs: int = 0
    ignored_dirs: int = 0
    ignore_basis: str = ""
    ignore_refusal: str = ""
    ignored_but_tracked: int = 0
    files_read_in_part: int = 0
    languages_read_in_part: tuple[tuple[str, int], ...] = ()
    languages_read: tuple[tuple[str, int], ...] = ()

    def by_kind(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for s in self.surfaces:
            counts[s.kind] = counts.get(s.kind, 0) + 1
        return dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))

    def by_provenance(self) -> dict[str, int]:
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

    ranked: tuple[RankedSurface, ...]
    blind_spots: tuple[str, ...]

    def counts(self) -> dict[str, int]:
        out = {RANK_DEEP: 0, RANK_WITNESS: 0, RANK_HYPOTHESIS: 0}
        for r in self.ranked:
            out[r.rank] += 1
        return out


GENERATED_DIRS = frozenset({
    "build", "_build", "cmake-build-debug", "cmake-build-release", "out", "dist",
    "node_modules", "vendor", "third_party", "target", ".tox", ".venv", "venv", "__pycache__",
})


def survey_repo(root, *, max_files: int = MAX_SURVEY_FILES) -> Survey:
    root = pathlib.Path(root)
    surfaces: list[Surface] = []
    files_read = 0
    truncated = False
    pruned = 0
    ignored = 0
    per_language: dict[str, int] = {}
    per_part: dict[str, int] = {}
    index = IgnoreIndex(root)

    for dirpath, dirnames, filenames in os.walk(root, onerror=lambda _e: None):
        here = pathlib.Path(dirpath)
        rel_dir = here.relative_to(root).as_posix()
        rel_dir = "" if rel_dir == "." else rel_dir
        index.load(rel_dir)

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
            per_language[language] = per_language.get(language, 0) + 1
            hits, in_part = _scan_file(here / name, root, language)
            surfaces.extend(hits)
            per_part[language] = per_part.get(language, 0) + in_part
        if truncated:
            break

    return Survey(surfaces=tuple(surfaces), files_read=files_read, truncated=truncated,
                  files_read_in_part=sum(per_part.values()), pruned_dirs=pruned, ignored_dirs=ignored,
                  ignore_basis=index.tracked_basis, ignore_refusal=index.tracked_refusal,
                  ignored_but_tracked=index.rescued,
                  languages_read_in_part=tuple((k, n) for k, n in sorted(per_part.items()) if n),
                  languages_read=tuple(sorted(per_language.items(), key=lambda kv: (-kv[1], kv[0]))))


TEST_DIRS = frozenset({
    "test", "tests", "testing", "spec", "specs", "__tests__", "fixtures", "testdata", "test_data",
    "e2e",
})

_TEST_FILE = re.compile(r"(^test[_-].*|.*[_-]test\.[^.]+$|.*\.(test|spec)\.[^.]+$|^conftest\.py$)")

GENERATED_LINE_CHARS = 500


def _provenance(rel: str, longest_line: int) -> str:
    if longest_line > GENERATED_LINE_CHARS:
        return "generated"
    parts = pathlib.PurePosixPath(rel).parts
    if any(part.lower() in TEST_DIRS for part in parts[:-1]):
        return "test"
    return "test" if _TEST_FILE.match(parts[-1].lower()) else "source"


def _scan_file(path: pathlib.Path, root: pathlib.Path,
               language: str) -> tuple[list[Surface], bool]:
    if not path.is_file():
        return [], False
    try:
        with open(path, "rb") as fh:
            raw = fh.read(MAX_FILE_BYTES + 1)
    except OSError:
        return [], False

    in_part = len(raw) > MAX_FILE_BYTES
    text = raw[:MAX_FILE_BYTES].decode("utf-8", errors="replace")
    rel = str(path.relative_to(root))
    lines = text.splitlines()
    provenance = _provenance(rel, max((len(ln) for ln in lines), default=0))
    found: list[Surface] = []
    for number, line in enumerate(lines, start=1):
        if len(found) >= MAX_HITS_PER_FILE:
            in_part = True
            break
        stripped = line.strip()
        if (kind := kind_of(line, stripped, language)) is not None:
            found.append(Surface(path=rel, line=number, kind=kind, language=language,
                                 evidence=stripped[:160], provenance=provenance))
    return found, in_part


def assess(survey: Survey, *, harness_kinds=(), witness_entry: str | None = None,
           deep_available: bool = True, languages=None) -> Assessment:
    deep_reachable = bool(deep_available and harness_kinds)
    witness_reachable = witness_entry is not None

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
    out: list[str] = []

    if survey.truncated:
        out.append(f"the scan stopped at {survey.files_read} files; every count is a floor, not a total")

    if survey.files_read_in_part:
        out.append(f"{survey.files_read_in_part} file(s) were read only in part — past "
                   f"{MAX_FILE_BYTES:,} bytes or past {MAX_HITS_PER_FILE} candidates the scan stops "
                   f"— so every count above is a floor for them, and a marker beyond either ceiling "
                   f"was never reached rather than absent")

    if not deep_available:
        out.append("licensed deep-mode harness construction is not present in this build; free diff "
                   "mode can still attach a reproducing input when a runnable witness entry point is "
                   "declared")
    elif not deep_reachable:
        out.append("no harness kind applies, so no candidate can be raised to a reproducing input. "
                   "Declare a harness at .shard/test_poc.sh")

    if not witness_reachable:
        out.append("no runnable entry point is declared, so simple mode cannot demonstrate anything "
                   "and every candidate below stays a hypothesis")

    if hypotheses := sum(1 for r in ranked if r.rank == RANK_HYPOTHESIS):
        out.append(f"{hypotheses} candidate(s) can be reasoned about but not proven in this configuration")

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

    if thin := sorted(lang for lang, n in survey.languages_read if n and lang not in MARKER_LANGUAGES):
        out.append("the marker table has NO language-specific rows for: " + ", ".join(thin)
                   + " — only its language-agnostic ones applied there, so coverage of those files is "
                     "thinner than for a language the table names, however many candidates it produced")

    if survey.pruned_dirs:
        out.append(f"{survey.pruned_dirs} generated/build directory(ies) were not surveyed "
                   f"({', '.join(sorted(GENERATED_DIRS)[:6])}, …) — deep mode needs a built tree, so "
                   f"they are normally artefacts, but a project that keeps source there was not read")

    if survey.ignored_dirs:
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
        out.append("no candidate surface was detected anywhere" + (
            ", and the scan did not finish — so this is a FLOOR and NOT the marker table's limit: a "
            "marker past one of the ceilings above was never reached rather than absent"
            if survey.truncated or survey.files_read_in_part else
            "; treat this as the marker table's limit rather than as a clean bill of health"))
    return tuple(out)


_SPREAD_CAUSE = {
    RANK_DEEP: "because a harness kind and a memory-unsafe language are facts about the REPOSITORY, "
               "which every candidate in it inherits",
    RANK_WITNESS: "because the one declared entry point reaches all of them equally",
    RANK_HYPOTHESIS: "because nothing here could carry proof",
}

_SAMPLED = (" Where a cap cuts this list, its head is a PROPORTIONAL SAMPLE across the tree rather "
            "than its first directory alphabetically.")


def _rank_spread(assessment: Assessment) -> str | None:
    total = len(assessment.ranked)
    if total < 2:
        return None
    reasons = {r.why for r in assessment.ranked}
    top_rank, top = max(assessment.counts().items(), key=lambda kv: kv[1])
    if len(reasons) > 1 and top < total:
        return None
    provenances = {r.surface.provenance for r in assessment.ranked}
    if len(provenances) > 1:
        return (f"this rank did not discriminate: {top} of {total} candidates share one label and one "
                f"reason, {_SPREAD_CAUSE[top_rank]} — that is a fact about this configuration, not "
                f"about the code. The list is still ORDERED: the target's own source first, then test "
                f"paths, then generated files.{_SAMPLED}")
    return (f"this rank did not discriminate: {top} of {total} candidates share one label and one "
            f"reason, so read the list as a map of where to look, not as an ordering.{_SAMPLED}")


def _provenance_line(survey: Survey) -> str:
    counts = survey.by_provenance()
    parts = [f"{counts['source']} in the target's own source"]
    if counts["test"]:
        parts.append(f"{counts['test']} in test paths")
    if counts["generated"]:
        parts.append(f"{counts['generated']} in generated files (a line over "
                     f"{GENERATED_LINE_CHARS} chars; the location is not usable)")
    return ", ".join(parts)


def summarise(survey: Survey, assessment: Assessment) -> str:
    counts = assessment.counts()
    lines = [
        f"scanned      {survey.files_read} source file(s)"
        + ("  (TRUNCATED — counts are a floor)" if survey.truncated else ""),
        f"candidates   {len(assessment.ranked)}"
        + (f"  ({', '.join(f'{k}={v}' for k, v in survey.by_kind().items())})"
           if survey.surfaces else ""),
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
    kept = assessment.ranked[:limit]
    return {
        "files_read": survey.files_read,
        "truncated": survey.truncated,
        "kinds": survey.by_kind(),
        "counts": assessment.counts(),
        "provenance": survey.by_provenance(),
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
