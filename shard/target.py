
from __future__ import annotations

import dataclasses
import os
import pathlib
import re
from dataclasses import dataclass

from shard.ignorefile import IgnoreIndex
from shard.tools import _VCS_DIRS
from shard.witness import offered_expectations


HARNESS_NAME = "test_poc.sh"

EXIT_MARKER = "__EXIT__="

EXIT_MARKER_FIX = f'echo {EXIT_MARKER}$?'

EXEC_TAIL_FIX = 'exec ./your-target "$1"'

SANITIZER_ABORT_FIX = 'export ASAN_OPTIONS=abort_on_error=1'


_REDIRECTION_WORD = re.compile(r"^\d*[<>]")


_QUOTED_RUN = re.compile(r"'[^']*'|\"(?:\\.|[^\"\\])*\"|\\.")

_CONTROL_OPERATOR = re.compile(r"[|;]|(?<![<>])&(?!>)")


def _carries_a_control_operator(line: str) -> bool:
    return bool(_CONTROL_OPERATOR.search(_QUOTED_RUN.sub(" ", line)))


def harness_execs_target(workdir) -> bool | None:
    text = _harness_text(workdir)
    if text is None:
        return None
    body = [line.strip() for line in text.splitlines()]
    body = [line for line in body if line and not line.startswith("#")]
    if not body or _carries_a_control_operator(body[-1]):
        return False
    words = body[-1].split()
    if not words or words[0] != "exec":
        return False
    return any(not _REDIRECTION_WORD.match(word) for word in words[1:])


def harness_prints_exit_marker(workdir) -> bool | None:
    text = _harness_text(workdir)
    return None if text is None else EXIT_MARKER in text


def _harness_text(workdir) -> str | None:
    try:
        return (pathlib.Path(workdir) / HARNESS_NAME).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


_ENTRYPOINT_IMAGE_RE = re.compile(r"--entrypoint\s+sh\s+(\S+)\s+-c")

VUL_IMAGE_RE = re.compile(r"^(?:cgmask-[0-9a-z]+:vul|[0-9a-z][\w./-]*:\d+-vul)$", re.IGNORECASE)


def vul_image_name(script: str) -> str | None:
    found = _ENTRYPOINT_IMAGE_RE.search(script)
    if not found:
        return None
    image = found.group(1)
    if "fix" in image.rsplit(":", 1)[-1].lower() or not VUL_IMAGE_RE.match(image):
        return None
    return image


def harness_names_vul_image(workdir) -> bool:
    text = _harness_text(workdir)
    return text is not None and vul_image_name(text) is not None
_COMMAND_POSITION = " \t\n\r;&|(`"


def _strip_shell_comments(text: str) -> str:
    out: list[str] = []
    quote = ""
    prev = "\n"
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if quote == "'":
            if ch == "'":
                quote = ""
        elif ch == "\\" and i + 1 < n and quote != "'":
            out.append(ch)
            out.append(text[i + 1])
            prev = "\x00"
            i += 2
            continue
        elif quote == '"':
            if ch == '"':
                quote = ""
        elif ch in "'\"":
            quote = ch
        elif ch == "#" and prev in _COMMAND_POSITION:
            nl = text.find("\n", i)
            if nl < 0:
                break
            i = nl
            prev = "\x00"
            continue
        out.append(ch)
        prev = ch
        i += 1
    return "".join(out)


_SEP = r"(?:\\\n|[^\S\n])+"

_CONTAINER_RUN = re.compile(
    r"(?:^|[\s;&|(`])(?:sudo" + _SEP + r")?"
    r"(?:docker-compose|podman-compose|docker|podman|nerdctl)"
    r"(?:" + _SEP + r"--?[A-Za-z0-9][\w.-]*(?:=\S+)?(?:" + _SEP + r"[^\s-]\S*)?)*"
    + _SEP + r"(?:compose" + _SEP + r")?"
    r"(?:run|create|exec|start|up)\b",
    re.MULTILINE)


def _drives_container_runtime(text: str | None) -> bool:
    if not text:
        return False
    return _CONTAINER_RUN.search(_strip_shell_comments(text)) is not None

@dataclass(frozen=True)
class WorkdirReport:

    workdir: str
    harness: bool
    harness_empty: bool
    exit_marker: bool | None
    corpus: bool
    repo_tree: bool
    description: bool
    vcs_in_repo: bool
    reasons: tuple[str, ...] = ()

    vul_image: bool = False

    control_crashed: bool | None = None

    exec_tail: bool | None = None

    marker_printed: bool | None = None

    @property
    def verdict(self) -> str:
        if not self.harness or self.harness_empty:
            return "unsupported"
        if self.control_crashed:
            return "unsupported"
        if self.known_bug:
            return "supported" if self.exit_marker else "degraded"
        return "supported" if self.exec_tail and self.marker_printed is not True else "degraded"

    @property
    def known_bug(self) -> bool:
        return self.vul_image


def validate_workdir(workdir) -> WorkdirReport:
    root = pathlib.Path(workdir)
    text = _harness_text(root)
    marker = None if text is None else EXIT_MARKER in text
    vul_image = text is not None and vul_image_name(text) is not None
    exec_tail = harness_execs_target(root)
    harness = text is not None
    harness_empty = harness and not text.strip()

    repo_tree = _is_dir(root / "repo")
    description = (root / "description.txt").is_file()
    reasons: list[str] = []

    if not harness:
        reasons.append(
            f"no {HARNESS_NAME}: there is no path from a candidate input to a verdict, so a run would "
            f"report 'audited' on a target it never tested")
    elif harness_empty:
        reasons.append(
            f"{HARNESS_NAME} is empty: it cannot exercise the target, so every replay is clean and the "
            f"run would report 'audited' on a target it never tested")
    elif vul_image:
        if not marker:
            reasons.append(
                f"{HARNESS_NAME} does not print {EXIT_MARKER}<n>: the oracle falls back to a sanitizer "
                f"report or a fatal signal, which recovers most crashes but not a target that dies "
                f"quietly. Add `{EXIT_MARKER_FIX}` as the last line, with nothing between it and the "
                f"target")
    elif not exec_tail:
        reasons.append(
            f"{HARNESS_NAME} does not end by exec'ing the target, so a fault cannot reach us AS a "
            f"fault: the script exits normally, the supervisor never sees the signal, and the only "
            f"channel left is a number the script printed — which a program that merely declined its "
            f"input produces too. Measured on this repository's own canary, one PoC and one gcc: a "
            f"tail of `{EXIT_MARKER_FIX}` reported NO finding on a run whose output carried a full "
            f"AddressSanitizer report, and `{EXEC_TAIL_FIX}` reproduced it. End the harness with "
            f"`{EXEC_TAIL_FIX}` and set `{SANITIZER_ABORT_FIX}` above it — the exec alone left the "
            f"same crash reporting as an ordinary exit 1")

    vcs_in_repo = repo_tree and any(_is_dir(root / "repo" / d) for d in sorted(_VCS_DIRS))
    if vcs_in_repo:
        reasons.append("./repo carries VCS metadata; strip it during preparation")

    return WorkdirReport(
        workdir=str(root),
        harness=harness,
        harness_empty=harness_empty,
        exit_marker=marker,
        corpus=_is_dir(root / "corpus") or bool(_glob_one(root, "*_seed_corpus.zip")),
        repo_tree=repo_tree,
        description=description,
        vcs_in_repo=vcs_in_repo,
        reasons=tuple(reasons),
        vul_image=vul_image,
        exec_tail=exec_tail,
    )



MAX_WALK_FILES = 200_000

EXT_LANGUAGE: dict[str, str] = {
    ".c": "c", ".h": "c",
    ".cc": "c++", ".cpp": "c++", ".cxx": "c++", ".hpp": "c++", ".hh": "c++", ".hxx": "c++",
    ".rs": "rust", ".go": "go", ".zig": "zig",
    ".py": "python", ".js": "javascript", ".ts": "typescript", ".jsx": "javascript",
    ".tsx": "typescript", ".java": "java", ".rb": "ruby", ".php": "php", ".cs": "c#",
    ".swift": "swift", ".kt": "kotlin", ".scala": "scala", ".s": "asm", ".asm": "asm",
    ".mjs": "javascript", ".cjs": "javascript", ".mts": "typescript", ".cts": "typescript",
}

_MEMORY_UNSAFE = frozenset({"c", "c++", "asm", "zig"})

_HEADER_EXTS = frozenset({".h", ".hh", ".hpp", ".hxx"})

_MAX_NATIVE_SAMPLE = 8

_PER_DIR_NATIVE = _MAX_NATIVE_SAMPLE


def _spread_sample(by_dir: dict[str, list[str]], limit: int) -> list[str]:
    picked: list[str] = []
    for depth in range(max((len(v) for v in by_dir.values()), default=0)):
        for name in sorted(by_dir):
            if len(picked) >= limit:
                return picked
            if depth < len(by_dir[name]):
                picked.append(by_dir[name][depth])
    return picked

_BUILD_MARKERS: dict[str, str] = {
    "CMakeLists.txt": "cmake", "configure.ac": "autotools", "configure.in": "autotools",
    "Makefile.am": "autotools", "meson.build": "meson", "Cargo.toml": "cargo",
    "go.mod": "go", "build.gradle": "gradle", "pom.xml": "maven", "BUILD.bazel": "bazel",
    "WORKSPACE": "bazel", "setup.py": "setuptools", "pyproject.toml": "python",
    "package.json": "npm", "Makefile": "make", "GNUmakefile": "make",
}

def _with_markers(markers: dict | None) -> tuple[dict, dict]:
    if not markers:
        return EXT_LANGUAGE, _BUILD_MARKERS

    def merged(baked: dict, key: str) -> dict:
        fresh = markers.get(key)
        if not isinstance(fresh, dict):
            return baked
        return {**baked, **{k: v for k, v in fresh.items()
                            if isinstance(k, str) and isinstance(v, str)}}

    return merged(EXT_LANGUAGE, "ext_language"), merged(_BUILD_MARKERS, "build_markers")


_FUZZ_DIRS = frozenset({"fuzz", "fuzzing", "fuzzers", "oss-fuzz", "ossfuzz", "test_fuzz"})

_FUZZ_ENTRY = re.compile(
    r"LLVMFuzzerTestOneInput|fuzz_target!\s*\(|func\s+Fuzz[A-Z_]\w*\s*\(\s*\w+\s+\*testing\.F")

_MAX_PROBE_FILES = 400
_MAX_PROBE_BYTES = 65_536

PREPARED_HARNESS_PATHS: tuple[str, ...] = (f".shard/{HARNESS_NAME}", HARNESS_NAME)


@dataclass(frozen=True)
class TargetProfile:

    root: str
    files: int
    source_bytes: int
    languages: dict[str, int]
    build_systems: tuple[str, ...]
    fuzz_harnesses: tuple[str, ...]
    oss_fuzz: bool
    truncated: bool
    prepared_harness: str | None = None
    header_files: dict[str, int] = dataclasses.field(default_factory=dict)
    native_sources: tuple[str, ...] = ()

    @property
    def primary_language(self) -> str | None:
        return next(iter(self.languages), None)

    @property
    def memory_unsafe(self) -> bool:
        return any(count > self.header_files.get(lang, 0)
                   for lang, count in self.languages.items() if lang in _MEMORY_UNSAFE)


def profile_repo(root, *, max_files: int = MAX_WALK_FILES, markers: dict | None = None) -> TargetProfile:
    root = pathlib.Path(root)
    ext_language, build_markers = _with_markers(markers)
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
        dirnames[:] = sorted(d for d in dirnames
                             if d not in _VCS_DIRS
                             and not index.ignored(f"{rel_dir}/{d}".lstrip("/"), is_dir=True))
        filenames = sorted(filenames)
        if here.name in {".clusterfuzzlite"} or "oss-fuzz" in here.name:
            oss_fuzz = True

        in_fuzz_dir = any(part.lower() in _FUZZ_DIRS for part in _relative_parts(here, root))
        for name in filenames:
            if name in build_markers:
                build.add(build_markers[name])
            if name in {"build.sh", "Dockerfile"} and in_fuzz_dir:
                oss_fuzz = True

            suffix = pathlib.PurePath(name).suffix.lower()
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
    found: list[str] = []
    for path in candidates:
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


_CARGO_FUZZ_TARGETS_DIR = "fuzz_targets"


@dataclass(frozen=True)
class CargoFuzzTarget:

    name: str
    source: str
    binary: str | None


def cargo_fuzz_targets(profile: TargetProfile) -> tuple[CargoFuzzTarget, ...]:
    root = pathlib.Path(profile.root)
    out: list[CargoFuzzTarget] = []
    for rel in profile.fuzz_harnesses:
        p = pathlib.PurePosixPath(rel)
        if p.suffix != ".rs" or p.parent.name != _CARGO_FUZZ_TARGETS_DIR:
            continue
        fuzz_root = p.parent.parent
        out.append(CargoFuzzTarget(name=p.stem, source=rel,
                                   binary=_cargo_fuzz_binary(root, fuzz_root, p.stem)))
    return tuple(out)


_LIBFUZZER_EXTS = frozenset({".c", ".cc", ".cpp", ".cxx"})


def libfuzzer_targets(profile: TargetProfile) -> tuple[str, ...]:
    return tuple(rel for rel in profile.fuzz_harnesses
                 if pathlib.PurePosixPath(rel).suffix.lower() in _LIBFUZZER_EXTS)


def _cargo_fuzz_binary(root: pathlib.Path, fuzz_root: pathlib.PurePosixPath, name: str) -> str | None:
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



def _relative_parts(here: pathlib.Path, root: pathlib.Path) -> tuple[str, ...]:
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



ENTRY_CANDIDATES: tuple[str, ...] = (".shard/entry.sh", ".shard/run.sh", ".shard/witness.sh")

PREPARED_ENTRY_CANDIDATES: tuple[str, ...] = PREPARED_HARNESS_PATHS


def demonstrability(root, declared: str = "") -> dict:
    base = pathlib.Path(root)

    def _runnable(rel: str) -> dict | None:
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


_ENTRY_INVOCATION: dict[str, str] = {
    "python": 'exec python3 .shard/witness.py "$PAYLOAD" 2>&1',
    "javascript": 'exec node .shard/witness.js "$PAYLOAD" 2>&1',
    "typescript": 'exec node .shard/witness.js "$PAYLOAD" 2>&1',
    "ruby": 'exec ruby .shard/witness.rb "$PAYLOAD" 2>&1',
    "php": 'exec php .shard/witness.php "$PAYLOAD" 2>&1',
    "java": 'exec java -cp build/classes Witness "$PAYLOAD" 2>&1',
    "go": 'exec ./witness "$PAYLOAD" 2>&1',
    "c": 'exec ./build/witness "$PAYLOAD" 2>&1',
    "c++": 'exec ./build/witness "$PAYLOAD" 2>&1',
    "rust": 'exec ./target/debug/witness "$PAYLOAD" 2>&1',
}

_EXPECTATION_HELP: dict[str, str] = {
    "fatal_signal": "the program dies on a signal (SIGSEGV, SIGABRT, ...)",
    "output_marker": "this script prints a marker string you choose",
    "nonzero_exit": "this script exits non-zero",
    "unhandled_exception": "the program dies on an uncaught exception / traceback",
}


def _expectation_lines() -> str:
    offered = offered_expectations()
    width = max((len(name) for name in offered), default=0)
    return "\n".join(f"#   {name:<{width}}   {_EXPECTATION_HELP.get(name, '')}".rstrip()
                     for name in offered)


def entry_template(language: str | None = None) -> str:
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



CALIBRATION = (
    ("31687294640", 1, 12, 2_800, 0.022426, 21_184),
    ("31693159403", 1, 1, 2_900, 0.026376, 50_547),
    ("31676495998", 3, 48, 120_000, 0.030164, 97_852),
    ("31675518894", 3, 48, 120_000, 0.044588, 131_410),
    ("31692946989", 3, 82, 190_000, 0.507274, 786_563),
)

CALIBRATION_TOKENS_ONLY = (
    ("dinum/docs, an auth-path SQL rewrite", 4, 144, 646_756),
    ("dinum/docs, the CPU follow-up", 5, 65, 866_609),
    ("etalab company directory, mismatch detection", 2, 223, 703_357),
    ("a ministry site, 30 files of contributions", 30, 825, 1_544_464),
    ("an Urssaf simulator, a navigation refactor", 7, 100, 774_078),
)

TOKENS_ONLY_BASIS = ("the token range also covers 5 runs of the shipped artefact on real third-party "
                     "repositories, 2026-08-25 — those ran on an endpoint that reports no price, so "
                     "they widen the TOKEN band and cannot correct the dollar one")

COST_DRIVER = ("the size of the FILES a change touches, not the size of the change — 82 lines of "
               "markdown in large files cost $0.51 while 48 lines of urllib3 cost $0.03")


def estimate_diff_cost(profile: TargetProfile) -> dict:
    usd = sorted(row[4] for row in CALIBRATION)
    tokens = sorted([row[5] for row in CALIBRATION] +
                    [row[3] for row in CALIBRATION_TOKENS_ONLY])
    typical = profile.source_bytes // max(profile.files, 1)
    return {
        "usd_low": usd[0], "usd_high": usd[-1], "usd_median": usd[len(usd) // 2],
        "tokens_low": tokens[0], "tokens_high": tokens[-1],
        "per_month_at_100_runs": {"low": round(usd[0] * 100, 2), "high": round(usd[-1] * 100, 2)},
        "basis": f"{len(CALIBRATION)} live PULL-REQUEST runs, 2026-08-12/13 — a SMALL SAMPLE, not a "
                 f"corpus, and taken BEFORE this product could execute code (2026-08-19), so read the "
                 f"dollars as a FLOOR: {len(CALIBRATION_TOKENS_ONLY)} runs since then used a median "
                 f"7.9x the tokens. It does NOT cover `--scan initial`, which is a different job and "
                 f"was measured far above this band",
        "tokens_basis": TOKENS_ONLY_BASIS,
        "tokens_median_ratio": round(
            (sorted(row[3] for row in CALIBRATION_TOKENS_ONLY)[len(CALIBRATION_TOKENS_ONLY) // 2])
            / max(sorted(row[5] for row in CALIBRATION)[len(CALIBRATION) // 2], 1), 1),
        "covers": "pull-request runs only",
        "driver": COST_DRIVER,
        "mean_source_file_bytes": typical,
        "resembles": ("the expensive end — large source files" if typical > 20_000 else
                      "the cheap end — small source files" if typical < 6_000 else
                      "the middle of the observed band"),
        "wall_clock": "minutes to ~15 on a small diff; measured 15m14s on a 3-file, 71-line change",
    }


LANGUAGE_RUNTIME: dict[str, str] = {
    "python": "python3",
    "javascript": "node", "typescript": "node",
    "java": "java", "kotlin": "java", "scala": "java",
    "ruby": "ruby", "php": "php", "c#": "dotnet", "go": "go", "rust": "cargo",
    "swift": "swift", "zig": "zig",
    "c": "cc", "c++": "c++", "asm": "cc",
}


def probe_runtimes(languages) -> dict:
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
        "absent": absent,
        "unknown": unknown,
        "note": (f"{', '.join(absent)}: no runtime for this on the machine running preflight, so an "
                 f"entry point that executes it cannot demonstrate anything HERE — and a finding "
                 f"without a demonstration can never fail a build. A self-hosted runner or a custom "
                 f"image may carry it; a project that runs a prebuilt binary may not need it."
                 if absent else ""),
    }


def free_tier_verdict(profile: TargetProfile, *, visibility: str = "") -> dict:
    if visibility not in ("public", "private"):
        return {"verdict": "unknown",
                "why": "repository visibility was not supplied. Public repositories always fit; "
                       "private repositories also require organisation facts this checkout cannot "
                       "observe.",
                "needs": []}
    if visibility == "public":
        return {"verdict": "fits",
                "why": "public repository: free, with no organisation-size or repository-count "
                       "limit.",
                "needs": []}
    needs = ["eligibility confirmation — the private-repository grant applies while group annual "
             "gross revenue is under USD $5M and no more than 10 individuals contribute to the "
             "private repositories reviewed; otherwise a commercial licence"]
    if profile.memory_unsafe:
        needs.append("sustained CPU if deep-mode fuzzing is required; ordinary construction uses "
                     "the paid image's GCC/G++ toolchain and does not require a Docker socket")
    return {"verdict": "unknown",
            "why": "private repository — this checkout cannot determine the organisation facts "
                   "that decide the small-organisation grant",
            "needs": needs}


__all__ = [
    "CALIBRATION", "COST_DRIVER", "ENTRY_CANDIDATES", "EXT_LANGUAGE", "HARNESS_NAME", "EXIT_MARKER",
    "EXIT_MARKER_FIX", "EXEC_TAIL_FIX", "SANITIZER_ABORT_FIX", "LANGUAGE_RUNTIME",
    "PREPARED_ENTRY_CANDIDATES",
    "CargoFuzzTarget", "TargetProfile", "WorkdirReport",
    "cargo_fuzz_targets", "demonstrability", "entry_template",
    "estimate_diff_cost",
    "libfuzzer_targets",
    "free_tier_verdict", "harness_execs_target", "harness_prints_exit_marker", "probe_runtimes",
    "profile_repo", "validate_workdir",
]
