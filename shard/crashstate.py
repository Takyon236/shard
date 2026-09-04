"""The crash taxonomy: what class of defect a sanitiser report is, and a name for it that is the
SAME next run.

**The defect this module exists for was measured, not suspected.** `report._sarif_result` writes
`partialFingerprints.shardCrashSignature`, and its own comment states the job exactly: *"what makes
an alert persist across runs instead of closing and re-opening on every push."* The value it writes
is a sha1 over the WHOLE normalised harness output, computed by the separate capability's
adjudicator. Measured 2026-08-28,
two runs of one cJSON heap-buffer-overflow READ in `parse_string`, differing only in what always
differs between two runs:

    run A   built in /src/cJSON        pc 0x4f1a2b   sig 81dbbccc9ece
    run B   built in /tmp/shard-wd-9f2 pc 0x513f7c   sig 1302c0d712db

`_VOLATILE` scrubs hex addresses, pids and long integers, and it is not enough: the BUILD DIRECTORY
is on every frame line and on the `SUMMARY:` line, and it is different on a customer's runner than
on ours, different between a container and a checkout, and different again after the workdir name
changes. So the same defect arrives in code scanning as a new alert on every run — the alert closes,
re-opens, loses its triage state and its assignee, and the field whose entire purpose is to prevent
that is what causes it.

**The fix is ClusterFuzz's crash state, adopted rather than reinvented.** Google's fuzzing
infrastructure solved this at a scale nobody else has: a crash's identity is its TYPE plus the top
three stack frames, after frames belonging to the sanitiser, the allocator and the fuzzing engine
are filtered out. Everything volatile — address, pc, build path, line number, allocation size,
shadow-byte dump — is discarded rather than normalised, because a normaliser can only remove noise
it was told about and this one was told about three kinds out of six.

**What was taken and what was left.** `STACK_FRAME_IGNORE_REGEXES` upstream is roughly 180 patterns
covering Chromium, V8, Android, Fuchsia, Skia, Golang, Swift, Windows CDB and the kernel. This tool
adjudicates libFuzzer and cargo-fuzz targets under ASan/UBSan/MSan/LSan and nothing else, so
`_IGNORED_FRAMES` below is the subset that can actually fire here. "Earn its place" forbids the
other 150: a pattern for `v8::internal::Isolate::PushStackTraceAndDie` in a tool that never sees V8
is a line a reader has to rule out.

**The second job this closes is A4**, the design notes: a Shard rule reaches
GitHub code scanning with no `security-severity` and no `external/cwe/cwe-NNN` tag, which are the
two fields the Security tab ranks and filters on — and the design notes closes the question of
building a control plane, so GitHub's taxonomy IS this product's reporting surface. That document
calls it the *"smallest fix with the largest reporting payoff"* and says why: the finding already
knows its bug class, so the mapping is a lookup table.

**IT CLASSIFIES OBSERVED OUTPUT, NEVER A RULE ID.** The classification is derived from what the
sanitiser printed, so it works identically on a deep finding and on a free-tier `fatal_signal`
witness that happened to run an instrumented binary, and it abstains on everything else. Keying it
on the rule id instead would have made the free tier's `output_marker` — which says how a finding
was DEMONSTRATED, not what class of defect it is — into a CWE claim nobody measured. `report.py`'s
`_crash_title` already holds this line: *"Never invents a defect class."*

Pure, stdlib-only and deterministic: no I/O, no clock, no environment. Every function here is a
string transform, which is what lets the maintainers' suite pin the whole taxonomy without a
compiler.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

#: How many application frames make up the identity. THREE, which is ClusterFuzz's number and not an
#: arbitrary one: one frame conflates every bug that ends in the same leaf helper (`memcpy_safe`,
#: `read_u32`), and a whole trace is not an identity at all because inlining decisions change it
#: between `-O1` and `-O2` on the same source.
CRASH_STATE_FRAMES = 3

#: The sanitiser that reported, normalised to one word. `Leak` is separate from `Address` on purpose:
#: LeakSanitizer runs inside ASan by default and reports a class with a different CWE and a different
#: severity: a harness that leaks on EVERY input is a measured shape, and reporting it as an
#: `Address` finding would attach the wrong CWE to every row it produced.
_ERROR_RE = re.compile(
    r"(?:ERROR|WARNING|SUMMARY):\s*"
    r"(?P<san>Address|HWAddress|UndefinedBehavior|Undefined Behavior|Memory|Thread|Leak)"
    r"Sanitizer:\s*(?P<type>[^\n]+)")

#: Where the crash TYPE ends and the volatile tail begins. The type is taken to end of line and cut
#: here, rather than matched by a character class, because the first attempt at this was a defect
#: worth recording: `[A-Za-z][A-Za-z0-9 _-]*` looks like it matches `heap-buffer-overflow` and in
#: fact matches `heap-buffer-overflow-on-address-0x602000000f7d-at-pc-0x0000004f1a2b-bp-...`. Every
#: character of the address is in `[A-Za-z0-9 _-]`. It classified nothing, mapped to no CWE, and gave
#: the two runs of one bug two identities — this module's own defect, in the module written to fix it.
_TYPE_TAIL = (" on ", " at ", " in ", " (", " /", ":", ";")

#: ASan's prose spellings, mapped to the hyphenated class the tables are keyed on. Four reports name
#: their class in a sentence rather than a token, and cutting at `_TYPE_TAIL` leaves a fragment.
#:
#: A fifth entry, `detected-memory-leaks -> detected-memory-leaks`, was written here and removed: it
#: is what `_crash_type` already produces, so it renamed nothing. "Earn its place" forbids the option
#: nobody sets and equally the table row that maps a value to itself — it reads as a decision and is
#: a no-op, which is worse than absent because a reader has to check.
_TYPE_ALIASES: dict[str, str] = {
    "attempting-free": "bad-free",
    "attempting-double-free": "double-free",
    "requested-allocation-size": "allocation-size-too-big",
    "unknown-crash": "segv",
}

#: libFuzzer's own reports, which carry no `Sanitizer:` prefix and are the two most common results on
#: a target with no sanitiser compiled in at all.
_LIBFUZZER_RE = re.compile(r"ERROR:\s*libFuzzer:\s*(?P<type>deadly signal|out-of-memory|timeout"
                           r"|out-of-memory \(malloc\(\d+\)\))")

#: UBSan does not print an `ERROR:` line for most checks — it prints `file.c:12:5: runtime error:
#: <prose>` and a `SUMMARY:` naming only `undefined-behavior`. The prose is the only place the CLASS
#: appears, so it is read here and mapped through `_UB_PROSE`. Without this arm every UBSan finding
#: classifies as the generic `undefined-behavior` and loses the CWE that makes it actionable.
_UB_RUNTIME_RE = re.compile(r"runtime error:\s*(?P<prose>[^\n]+)")

#: ASan's access line. The READ/WRITE distinction is the single biggest severity lever in the whole
#: taxonomy — see `_SEVERITY` — and it is also the CWE-125 / CWE-787 axis, which is the axis MITRE's
#: Top 25 is sliced on and therefore the one a security team filters by.
_ACCESS_RE = re.compile(r"^\s*(?P<access>READ|WRITE) of size \d+", re.MULTILINE)

#: One stack frame. Symbolized (`#0 0x4f1 in parse_string /src/p.c:10:3`) and unsymbolized
#: (`#0 0x4f1 in (/out/fuzz+0x4f1a2b)`) both match; `_frame_name` decides what to keep from `rest`.
_FRAME_RE = re.compile(r"^\s*#(?P<id>\d+)\s+0x[0-9a-fA-F]+\s+(?:in\s+)?(?P<rest>\S.*?)\s*$")

#: A trailing source location on a frame line: ` /src/p.c:1071:17`, ` p.c:1071` or ` p.c`.
#: STRIPPED, and dropping the LINE NUMBER is a deliberate trade with a cost. Two distinct defects in
#: one function collapse to one identity, which under-counts. Keeping the line number would make the
#: identity change every time an unrelated edit above the function moves it down a line, which
#: re-opens the alert — the exact defect this module exists to fix, arriving through the fix. The
#: line is not lost: it stays in `Finding.evidence`, which is what a human reads.
_FRAME_LOC_RE = re.compile(r"\s+[\w./+-]+\.(?:c|cc|cpp|cxx|h|hpp|hh|rs|go|py|java|m|mm)(?::\d+){0,2}$",
                           re.IGNORECASE)

#: The unsymbolized tail: ` (/out/fuzz_target+0x4f1a2b)`. The module BASENAME is kept as the frame
#: name when there is nothing else, because `fuzz_target` is a weaker identity than `parse_string`
#: and a far better one than dropping the frame — which would silently promote a deeper, unrelated
#: frame into the top three and merge two different bugs.
_FRAME_MODULE_RE = re.compile(r"\((?P<path>[^()+]+)\+0x[0-9a-fA-F]+\)\s*$")

#: A trailing C++ parameter list. Stripped because llvm-symbolizer prints `parse(char const*, int)`
#: or `parse` depending on the build's `-fno-optimize-sibling-calls`, DWARF level and whether
#: `ASAN_SYMBOLIZER_PATH` resolved — three build-time knobs that must not change a bug's identity.
#: Anchored to require a name before the parenthesis so `operator()` is not reduced to `operator`.
_FRAME_ARGS_RE = re.compile(r"(?<=\w)\([^()]*\)\s*(?:const)?\s*$")

#: Frames that belong to the sanitiser, the allocator, libc's checked-string family or the fuzzing
#: engine — never to the defect. Adopted from ClusterFuzz's `STACK_FRAME_IGNORE_REGEXES`, restricted
#: to the runtimes this tool meets.
#:
#: **This list is what makes the identity mean anything.** ASan's report opens with its own reporting
#: machinery, so an unfiltered top-three is `__asan_report_load1 / __interceptor_memcpy / malloc` for
#: EVERY heap bug in the program — one identity for the whole class, which is worse than no
#: deduplication because it merges unrelated defects into one alert.
#:
#: `^main` and `^LLVMFuzzerTestOneInput` are here for the opposite reason: they are at the BOTTOM of
#: every trace, they are the same string in every project, and a crash shallow enough to reach them
#: within three frames gets a truer identity from the two real frames above.
_IGNORED_FRAMES = tuple(re.compile(p) for p in (
    # sanitiser runtimes
    r"^__asan::", r"^__asan_", r"^_asan_", r"^asan_", r"^__hwasan::", r"^__hwasan_",
    r"^__lsan::", r"^__lsan_", r"^__msan::", r"^__msan_", r"^__tsan::", r"^__tsan_",
    r"^__ubsan::", r"^__ubsan_", r"^__sanitizer::", r"^__sanitizer_", r"^__interceptor_",
    r"^___interceptor_",
    # the allocator, and C++'s allocation operators
    r"^malloc$", r"^calloc$", r"^realloc$", r"^free$", r"^operator", r"^new$", r"^delete$",
    # libc's checked string/memory family: a report names the interceptor, never the caller's bug
    r"^(?:__)?mem(?:cmp|cpy|move|set)", r"^(?:__)?str(?:cmp|cpy|dup|len|ncpy)",
    r"^__chk_fail$", r"^__fortify_fail$", r"^__libc_", r"^__GI_",
    # process teardown
    r"^abort$", r"^exit$", r"^raise$", r"^gsignal$", r"^_start$", r"^__assert_",
    r"^pthread_create$", r"^pthread_kill$", r"^__pthread_kill",
    # the fuzzing engines and their drivers
    r"^fuzzer::", r"^LLVMFuzzerTestOneInput", r"^main$", r"^__libfuzzer",
    # cargo-fuzz / Rust panics and the std backtrace machinery
    r"^rust_fuzzer_test_input", r"^libfuzzer_sys::", r"^rust_begin_unwind", r"^rust_panic",
    r"^core::panic", r"^std::panic", r"^std::process::abort", r"^std::sys::backtrace",
    r"^std::sys_common::backtrace", r"^__rust_start_panic", r"^__rust_try",
    # unsymbolized placeholders — a name that identifies nothing
    r"^<unknown>$", r"^<null>", r"^\?\?$",
))

#: UBSan prose to a crash type. Keyed on a substring of the `runtime error:` line, longest first so
#: `unsigned integer overflow` is not swallowed by `integer overflow`.
_UB_PROSE: tuple[tuple[str, str], ...] = (
    ("signed integer overflow", "signed-integer-overflow"),
    ("unsigned integer overflow", "unsigned-integer-overflow"),
    ("shift exponent", "shift-exponent"),
    ("left shift of negative value", "shift-negative"),
    ("division by zero", "divide-by-zero"),
    ("member access within null pointer", "null-dereference"),
    ("member call on null pointer", "null-dereference"),
    ("load of null pointer", "null-dereference"),
    ("null pointer passed as argument", "null-dereference"),
    ("applying zero offset to null pointer", "null-dereference"),
    ("misaligned address", "misaligned-address"),
    ("load of misaligned address", "misaligned-address"),
    ("index ", "index-out-of-bounds"),
    ("outside the range of representable values", "float-cast-overflow"),
    ("through pointer to incorrect function type", "incorrect-function-pointer-type"),
    ("variable length array bound evaluates to non-positive", "non-positive-vla-bound-value"),
    ("load of value", "invalid-bool-load"),
    ("execution reached an unreachable", "unreachable-code"),
)

#: Crash type to CWE, most specific FIRST. Two ids where two are true: `heap-buffer-overflow WRITE`
#: is both CWE-787 (out-of-bounds write, MITRE Top 25 rank 2) and CWE-122 (heap-based buffer
#: overflow, the specific variant). Both are emitted because they answer different questions — the
#: Top 25 id is what an estate dashboard groups on, the specific id is what a fix is written against.
#:
#: **The READ/WRITE split is why this is keyed on the pair and not on the type.** A
#: heap-buffer-overflow READ is CWE-125 and a WRITE is CWE-787, and reporting an out-of-bounds read
#: as a write is a materially wrong claim about exploitability in the field a security team ranks on.
#:
#: One mapping here disagrees with a published source and the disagreement is deliberate. A 2025
#: taxonomy paper maps UBSan `shift-error` to CWE-1025 (Comparison Using Wrong Types), which does not
#: describe a bad shift at all; CWE-1335 (Incorrect Bitwise Shift of Integer) does, and is what is
#: used below.
_CWE: dict[tuple[str, str], tuple[str, ...]] = {
    ("heap-buffer-overflow", "READ"): ("125", "122"),
    ("heap-buffer-overflow", "WRITE"): ("787", "122"),
    ("heap-buffer-overflow", ""): ("122", "119"),
    ("stack-buffer-overflow", "READ"): ("125", "121"),
    ("stack-buffer-overflow", "WRITE"): ("787", "121"),
    ("stack-buffer-overflow", ""): ("121", "119"),
    ("stack-buffer-underflow", ""): ("124", "787"),
    ("dynamic-stack-buffer-overflow", ""): ("787", "121"),
    ("global-buffer-overflow", "READ"): ("125",),
    ("global-buffer-overflow", "WRITE"): ("787",),
    ("global-buffer-overflow", ""): ("787", "125"),
    ("container-overflow", ""): ("125", "787"),
    ("index-out-of-bounds", ""): ("129", "125"),
    ("heap-use-after-free", ""): ("416",),
    ("stack-use-after-return", ""): ("562", "416"),
    ("stack-use-after-scope", ""): ("562", "416"),
    ("use-after-poison", ""): ("416",),
    ("double-free", ""): ("415",),
    ("bad-free", ""): ("590", "415"),
    ("alloc-dealloc-mismatch", ""): ("762",),
    ("memcpy-param-overlap", ""): ("475",),
    ("bad-cast", ""): ("843",),
    ("incorrect-function-pointer-type", ""): ("843",),
    ("object-size", ""): ("119",),
    ("negative-size-param", ""): ("1284", "787"),
    ("allocation-size-too-big", ""): ("789",),
    ("requested-allocation-size-exceeds", ""): ("789",),
    ("out-of-memory", ""): ("789", "400"),
    ("stack-overflow", ""): ("674",),
    ("detected-memory-leaks", ""): ("401",),
    ("memory-leaks", ""): ("401",),
    ("use-of-uninitialized-value", ""): ("457", "908"),
    ("signed-integer-overflow", ""): ("190",),
    ("unsigned-integer-overflow", ""): ("191", "190"),
    ("shift-exponent", ""): ("1335",),
    ("shift-negative", ""): ("1335",),
    ("divide-by-zero", ""): ("369",),
    ("float-cast-overflow", ""): ("681", "197"),
    ("null-dereference", ""): ("476",),
    ("misaligned-address", ""): ("1319", "704"),
    ("non-positive-vla-bound-value", ""): ("1284",),
    ("invalid-bool-load", ""): ("704",),
    ("unreachable-code", ""): ("561",),
    ("data-race", ""): ("362",),
    ("thread-leak", ""): ("404",),
    ("deadly signal", ""): ("476",),
    ("segv", ""): ("476",),
    ("fpe", ""): ("369",),
}

#: Crash type to a severity band, ADOPTED FROM ClusterFuzz's `severity_analyzer` and deliberately not
#: re-derived. Its lists, verbatim: HIGH is `Bad-cast, Heap-double-free, Heap-use-after-free, Security
#: DCHECK failure, Use-after-poison`; MEDIUM is `Container-overflow, Heap-buffer-overflow,
#: Incorrect-function-pointer-type, Index-out-of-bounds, Memcpy-param-overlap,
#: Non-positive-vla-bound-value, Object-size, Stack-buffer-overflow, UNKNOWN,
#: Use-of-uninitialized-value`.
#:
#: **A WRITE bumps one band and the cap stays HIGH**, which is upstream's rule and upstream's cap. A
#: `critical` band assigned from the crash type alone would be an adjective this module has not
#: measured — the maintainers' style guide's register, in the numeric field a board reads. Confidence that
#: the finding is real is a DIFFERENT axis and rides on the rule's `precision`, which is where SARIF
#: puts it: a Shard `error` always carries a reproducing input, so it is `very-high` there while
#: staying `medium` here.
_SEVERITY: dict[str, str] = {
    "heap-use-after-free": "high", "stack-use-after-return": "high", "stack-use-after-scope": "high",
    "use-after-poison": "high", "double-free": "high", "bad-free": "high", "bad-cast": "high",
    "alloc-dealloc-mismatch": "high",
    "heap-buffer-overflow": "medium", "stack-buffer-overflow": "medium",
    "stack-buffer-underflow": "medium", "dynamic-stack-buffer-overflow": "medium",
    "global-buffer-overflow": "medium", "container-overflow": "medium",
    "index-out-of-bounds": "medium", "object-size": "medium", "memcpy-param-overlap": "medium",
    "incorrect-function-pointer-type": "medium", "non-positive-vla-bound-value": "medium",
    "use-of-uninitialized-value": "medium", "negative-size-param": "medium",
    "signed-integer-overflow": "medium", "unsigned-integer-overflow": "medium",
    "null-dereference": "medium", "segv": "medium", "deadly signal": "medium",
    "shift-exponent": "low", "shift-negative": "low", "divide-by-zero": "low", "fpe": "low",
    "float-cast-overflow": "low", "misaligned-address": "low", "invalid-bool-load": "low",
    "unreachable-code": "low", "detected-memory-leaks": "low", "memory-leaks": "low",
    "allocation-size-too-big": "low", "requested-allocation-size-exceeds": "low",
    "out-of-memory": "low", "stack-overflow": "low", "data-race": "medium", "thread-leak": "low",
}

#: Band to the number GitHub ranks on. The value sits in the MIDDLE of GitHub's own published band —
#: critical 9.0+, high 7.0-8.9, medium 4.0-6.9, low 0.1-3.9 — rather than at an edge, because an
#: edge value lands in a different bucket the moment GitHub moves a boundary by a tenth.
_SEVERITY_SCORE: dict[str, str] = {"critical": "9.3", "high": "7.5", "medium": "5.5", "low": "2.0"}

_BANDS = ("low", "medium", "high", "critical")


@dataclass(frozen=True)
class CrashState:
    """One sanitiser report, classified. Frozen for the same reason the separate capability's own
    verdict record is frozen: a classification a later stage can edit is not a classification.

    ``parsed`` is the abstention flag and every consumer must read it. False means the output was not
    a sanitiser report this module recognises — which is the ordinary case for a free-tier
    ``output_marker`` finding — and the caller must fall back to its existing behaviour rather than
    emit an unclassified CWE or a default severity. The failure this prevents is the one
    ``report._crash_title`` already guards against in prose: inventing a defect class.
    """

    sanitizer: str = ""            # "address", "undefined", "memory", "thread", "leak", "libfuzzer"
    crash_type: str = ""           # "heap-buffer-overflow", "signed-integer-overflow", ...
    access: str = ""               # "READ", "WRITE", or "" when the report named neither
    frames: tuple[str, ...] = ()   # the top CRASH_STATE_FRAMES application frames, function names
    parsed: bool = False

    @property
    def signature(self) -> str:
        """The stable identity: 16 hex characters over the class and the application frames.

        Empty when nothing parsed, so a caller cannot accidentally key on the hash of an empty
        tuple — which would be one identity shared by every unclassified finding, the exact
        collision `Finding.fingerprint` hashes its fallback seed to avoid.
        """
        if not self.parsed:
            return ""
        seed = "\x00".join((self.sanitizer, self.crash_type, self.access) + self.frames)
        return hashlib.sha256(seed.encode()).hexdigest()[:16]

    @property
    def cwe_ids(self) -> tuple[str, ...]:
        """CWE numbers, most specific first. Empty when the class is unknown — never a default."""
        if not self.parsed:
            return ()
        return _CWE.get((self.crash_type, self.access)) or _CWE.get((self.crash_type, "")) or ()

    @property
    def severity(self) -> str:
        """`low` / `medium` / `high`, or "" when the class is unknown."""
        band = _SEVERITY.get(self.crash_type, "")
        if not band:
            return ""
        if self.access == "WRITE":
            band = _BANDS[min(_BANDS.index(band) + 1, _BANDS.index("high"))]
        return band

    @property
    def security_severity(self) -> str:
        """The numeric string GitHub code scanning ranks on, or "" when there is no band."""
        return _SEVERITY_SCORE.get(self.severity, "")

    @property
    def tags(self) -> tuple[str, ...]:
        """SARIF rule tags. `security` always — this is a security tool and the tag is what puts an
        alert in the Security tab at all — plus one `external/cwe/cwe-NNN` per mapped id, which is
        the spelling GitHub filters on."""
        return ("security",) + tuple(f"external/cwe/cwe-{n}" for n in self.cwe_ids)

    def describe(self) -> str:
        """One line for a human: the class, the access, and the frames that identify it.

        The frames are the part that was missing. `report.py`'s own header records it as a defect:
        *"`sanitizer` — the error-type line — and the frames are not on it."* The separate
        capability has had a pure frame extractor since before this module existed and no field
        carried its output, so a reader of the markdown could see WHAT crashed and never WHERE, in a
        report whose subject is a crash.
        """
        if not self.parsed:
            return ""
        head = self.crash_type + (f" {self.access}" if self.access else "")
        return f"{head} in {' <- '.join(self.frames)}" if self.frames else head


def _frame_name(rest: str) -> str:
    """The identifying name out of one frame line's tail, or "" when there is none.

    Order matters and is measured against real traces: the source location is stripped BEFORE the
    argument list, because `parse(char const*) /src/p.c:10:3` ends in the location and the argument
    regex is anchored at end-of-string.
    """
    text = _FRAME_LOC_RE.sub("", rest).strip()
    module = _FRAME_MODULE_RE.search(text)
    if module:
        # `foo (/out/fuzz+0x4f1)` keeps `foo`; a bare `(/out/fuzz+0x4f1)` keeps the module basename.
        text = text[:module.start()].strip() or module.group("path").rsplit("/", 1)[-1]
    text = _FRAME_ARGS_RE.sub("", text).strip()
    return text


def _ignored(name: str) -> bool:
    return any(rx.search(name) for rx in _IGNORED_FRAMES)


def crash_frames(output: str, limit: int = CRASH_STATE_FRAMES) -> tuple[str, ...]:
    """The top ``limit`` APPLICATION frames of a sanitiser trace, sanitiser and engine frames removed.

    Reads the FIRST stack only. ASan prints a second stack for the allocation site of a
    use-after-free and MSan prints one for the origin, and both are frames of a different event: a
    use-after-free's identity is where the use happened, and mixing the allocation site in makes two
    uses of one bad pointer look like two defects. The frame ids restart at `#0`, which is how the
    boundary is detected without knowing which sanitiser wrote it.
    """
    names: list[str] = []
    seen_first_stack = False
    for line in (output or "").splitlines():
        match = _FRAME_RE.match(line)
        if not match:
            continue
        if match.group("id") == "0":
            if seen_first_stack:
                break                        # a second stack begins; its frames are a different event
            seen_first_stack = True
        name = _frame_name(match.group("rest"))
        if name and not _ignored(name):
            names.append(name)
            if len(names) >= limit:
                break
    return tuple(names)


def _crash_type(raw: str) -> str:
    """The class out of an error line's tail: cut at the volatile part, hyphenate, alias."""
    text = raw.strip()
    cuts = [text.find(sep) for sep in _TYPE_TAIL]
    end = min([c for c in cuts if c > 0], default=len(text))
    kind = "-".join(text[:end].strip().lower().split())
    return _TYPE_ALIASES.get(kind, kind)


def _classify(output: str) -> tuple[str, str]:
    """The sanitiser and the crash type, or ("", "") when the text is not a report we recognise."""
    match = _ERROR_RE.search(output)
    if match:
        san = match.group("san").replace(" ", "").lower().replace("undefinedbehavior", "undefined")
        kind = _crash_type(match.group("type"))
        if kind == "undefined-behavior" or san == "undefined":
            # ASan's generic label. The class lives in the `runtime error:` prose, if there is any.
            return "undefined", _ub_type(output) or kind
        return san, kind
    if _LIBFUZZER_RE.search(output):
        return "libfuzzer", _LIBFUZZER_RE.search(output).group("type").split(" (")[0]
    ub = _ub_type(output)
    if ub:
        # UBSan's default `-fsanitize=undefined` prints the runtime error and NO `ERROR:` line at all
        # unless `halt_on_error` is set. Recognising it here is what stops every default-configured
        # UBSan finding from arriving unclassified.
        return "undefined", ub
    return "", ""


def _ub_type(output: str) -> str:
    match = _UB_RUNTIME_RE.search(output)
    if not match:
        return ""
    prose = match.group("prose").lower()
    for needle, kind in _UB_PROSE:
        if needle in prose:
            return kind
    return "undefined-behavior"


def parse(output: str) -> CrashState:
    """Classify one harness output. Never raises, never guesses: an unrecognised text returns
    ``CrashState()`` with ``parsed`` False and every derived field empty."""
    text = output or ""
    sanitizer, crash_type = _classify(text)
    if not crash_type:
        return CrashState()
    access_match = _ACCESS_RE.search(text)
    return CrashState(sanitizer=sanitizer, crash_type=crash_type,
                      access=access_match.group("access") if access_match else "",
                      frames=crash_frames(text), parsed=True)


def classify(evidence: str, sanitizer_line: str | None = None) -> CrashState:
    """`parse` over the two fields a `report.Finding` carries, evidence first.

    Evidence is the harness's whole output and is the only one of the two that carries frames;
    the sanitiser line is a single line kept for the case where evidence was never captured or was
    truncated past the report. Trying evidence first and the line second means a finding recorded
    before evidence existed still classifies, at the cost of an empty frame tuple — which
    `signature` handles, because a class with no frames is still a far better identity than a hash
    of a build path.
    """
    state = parse(evidence)
    return state if state.parsed else parse(sanitizer_line or "")


__all__ = ["CRASH_STATE_FRAMES", "CrashState", "classify", "crash_frames", "parse"]
