
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

CRASH_STATE_FRAMES = 3

_ERROR_RE = re.compile(
    r"(?:ERROR|WARNING|SUMMARY):\s*"
    r"(?P<san>Address|HWAddress|UndefinedBehavior|Undefined Behavior|Memory|Thread|Leak)"
    r"Sanitizer:\s*(?P<type>[^\n]+)")

_TYPE_TAIL = (" on ", " at ", " in ", " (", " /", ":", ";")

_TYPE_ALIASES: dict[str, str] = {
    "attempting-free": "bad-free",
    "attempting-double-free": "double-free",
    "requested-allocation-size": "allocation-size-too-big",
    "unknown-crash": "segv",
}

_LIBFUZZER_RE = re.compile(r"ERROR:\s*libFuzzer:\s*(?P<type>deadly signal|out-of-memory|timeout"
                           r"|out-of-memory \(malloc\(\d+\)\))")

_UB_RUNTIME_RE = re.compile(r"runtime error:\s*(?P<prose>[^\n]+)")

_ACCESS_RE = re.compile(r"^\s*(?P<access>READ|WRITE) of size \d+", re.MULTILINE)

_FRAME_RE = re.compile(r"^\s*#(?P<id>\d+)\s+0x[0-9a-fA-F]+\s+(?:in\s+)?(?P<rest>\S.*?)\s*$")

_FRAME_LOC_RE = re.compile(r"\s+[\w./+-]+\.(?:c|cc|cpp|cxx|h|hpp|hh|rs|go|py|java|m|mm)(?::\d+){0,2}$",
                           re.IGNORECASE)

_FRAME_MODULE_RE = re.compile(r"\((?P<path>[^()+]+)\+0x[0-9a-fA-F]+\)\s*$")

_FRAME_ARGS_RE = re.compile(r"(?<=\w)\([^()]*\)\s*(?:const)?\s*$")

_IGNORED_FRAMES = tuple(re.compile(p) for p in (
    r"^__asan::", r"^__asan_", r"^_asan_", r"^asan_", r"^__hwasan::", r"^__hwasan_",
    r"^__lsan::", r"^__lsan_", r"^__msan::", r"^__msan_", r"^__tsan::", r"^__tsan_",
    r"^__ubsan::", r"^__ubsan_", r"^__sanitizer::", r"^__sanitizer_", r"^__interceptor_",
    r"^___interceptor_",
    r"^malloc$", r"^calloc$", r"^realloc$", r"^free$", r"^operator", r"^new$", r"^delete$",
    r"^(?:__)?mem(?:cmp|cpy|move|set)", r"^(?:__)?str(?:cmp|cpy|dup|len|ncpy)",
    r"^__chk_fail$", r"^__fortify_fail$", r"^__libc_", r"^__GI_",
    r"^abort$", r"^exit$", r"^raise$", r"^gsignal$", r"^_start$", r"^__assert_",
    r"^pthread_create$", r"^pthread_kill$", r"^__pthread_kill",
    r"^fuzzer::", r"^LLVMFuzzerTestOneInput", r"^main$", r"^__libfuzzer",
    r"^rust_fuzzer_test_input", r"^libfuzzer_sys::", r"^rust_begin_unwind", r"^rust_panic",
    r"^core::panic", r"^std::panic", r"^std::process::abort", r"^std::sys::backtrace",
    r"^std::sys_common::backtrace", r"^__rust_start_panic", r"^__rust_try",
    r"^<unknown>$", r"^<null>", r"^\?\?$",
))

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

_SEVERITY_SCORE: dict[str, str] = {"critical": "9.3", "high": "7.5", "medium": "5.5", "low": "2.0"}

_BANDS = ("low", "medium", "high", "critical")


@dataclass(frozen=True)
class CrashState:

    sanitizer: str = ""
    crash_type: str = ""
    access: str = ""
    frames: tuple[str, ...] = ()
    parsed: bool = False

    @property
    def signature(self) -> str:
        if not self.parsed:
            return ""
        seed = "\x00".join((self.sanitizer, self.crash_type, self.access) + self.frames)
        return hashlib.sha256(seed.encode()).hexdigest()[:16]

    @property
    def cwe_ids(self) -> tuple[str, ...]:
        if not self.parsed:
            return ()
        return _CWE.get((self.crash_type, self.access)) or _CWE.get((self.crash_type, "")) or ()

    @property
    def severity(self) -> str:
        band = _SEVERITY.get(self.crash_type, "")
        if not band:
            return ""
        if self.access == "WRITE":
            band = _BANDS[min(_BANDS.index(band) + 1, _BANDS.index("high"))]
        return band

    @property
    def security_severity(self) -> str:
        return _SEVERITY_SCORE.get(self.severity, "")

    @property
    def tags(self) -> tuple[str, ...]:
        return ("security",) + tuple(f"external/cwe/cwe-{n}" for n in self.cwe_ids)

    def describe(self) -> str:
        if not self.parsed:
            return ""
        head = self.crash_type + (f" {self.access}" if self.access else "")
        return f"{head} in {' <- '.join(self.frames)}" if self.frames else head


def _frame_name(rest: str) -> str:
    text = _FRAME_LOC_RE.sub("", rest).strip()
    module = _FRAME_MODULE_RE.search(text)
    if module:
        text = text[:module.start()].strip() or module.group("path").rsplit("/", 1)[-1]
    text = _FRAME_ARGS_RE.sub("", text).strip()
    return text


def _ignored(name: str) -> bool:
    return any(rx.search(name) for rx in _IGNORED_FRAMES)


def crash_frames(output: str, limit: int = CRASH_STATE_FRAMES) -> tuple[str, ...]:
    names: list[str] = []
    seen_first_stack = False
    for line in (output or "").splitlines():
        match = _FRAME_RE.match(line)
        if not match:
            continue
        if match.group("id") == "0":
            if seen_first_stack:
                break
            seen_first_stack = True
        name = _frame_name(match.group("rest"))
        if name and not _ignored(name):
            names.append(name)
            if len(names) >= limit:
                break
    return tuple(names)


def _crash_type(raw: str) -> str:
    text = raw.strip()
    cuts = [text.find(sep) for sep in _TYPE_TAIL]
    end = min([c for c in cuts if c > 0], default=len(text))
    kind = "-".join(text[:end].strip().lower().split())
    return _TYPE_ALIASES.get(kind, kind)


def _classify(output: str) -> tuple[str, str]:
    match = _ERROR_RE.search(output)
    if match:
        san = match.group("san").replace(" ", "").lower().replace("undefinedbehavior", "undefined")
        kind = _crash_type(match.group("type"))
        if kind == "undefined-behavior" or san == "undefined":
            return "undefined", _ub_type(output) or kind
        return san, kind
    if _LIBFUZZER_RE.search(output):
        return "libfuzzer", _LIBFUZZER_RE.search(output).group("type").split(" (")[0]
    ub = _ub_type(output)
    if ub:
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
    text = output or ""
    sanitizer, crash_type = _classify(text)
    if not crash_type:
        return CrashState()
    access_match = _ACCESS_RE.search(text)
    return CrashState(sanitizer=sanitizer, crash_type=crash_type,
                      access=access_match.group("access") if access_match else "",
                      frames=crash_frames(text), parsed=True)


def classify(evidence: str, sanitizer_line: str | None = None) -> CrashState:
    state = parse(evidence)
    return state if state.parsed else parse(sanitizer_line or "")


__all__ = ["CRASH_STATE_FRAMES", "CrashState", "classify", "crash_frames", "parse"]
