"""The survey — what this codebase is, and what we might look for in it.

the design notes This is **not** `preflight`, and conflating them would lose both.
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

The markers below are **candidate surfaces, not findings.** Nothing here may be reported as a defect.
the maintainers' notes is explicit that a heuristic from outside the project must be validated against real project
data before anything is built on it — *"research is useful for generating hypotheses, not for shipping
features"* — and the accuracy of this table is **unmeasured**. It is a map of where to look, produced
cheaply, and it is wrong in both directions: `memcpy` appears in safe code constantly, and a defect can
sit somewhere no marker fires.

Consequences held in the code: surfaces never become `report.Finding`s, `assess` never emits a severity,
and `summarise` says "candidate" everywhere it says anything.
"""

from __future__ import annotations

import os
import pathlib
import re
from dataclasses import dataclass

from shard.ignorefile import IgnoreIndex
from shard.target import EXT_LANGUAGE
from shard.tools import _VCS_DIRS

#: Reading is what makes the survey more expensive than `profile_repo`, so it is bounded on three axes
#: and every cap is REPORTED. the design notes: a truncated scan that found nothing
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
#: had **every source file skipped** — and two marker rows below are language-AGNOSTIC, `parser` among
#: them, so that was lost coverage and not merely a lost count.
_EXT_LANG = EXT_LANGUAGE

# CANDIDATE markers. See the module docstring: unmeasured, wrong in both directions, and never a
# finding. Each entry is (kind, language-group, pattern). Kept small on purpose — a longer table would
# look more thorough and be no more true.
#
# ── THE TEST A NEW ROW MUST PASS, and it is not the noise figure ─────────────────────────────────────
#
# **Is the sink dangerous BY ITSELF, or only in a context that is not on the line?**
#
# Two candidates were measured and refused on 2026-08-12, both with rates INSIDE the band, and both for
# this reason. They are recorded because a low number was what made each of them look shippable:
#
#   path_traversal   `Path.Combine(dir, fileName)` — the sink is every path join in the program. The
#                    row shipped at 0.02/KLOC and was withdrawn: all 48 hits were internal.
#   weak crypto      `Digest::MD5` — 0.03/KLOC across 11,356 KLOC, and at least half of the highest-
#                    volume language's hits are ActiveStorage `checksum:` lines. MD5 for a cache key is
#                    correct; MD5 for a password is a bug; the LINE does not say which.
#
# Every row that survives has the opposite property. `shell_exec(`, `eval(`, `BinaryFormatter`,
# `include $var`, `.innerHTML =` with a dynamic value, `__proto__` in a write position, `[DllImport` —
# each of these is the danger, not merely adjacent to it. Where a row needed context it got it from the
# SAME EXPRESSION (`shell: true`, `fmt.Sprintf` inside `.Query(`), never from the surrounding function.
#
# So: a marker table can find dangerous CALLS. It cannot find dangerous DATA FLOW, and a conjunction
# that reaches for flow with a regex produces a low, respectable-looking rate full of wrong matches —
# which is worse than a high one, because nothing flags it. **Read the matches, not just the rate.**
_C_LIKE = frozenset({"c", "c++", "zig"})

_MARKERS: tuple[tuple[str, frozenset[str] | None, re.Pattern[str]], ...] = (
    # Where untrusted bytes enter the process.
    ("input_boundary", _C_LIKE,
     re.compile(r"\b(?:fread|recv|recvfrom|fgets|getline|read)\s*\(")),
    ("input_boundary", None, re.compile(r"\bmain\s*\(\s*int\s+argc")),
    ("input_boundary", frozenset({"python"}),
     re.compile(r"\b(?:sys\.argv|input\s*\(|\.read\s*\(|request\.(?:args|form|data|json))")),
    ("input_boundary", frozenset({"go"}), re.compile(r"\b(?:os\.Args|bufio\.NewReader|r\.Body)")),

    # Operations whose safety depends entirely on a length the caller computed.
    ("unsafe_op", _C_LIKE,
     re.compile(r"\b(?:strcpy|strcat|sprintf|gets|alloca|sscanf|memcpy|memmove)\s*\(")),

    # Code whose job is to interpret attacker-shaped structure.
    #
    # THE `deserial` ARM IS SPLIT OUT, and that shape is load-bearing rather than cosmetic. Written as
    # one alternation — `(?:…|deserial\w*|…)[A-Za-z_]*` — the `\w*` and the shared `[A-Za-z_]*` that
    # follows it overlap, so every way of splitting a trailing word-run is retried on a non-match. That
    # is quadratic: measured on a single line of `deserial` + n×`a`, 0.4s at n=8,000, 6.4s at n=32,000
    # and 25.5s at n=64,000 — and one 160 KB source file took `survey_repo` 43.9s while finding nothing.
    # There is no timeout anywhere in the scan, so it is a CI hang, not a slow row.
    #
    # Splitting the arm keeps `\w*` (which absorbs digits, so `deserialize2(` still fires) while giving
    # it no ambiguous suffix to backtrack against: 1.3ms at n=64,000. Verified equivalent, not assumed —
    # 25,985 generated identifiers across both patterns, zero divergences. Truncating to `deserial`
    # instead WOULD have changed behaviour, silently dropping `deserialize2(`.
    ("parser", None,
     re.compile(r"\b(?:(?:parse|decode|unmarshal|demarshal)[A-Za-z_]*|deserial\w*)\s*\(")),

    # Boundaries where the language's own guarantees stop.
    ("ffi", frozenset({"rust"}), re.compile(r"\bunsafe\s*\{|\bextern\s+\"C\"")),
    ("ffi", frozenset({"go"}), re.compile(r"^\s*import\s+\"C\"", re.M)),
    ("ffi", frozenset({"python"}), re.compile(r"\b(?:ctypes|cffi)\b")),
    ("ffi", frozenset({"java"}), re.compile(r"\bnative\s+\w+\s+\w+\s*\(")),

    # Turning bytes back into objects, which is where memory-safe languages get their worst bugs.
    ("deserialiser", frozenset({"python"}),
     re.compile(r"\b(?:pickle\.loads?|yaml\.load\s*\(|eval\s*\(|exec\s*\()")),
    ("deserialiser", frozenset({"javascript", "typescript"}),
     re.compile(r"\beval\s*\(|\bvm\.runIn\w+|\bFunction\s*\(")),
    ("deserialiser", frozenset({"java"}), re.compile(r"\breadObject\s*\(")),
    ("deserialiser", frozenset({"ruby"}), re.compile(r"\b(?:Marshal\.load|YAML\.load)\s*\(")),
    ("deserialiser", frozenset({"php"}), re.compile(r"\bunserialize\s*\(")),

    # Python's real bug classes, added in W9 P1.2. The per-KLOC figures below are NOISE measurements
    # over 1,235.9 KLOC of real Python (A=shard-v2 40.3 KLOC, B=the benchmark+attacks 153.3 KLOC, C=Hermes
    # 1,042.3 KLOC) — how often each pattern fires on ordinary code, NOT precision against ground truth.
    # Precision is still UNMEASURED (it needs the P1.1 canary + a CVE corpus, which is P1.3). Like every
    # row above, these are candidate surfaces and never a finding. Scoped to python because that is the
    # only language the measurement covered; the narrow shape is what earns the row over the naive one.

    # Shelling out to the OS — Python's highest-signal injection sink, and the one whose demonstration is
    # close to unforgeable: an injected command's OUTPUT (inject `id`, observe `uid=` the agent did not
    # supply) is witnessable via `output_marker`. Narrowed to os.system/os.popen/shell=True at
    # 0.00-0.20/KLOC; naive `subprocess.run(` was 0.60-0.73/KLOC of SAFE list-form calls and is rejected.
    ("command_exec", frozenset({"python"}),
     re.compile(r"\bos\.(?:system|popen)\s*\(|\bshell\s*=\s*True\b")),

    # Server-side template rendering of a dynamic string (SSTI). The cleanest keep by the numbers:
    # 0.00-0.01/KLOC, every hit the genuine sink. The safe path renders a FILE (`render_template`); only
    # the string form is matched. Its demonstrability is not measured — do not assume the command_exec claim.
    ("template_injection", frozenset({"python"}),
     re.compile(r"\brender_template_string\s*\(")),

    # A string-built query reaching a cursor. The WEAKEST keep, f-string variant ONLY (0.00-0.04/KLOC):
    # naive `.execute(` is 0.42-1.24/KLOC and mostly non-SQL (`session.execute(CmdRunAction(...))`,
    # `conn.execute("PRAGMA ...")`). The known false positive is stated, not hidden: this cannot tell an
    # interpolated placeholder from an interpolated value, so a safe parametrized `execute(f"…IN ({ph})",
    # ids)` still fires. If the table must shrink, this is the first cut. Demonstrability unmeasured.
    ("sql_injection", frozenset({"python"}),
     re.compile(r"\.execute\s*\(\s*f[\"']")),

    # JavaScript's shell sink, added in W9 P2.2 and measured the same way the Python rows above were:
    # NOISE over 267.8 KLOC of real JS/TS across FIVE corpora (a real repository 49.0, reyse 2.6, TTLV 133.8,
    # lucebox-hub 48.8, strudel-MCP 33.5), node_modules/dist/minified excluded. Precision is UNMEASURED,
    # exactly as it is for every row above.
    #
    # 0.00/KLOC — ONE hit in 267.8 KLOC — which is at or below the 0.00-0.20 the kept Python row scored.
    #
    # THE NAIVE VARIANT IS REJECTED AND THE REASON IS THE WHOLE POINT OF THE ROW. A bare `exec(` measures
    # 0.53/KLOC, and **94% of those (134 of 142) are `regex.exec(`** — `RegExp.prototype.exec`, which is
    # string matching and not a sink at all. That is the same trap as Python's naive `subprocess.run(`
    # and it is far worse here, because in JavaScript the safe meaning is the COMMON meaning. Matching
    # `execSync`/`execFile*`/`shell: true` avoids it: none of those is a RegExp method.
    #
    # This is also the one JavaScript class measured WITNESSABLE. canary-js confirms against the real
    # adjudicator that an injected `id` producing `uid=` demonstrates at exit 0 via `output_marker`, for
    # both the direct injection and the prototype-pollution gadget — the same unforgeable route the
    # Python row cites. Every other JS class measured there is silent on success.
    ("command_exec", frozenset({"javascript", "typescript"}),
     re.compile(r"\bexecSync\s*\(|\bexecFile(?:Sync)?\s*\(|\bshell\s*:\s*true\b")),

    # ---- W9 P2b tier 2. Same method as the Python and JavaScript rows above: NOISE per KLOC over
    # three or more real corpora, cloned at their default branch, tests and vendored trees excluded.
    # PRECISION IS UNMEASURED for every row here, exactly as it is for every row above.
    #
    # A row is kept only if its narrow pattern FIRED AT LEAST ONCE on real code at <=0.20/KLOC. A
    # pattern scoring 0.00 with ZERO hits is not evidence it is well-shaped — it cannot be told apart
    # from a regex that matches nothing — and three such candidates were DEFERRED rather than kept.
    # the maintainers' notes §9 has them with their numbers.

    # C# had NO markers at all: detected by extension with nothing behind it, which
    # the design notes calls the sharpest hole. These four close it.
    # Corpora: jellyfin 339k, ShareX 235k, aspnetcore 1,731k = 2,305 KLOC.
    #
    # .NET's deserialisation RCE family, all four of which are the documented dangerous ones.
    # 0.00/KLOC (6 hits). Naive `*Serializer`/`Deserialize(` is 0.79/KLOC (1,815 hits) of ordinary,
    # safe serialisation and is rejected — the same shape of error as JavaScript's `regex.exec(`.
    ("deserialiser", frozenset({"c#"}),
     re.compile(r"\bBinaryFormatter\b|\bTypeNameHandling\s*[.=]|\bLosFormatter\b|"
                r"\bNetDataContractSerializer\b|\bObjectStateFormatter\b")),
    # The managed/native boundary. 0.10/KLOC (221 hits) — the busiest row here and still inside the
    # band, because `[DllImport` means exactly one thing.
    ("ffi", frozenset({"c#"}), re.compile(r"\[\s*DllImport")),
    # Shelling out. 0.00/KLOC (10 hits). Naive `Process.Start(` is 0.01/KLOC and mostly opens a URL or
    # a document with no shell involved, so the flag rather than the call is what is matched.
    ("command_exec", frozenset({"c#"}), re.compile(r"\bUseShellExecute\s*=\s*true\b")),
    # A query built by interpolation or concatenation. 0.00/KLOC (5 hits).
    ("sql_injection", frozenset({"c#"}),
     re.compile(r"new\s+SqlCommand\s*\(\s*[$\"].*[+{]|\.CommandText\s*=\s*[$\"].*[+{]")),

    # PHP. Corpora: guzzle 59k, PHPMailer 20k, laravel 551k.
    #
    # The shell sinks, and the qualifier is the measurement. `(?<![>:$\w])` drops `$pdo->exec(` and
    # `::exec(`: measured, PHP's bare `exec(` is 44 hits of which almost all are METHOD calls —
    # overwhelmingly PDO's `->exec()`, which is SQL and not a shell. Unqualified scores 0.07/KLOC of
    # mostly-wrong hits; qualified scores 0.05/KLOC (16 hits) and every hit is a real builtin. This is
    # JavaScript's `regex.exec(` trap in a second language, which is why the qualifier is not optional.
    ("command_exec", frozenset({"php"}),
     re.compile(r"(?<![>:$\w])\b(?:exec|system|shell_exec|passthru|popen|proc_open)\s*\(")),
    # LFI/RFI — PHP's signature class and a KIND no other language here needs, which is exactly the
    # "new kinds, not more regexes of the old kinds" that P1.2 asks for. Including a VARIABLE path is
    # the whole signal: 0.04/KLOC (28 hits), where any `include`/`require` is 0.37/KLOC (235 hits) and
    # is almost entirely static requires of a literal file.
    ("file_inclusion", frozenset({"php"}),
     re.compile(r"\b(?:include|include_once|require|require_once)\s*\(?\s*\$")),

    # Java. Corpora: gson 56k, okhttp 4k, commons-lang 203k, spring-framework 1,509k = 1,774 KLOC.
    # 0.00/KLOC (4 hits). Naive `.executeQuery(` is 0.02/KLOC (37 hits) of parametrised, safe calls.
    ("sql_injection", frozenset({"java"}),
     re.compile(r"\.execute(?:Query|Update)?\s*\(\s*\"[^\"]*\"\s*\+|"
                r"\.execute(?:Query|Update)?\s*\(\s*String\.format\s*\(")),

    # Ruby. Corpora: sinatra 24k, jekyll 22k, fastlane 166k, rails 563k = 778 KLOC.
    # Interpolation into a query fragment. 0.03/KLOC (22 hits); any `.where(` is 2.23/KLOC (1,734).
    #
    # ITS SIBLING WAS REJECTED AND THE NUMBER IS THE REASON. A `command_exec` row keyed on backticks or
    # `system` carrying `#{}` measures 0.44/KLOC — over twice the band — because **Ruby's backtick is
    # also a prose quoting character**, and the hits are overwhelmingly error and documentation strings
    # (`` ` to produce a match to #{tag_match}, but did not `` ). Recorded rather than tuned: a marker
    # that fires on a language's punctuation habits is the naive variant, whatever it is keyed on.
    ("sql_injection", frozenset({"ruby"}),
     re.compile("\\.(?:where|find_by_sql|order|group)\\s*\\(?\\s*\"[^\"\n]*#\\{")),

    # ---- W9 P2b tier 2, completion pass. Same method, and the corpora were EXTENDED first because
    # three candidates had scored zero on libraries that never shell out or touch SQL. A zero measured
    # on a corpus that cannot show the class is not a result, and two of the three changed once the
    # corpus could: java command_exec 0 -> 4 hits, go sql_injection 0 -> 52.

    # Java. Corpora now +jenkins 337k +dubbo 485k = 2,597 KLOC.
    # The famous one, and it needed a corpus that actually spawns processes. 0.00/KLOC (4 hits);
    # `new ProcessBuilder(` is 12 hits of the SAFE list form and is not matched.
    ("command_exec", frozenset({"java"}),
     re.compile(r"getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(")),
    # XXE — Java's signature class, and a KIND no other language here needs. A factory left at its
    # unsafe default is the whole bug. 0.02/KLOC (51 hits). It fires on the SAFE configuration too,
    # which is the honest limit of a marker: it says "an XML parser is constructed here", not "this one
    # is vulnerable". That is what a candidate surface IS, and the docstring above says so for all of them.
    ("xxe", frozenset({"java"}),
     re.compile(r"(?:DocumentBuilderFactory|SAXParserFactory|XMLInputFactory)\s*\.\s*newInstance\s*\(")),

    # Go. Corpora now +docker/cli 107k +gitea 468k = 1,256 KLOC.
    # 0.04/KLOC (52 hits); any `.Query(` is 0.12/KLOC (152) and is mostly the safe placeholder form.
    #
    # NO `command_exec` ROW FOR GO, and this is a measured finding rather than a gap: across 1,256 KLOC
    # including two CLIs that shell out constantly, `exec.Command` appears 68 times and **not once with
    # a shell as argv0**. Go's standard library makes the safe form the natural one, so the marker would
    # be near-dead. Recorded in the maintainers' notes §9.
    ("sql_injection", frozenset({"go"}),
     re.compile(r"\.(?:Query|QueryRow|Exec)(?:Context)?\s*\(\s*fmt\.Sprintf\s*\(")),

    # NO `path_traversal` ROW IN ANY LANGUAGE, and this is a measured retraction rather than a gap.
    # CWE-22 is rank 6 on the 2025 CWE Top 25, so it was attempted; the design notes
    # carries the analysis and the maintainers' notes §15 the numbers.
    #
    # A row keyed on `Path.Combine` plus a "request-derived" token SHIPPED here on 2026-08-12 at
    # 0.02/KLOC and was withdrawn the same day. Audited, all 48 of its hits were internal path building
    # — `Path.Combine(dir, fileName)`, `Path.Combine(screenshotsFolder, fileName)`, and even
    # `Path.Combine(path, MetafileName)` — because the token list contained `fileName` and `param`,
    # which are ordinary variable names and not evidence of anything. With genuinely request-only
    # tokens the same corpora yield **zero**.
    #
    # The general result, measured across six languages and ~8,700 KLOC: **path traversal is
    # taint-shaped, not marker-shaped.** Its sink — `open`, `File.join`, `Path.Combine`, `os.ReadFile`
    # — is ubiquitous and benign, so unlike `innerHTML =` or `shell_exec(` the sink alone says nothing.
    # Only the taint makes it a bug, and the taint is almost never on the same LINE as the sink. Strict
    # request-token conjunction finds 0-1 hits per corpus (js 0, php 0, java 1, go 1, ruby 21) while the
    # loose form finds everything and means nothing. There is no useful operating point between them.

    # PHP. A variable interpolated straight into a query string. 0.00/KLOC (2 hits) against 66 for any
    # `->query(`. THE THINNEST ROW HERE — two hits is barely a measurement, and it is kept because the
    # shape is unambiguous rather than because the number is strong. First candidate to cut if the
    # table must shrink.
    ("sql_injection", frozenset({"php"}),
     re.compile(r"(?:->query|->exec|mysqli_query|pg_query)\s*\(\s*[\"'][^\"']*\$")),

    # JavaScript/TypeScript. Prototype pollution — the class JS has that C and Python do not, and the
    # ONE JavaScript class canary-js measured WITNESSABLE end to end: a polluted `shell` key reaching a
    # gadget, demonstrated at exit 0 through `output_marker` via `id` -> `uid=`.
    # 0.00/KLOC (2 hits) over 987 KLOC of express, nest, lodash, vue and strapi; any mention of
    # `__proto__` is 0.04/KLOC (41), most of it guards and tests checking FOR the bug. Matching only the
    # WRITE position is what separates the sink from its own mitigation.
    ("prototype_pollution", frozenset({"javascript", "typescript"}),
     re.compile(r"\[\s*[\"']__proto__[\"']\s*\]\s*=|\.__proto__\s*=|"
                r"\[\s*[\"']constructor[\"']\s*\]\s*\[\s*[\"']prototype[\"']\s*\]")),

    # ---- XSS, CWE-79, RANK 1 on the 2025 CWE Top 25 and the largest gap this table had.
    # the design notes has the analysis that found it. Three languages ship; two were
    # measured and REFUSED, and the reason is reachability rather than noise — see below.
    #
    # THE WRITE POSITION IS THE WHOLE MARKER. `innerHTML` is READ as often as written and
    # `.innerHTML = ''` is the standard clearing idiom, so the naive assignment form scores 0.24/KLOC
    # against 0.18 for this one. Twelve controls pin the boundary, including `=== ` and `==`, which an
    # earlier draft matched because `=\s*` happily consumes the first character of `===`.
    #
    # 0.18/KLOC (200 hits) over 1,084 KLOC of express, nest, lodash, vue, strapi, a real repository and reyse.
    # **This is the noisiest row kept in this table and the per-corpus spread is wide** — 0.00 in
    # express/nest/strapi, 0.39 in lodash, 0.78 in vue. Vue is a DOM renderer, so assigning innerHTML
    # is literally its job; excluding it the rate is 0.08/KLOC. Both figures are recorded because
    # dropping the inconvenient corpus is the same error as choosing a corpus that cannot fail.
    ("xss", frozenset({"javascript", "typescript"}),
     re.compile(r"\.(?:inner|outer)HTML\s*=(?!=)\s*(?![\"'\s;])|"
                r"\.(?:inner|outer)HTML\s*=(?!=)\s*`[^`]*\$\{|"
                r"\binsertAdjacentHTML\s*\(|\bdangerouslySetInnerHTML\b|\bv-html\b|"
                r"\bdocument\.write(?:ln)?\s*\(")),

    # Blade's unescaped echo. 0.08/KLOC (53 hits) over 630 KLOC; any `echo` is 0.68/KLOC (428).
    # Reachable because `x.blade.php` has suffix `.php`, which `_EXT_LANG` maps — checked, not assumed.
    # All 53 hits are in laravel: guzzle and PHPMailer carry no templates, so this is effectively a
    # ONE-corpus measurement and is labelled as such.
    ("xss", frozenset({"php"}), re.compile(r"\{!!|<\?=\s*\$")),

    # Rails' escape hatch. 0.07/KLOC (54 hits) over 784 KLOC; the bare word `raw` is 0.52/KLOC and
    # `.html_safe` 0.28.
    #
    # `raw\s*\(` — the CALL form — and not `\braw\b`, because an earlier draft matched the identifier
    # PREFIX in `raw_connection` (193 hits), `raw_value` (42) and `raw_post` (31) and measured 1.25/KLOC.
    # That was a bug in the pattern, not a fact about Ruby.
    #
    # `<%==` is deliberately NOT included even though it is a real ERB sink: `_EXT_LANG` has no `.erb`,
    # so the survey never opens those files and half the pattern could never fire. Adding `.erb` is a
    # coverage decision with its own measurement, not a free rider on this row.
    ("xss", frozenset({"ruby"}), re.compile(r"\braw\s*\(")),

    # SQL injection for JavaScript/TypeScript — CWE-89, rank 2, and the two most-used languages were the
    # only ones without it. A template literal carrying `${` straight into `.query`/`.raw`: 0.03/KLOC
    # (26 hits) over 985 KLOC of express, nest, strapi, vue and a real repository, where any `.query(` is
    # 0.83/KLOC (820 hits) of ordinary parametrised calls.
    #
    # It passes the rule above because the danger is IN THE SAME EXPRESSION as the sink: `.query(sql)`
    # says nothing, but `` .raw(`SELECT * FROM ${t}`) `` carries the interpolation with it. Measured
    # matches are exactly that shape — `.raw(`SELECT * FROM ${`, `.raw(`ALTER TABLE ?? ... ${`.
    ("sql_injection", frozenset({"javascript", "typescript"}),
     re.compile(r"\.(?:query|raw|unprepared)\s*\(\s*`[^`]*\$\{")),
)

#: LANGUAGES THE MARKER TABLE NAMES, derived from the table rather than written out beside it — a second
#: list drifts the first time a row moves, which is precisely the defect the two extension tables were.
#:
#: Deliberately NOT the same set as `EXT_LANGUAGE`'s values. Two rows above are language-AGNOSTIC, one of
#: them `parser`, which produced 353 of 413 candidates on a real repository's survey — so a language absent from
#: this set is still scanned and still yields candidates. What it does not get is a single rule written
#: with it in mind, and `_blind_spots` states that rather than leaving a customer to infer it from a
#: small number.
_MARKER_LANGUAGES = frozenset(lang for _kind, langs, _pattern in _MARKERS if langs for lang in langs)

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


#: Directories holding GENERATED output, pruned from the walk. the design notes's tail: one of
#: libexpat's 70 candidates was `expat/build/CMakeFiles/3.28.1/CompilerIdC/CMakeCCompilerId.c`, a CMake
#:
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
            surfaces.extend(_scan_file(here / name, root, language))
        if truncated:
            break

    return Survey(surfaces=tuple(surfaces), files_read=files_read, truncated=truncated,
                  pruned_dirs=pruned, ignored_dirs=ignored,
                  # WHAT THE IGNORE DECISIONS RESTED ON, and how many the index overruled. Reported
                  # rather than assumed: with no readable index the walk answers a weaker question, and
                  # `_blind_spots` has to be able to say which one it answered.
                  ignore_basis=index.tracked_basis, ignore_refusal=index.tracked_refusal,
                  ignored_but_tracked=index.rescued,
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


def _scan_file(path: pathlib.Path, root: pathlib.Path, language: str) -> list[Surface]:
    """Match the marker table against one file. Capped per file so one generated blob cannot dominate."""
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
        return []
    try:
        with open(path, "rb") as fh:
            text = fh.read(MAX_FILE_BYTES).decode("utf-8", errors="replace")
    except OSError:
        return []

    rel = str(path.relative_to(root))
    lines = text.splitlines()
    # Free: this file is already read and already being walked line by line.
    provenance = _provenance(rel, max((len(ln) for ln in lines), default=0))
    found: list[Surface] = []
    for number, line in enumerate(lines, start=1):
        if len(found) >= MAX_HITS_PER_FILE:
            break
        stripped = line.strip()
        if not stripped or _is_comment(stripped, language):
            # A marker inside a comment is not code. Crude and deliberately so — a real parse would be
            # a per-language commitment this table has not earned.
            continue
        for kind, langs, pattern in _MARKERS:
            if langs is not None and language not in langs:
                continue
            if pattern.search(line):
                found.append(Surface(path=rel, line=number, kind=kind, language=language,
                                     evidence=stripped[:160], provenance=provenance))
                break                                  # one surface per line, first kind wins
    return found


def _is_comment(stripped: str, language: str) -> bool:
    if language == "python" or language == "ruby":
        return stripped.startswith("#")
    if language == "asm":
        # `;` is assembly's comment and nothing else here uses it. Added when `.s`/`.asm` reached this
        # function at all — before 2026-08-17 the survey's table had no assembly extension, so the
        # fallback below was never asked about one, and a commented `; parse_header(` would have raised
        # a candidate against a comment.
        return stripped.startswith((";", "#", "//", "/*", "*"))
    return stripped.startswith(("//", "/*", "*", "#"))


def assess(survey: Survey, *, harness_kinds=(), witness_entry: str | None = None,
           deep_available: bool = True, languages=None) -> Assessment:
    """Rank each surface by whether Shard could attach proof there, and name what it cannot check.

    Capability facts arrive as ARGUMENTS. That is what keeps this module simple-safe: the harness
    dictionary lives behind the separate package and the free image does not contain it, so the caller resolves
    what it can and passes the answer in.
    """
    deep_reachable = bool(deep_available and harness_kinds)
    witness_reachable = witness_entry is not None

    ranked = tuple(sorted(
        (_rank_one(s, deep_reachable, witness_reachable, witness_entry) for s in survey.surfaces),
        key=lambda r: (_RANK_ORDER[r.rank],
                       # `.get(..., 1)` rather than `[...]`: a future provenance value must not raise
                       # here, and the middle of the order is the honest place for an unknown one —
                       # ahead of what is known to be unusable, behind what is known to be the
                       # customer's own code.
                       _PROVENANCE_ORDER.get(r.surface.provenance, 1),
                       r.surface.path, r.surface.line)))

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

    if not deep_available:
        out.append("deep capability is not present in this build, so nothing here can carry a "
                   "reproducing input")
    elif not deep_reachable:
        out.append("no harness kind applies, so no candidate can be raised to a reproducing input. "
                   "Declare a harness at .shard/test_poc.sh")

    if not witness_reachable:
        out.append("no runnable entry point is declared, so simple mode cannot demonstrate anything "
                   "and every candidate below stays a hypothesis")

    hypotheses = sum(1 for r in ranked if r.rank == RANK_HYPOTHESIS)
    if hypotheses:
        out.append(f"{hypotheses} candidate(s) can be reasoned about but not proven in this "
                   f"configuration")

    # A LANGUAGE WITH NO CANDIDATES: two facts wearing one sentence until 2026-08-17.
    #
    # This used to answer every such language with *"this may mean there is none, or that the marker
    # table does not cover it"* — a hedge over something the walk MEASURED. The two halves call for
    # opposite actions: files read and nothing matched is a limit of the marker table, and no file read
    # at all is a limit of the walk, which the customer can often fix (the cap, an ignore rule, a
    # directory on `GENERATED_DIRS`). Splitting them cost nothing but the count.
    seen = {s.language for s in survey.surfaces}
    read = dict(survey.languages_read)
    unseen = sorted(set(languages or ()) - seen)
    scanned = [lang for lang in unseen if read.get(lang)]
    unread = [lang for lang in unseen if not read.get(lang)]
    if scanned:
        out.append("no candidate surface was detected in: "
                   + ", ".join(f"{lang} ({read[lang]} file(s) read)" for lang in scanned)
                   + " — those files WERE read and nothing in the marker table matched, so this is that "
                     "table's limit rather than a clean bill of health")
    if unread:
        out.append("NOT ONE FILE was read in: " + ", ".join(unread)
                   + " — preflight found that language in this repository and the survey opened none of "
                     "it, so nothing here is a statement about that code. Every such file sat behind the "
                     "file cap, an ignore rule or a generated directory named above")

    # WHICH LANGUAGES THE TABLE ACTUALLY KNOWS SOMETHING ABOUT. Two of its rows are language-agnostic —
    # `parser` is one, and it is the highest-volume kind measured — so a language with no row of its own
    # still produces candidates, and its coverage is thinner in a way no count reveals. A Kotlin project
    # getting `parser` hits and nothing else should be told that is all there was to get.
    thin = sorted(lang for lang, count in survey.languages_read
                  if count and lang not in _MARKER_LANGUAGES)
    if thin:
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
        out.append("no candidate surface was detected anywhere; treat this as the marker table's "
                   "limit rather than as a clean bill of health")
    return tuple(out)


def _rank_spread(assessment: Assessment) -> str | None:
    """Say so when the rank did not discriminate. Returns None when it did, or when there is nothing.

    the design notes calls a rank that never discriminates *"a wish list with a rank column"* —
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
    top = max(assessment.counts().values())
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
                f"reason, because nothing here could carry proof — that is a fact about this "
                f"configuration, not about the code. The list is still ORDERED: the target's own "
                f"source first, then test paths, then generated files")
    return (f"this rank did not discriminate: {top} of {total} candidates share one label and one "
            f"reason, so read the list as a map of where to look, not as an ordering")


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
        # NOT "provable". the design notes: the rank is computed from two REPOSITORY-level facts
        # — a harness kind applies, the language is memory-unsafe — so on any C repository carrying a
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
        "omitted": max(0, len(assessment.ranked) - len(kept)),
        "blind_spots": list(assessment.blind_spots),
        # THE VERSION OF THE MARKER TABLES THIS IMAGE WAS BUILT FROM. `"0"` means the tables come
        # straight from source (no published pack yet); any other value names a versioned pack that
        # can be pinned and compared across runs. Written into the emitted tree by `build_free_tree.py
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
