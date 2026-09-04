"""One line of source in; the candidate-surface kind it names, or nothing.

`shard/survey.py` walks a checkout, ranks what it found and narrates it. This is the table it asks
about each line — plus the comment rule that decides which lines it may ask about at all, which is
part of the same question and measured in the same units.

## Why this is not in `survey.py`

The size ratchet refused it there: `survey.py` stood at 411 code lines against a 400 ceiling and the
gate's own instruction is *"put the new code in a new module"*. `shard/spread.py` left the same file
the same day for the same reason.

The seam is not merely where the line count fell, and the history says so. Of the 24 commits that
have changed `shard/survey.py` against a predecessor, **8 moved this table's code lines, 15 moved
the rest's, and 2 moved both.** The table grows when a row is measured against a new corpus: 23 code
lines on 2026-08-07 to 70 today, and every one of those 47 arrived on one of three days —
2026-08-11 and 2026-08-12 (the W9 language rows) and 2026-09-02 (ruby `unsafe_load`, php's
concatenation chain). The rest went 179 to 341 across the 13 commits that left this table untouched
— ignore-file semantics, provenance, the per-file caps, the blind spots. Two jobs with two change
histories, sharing a filename.

The dependency points one way, as `spread`'s does: this module imports nothing from `shard`, and
`survey` imports `kind_of` and `MARKER_LANGUAGES` from it. `kind_of` rather than `MARKERS` at the
call site is the load-bearing half — the scan then knows nothing about a row's SHAPE, so a fourth
field on a row is an edit here and nowhere else. `survey._scan_file` used to iterate the tuple
layout itself.

## The name says WHOSE markers, and that is not decoration

`markers` was already taken, one import away. A maintenance script::build_markers_pack` publishes
an library pack of that name built out of `shard/target.py`'s `EXT_LANGUAGE`, `LANGUAGE_RUNTIME`
and `_BUILD_MARKERS`, and `survey.to_payload` stamps every artefact with its `markers_pack_version`.
Those are recognition tables of a different kind — extension to language — and **nothing in this
file is in that pack.** Two tables called "markers" one import apart is the exact defect this
project has already paid for: `survey.py` and `target.py` each kept an extension table, neither
could see what the other saw, and a Kotlin or Swift repository had every source file skipped.

## No precision claim is made, and this is the important paragraph

The rows below are **candidate surfaces, not findings.** Nothing here may be reported as a defect.
The maintainers' notes is explicit that a heuristic from outside the project must be validated against real
project data before anything is built on it — *"research is useful for generating hypotheses, not
for shipping features"* — and the accuracy of this table is **unmeasured**. It is a map of where to
look, produced cheaply, and it is wrong in both directions: `memcpy` appears in safe code
constantly, and a defect can sit somewhere no marker fires.

Every rate below is a NOISE measurement — how often a pattern fires per thousand raw lines of
ordinary code — and never precision against ground truth. It is stated on `#` comment lines and
nowhere else, which is not a formatting habit:
the maintainers' suite::test_every_NOISE_RATE_that_states_its_HITS_divides_by_a_TOTAL_in_the_SAME_ROW`
reconciles each rate against a corpus total in its own comment block, and reads comment blocks
only. A rate in a docstring is a rate that has stopped being checked, and this paragraph was
refused by that guard on its first run for saying so with the unit in it.

The consequences are held in `shard/survey.py`: surfaces never become `report.Finding`s, `assess`
never emits a severity, and `summarise` says "candidate" everywhere it says anything.
"""

from __future__ import annotations

import re

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
#
# ── THE DENOMINATOR EVERY RATE BELOW IS ON, and it is one denominator ────────────────────────────────
#
# Hits per 1,000 **raw** lines of the files the survey itself reads for that language — `survey._EXT_LANG`
# match, VCS directories pruned, blank and comment lines INSIDE the count, matches inside comments
# outside the numerator. Every corpus header below states its size that way; the totals there are
# rounded and come from the checkout each row was first measured on, so they drift by a fraction of a
# percent, which is drift on ONE basis rather than a second one.
#
# Written down on 2026-09-02 because it had been implicit and two rows had just landed without it. The
# non-blank-line denominator they used is 16% smaller here and inflates every rate by 19%: ruby's four
# corpora are 777.0k raw against 649.7k non-blank, php's three are 626.1k against 526.9k. A rate on
# that basis cannot be compared with the row above it, which is the only thing recording a rate is for.
# Both rows are restated below, re-measured rather than converted.
_C_LIKE = frozenset({"c", "c++", "zig"})

MARKERS: tuple[tuple[str, frozenset[str] | None, re.Pattern[str]], ...] = (
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
    # and 25.5s at n=64,000 — and one 160 KB source file took `survey.survey_repo` 43.9s while finding nothing.
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
    # `unsafe_load` was ADDED 2026-09-02 and the row was blind to it before: `YAML\.load\s*\(` needs
    # `(` straight after `load`, so `YAML.unsafe_load(text)` — Psych's opt-in to object construction,
    # and the exact defect `examples/ruby-yaml-deserialise` ships to demonstrate — matched nothing. The
    # shipped example reported `candidates 0`.
    #
    # Measured the same way every row here was: NOISE over the 777.0 raw KLOC of sinatra, jekyll,
    # fastlane and rails that the Ruby block below is measured on. **0.05/KLOC (37 hits), and all 37
    # read as genuine `YAML.unsafe_load` calls** — 36 in rails (its own YAML column coder, schema cache
    # and serialisation tests) and 1 in sinatra. Precision against ground truth is UNMEASURED, as it is
    # for every row above. (This read 0.06 for one day: the same 37 hits over 649.7k NON-BLANK lines,
    # a denominator no other row in this table uses. Re-measured on the raw basis, not converted.)
    #
    # Keyed on the bare method name rather than on a receiver: `\bunsafe_load` and
    # `(?:YAML|Psych)\.unsafe_load` scored IDENTICALLY on that corpus (37 hits each), so the receiver
    # qualifier bought nothing and would miss `Psych` under an alias. This is not the `regex.exec(`
    # trap that made PHP's and JavaScript's rows need a qualifier — `unsafe_load` has no safe meaning.
    ("deserialiser", frozenset({"ruby"}),
     re.compile(r"\b(?:Marshal\.load|YAML\.load)\s*\(|\bunsafe_load(?:_file)?\s*\(")),
    ("deserialiser", frozenset({"php"}), re.compile(r"\bunserialize\s*\(")),

    # Python's real bug classes, added in W9 P1.2. The per-KLOC figures below are NOISE measurements
    # over 1,235.9 KLOC of real Python (A=the development tree 40.3 KLOC, B=the benchmark+attacks 153.3 KLOC, C=Hermes
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
    # 0.00/KLOC (1 hit) in 267.8 KLOC — at or below the 0.00-0.20 the kept Python row scored.
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
    # The managed/native boundary. 0.10/KLOC (221 hits) over 2,305 KLOC — the busiest row here and
    # still inside the band, because `[DllImport` means exactly one thing.
    ("ffi", frozenset({"c#"}), re.compile(r"\[\s*DllImport")),
    # Shelling out. 0.00/KLOC (10 hits) over 2,305 KLOC. Naive `Process.Start(` is 0.01/KLOC and mostly
    # opens a URL or a document with no shell involved, so the flag rather than the call is matched.
    ("command_exec", frozenset({"c#"}), re.compile(r"\bUseShellExecute\s*=\s*true\b")),
    # A query built by interpolation or concatenation. 0.00/KLOC (5 hits) over 2,305 KLOC.
    ("sql_injection", frozenset({"c#"}),
     re.compile(r"new\s+SqlCommand\s*\(\s*[$\"].*[+{]|\.CommandText\s*=\s*[$\"].*[+{]")),

    # PHP. Corpora: guzzle 59k, PHPMailer 20k, laravel 551k.
    #
    # The shell sinks, and the qualifier is the measurement. `(?<![>:$\w])` drops `$pdo->exec(` and
    # `::exec(`: measured, PHP's bare `exec(` is 44 hits of which almost all are METHOD calls —
    # overwhelmingly PDO's `->exec()`, which is SQL and not a shell. Unqualified scores 0.07/KLOC of
    # mostly-wrong hits; qualified scores 0.03/KLOC (16 hits). This is JavaScript's `regex.exec(` trap
    # in a second language, which is why the qualifier is not optional.
    #
    # THE QUALIFIED RATE READ 0.05 UNTIL 2026-09-02, and 16 hits over this corpus is not 0.05 on any
    # denominator — 0.03 raw, 0.03 non-blank — so that one was arithmetic rather than a second basis.
    # Re-measured 2026-09-02: still 0.03/KLOC (17 hits) over 626.1 raw KLOC. The row also claimed
    # every hit is a real builtin and that does not survive the re-read — 5 of the 17 are not a live
    # call. Two are DECLARATIONS (`public function exec($command, ...)` in laravel's Schedule,
    # `protected function passthru(...)` in LazyCollection), which the lookbehind cannot see because a
    # space precedes the name; three are the name inside a STRING (a `markTestSkipped` message,
    # `exec(...)` inside a SQL statement, and a fixture payload
    # `'<?php var_dump(system($_GET["cmd"])); ?>'`).
    # Both classes are the marker table's declared crudeness rather than this qualifier's, and 12 of
    # 17 remain what the row says they are.
    ("command_exec", frozenset({"php"}),
     re.compile(r"(?<![>:$\w])\b(?:exec|system|shell_exec|passthru|popen|proc_open)\s*\(")),
    # LFI/RFI — PHP's signature class and a KIND no other language here needs, which is exactly the
    # "new kinds, not more regexes of the old kinds" that P1.2 asks for. Including a VARIABLE path is
    # the whole signal: 0.04/KLOC (28 hits) over 630 KLOC, where any `include`/`require` is
    # 0.37/KLOC (235 hits) over the same 630 and is almost entirely static requires of a literal file.
    # Those two are on the 630 corpus HEADER total, not on the 626.1 re-measure below, and the division
    # is how that is known rather than remembered: 235/630 rounds to 0.37 while 235/626.1 rounds to
    # 0.38. Naming the denominator on the row is what makes a stated rate checkable at all.
    #
    # THE CONCATENATION CHAIN WAS ADDED 2026-09-02, because `\s*\(?\s*\$` required the variable to be
    # the FIRST term. Almost nobody writes `include $page;` — they write `include TEMPLATE_ROOT . '/' .
    # $name . '.php';`, which is what `examples/php-template-include` ships as its defect and what the
    # row scored `candidates 0` on. The chain is literal terms (identifier, single- or double-quoted
    # string) joined by `.`, and the double-quoted arm catches interpolation inside the string itself.
    #
    # Re-measured over 626.1 raw KLOC of guzzle, PHPMailer and laravel: **28 -> 29 hits, ONE added,
    # 0.045 -> 0.046/KLOC** — laravel's `include __DIR__."/../../resources/views/components/$view.php";`,
    # a genuine variable-path include. Three decimals here and two everywhere else because the widening
    # is one hit and 0.04 -> 0.05 would read as a change the corpus does not contain. Any
    # `include`/`require` is 0.21-0.62/KLOC per corpus and 0.29/KLOC (179 hits) across the three.
    # (This read `0.05 -> 0.06/KLOC over 526.9 KLOC` for one day, on the NON-BLANK denominator; the
    # row four lines above still said the same 28 hits were 0.04, so one comment block held both bases
    # at once.)
    #
    # THE BASELINE DISAGREES WITH ITSELF AND THAT IS RECORDED RATHER THAN RESOLVED. The same loose
    # `include`/`require` pattern over the same three repositories is 235 hits above and 179 here — a
    # 24% drop, against a 0.6% difference in corpus size (630 -> 626.1), so it is a different checkout
    # and not a rounding artefact. Neither figure has been re-measured since and neither is a row this
    # table keeps: both exist only as the loose form the kept pattern is contrasted with. Left as two
    # dated numbers because replacing one with the other would assert a re-measurement nobody ran.
    #
    # THE LOOSE FORM WAS MEASURED AND REJECTED. `\b(?:include|…)\b[^;]*\$` — "a `$` anywhere in the
    # statement" — adds 16 instead of 1, and they are prose: `'URI must include a scheme and host…',
    # $request`, `'require it please!'`, `$included = $this->input('include')`, `'require' =>` array
    # keys. `[^;]*` runs past the include's own expression and the keyword matches inside string
    # literals. Bounding the tail to concatenation terms is what separates the two.
    ("file_inclusion", frozenset({"php"}),
     re.compile(r"\b(?:include|include_once|require|require_once)\s*\(?\s*"
                r"(?:(?:[A-Za-z_\\][A-Za-z0-9_\\]*|'[^'\n]*')\s*\.\s*)*"
                r"(?:\$|\"[^\"\n]*\$)")),

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
    # unsafe default is the whole bug. 0.02/KLOC (51 hits) over 2,597 KLOC. It fires on the SAFE
    # configuration too, which is the honest limit of a marker: it says "an XML parser is constructed
    # here", not "this one is vulnerable". That is what a candidate surface IS, and the docstring above
    # says so for all of them.
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

    # PHP. A variable interpolated straight into a query string. 0.00/KLOC (2 hits) over 630 KLOC,
    # against 66 for any `->query(`. THE THINNEST ROW HERE — two hits is barely a measurement, and it
    # is kept because the shape is unambiguous rather than because the number is strong. First
    # candidate to cut if the table must shrink.
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
    # Reachable because `x.blade.php` has suffix `.php`, which `survey._EXT_LANG` maps — checked, not assumed.
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
    # `<%==` is deliberately NOT included even though it is a real ERB sink: `survey._EXT_LANG` has no `.erb`,
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
#: with it in mind, and `survey._blind_spots` states that rather than leaving a customer to infer it from a
#: small number.
MARKER_LANGUAGES = frozenset(lang for _kind, langs, _pattern in MARKERS if langs for lang in langs)


def _is_comment(stripped: str, language: str) -> bool:
    if language == "python" or language == "ruby":
        return stripped.startswith("#")
    if language == "asm":
        # `;` is assembly's comment and nothing else here uses it. Added when `.s`/`.asm` reached this
        # function at all — before 2026-08-17 the survey's table had no assembly extension, so the
        # fallback below was never asked about one, and a commented `; parse_header(` would have raised
        # a candidate against a comment.
        return stripped.startswith((";", "#", "//", "/*", "*"))
    if stripped.startswith("*"):
        # A LEADING `*` IS A DEREFERENCE AS OFTEN AS IT IS A BLOCK-COMMENT CONTINUATION, and
        # `*out = read_something(...)` is C's out-parameter idiom — the line untrusted bytes actually
        # land on. Unqualified, this arm skipped libyaml's `*size_read = fread(buffer, 1, size,
        # parser->input.file);` (src/api.c:280, the body of `yaml_file_read_handler`), so the survey
        # reported `input_boundary=14` with all fourteen in `tests/` and none in the library that
        # ships. That is valid code discarded, not the marker-inside-a-comment crudeness `survey._scan_file`
        # admits to.
        #
        # After the `*` run, comment prose is empty, whitespace, or the `/` of `*/`; a statement's next
        # character is the identifier being written, which is why `**pp = x;` survives too. Measured
        # across libyaml, libgit2, curl, openssl, nlohmann/json, docker/cli, lodash, guzzle, PHPMailer
        # and laravel: 4 surfaces RECOVERED, all genuine out-parameter writes, and 0 comment lines
        # newly admitted — libgit2's 5 leading-`*` marker matches are prose and are still suppressed.
        return stripped.lstrip("*")[:1].strip() in ("", "/")
    # `#` IS WRONG FOR C AND IT STAYS WRONG, and 2026-09-02 is when the figure that keeps it wrong got
    # measured instead of owed. The arm mis-classifies code by construction: `#` is the preprocessor in
    # C, C++ and C#, an attribute in Rust, a compile-time directive in Swift and a private field in
    # JavaScript. It is a comment only in Python, Ruby, PHP and assembly, and three of those return
    # above. That is the same defect as the `*` arm; the reason it is refused rather than fixed the
    # same way is the matches, not the rate.
    #
    # Dropping it for the languages where `#` is not a comment, over the same ten trees (3,233.4 raw
    # KLOC, 2,606.7 of it not PHP): **0.0065/KLOC (21 hits)** — thirty times inside the
    # <=0.20 band every kept row sits in, so the rate test passes and decides nothing. Reading all 21
    # is what refuses it. 14 are C preprocessor bodies and 12 of those are portability aliases
    # (`#define readsocket(s,b,n) recv(...)` five times in one openssl header, `#define sread(x,y,z)
    # read(...)`, `#define p_recv(...) recv(...)`) — the definition of a macro, not a line bytes land
    # on. 6 are the marker firing inside a TRAILING `/* ... */` on the directive (`#include <string.h>
    # /* for memcpy() */`, `#define _CRT_SECURE_NO_WARNINGS /* for getenv(), sscanf() */`) and are
    # simply wrong. 1 is a Markdown heading in a Blade template.
    #
    # And no repository's conclusion moves: per tree the admissions are libyaml 0, nlohmann/json 0,
    # docker/cli 0, lodash 0, guzzle 0, PHPMailer 0, libgit2 1, laravel 1, curl 5, openssl 13, against
    # candidate counts in the hundreds. The `*` arm was taken because it flipped libyaml's headline
    # from "14 input_boundary, all in tests/" to naming the shipping library. This one changes no
    # headline and puts six visibly wrong candidates in a customer's artefact, so it is refused with
    # the number rather than left unmeasured. `_is_comment` therefore reports two different things by
    # language, and the C answer is knowingly the wrong one.
    return stripped.startswith(("//", "/*", "#"))


def kind_of(line: str, stripped: str, language: str) -> str | None:
    """The marker kind this line names, or None for a blank line, a comment, or no match.

    BOTH FORMS OF THE LINE, because the two halves have always read different ones and the caller
    holds both anyway. The comment test reads the STRIPPED line — every prefix it knows is a leading
    one, so indentation defeats it, and that half is load-bearing: handed the raw line instead, an
    indented `// parse(x)` becomes a `parser` candidate.

    THE PATTERN HALF IS NOT, AND THAT IS MEASURED RATHER THAN ASSUMED. It reads the RAW line because
    that is what `survey._scan_file` matched against before this function existed. Mutated
    2026-09-03 to pass the stripped line to the patterns as well: the whole suite stayed green, so
    no row in the table today distinguishes the two — the one anchored row, `ffi`/go's
    `^\\s*import "C"`, matches either. Kept as the raw line because a move should not quietly change
    what a table is matched against, not because a defect was found on the other side of it.

    ONE SURFACE PER LINE, FIRST KIND WINS. A line matching two rows is one place to look, not two, so
    the table's ORDER decides which kind is reported — a property of the table, not a claim about the
    line. `memcpy(dst, parse(src), n)` in C comes out `unsafe_op` and not `parser` because the C-like
    row sits above the language-agnostic one; nothing has measured which of the two a reader would
    rather have been told.
    """
    if not stripped or _is_comment(stripped, language):
        # A marker inside a comment is not code. Crude and deliberately so — a real parse would be a
        # per-language commitment this table has not earned.
        return None
    for kind, langs, pattern in MARKERS:
        if langs is not None and language not in langs:
            continue
        if pattern.search(line):
            return kind
    return None


__all__ = ["MARKERS", "MARKER_LANGUAGES", "kind_of"]
