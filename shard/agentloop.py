"""Native tool-calling agent loop — the SOTA reasoner path, replacing the single-JSON-action
ReAct loop that is retired and ships in no tree.

Why this exists: the JSON-action loop serializes ONE action as text per turn and parses it back, which
is exactly where weaker/reasoning models drift into prose and stall (sonnet bailed on prose, GLM
procrastinated). A frontier coding agent — Claude Code itself, OpenHands, the SOTA benchmark agents —
does not work that way. It uses the provider's **native function-calling**: the model emits
``tool_calls``, the harness executes each and returns a ``role:"tool"`` result, and the model continues
fluidly across many tools per turn until it stops calling them. This module is that loop, kept
model-agnostic (any OpenRouter model exposes OpenAI-style tool-calling).

It is deliberately separate from ``ShardLoop``: the self-improve flow keeps the JSON-action loop
precisely so the human-gate sees each individual action (see the maintainers' notes). The benchmark solver is fully
autonomous (no gate), so it gets the stronger native loop with no downside.

Deterministic to test via ``ScriptedChatBackend`` — no network, no LLM.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field

from shard.budget import BudgetExceeded, BudgetGovernor
from shard.diag import get_logger
from shard.journal import Journal
from shard.memory import fence
from shard.reasoning import ensure_compute_runway, render_self_review
from shard.tools import OBS_WINDOW_CHARS, READ_MAX_FILE_BYTES, ToolRegistry, ToolResult
from shard.toolvalidate import suggest_tool, validate_call_args

# --- Loop hygiene: repeat-call circuit-breaker (LEVER 2) -------------------------------------------
# The loop already bounds empty (``max_empty``) and truncated (``max_truncated``) turns, but NOTHING
# catches a model that calls the SAME tool with byte-identical arguments turn after turn. The canonical
# trap is a bare ``read_file`` re-read: the paging tool returns the identical head, the model reads it
# again, forever — and every repeat re-bills the whole (growing) context. The campaign stall-detector
# can't see this: it keys only on ``test_poc`` outcomes, so a NON-test loop (read/grep/list) is invisible
# to it. We track the last executed call SIGNATURE and count byte-identical consecutive repeats: at
# ``REPEAT_ADVISORY_AT`` we inject a one-time in-observation warning (cheap recovery — a model usually
# breaks its own loop once told), and only if it *keeps* going to ``REPEAT_BREAK_AT`` do we hard-stop the
# run (like a ``max_empty`` streak). Byte-identical ONLY (never near-matches) so a legitimately-iterating
# agent — e.g. one re-reading the same file at DIFFERENT offsets — is never tripped.
REPEAT_ADVISORY_AT = 4      # consecutive byte-identical (name,args) calls → inject a one-time advisory
REPEAT_BREAK_AT = 6         # …still identical this many in a row → hard-stop the run (status="repeat")

# --- Loop hygiene: per-turn tool_call CAP (in-turn degeneration guard) ------------------------------
# The repeat-breaker above catches identical calls ACROSS turns, but NOTHING bounds a SINGLE turn that
# degenerates into a massive batch of near-identical tool_calls. Observed live on GLM-5.2: ONE assistant
# turn emitting 1788 ``read_file`` calls (empty/degenerate args), which then executes hundreds of phantom
# reads and burns ~18-40k tokens before the cross-turn breaker can even see a SECOND turn. This is NOT a
# streaming/assembly bug — the SSE assembly correctly keyed 1788 distinct-index calls; the model genuinely
# emitted them, a model repetition failure the harness must survive for ANY model (LLM-agnostic). A
# LEGITIMATE parallel batch is small (≤ ~8-16); far above that is degeneration. When a turn EXCEEDS the
# cap we DEDUPE byte-identical (name,args) repeats — the degeneration signature — then CAP the remainder,
# execute ONLY that subset, truncate the assistant message's tool_calls to match (OpenAI protocol: every
# remaining tool_call must be answered, and every answer must map to a tool_call — so the dropped calls
# and their answer-obligations are removed together), and inject a nudge steering the model OUT of the
# loop. Composes with the repeat-breaker: the cap fires WITHIN a turn, the breaker ACROSS turns; deduping
# leaves the executed subset with no in-turn repeat, so the breaker still trips only on a genuine
# cross-turn identical-call streak. Pure guard on the tool_calls list — no LLM call, cheap, model-agnostic.
MAX_TOOLCALLS_PER_TURN = 16     # execute at most this many (deduped) tool calls from a single turn

# --- Loop hygiene: stale-observation context compaction (LEVER 3) ---------------------------------
# ``run()`` re-sends the ENTIRE messages array to ``backend.chat`` every step with NO eviction, so a
# 12 KB read taken at step 30 of a 300-step run is re-billed on every later step (~270×); the token cost
# of a run grows ~O(steps^1.9). We keep the last ``COMPACT_KEEP_RECENT`` tool observations verbatim (the
# live working set the model is actively reasoning over) and, for OLDER observations that are both large
# (> ``COMPACT_MIN_CHARS``) and produced by a READ-type tool whose output re-derives byte-for-byte on a
# re-run, we replace the body with a one-line stub (tool + args + first line + original size + how to get
# it back). This is pure TOKEN hygiene: no crash signal is ever lost, because a tool NOT in
# ``COMPACT_READ_TOOLS`` — every ``test_poc`` / ``fuzz`` / ``auto_fuzz`` / ``write_poc`` / sanitizer
# verdict — is kept verbatim regardless of age or size. ``COMPACT_NEVER_TOOLS`` names that crash-signal
# set explicitly: it is redundant with "not in COMPACT_READ_TOOLS" today, but it HARD-GUARDS the
# invariant against a future edit that widens the read set (e.g. adds run_bash-derived crash repro).
# NOTE: ``run_bash`` IS a read-type here (per the audit: the agent uses it for cat/sed code reads); a
# crash reproduced via run_bash can be elided, but its scoring-relevant signal is re-captured by the
# ``test_poc`` verdict (never stubbed) and the stub tells the agent exactly how to re-run it.
COMPACT_KEEP_RECENT = 8     # most-recent tool observations always kept verbatim (the live window)
COMPACT_MIN_CHARS = 1500    # only observations larger than this are worth stubbing
# Read-type tools whose observation is a re-derivable code/text dump — safe to elide (re-running the
# exact call reproduces it). Keyed on the tool NAME, not its registry ``kind``: write_poc / apply_patch /
# gdb_run all share kind="run_bash" but must NOT be treated as reads — matching on NAME excludes them.
# ``code_query`` (weggli AST search, LEVER 1) is a read: its observation is a re-derivable code dump,
# and eliding a STALE one is the whole point — the tool exists to CUT context mass, so a >1500-char
# result kept verbatim every turn would re-inflate exactly the bloat it was added to remove.
COMPACT_READ_TOOLS = frozenset({"read_file", "grep", "list_dir", "run_bash", "code_query"})
# Crash/verification-signal tools whose observation MUST survive verbatim forever (belt-and-suspenders).
COMPACT_NEVER_TOOLS = frozenset({"test_poc", "write_poc", "auto_fuzz", "fuzz", "sanitizer", "run_sanitizer"})
COMPACT_STUB_PREFIX = "[stale-read elided]"   # marks an already-compacted body (idempotent re-compaction)

# --- Loop cadence: bounded-repeatable measure nudge (P0c) -----------------------------------------
# The diagnosed "never-measure" failure: across the IC journals the median run made only ~4.5 test_poc
# calls and burned its budget reading source. ``step_nudge`` fixes the FIRST write but fires ONCE —
# nothing SUSTAINS the write→test→refine cadence afterward. This nudge is the sustaining half: every
# ``MEASURE_INTERVAL`` analysis steps WITHOUT a fresh test_poc, inject a "refresh ./poc and measure now,
# THEN keep analyzing" directive, BOUNDED to ``MEASURE_MAX`` per run so a genuinely deep-reachability
# task that needs long uninterrupted analysis is never starved (the phrasing is "commit AND keep
# analyzing", never "stop analyzing"). The counter RESETS whenever a test_poc result is observed, so an
# agent that already measures on its own never sees it. Mirrors the once-only ``step_nudge`` + the
# ``REPEAT_ADVISORY`` dedup discipline, but this REPEATS — that repetition is exactly what lifts the
# test_poc cadence. Firing resets the counter, guaranteeing ≥ MEASURE_INTERVAL steps between nudges
# (min-interval dedup).
MEASURE_INTERVAL = 6     # analysis steps since the last test_poc before a measurement is nudged
MEASURE_MAX = 4          # total measure nudges per run (a cap so deep analysis is never starved)

# --- Loop cadence: bounded-repeatable CONSTRUCT nudge (the "never-construct" fix) -----------------
# Diagnosed live: a GLM solver IGNORES the construction tools (use_corpus/build_emit/instrument/
# batch_test) and defaults to aimless read/grep/run_bash exploration (run_bash 239, read 119, grep 69 vs
# construction 0 across 7 tasks at 200+ steps). The measure nudge sustains the write→test cadence once a
# ./poc exists; this one fires EARLIER, on a pure INSPECTION streak with no candidate yet: every
# ``CONSTRUCT_INTERVAL`` steps of ONLY read/grep/run_bash (no fuzz/construction/test) it injects "stop
# exploring — CONSTRUCT now". The counter RESETS whenever a non-exploration tool executes (fuzz,
# use_corpus, build_emit, instrument, batch_test, write_poc, test_poc, …), so an agent that already
# constructs/measures never sees it; BOUNDED to ``CONSTRUCT_MAX`` per run and min-interval-deduped
# (firing resets the counter). Same discipline as the measure nudge; default None = disabled.
CONSTRUCT_INTERVAL = 8   # steps of non-construction work before a CONSTRUCT nudge
CONSTRUCT_MAX = 5        # total construct nudges per run (a cap so genuine inspection is never starved)
# Tools that count as EXPLORATION only — they do NOT reset the construct-cadence counter.
CONSTRUCT_EXPLORE_TOOLS = frozenset({"read_file", "list_dir", "grep", "run_bash"})
# ONLY a genuine CONSTRUCT-AS-CODE (or fuzz) tool counts as PROGRESS toward reaching the sink and resets
# the cadence. Critically, write_poc/apply_patch (hand-writing bytes) are DELIBERATELY EXCLUDED: hand-
# writing is the exact behavior the CONSTRUCT nudge exists to correct, so it must not silence the nudge —
# a hand-write→test grind that never reaches the sink keeps the counter climbing and keeps getting nudged.
CONSTRUCT_PROGRESS_TOOLS = frozenset({"fuzz", "use_corpus", "build_emit", "build_preset", "instrument", "batch_test"})

# --- Auto-push cadence for the CAMPAIGN-LESS escalations (the "shipped lever never fired" fix) -------
# ``--campaign``, ``--specialist`` and ``--strategy-file`` are THREE INDEPENDENT opt-in flags, but the
# curated-playbook push (``recall_hook``) and the instrumentation-specialist escalation (``specialist_hook``)
# were both nested inside ``if self.campaign is not None:`` — so a ``--specialist``-only run registered the
# tool and added its system-prompt note while the escalation the module notes call the lever fired ZERO
# times, and likewise for the playbook push (which exists precisely BECAUSE the model called
# ``recall_playbook`` itself in only 1 of 212 tasks). Both pushes now fire whenever their hook is wired.
# WITH a campaign the trigger and throttle are unchanged (campaign-derived stall/drift, gated on the
# summary having CHANGED). WITHOUT one there is no campaign summary to key on, so the trigger is the loop's
# OWN grind counters — the same "inspecting without constructing or measuring" condition the CONSTRUCT and
# MEASURE nudges already enforce — throttled to at most one push per ``AUTOPUSH_MIN_INTERVAL`` steps. The
# window is CONSUMED whether or not a hook yields text, so a wired-but-quiet hook is invoked at most once
# per interval (the specialist hook runs a sub-agent; it must never be re-entered every step).
AUTOPUSH_MIN_INTERVAL = CONSTRUCT_INTERVAL   # min steps between campaign-less auto-pushes; the match to
#                                              the CONSTRUCT cadence is now structural, not a paired literal

# --- Loop budget-hygiene: stall-triggered early-stop (opt-in, default OFF) --------------------------
# INC-0 (the fold-01 token decomposition, an internal audit) established that the 8M/task
# cap is exhausted almost entirely by 300-600-step DEEP-REACHABILITY GRINDS — runs that never land a crash
# and grind read/run_bash/test_poc without making progress toward the sink (100% of budget misses never
# crashed, both arms). The existing guards do NOT catch this: the repeat-breaker keys on BYTE-IDENTICAL
# consecutive calls (a varied-but-fruitless grind slips past it) and the campaign stall-detector needs a
# CampaignState and keys only on test_poc outcomes (a run_bash grind with no test_poc is invisible to it).
# This is the general, campaign-less guard: count SENDS-SINCE-PROGRESS (a send that produced no NEW signal
# toward a crash) and, once that streak crosses ``stall_stop_after`` AND enough of the token budget is
# already spent (``stall_stop_min_pressure`` — so a deliberate short task is never cut and only a genuine
# budget-burning grind trips it), stop the run with status="stall" instead of grinding to the hard cap.
# PROGRESS = an executed tool in ``STALL_PROGRESS_TOOLS`` whose OUTCOME CLASS differs from that tool's LAST
# outcome (a new crash/reachability signal), NOT a byte-difference in its result: keying on the whole result
# dict would fold in the volatile per-call ``output``/``probe_output`` window (``_test_poc`` returns a 12000-
# char error window that changes every call), so a fruitless write→test→never-crash grind would look like
# "progress" on every measurement and never stall — the exact population INC-0 targets (the review workflow Attack 3).
# So progress is keyed on ``_stall_outcome_sig`` (the stable outcome-class projection below). ``write_poc`` is
# DELIBERATELY EXCLUDED (mirroring CONSTRUCT_PROGRESS_TOOLS): hand-writing a candidate is churn, not progress
# toward a crash. A repeat of the same outcome, and any pure read/grep/list, is NOT progress. Default
# ``stall_stop_after=0`` = OFF → the loop is byte-identical to today (ships as A/B-able inert infra; the paid
# fold A/B decides the ON value — see the plan doc). It is a COST/THROUGHPUT lever, not a solve-rate lever: it
# only ends already-doomed grinds sooner (per-task budgets don't transfer) — it must NEVER cut a progressing task.
STALL_PROGRESS_TOOLS = CONSTRUCT_PROGRESS_TOOLS | frozenset({"test_poc", "auto_fuzz"})
# Stable outcome-class fields across the progress tools' real result dicts — test_poc (crashed/inner_exit/
# sanitizer, the predecessor project), fuzz (found/n_crashes), instrument (reached/probes_hit/inner_exit),
# batch_test (crashed/sanitizer/reached_sink). EXCLUDES the volatile content fields
# (``output``/``probe_output``/byte dumps).
# ``reached_sink`` was listed here against ``instrument``, which has never emitted it — the separate package
# emits ``reached``, a different question (did the AGENT'S anchor fire, not did the DESCRIBED sink run).
# The key was therefore projected out of no result dict at all until `batch_test` began emitting it on
# 2026-08-31 (the separate package). Attributed to its real producer here; the stall lever itself
# ships OFF, so the widened projection changes no shipped behaviour.
STALL_OUTCOME_KEYS = ("crashed", "inner_exit", "sanitizer", "found", "n_crashes", "reached",
                      "probes_hit", "reached_sink", "build_ok", "rebuilt", "exhausted")

# --- Enactment circuit-breaker WITH AUTHORITY (opt-in, default OFF) ----------------------------------
# The trace forensic found 4 misses (arvo:46653/63179, oss-fuzz:372547409/383170474) that READ FOREVER and
# constructed ~0 candidates (arvo:63179 = 105/112 calls were reads; 383170474 = 0 candidates in 87 turns).
# The self-review scaffold CORRECTLY told them "STOP reading, CONSTRUCT" 5-7× and was IGNORED every time —
# soft nudges have no teeth on GLM-5.2. This breaker has teeth: after ``enactment_break_after`` executed
# read-only calls with NO construct/test in between, the read tools are REMOVED from the advertised set AND
# rejected at execution, forcing a use_corpus/build_emit/emit_struct→test_poc cycle. ``run_bash`` is
# DELIBERATELY NOT denied — it is the struct.pack construction escape-hatch all 3 SOLVED tasks hand-rolled
# through (denying it would kill the positive template). ``instrument`` is NOT a re-arm tool (it is a
# perception tool, not a candidate — un-sticking the breaker must require actually building/testing an
# input). Default ``enactment_break_after=0`` = OFF → byte-identical to today (A/B-able inert infra, same
# discipline as ``stall_stop_after``; the paid held-out fold picks the ON value ~16-24).
ENACTMENT_DENY_TOOLS = frozenset({"read_file", "grep", "list_dir"})
# The read-loophole (lever-check 2026-07-23): a tripped GLM-5.2 evaded the breaker by routing reads through
# run_bash (`cat`/`grep`/`sed` — 40-99 calls/task, ~0 construction). run_bash is NOT denied wholesale (it is
# the struct.pack construction escape-hatch), so a run_bash whose command is a PURE READ is denied when
# tripped, while a construction run_bash (writes ./poc/seeds, compiles, runs a python generator) still runs.
_BASH_READ_CMDS = frozenset({"cat", "head", "tail", "sed", "grep", "egrep", "fgrep", "rg", "ag", "less",
                             "more", "find", "ls", "tree", "strings", "od", "xxd", "hexdump", "nl", "wc",
                             "awk", "readelf", "nm", "objdump", "file", "stat", "cut", "sort", "uniq"})


def _is_read_shaped_bash(arguments) -> bool:
    """True when a run_bash command is a PURE READ (cat/grep/sed/find/…) with no construction output — the
    loophole a tripped agent uses to keep reading. Conservative: any command that WRITES a candidate
    (./poc, seeds/, a `>` redirect), COMPILES (gcc/clang/cc/g++/make), or runs a PYTHON generator is treated
    as construction and NOT denied. Only a leading read-utility with none of those signals is read-shaped."""
    cmd = str((arguments or {}).get("command", "")).strip()
    if not cmd:
        return False
    low = cmd.lower()
    if any(m in low for m in ("./poc", "seeds/", "python", "struct.pack", "gcc", "clang", "g++", " cc ",
                              "make ", "printf ", "> ./", ">./", "tee ", "dd ")):
        return False                                   # constructs / writes a candidate → not a read
    body = re.sub(r"^\s*cd\s+[^;&|]+[;&|]+\s*", "", cmd)          # strip a leading `cd X && ` / `cd X; `
    first = re.split(r"[\s;|&<>]", body.strip(), maxsplit=1)[0].rsplit("/", 1)[-1]  # basename of exec token
    return first in _BASH_READ_CMDS
# RE-ARM ONLY ON A TEST ACTION (the aggression fix, held-out A/B 2026-07-23). The first version re-armed on
# pure CONSTRUCTION too — and a tripped GLM-5.2 exploited it: on arvo:21514 it constructed 10× and TESTED 0×
# in 108 turns, using each construct to reset the read budget and grinding to the wall (a baseline-solve LOST
# under the breaker). Re-arming only on a test (test_poc/batch_test/fuzz/auto_fuzz — "you actually RAN a
# candidate") forces the construct→TEST loop to close: after tripping, the agent may construct freely (those
# tools are not denied) but only a TEST earns the read tools back. instrument/write_poc/apply_patch/use_corpus/
# build_emit/emit_struct are in NEITHER deny nor re-arm — they run freely but don't release the breaker.
ENACTMENT_REARM_TOOLS = frozenset({"test_poc", "batch_test", "fuzz", "auto_fuzz"})
# Keys whose PRESENCE proves a re-arm tool reached a verdict. ``crashed`` = the test_poc / per-candidate
# batch_test replay (the predecessor project); ``found``/``n_crashes`` = fuzz + auto_fuzz
# (the predecessor project); ``n_crashed`` = the batch_test aggregate (the predecessor project).
ENACTMENT_VERDICT_KEYS = ("crashed", "found", "n_crashes", "n_crashed")


def _is_enactment_measurement(result) -> bool:
    """True when a re-arm-set tool call actually PRODUCED A MEASUREMENT — i.e. it really ran a candidate
    and came back with a verdict. Merely NAMING a re-arm tool must not release the breaker.

    WHY (the third loophole in this class, after the read-shaped ``run_bash`` of 3d23765 and the
    construct-grind of d4e4db0): the re-arm used to key on the tool NAME alone, so a call that failed
    INSTANTLY and did no work still reset the read budget — ``test_poc`` with no ``./poc`` returns
    ``ToolResult(False, "poc not found: … (write ./poc first)")`` with no docker run at all
    (`the predecessor project`), ``fuzz`` returns ``ToolResult(False, "fuzzer unavailable …")`` when its
    helper will not import, ``batch_test`` returns ``ToolResult(False, "no candidates to test …")``.
    A tripped agent could therefore disarm the breaker for free and keep reading — exactly the evasion
    the breaker exists to stop.

    The rule, kept deliberately permissive at the edges so a genuine measurement is NEVER penalised:
      * ``ok`` is FALSE → not a measurement. This alone closes every observed no-op (and any failed
        tool in a CUSTOM re-arm set, e.g. a ``build_emit`` that did not compile).
      * a ``crashed`` / ``found`` verdict key is present → a measurement, WHATEVER its value. A real
        ``test_poc`` reporting ``crashed: false`` is a genuine measurement and MUST re-arm — the breaker
        must reward running the candidate, not only crashing it.
      * ``n_tested`` present → a measurement iff it is > 0 (``batch_test`` replayed something). Not
        reachable from today's tools (see the comment at the branch) but retained as a guard: without
        it the shape falls to the permissive fallback and re-arms for free.
      * ok, but the result carries none of those keys → treated as a measurement. A future/injected
        re-arm tool with an unrecognised result shape must not leave the breaker permanently latched;
        the ``ok`` gate above already removed the free-disarm loophole.
    """
    d = result.to_dict()
    if not d.get("ok"):
        return False
    data = d.get("data")
    if not isinstance(data, dict):
        return True                          # ok with a non-dict payload — no verdict to inspect
    for key in ENACTMENT_VERDICT_KEYS:
        if key in data:
            return True                      # a verdict exists; its VALUE (crashed true/false) is irrelevant
    # UNREACHABLE from today's tools, and RETAINED deliberately. The only emitter (``_batch_test``) always
    # ships ``n_tested`` alongside ``n_crashed``, which short-circuits above, and it returns ok=False with
    # no candidates — so a review flagged this branch as dead. But deleting it does not make the shape
    # inert, it routes it to the permissive fallback below, which RE-ARMS: an ``{"n_tested": 0}`` result
    # would disarm the breaker having replayed nothing. This breaker has already shipped three separate
    # free-disarm loopholes (3d23765, d4e4db0, and the failed-call re-arm fixed alongside this comment),
    # so a five-line guard against the next one earns its place. The fallback is for UNRECOGNISED shapes;
    # a shape we recognise and know to be empty is not one of them.
    if "n_tested" in data:
        try:
            return int(data["n_tested"]) > 0     # an empty batch replayed nothing → not a measurement
        except (TypeError, ValueError):
            return False
    return True


def _stall_outcome_sig(result) -> str:
    """A stable, content-free signature of a progress-tool result — its OUTCOME CLASS, not its raw bytes. A
    CHANGE in this signature is what counts as new progress toward a crash for the stall-stop (lever ①). Only
    the outcome-class keys are projected, so a differing ``output``/``probe_output`` window (which changes on
    every ``test_poc`` of a new poc variant) does NOT register as progress and cannot defeat the stall."""
    d = result.to_dict()
    data = d.get("data") if isinstance(d.get("data"), dict) else {}
    proj = {k: data.get(k) for k in STALL_OUTCOME_KEYS if k in data}
    return json.dumps({"ok": d.get("ok"), **proj}, default=str, sort_keys=True)

# --- Observation clamp: keep the tool observation VALID JSON and never drop a scalar ----------------
# The old clamp was a blind tail-slice of the serialized result — ``json.dumps(result.to_dict())[:limit]``
# — which is destructive in exactly the case that matters most. Reproduced on a realistic 300-frame ASan
# trace from ``test_poc``: the full JSON is 12,470 chars against a 12,000 limit, and the slice deletes
# ``crash_rate``, ``reliability``, ``precision``, ``sanitizer`` and ``crash_count`` outright while leaving
# the observation mid-string and UNPARSEABLE. The system prompt tells the model eleven times to finish
# ONLY on ``crash_rate 5/5``, so the harness was deleting the exact field the agent is told to gate its
# finish on, on precisely the deep traces where the trace is longest.
#
# The fix truncates the LARGEST STRING VALUES instead of the tail of the serialized text:
#   * keys are never removed and non-string values (bool/int/float/None) are never touched, so every
#     scalar verdict field survives — the finish criterion is always visible;
#   * the envelope always parses (``json.loads(obs)`` succeeds), so a model that reads the observation
#     as JSON is not handed a syntax error at the worst possible moment;
#   * a value that WAS cut carries an explicit marker in the tools.py:204 house style, so the model can
#     tell "the blob was clipped" from "the tool returned little";
#   * the HOT PATH is byte-identical: a result that already fits is serialized exactly as before.
# This composes with (and does not depend on) the producing side reordering scalars ahead of the blob —
# either fix alone keeps the verdict fields, so neither is load-bearing.
_CLAMP_SEARCH_STEPS = 20    # bisection steps on the per-string cap (resolves a 1 MB blob to the char)


def _cap_strings(node, cap: int):
    """Rebuild ``node`` with every STRING leaf longer than ``cap`` truncated + marked. Pure (returns a new
    structure); dict keys, list order and every non-string leaf are preserved exactly."""
    if isinstance(node, str):
        if len(node) <= cap:
            return node
        return node[:cap] + f"\n...[truncated: {len(node) - cap} more chars of this value]"
    if isinstance(node, dict):
        return {k: _cap_strings(v, cap) for k, v in node.items()}
    if isinstance(node, list):
        return [_cap_strings(v, cap) for v in node]
    return node


def clamp_observation(payload: dict, limit: int) -> str:
    """Serialize a ``ToolResult.to_dict()`` into at most ``limit`` chars of VALID JSON, shrinking only the
    largest string values. See the module note above for WHY the old blind slice was destructive.

    Bisects the largest uniform per-string cap that fits. Bisection is used for speed, not because size is
    strictly monotonic in the cap (adding a marker to a just-crossed short string can nudge it) — every
    candidate is REBUILT AND MEASURED, and a cap is accepted only when it verifiably fits, so the returned
    string is always within budget regardless. Falls back to a minimal (still valid) envelope in the
    pathological case where the structure alone — with every string emptied — exceeds the budget."""
    full = json.dumps(payload, default=str)
    if len(full) <= limit:
        return full                          # hot path: unchanged from the old blind slice, byte for byte
    floor = json.dumps(_cap_strings(payload, 0), default=str)
    if len(floor) > limit:
        # Every string emptied and it still does not fit: the structure itself is over budget. Return a
        # valid, minimal envelope rather than an unparseable slice — ``ok`` survives, and the marker tells
        # the model to narrow its call.
        return json.dumps({"ok": payload.get("ok") if isinstance(payload, dict) else None,
                           "error": f"observation of {len(full)} chars could not be rendered within "
                                    f"{limit}; re-call the tool with a narrower scope",
                           "truncated": True}, default=str)
    best, lo, hi = floor, 0, max(len(full), limit)
    for _ in range(_CLAMP_SEARCH_STEPS):
        if lo >= hi:
            break
        mid = (lo + hi + 1) // 2
        candidate = json.dumps(_cap_strings(payload, mid), default=str)
        if len(candidate) <= limit:
            best, lo = candidate, mid
        else:
            hi = mid - 1
    return best


def _source_read_fields(result: ToolResult) -> dict | None:
    """Only reader-owned scalar bounds may establish that source reached an observation."""
    metadata = result.source_read
    if not isinstance(metadata, dict):
        return None
    path = metadata.get("path")
    bounds = [metadata.get(key) for key in ("start_line", "end_line", "total_lines")]
    partial = metadata.get("partial_line")
    if not isinstance(path, str) or not path or len(path) > 4096 or type(partial) is not bool:
        return None
    if any(type(value) is not int for value in bounds):
        return None
    start, end, total = bounds
    if not 0 <= start <= end <= total <= READ_MAX_FILE_BYTES:
        return None
    if start == 0 and (end != 0 or partial):
        return None
    return {"path": path, "start_line": start, "end_line": end,
            "total_lines": total, "partial_line": partial}


# --- Loop cadence: periodic FORCED self-review (Rule 3 — the trajectory-management surface) ---------
# A general-agent metacognition turn injected every ``SELF_REVIEW_INTERVAL`` steps: the agent must assess,
# in writing, where it stands vs the goal, what worked vs what it churned, whether to change trajectory, and
# whether a "done"-looking state actually meets the finish criterion — then act on its own conclusion. It is
# ALWAYS ON (unlike the campaign stall/drift retasking, which needs a CampaignState and keys only on
# test_poc): self-review fires on a pure step cadence so it covers any campaign-less run and triggers the
# "task done but not properly concluded" re-check. The TEXT lives in ``reasoning``; the CADENCE lives here
# beside MEASURE_INTERVAL because the loop enforces it. It never relaxes a finish gate.
SELF_REVIEW_INTERVAL = 15   # steps between forced self-reviews the benchmark solver passes in (0 = off)

_log = get_logger(__name__)


#: Every status this loop can end a run with. **A TUPLE AND NOT A COMMENT, because a rename here
#: silently un-wires a gate two modules away.**
#:
#: `gate.exit_code` refuses to pass a build when `status == "error"`; `report._summary_table` renders
#: the stopped-by row on `status == "maxsteps"`; `budget` reads `"error"` to tell a backend failure
#: from a solver one. All three compare against a LITERAL. Until this constant existed the set they
#: compare against lived in a `#` comment on the line below — which a maintenance script deletes — so
#: renaming a status would have left every one of those comparisons compiling, passing, and never
#: matching again. The errored-run gate would have gone quietly back to returning a green check over a
#: review that never ran, which is the defect it was added to close.
#:
#: The maintainers' suite pins the consumers against this tuple by AST, so a new status
#: that nothing handles, or a consumer comparing against a status nothing emits, is a failing test
#: rather than a silent no-op.
RUN_STATUSES: tuple[str, ...] = ("done", "budget", "error", "maxsteps", "repeat", "stall")


@dataclass
class AgentResult:
    status: str                       # one of RUN_STATUSES
    final_text: str = ""
    steps: int = 0                    # assistant turns taken
    tool_calls: int = 0               # total tools executed
    tokens: int = 0
    journal_path: str = ""
    #: WHICH metered resource stopped the run — `tokens`, `wall_seconds`, `usd`, … — or "" when the
    #: run did not end on a budget. `status` collapses all of them to the single word `budget`, and
    #: the word a customer reads is the one that decides what they do next: a run stopped by the clock
    #: needs `--max-minutes` raised and a run stopped by tokens needs `--max-tokens`. Telling them to
    #: raise the wrong ceiling is the defect the maintainers' notes already records for
    #: `--max-spend-usd` being inert on an unpriced route. `BudgetExceeded` has always carried this;
    #: nothing carried it out.
    limit_hit: str = ""


def _context_chars(messages: list) -> int:
    """Total characters in the message list about to be sent — the measured half of the context curve.

    Counts `content` only, and counts it as `str`: a tool-call message carries its arguments in a
    `tool_calls` list rather than in `content`, so this UNDERCOUNTS a turn that made many calls. Stated
    rather than corrected, because the curve's job is the SHAPE of growth between steps and a
    consistent undercount does not change a shape. Never raises — a telemetry helper that can fail the
    send it measures would be worse than no telemetry.
    """
    total = 0
    for m in messages:
        if isinstance(m, dict):
            body = m.get("content")
            if body is not None:
                total += len(body if isinstance(body, str) else str(body))
    return total


@dataclass
class LoopState:
    """One ReAct run's bookkeeping, as a named record rather than as loose locals.

    **THE NAMES ARE THE POINT, AND THEY ARE WHAT SURVIVES THE BUILD.** A maintenance script strips
    every docstring and comment, so in the artefact a paying customer maintains, this text does not
    exist and neither did the twenty-three comments these fields replaced — `run` opened with a wall
    of bare assignments (`stall_retries = 0`) whose meaning had been deleted at build time. A field
    name is not deleted. A maintenance script is what measures the difference.

    Nothing here is derived and nothing here is a ceiling. Every field is a counter, a flag or a
    last-seen value that one iteration writes and a later one reads; the ceilings live on the loop.
    """

    #: Tokens charged to the governor by this run so far.
    spent: int = 0
    #: Tool calls executed, across every tool.
    n_calls: int = 0
    #: `step_nudge` fires at most once per run.
    nudged: bool = False
    #: Consecutive empty-response turns.
    empty: int = 0
    #: Consecutive provider throughput/idle stalls.
    #:
    #: **NOT `stalled`.** That name is taken by the campaign block's per-step flag, which resets every
    #: iteration and would clobber this counter — making the retry UNBOUNDED against a dead provider.
    #: `test_a_sustained_stall_still_terminates_in_bounded_time` is what caught it, and moving the
    #: counter into this record is what makes the collision impossible rather than merely tested.
    stall_retries: int = 0
    #: Consecutive `max_tokens`-truncated turns, bounded.
    truncated: int = 0
    #: Last campaign summary injected; re-injected only when it changes.
    camp_last: str = ""
    #: Last playbook procedure pushed, to dedup re-injection.
    pb_last: str = ""
    #: Last specialist constraints block pushed (INC-5 dedup).
    spec_last: str = ""
    #: Signature of the last executed tool call (LEVER 2).
    repeat_sig: str = ""
    #: Consecutive byte-identical repeats of `repeat_sig`.
    repeat_n: int = 0
    #: Advisory injected once per distinct repeat streak.
    repeat_advised: bool = False
    #: message-index -> compact args, for compaction stubs (LEVER 3).
    obs_args: dict[int, str] = field(default_factory=dict)
    #: Analysis steps since the last `test_poc` (P0c measure cadence).
    steps_since_test: int = 0
    #: Measure nudges fired so far, capped at `MEASURE_MAX`.
    measure_nudges: int = 0
    #: Steps of inspection-only exploration (construct cadence).
    steps_since_construct: int = 0
    #: Construct nudges fired so far, capped at `CONSTRUCT_MAX`.
    construct_nudges: int = 0
    #: Last advertised tool-slice signature (F4 rotation log dedup).
    adv_last: str = ""
    #: Productive sends with no NEW crash-progress (stall-stop lever).
    sends_since_progress: int = 0
    #: Per progress-tool: its last result signature. A new signature means progress.
    progress_last: dict[str, str] = field(default_factory=dict)
    #: Executed non-re-arm tool calls since the last construct/test.
    reads_since_progress: int = 0
    #: Is the enactment breaker currently tripped, denying reads?
    enact_denied: bool = False
    #: Last step a campaign-less auto-push window opened. Seeded one full interval in the PAST so the
    #: first grind streak can push immediately rather than waiting out a phantom cooldown.
    autopush_last: int = -AUTOPUSH_MIN_INTERVAL
    #: **THE MOST EXPENSIVE MODEL CALL THIS RUN HAS MADE, in dollars.** Not a ceiling and not derived
    #: from one — it is a last-seen value, which is why it lives here. `_unaffordable_next_call` reads
    #: it as the price a call is assumed to cost before it is made, and 0.0 (the first turn, or any
    #: unpriced route) makes that guard inert by construction.
    max_call_usd: float = 0.0
    #: Dollars this loop has CLAIMED on the shared governor for a call in flight, and not yet given
    #: back. `_unaffordable_next_call` takes the claim atomically so concurrent sub-loops cannot each
    #: read the same headroom and each spend it; `_release_call` returns it once the real charge has
    #: landed. Zero whenever no call is outstanding, which is every state a reader of this record can
    #: observe from outside the turn.
    reserved_usd: float = 0.0


@dataclass(frozen=True)
class _CarriedUsage:
    """The invoice for a forced call discarded before its unforced replacement."""

    tokens: int = 0
    cost_usd: float = 0.0
    abandoned: int = 0
    unpriced: int = 0
    tokens_reported: bool = True
    cost_reported: bool = True

    @classmethod
    def from_result(cls, result) -> "_CarriedUsage":
        return cls(
            tokens=int(getattr(result, "tokens", 0) or 0),
            cost_usd=float(getattr(result, "cost_usd", 0.0) or 0.0),
            abandoned=int(getattr(result, "abandoned_attempts", 0) or 0),
            unpriced=int(getattr(result, "unpriced_attempts", 0) or 0),
            tokens_reported=getattr(result, "tokens_reported", None) is not False,
            cost_reported=getattr(result, "cost_reported", None) is not False,
        )


class ToolCallingLoop:
    """Drive a native tool-calling agent to a terminal state.

    The model finishes by returning a turn with NO tool_calls (it just talks). ``finish_gate`` —
    mirroring ``ShardLoop.final_gate`` — can REJECT that finish: it returns a string that is appended
    as a user turn so the agent keeps working (e.g. "./poc does not crash yet"); None accepts it.
    """

    def __init__(self, *, backend, registry: ToolRegistry, journal: Journal, system: str,
                 model: str = "opus", max_steps: int = 40, governor: BudgetGovernor | None = None,
                 tool_names: list[str] | None = None, max_obs_chars: int = OBS_WINDOW_CHARS,
                 finish_gate=None, step_nudge=None, max_empty: int = 6, max_truncated: int = 6,
                 max_stall: int = 2, stall_backoff: float = 30.0, sleep=time.sleep,
                 timeout: int = 600, campaign=None, campaign_hook=None, recall_hook=None,
                 measure_nudge=None, specialist_hook=None, construct_nudge=None,
                 force_tool_hook=None, repeatable_nudge=None,
                 compact_read_tools: frozenset[str] | None = None,
                 compact_never_tools: frozenset[str] | None = None,
                 tool_names_resolver=None, allowed_tools=None,
                 self_review_interval: int = 0,
                 compact_keep_recent: int | None = None,
                 stall_stop_after: int = 0, stall_stop_min_pressure: float = 0.5,
                 enactment_break_after: int = 0, enactment_deny_tools: frozenset[str] | None = None,
                 enactment_rearm_tools: frozenset[str] | None = None,
                 role: str = "main") -> None:
        if not hasattr(backend, "chat"):
            # THE MESSAGE A CUSTOMER READS, so it names no internal document. It used to cite
            # the design notes, which does not exist in the published distribution — a reader who
            # went looking for the reasoning found nothing, on the one line that told them their
            # endpoint was unusable.
            raise TypeError("the backend must expose .chat — Shard requires native tool calling, and "
                            "an endpoint without it cannot run the loop")
        self.backend = backend
        self.registry = registry
        self.journal = journal
        # WHICH loop emitted an event. A solver run shares ONE journal across up to nine loops (the real
        # solver loop, plus sub-agent / specialist / verifier / oracle / stage / variant loops), and each
        # keeps its OWN independent ``step`` counter. Without this field the journal's ``step`` has no
        # owner, so a per-step firing rate is uninterpretable: 28% of 977 committed journals show a step
        # DECREASE, which is proof of interleaved loops, and the census read `self_review` as firing on
        # only 43% of runs when in fact 8 of the 9 loops leave it OFF by design. A rate whose denominator
        # mixes loops that cannot fire the lever is the retarget mistake again — so identity is recorded
        # rather than inferred. Stamped on every event THIS loop records; nothing infers it downstream.
        self.role = role
        # Rule 1 (compute runway): enforced HERE — the single choke-point every solver passes
        # through — so the benchmark solver (and any future solver that reuses this loop) gets the
        # generation-side "think before you act" directive. Idempotent: a solver that already appended it is unchanged.
        self.system = ensure_compute_runway(system)
        self.model = model
        self.max_steps = max_steps
        self.governor = governor
        # Which registry tools to expose (the solver exposes its solver set, not the gated git stubs).
        self.tool_names = tool_names
        self.max_obs_chars = max_obs_chars
        self.finish_gate = finish_gate
        # An empty model turn (no content, no tool_calls) is a known intermittent provider glitch
        # (Amazon Bedrock for opus, AkashML for GLM). chat() already retries it at the HTTP layer;
        # this tolerates up to max_empty CONSECUTIVE such turns at the loop layer before giving up,
        # so a transient streak doesn't kill an otherwise-productive (and expensive) attempt.
        self.max_empty = max_empty
        # A reasoning turn CUT OFF at max_tokens (finish_reason="length") emits no tool_call, so it
        # would otherwise be misread as a finish and bounced by finish_gate — burning steps on exactly
        # the hard-tail tasks. Instead we nudge it to continue and re-emit its next tool call (NOT to
        # "think less" — with a 32k token budget this path is rare, and pressuring a reasoning model to
        # truncate its own analysis is the anti-pattern we want gone), tolerating up to max_truncated
        # such nudges before falling through to a clean finish (so a chronically-truncating model still
        # terminates rather than looping forever).
        self.max_truncated = max_truncated
        # A PROVIDER THROUGHPUT STALL IS TRANSIENT, NOT TERMINAL — and until 2026-07-31 it was treated as
        # terminal, which is measured, not hypothetical: in `tb150-baseline` (150 tasks) NINE tasks died
        # this way, each on its FIRST stall, discarding ~37.6M tokens of paid budget — one at 95% of its
        # budget unused, another at 91%. That is 6% of a benchmark run lost to a transport hiccup.
        #
        # `chat()` already retries the local timeout at the HTTP layer (5 attempts, reroute on 2-5,
        # ~30s of backoff), so
        # reaching here means that ladder is exhausted. The evidence says exhausting it is NOT the same as
        # the provider being down: the nine kills were spread over eight hours (05:39 … 13:54, only one pair
        # inside five minutes) and reported 4-12 tok/s against the 40 floor — independent transient dips on
        # a stream that was still PRODUCING, not a sustained outage. A slower loop-layer retry therefore has
        # a real chance where the fast HTTP ladder failed, which is exactly the `max_empty` argument applied
        # to a different transient.
        #
        # Bounded and backed off (`stall_backoff * n`, so 30s then 60s) so a genuinely dead provider still
        # terminates the attempt in bounded time rather than grinding — the throughput floor keeps doing its
        # job of not letting a run crawl forever. The counter resets on a productive turn, so this tolerates
        # repeated ISOLATED dips across a long task while still stopping a sustained one.
        self.max_stall = max_stall
        self.stall_backoff = stall_backoff
        self._sleep = sleep                         # injected so the deterministic suite never really waits
        # Proactive forcing-function, fired AT MOST ONCE before a turn (mirrors ShardLoop.step_nudge).
        # Callable[[step, messages], str|None]; a returned string is injected as a user turn. This is
        # the fix for the diagnosed "never_committed_to_writing" failure: without it the agent can
        # explore to max_steps and never write/test ./poc. Errors are swallowed (never trap the loop).
        self.step_nudge = step_nudge
        # REPEATABLE nudge — same Callable[[step, messages], str|None] contract, but evaluated EVERY step
        # (not gated by the once-only `nudged` flag). Injectable so a caller with an EVOLVING, multi-stage
        # failure mode can compose per-mode sub-nudges that each self-dedup (fire once); a single once-only
        # step_nudge would fire on whichever stage comes first and starve the later, more-important ones.
        #
        # ⚠ UNWIRED. This comment used to read "Today only the benchmark solver wires this" — it does not,
        # and nothing else does either: `repeatable_nudge` is passed by no caller in the package, no test
        # and no script. It is a built-and-tested mechanism that no production path can reach, which is the
        # same class of finding as the six in MEMORY's levers-exist-but-ship-off entry. Do not delete it on
        # that basis alone (the web-pentest deletion was justified on exactly such a premise and was wrong)
        # — but do not read the parameter's existence as evidence that anything uses it. Its journal events
        # carry kind="repeatable" precisely so that, if it is ever wired, the census can tell them from the
        # once-only step_nudge instead of pooling both under a lever labelled "once-only".
        self.repeatable_nudge = repeatable_nudge
        # Per-turn tool_choice FORCING (weak-model lever). Callable[[step:int], str|dict|None]: returns the
        # tool_choice for that step — "required" (force ANY tool), a {"type":"function","function":{"name":...}}
        # dict (force a specific tool), or None → "auto". Lets the harness force a construction/fuzz call on the
        # early turns when a weak model would otherwise read source in prose (GLM: build_emit 1x/58). Errors are
        # swallowed → "auto" (a broken hook must never trap the loop). Only reaches a backend whose chat() accepts
        # tool_choice (OpenRouter native FC); the CLI/JSON-action path never sees it.
        self.force_tool_hook = force_tool_hook
        self.timeout = timeout
        # Structured cross-turn record (CampaignState — duck-typed: needs summary()/is_stalled()/
        # is_drifting()). When present, its summary is injected — fenced, as untrusted working memory —
        # before a turn whenever it CHANGES (a natural throttle: state only moves when the agent tests
        # or records a note), and a stall/drift is escalated to a strategy-change directive. The state
        # is fed by ``campaign_hook(tool_name, arguments, result)``, called after each tool executes so
        # the loop stays generic — the benchmark-specific extraction (sanitizer line, ./poc signature)
        # lives in the hook the solver supplies, not here.
        self.campaign = campaign
        self.campaign_hook = campaign_hook
        # Demand-driven curated-recall push (fix 9). Callable[[campaign, step], str|None] — ``step`` is
        # the current loop step, so the hook can THROTTLE a strategy rotation by loop-step spacing (see
        # CampaignState.maybe_rotate). On a detected stall/drift the loop calls this to PULL a
        # situation-keyed expert procedure and inject it
        # server-side — the fix for the under-used ``recall_playbook`` tool (GLM called it 1/212 tasks):
        # a stuck agent gets the class-specific method the OPENING keywords missed exactly when it is
        # churning, without having to remember to call the tool. The hook keys on the campaign's own
        # gap/mismatch text (the solver builds it), so the query sharpens as the agent learns what it is
        # stuck on. Its content is TRUSTED (the curated playbook renders authoritative, unlike the
        # untrusted campaign summary) so it is injected UNFENCED. Generic: the playbook lookup lives in
        # the solver's hook, not here. Fired at most once per distinct procedure text (a natural throttle).
        self.recall_hook = recall_hook
        # Bounded-repeatable measure cadence (P0c). Callable[[steps_since_test, step], str|None]. UNLIKE
        # the once-only step_nudge, this REPEATS: every MEASURE_INTERVAL analysis steps with no fresh
        # test_poc result the loop calls it for the directive text and injects it as a user turn, capped
        # at MEASURE_MAX per run and min-interval-deduped (firing resets the counter). The counter resets
        # the instant a test_poc tool result is observed, so an agent that measures on its own never sees
        # it. Default None = disabled (the deterministic suite + non-solver callers are untouched). The
        # message is authored by the solver's callable (it names steps_since_test); the CADENCE is owned
        # here so MEASURE_INTERVAL/MEASURE_MAX live with the loop that enforces them.
        self.measure_nudge = measure_nudge
        # Bounded-repeatable CONSTRUCT cadence (the never-construct fix). Callable[[steps_since_construct,
        # step], str|None]. Fires on a pure INSPECTION streak — CONSTRUCT_INTERVAL steps of only
        # read/grep/list/run_bash with no construction/fuzz/test — capped at CONSTRUCT_MAX and
        # min-interval-deduped (firing resets the counter). The counter resets the instant a
        # non-exploration tool executes (see CONSTRUCT_EXPLORE_TOOLS), so an agent that already constructs
        # never sees it. The message (and any ./poc/./seeds "already have a candidate" gating) is authored
        # by the solver's callable; the CADENCE lives here. Default None = disabled (suite untouched).
        self.construct_nudge = construct_nudge
        # INC-5 — the instrumentation/data-flow SPECIALIST escalation hook. Callable[[campaign, step],
        # str|None] — the ESCALATION tier of the reachability ladder above the always-on `instrument`
        # tool. Fired inside the same on-change campaign block as recall_hook, but on a BROADER trigger:
        # stalled OR drifting OR (duck-typed) ``campaign.is_reaching_uncrashed()`` — an m5 streak where a
        # candidate ./poc reaches the harness but never fires the sink, which is exactly when runtime
        # data-flow signal helps most. The hook itself (benchmark-side) runs a SINGLE sequential sub-agent
        # on its OWN budget over the candidate ./poc and returns compact runtime constraints; the loop
        # injects that as a user turn (deduped via spec_last), like the recall_hook path. It NEVER fans out
        # N replicas and it never gates a finish — advisory reachability signal only. Default None =
        # disabled (the deterministic suite + non-specialist callers are untouched). A broken hook is
        # swallowed (never traps the loop), same discipline as recall_hook.
        self.specialist_hook = specialist_hook
        # Per-MODE compaction tool sets (F6). ``_compact`` stubs a stale observation only when its tool is
        # in the READ set AND not in the NEVER set; the module-level ``COMPACT_READ_TOOLS`` names the
        # the benchmark read tools. Both sets are INJECTABLE so a second solver could pass its own read and
        # never-stub sets without changing the module constants; today only the benchmark solver does
        # (None → the module constants, so every existing caller/test is unchanged). The NEVER set is the
        # hard invariant that a crash/verification observation survives verbatim forever, even if a future
        # edit widens the read set.
        self._compact_read_tools = COMPACT_READ_TOOLS if compact_read_tools is None else compact_read_tools
        self._compact_never_tools = (COMPACT_NEVER_TOOLS if compact_never_tools is None
                                     else compact_never_tools)
        # Per-STEP tool advertisement (F4). Injectable so a solver with stage-based machinery can rotate
        # the advertised tool slice with the campaign stage instead of fixing it once at run start. When
        # set, a ``Callable[[step:int], list[str]|None]`` returns the tool NAMES to advertise for THAT
        # step; the loop re-derives ``openai_tools`` from them each turn. None → the fixed ``tool_names``
        # list is advertised once, so the benchmark/default path is byte-for-byte unchanged.
        self.tool_names_resolver = tool_names_resolver
        # ITEM-1 enforcement UNION. With a rotating resolver the advertised slice is only PART of what the
        # agent may legitimately reach for (a tool advertised at one stage must not be rejected when the
        # resolver momentarily returns a narrower slice), so execution is enforced against this wider union
        # — the solver's full registered set — rather than the current slice. A genuinely-unregistered
        # tool is still rejected. None → enforce against ``tool_names`` exactly as before (default path unchanged).
        self._allowed_union = sorted(allowed_tools) if allowed_tools is not None else None
        # Rule 3 (self-review) cadence — OPT-IN per loop, unlike the unconditional compute runway. The
        # benchmark solver passes ``SELF_REVIEW_INTERVAL``; the bounded sub-agents (verifier, oracle,
        # specialist, investigation) leave it 0 (OFF) so a forced "assess/change-trajectory" turn never
        # lands on the final decisive step of a short refute/grade/investigate loop where it is off-target.
        # 0 disables it entirely (every existing caller/test unchanged unless it opts in).
        self.self_review_interval = max(0, int(self_review_interval or 0))
        # Live-read-window size (INC-0 lever ③). The 8-deep verbatim window of recent read/run_bash
        # observations is the LARGEST single dynamic re-billed mass (~57-60% of reconstructed variable
        # tokens on budget-miss tasks). Making it a constructor knob lets a paid A/B shrink it without a
        # code change; None → the module default COMPACT_KEEP_RECENT (8), so every existing caller/test is
        # byte-identical. A smaller value stubs stale reads SOONER (cheaper sends → more grind per 8M budget).
        self._compact_keep_recent = (COMPACT_KEEP_RECENT if compact_keep_recent is None
                                     else max(1, int(compact_keep_recent)))
        # Stall-triggered early-stop (INC-0 lever ①). 0 = OFF (byte-identical to today). See the module note.
        self.stall_stop_after = max(0, int(stall_stop_after or 0))
        # Only fire the stall-stop once at least this fraction of the token budget is spent, so a deliberate
        # short run is never cut — only a genuine budget-burning grind trips it. pressure() is 0.0 when there
        # is no token cap, so with the default 0.5 the stall-stop is inert without a metered token budget.
        self.stall_stop_min_pressure = float(stall_stop_min_pressure)
        # Enactment circuit-breaker (lever L4). 0 = OFF (byte-identical to today). See the module note.
        self._enact_break_after = max(0, int(enactment_break_after or 0))
        self._enact_deny = ENACTMENT_DENY_TOOLS if enactment_deny_tools is None else frozenset(enactment_deny_tools)
        self._enact_rearm = ENACTMENT_REARM_TOOLS if enactment_rearm_tools is None else frozenset(enactment_rearm_tools)

    def _meter(self, tokens: int, cost_usd: float = 0.0, *, state: LoopState | None = None) -> str:
        """Spend a turn's tokens AND its dollars on the budget.

        Returns the NAME of the resource that crossed its cap, or "" to continue. A name
        rather than a bool because `status` collapses every cap to the word `budget`, and the
        customer's next action differs by which one it was.

        The dollar half is a deliberate divergence from the predecessor project, and the reason is measured rather
        than theoretical. `BudgetGovernor` has carried a `usd` resource since it was written and
        `check()` has always compared it — but the only `spend()` calls in the tree were `tokens` here
        and `subagents` in the separate package, so **nothing ever debited it**. `--max-spend-usd` was
        passed on every run of 2026-08-08 and did nothing; a governor built from `--max-spend-usd 5` and
        charged 50,000,000 tokens still passes `check()`. The number the ceiling needs was already
        arriving on every response (`llm.py` accumulates `usage["cost"]`) and was simply never handed
        over. The design notes.

        Both resources are charged before either return, and that ordering is load-bearing for the same
        reason `BudgetGovernor.spend` commits before it raises: the tokens and the dollars of a
        trip-wire turn are BOTH already spent at the provider, so a ledger that recorded one and dropped
        the other would misreport the very run that blew the cap. Whichever cap the turn crossed, the
        run stops.
        """
        if not self.governor:
            return ""
        # The FIRST resource to cross, not the last: both are charged either way (see above), but the
        # one a customer is told about should be the one that actually stopped them.
        stop = ""
        exceeded: list[BudgetExceeded] = []
        invalid: list[tuple[str, ValueError]] = []
        for resource, amount in (("tokens", tokens), ("usd", cost_usd)):
            if resource == "usd" and state is not None and state.reserved_usd:
                settled = False
                try:
                    self.governor.settle("usd", state.reserved_usd, cost_usd)
                    settled = True
                except BudgetExceeded as e:
                    settled = True       # settle commits the crossing charge before it raises
                    exceeded.append(e)
                    stop = stop or e.resource
                except ValueError as e:
                    invalid.append((resource, e))
                finally:
                    # This loop no longer owns the claim once settlement committed it. Clear that
                    # ownership before journal I/O: if recording the crossing fails, `run`'s outer
                    # finally must not release another concurrent loop's still-live reservation.
                    if settled:
                        state.reserved_usd = 0.0
                continue
            if not amount:
                continue
            try:
                self.governor.spend(resource, amount)
            except BudgetExceeded as e:
                exceeded.append(e)
                stop = stop or e.resource
            except ValueError as e:
                invalid.append((resource, e))
        # Charge every resource before writing either event. A journal failure must not make the
        # provider's already-incurred token or dollar charge disappear from the run ledger.
        for error in exceeded:
            self._rec("budget_exceeded", detail=str(error))
        for resource, error in invalid:
            self._rec("budget_value_invalid", resource=resource, detail=str(error))
        return "invalid_usage" if invalid else stop

    def _unaffordable_next_call(self, st: LoopState) -> float:
        """The dollar headroom a call needs and does not have, or 0.0 to proceed.

        **`--max-spend-usd` WAS NOT A CEILING, AND THIS IS WHAT MAKES IT ONE.** Measured on a real run
        of 2026-08-22: a $2.50 cap produced $2.5866. `BudgetGovernor.spend` meters POST HOC — it commits
        the spend and then raises, because the provider has already charged for that call and a ledger
        that refused to record it would misreport the very run that blew the cap. That ordering is right
        and it is not what is being changed here. The consequence was that the cap stopped the call
        AFTER the one that crossed it, so the customer's ceiling was really "your ceiling, plus one
        model call" — and the integration guide sells the ceilings as the thing that makes cost
        predictable. An approximate ceiling is a different product claim from a ceiling.

        So the enforcement point moves to BEFORE the call, where a refusal costs nothing: if the
        remaining budget cannot cover a call priced like the most expensive one this run has already
        made, the run stops here rather than making it.

        **THE PRICE IS OBSERVED, NOT GUESSED.** A fixed reserve would be a magic number that is wrong
        for every model — `st.max_call_usd` is the highest real charge this run has seen, so the guard
        calibrates itself to the model, the prompt size and the provider actually in use. It also
        cannot be conservative in the wrong direction on a cheap run: a run whose calls cost $0.002
        reserves $0.002.

        **THE RESIDUAL, STATED RATHER THAN HIDDEN.** Two cases still cross, and both are bounded by one
        call. The FIRST call of a run has no observation behind it (`max_call_usd` is 0.0), and a later
        call can be priced above every call before it. Neither is fixable from inside the loop: no
        provider on any route we support will accept a spend cap as a request parameter, so the true
        cost of a call is knowable only after it returns. What IS fixable is the claim, and
        `--max-spend-usd`'s help, `action.yml` and the report now say this rather than promising an
        exactness the wire cannot deliver.

        **A READ IS NOT A CHECK WHEN THE GOVERNOR IS SHARED.** `remaining("usd")` answered from a
        ledger that would not change until the call it is guarding had already been made and billed,
        and the separate package fans sub-loops out over ONE governor on a thread pool. Every one of them
        read the same headroom, every one concluded it could afford a call, and every one made it — so
        the ceiling was crossed by as many calls as there were loops, not by the single call the
        residual below accounts for. The reservation is taken atomically instead, and `_release_call`
        gives it back once the real charge has landed.
        """
        if self.governor is None or st.max_call_usd <= 0.0:
            return 0.0
        # An unpriced route leaves the limit None and `reserve` always fits, so this is inert there too
        # — which matters, because `--max-spend-usd` on a route that reports no cost must not stop a run
        # on a number nobody measured.
        if self.governor.reserve("usd", st.max_call_usd):
            st.reserved_usd = st.max_call_usd
            return 0.0
        # The reservation failed, so `max_call_usd` is STRICTLY greater than the free headroom and this
        # subtraction is positive by construction — no epsilon, and no branch that could return 0.0 on
        # the refusal path and let the call through anyway.
        return st.max_call_usd - (self.governor.remaining("usd") - self.governor.reserved("usd"))

    def _release_call(self, st: LoopState) -> None:
        """Give back the headroom `_unaffordable_next_call` claimed, on every path out of a turn.

        Paired with the reservation rather than folded into `_meter`, because a turn can end without
        being metered at all — a raising backend, a forced-tool rejection, a `continue` on an empty
        response — and a reservation nothing releases is budget the run permanently denies itself.
        """
        if self.governor is not None and st.reserved_usd:
            self.governor.release("usd", st.reserved_usd)
            st.reserved_usd = 0.0

    def _budget_stop(self, st: LoopState, step: int) -> AgentResult | None:
        """Does the budget end the run before this step? The terminal result if so, else None.

        **ONE QUESTION, TWO TENSES**, which is why they belong in one place rather than as two blocks
        at the top of `run`. `check()` asks whether a cap has ALREADY been crossed — the post-hoc
        question, answered from the ledger. `_unaffordable_next_call` asks whether the call this step
        is about to make can be paid for — the question that has to be asked before anything is sent,
        because a provider bills for a call whatever the ledger would have preferred.

        The second is what makes `--max-spend-usd` a ceiling. `check()` alone let a $2.50 cap bill
        $2.5866 on a real run, because the only thing it could do was notice afterwards.
        """
        if self.governor is None:
            return None
        # LAST STEP'S CLAIM GOES BACK BEFORE THIS STEP TAKES ONE. The call it was reserved for has
        # either been billed by `_meter` or never happened, and either way the claim is stale — holding
        # it while claiming again would make one loop reserve the same money twice per step.
        self._release_call(st)
        try:
            self.governor.check()
        except BudgetExceeded as e:
            self._rec("budget_exceeded", detail=str(e))
            return self._result("budget", step - 1, st.n_calls, st.spent, str(e), limit_hit=e.resource)

        if self._unaffordable_next_call(st) <= 0.0:
            return None
        left = self.governor.remaining("usd")
        self._rec("budget_headroom", step=step, resource="usd",
                  need=round(st.max_call_usd, 6), remaining=round(left, 6))
        return self._result(
            "budget", step - 1, st.n_calls, st.spent,
            f"stopping before a call this run cannot afford: the most expensive call so far cost "
            f"${st.max_call_usd:.4f} and ${left:.4f} of the --max-spend-usd ceiling is left",
            limit_hit="usd")

    def _send_and_bill(self, st: LoopState, messages: list, tools: list,
                       step: int) -> tuple[object, str]:
        """Make this step's provider call and charge what it cost. `(result, capped-resource-or-"")`.

        **ONE STEP CAN MAKE TWO PROVIDER CALLS, and until 2026-08-24 it metered one.** A forced
        `tool_choice` a provider rejects answers with an HTTP error or a refusal — `opus-4.8` burned
        9,003 prompt tokens refusing one, four attempts out of four — and the degrade-safe retry below
        overwrote the result, dropping that charge on the floor. It is carried in a local record
        rather than folded onto the result object, because `backend` is an injection point and a
        double's result need not be a dataclass this could rebuild.

        Extracted from `run` for the reason the maintainers' suite exists to reward: "send the turn
        and account for it" is a whole decision, and leaving it inline grew the largest function in the
        shipped tree past the ceiling its own ratchet defends.
        """
        sent_at = time.monotonic()
        res, carried = self._send_turn(messages, tools, step)
        usage = self._turn_usage(res, carried)
        identity = self._identity_fields(res)
        step_tokens = usage["tokens"]
        step_usd = usage["cost_usd"]
        self._rec("llm_request", step=step, seconds=round(time.monotonic() - sent_at, 3),
                  total_tokens=step_tokens, cost_usd=step_usd,
                  abandoned=usage["abandoned"], unpriced=usage["unpriced"],
                  tokens_reported=usage["tokens_reported"],
                  cost_reported=usage["cost_reported"], **identity,
                  ok=bool(getattr(res, "ok", True)),
                  finish_reason=getattr(res, "finish_reason", "") or "")
        st.spent += step_tokens
        st.max_call_usd = max(st.max_call_usd, step_usd)
        hit = self._meter(step_tokens, step_usd, state=st)
        gaps = self._usage_gaps(usage)
        for gap in gaps:
            self._rec("llm_usage_gap", step=step, resource=gap.removeprefix("unreported_"),
                      requested_model=identity["requested_model"],
                      served_model=identity["served_model"],
                      identity_verdict=identity["identity_verdict"])
        return res, self._enforced_usage_gap(gaps) or hit

    def _forced_choice(self, step: int):
        """The forcing hook's choice, degrading a broken hook to the ordinary call."""
        if self.force_tool_hook is None:
            return None
        try:
            return self.force_tool_hook(step)
        except Exception as e:            # a broken hook degrades to "auto", never traps the loop
            self._rec("force_tool_hook_error", step=step, error=f"{type(e).__name__}: {e}")
            return None

    def _send_turn(self, messages: list, tools: list,
                   step: int) -> tuple[object, _CarriedUsage]:
        """Send once, or replace a rejected forced call while retaining its invoice."""
        # Per-turn tool_choice forcing (weak-model lever): the hook may force a tool call on early
        # turns. Only pass tool_choice when forcing is ACTIVE (non-None) — the default path keeps the
        # exact old chat() signature, so backends/mocks whose chat() predates tool_choice are
        # unaffected.
        choice = self._forced_choice(step)
        if choice is None:
            return (self.backend.chat(messages, tools, model=self.model, timeout=self.timeout),
                    _CarriedUsage())
        self._rec("force_tool", step=step, tool_choice=choice)
        result = self.backend.chat(messages, tools, model=self.model, timeout=self.timeout,
                                   tool_choice=choice)
        if result.ok:
            return result, _CarriedUsage()
        self._rec("force_tool_rejected", step=step, error=(result.error or "")[:200],
                  **self._identity_fields(result))
        # Only a response that explicitly rejected the forced-choice field earns an unforced retry.
        # Treating every generic failure as eligible duplicated expired credentials and policy 403s;
        # treating an unknown backend result as eligible also hid its first failure behind a second.
        if not getattr(result, "forcing_retry_safe", False):
            return result, _CarriedUsage()
        replacement = self.backend.chat(messages, tools, model=self.model, timeout=self.timeout)
        return replacement, _CarriedUsage.from_result(result)

    def _turn_usage(self, result, carried: _CarriedUsage) -> dict:
        """One step's known invoice and whether every request supplied each measurement."""
        abandoned = int(getattr(result, "abandoned_attempts", 0) or 0) + carried.abandoned
        unpriced = int(getattr(result, "unpriced_attempts", 0) or 0) + carried.unpriced
        tokens_reported = getattr(result, "tokens_reported", None)
        cost_reported = getattr(result, "cost_reported", None)
        if not carried.tokens_reported:
            tokens_reported = False
        if not carried.cost_reported:
            cost_reported = False
        if abandoned:
            tokens_reported = cost_reported = False
        if unpriced:
            cost_reported = False
        return {
            "tokens": int(getattr(result, "tokens", 0) or 0) + carried.tokens,
            "cost_usd": float(getattr(result, "cost_usd", 0.0) or 0.0) + carried.cost_usd,
            "abandoned": abandoned,
            "unpriced": unpriced,
            "tokens_reported": tokens_reported,
            "cost_reported": cost_reported,
        }

    def _identity_fields(self, result) -> dict:
        return {
            "requested_model": getattr(result, "model", "") or self.model,
            "served_model": getattr(result, "served_model", "") or "",
            "identity_verdict": getattr(result, "identity_verdict", "") or "unreported",
        }

    @staticmethod
    def _usage_gaps(usage: dict) -> tuple[str, ...]:
        """Every missing measurement, independent of whether this run set that ceiling."""
        gaps = []
        if usage["tokens_reported"] is False:
            gaps.append("unreported_tokens")
        if usage["cost_reported"] is False:
            gaps.append("unreported_usd")
        return tuple(gaps)

    def _enforced_usage_gap(self, gaps: tuple[str, ...]) -> str:
        """The first gap that makes a configured finite ceiling unenforceable."""
        if self.governor is None:
            return ""
        if self.governor.budget.tokens is not None and "unreported_tokens" in gaps:
            return "unreported_tokens"
        if self.governor.budget.usd is not None and "unreported_usd" in gaps:
            return "unreported_usd"
        return ""

    def _meter_stop_result(self, hit: str, step: int, state: LoopState) -> AgentResult:
        """Translate a metering stop token without adding branches to the main loop."""
        errors = {
            "invalid_usage": "the model endpoint returned a non-finite or negative usage value",
            "unreported_tokens": (
                "the model endpoint did not report token usage, so the finite token ceiling cannot "
                "be enforced"),
            "unreported_usd": (
                "the model endpoint did not report cost, so the finite dollar ceiling cannot be "
                "enforced"),
        }
        if hit in errors:
            return self._result("error", step, state.n_calls, state.spent, errors[hit])
        return self._result("budget", step, state.n_calls, state.spent, "run budget exhausted",
                            limit_hit=hit)

    def _rec(self, type: str, **data) -> dict:
        """Journal an event stamped with THIS loop's ``role``.

        Every event the loop records goes through here so identity can never be forgotten at one call
        site — which is the failure mode that made the shared journal's ``step`` field unattributable."""
        return self.journal.record(type, role=self.role, **data)

    def _record_source_observation(self, name: str, args: dict, result: ToolResult, obs: str) -> None:
        """Record passive inspection evidence after the same clamp that feeds the model."""
        if name not in {"read_file", "grep"}:
            return
        if name == "read_file" and result.ok:
            fields = _source_read_fields(result)
            if fields is None:
                return
        else:
            path = args.get("path", "." if name == "grep" else None)
            if not isinstance(path, str) or not path or len(path) > 4096:
                return
            fields = {"path": path}
        self._rec("source_read" if name == "read_file" else "source_search", **fields,
                  ok=bool(result.ok), observation_complete=(obs == json.dumps(result.to_dict(), default=str)))

    def _campaign_and_push(self, st: LoopState, messages: list[dict], step: int) -> None:
        """Re-inject the campaign record when it changed, then fire the two auto-pushes.

        Everything this decides — `stalled`, `drifting`, `camp_changed`, `push_open`, `want_push` —
        is born and dies inside this call. That is why it is a method rather than a band of `run`:
        five locals that look loop-carried from the outside are in fact one step's worth of state,
        and the enclosing function had no way to say so.

        The two pushes sit OUTSIDE the campaign block deliberately — `--campaign`, `--specialist` and
        `--strategy-file` are independent flags, and nesting them under `campaign is not None` meant a
        specialist-only or playbook-only run never fired them once. See AUTOPUSH_MIN_INTERVAL.

        Every hook is wrapped: a broken campaign, recall or specialist hook must never crash the loop.
        """
        # Campaign context BEFORE the turn: re-inject the structured cross-turn record whenever it
        # CHANGED since we last showed it (on-change = a natural throttle). On a stall/drift, escalate
        # to a strategy-change directive so a churning agent is pushed to re-localize, not refine.
        # ``stalled``/``drifting`` are hoisted out of the campaign block because the two auto-pushes
        # below now read them whether or not a campaign is wired (see AUTOPUSH_MIN_INTERVAL). They are
        # re-initialised EVERY step — a stall detected on step N must not leak into step N+1.
        stalled = drifting = False
        camp_changed = False             # did the campaign summary change THIS step? (the old push gate)
        if self.campaign is not None:
            try:
                summ = self.campaign.summary()
            except Exception as e:   # a broken campaign object must never crash the loop
                self._rec("campaign_error", error=f"{type(e).__name__}: {e}")
                summ = ""
            if summ and summ != st.camp_last:
                try:
                    stalled, drifting = self.campaign.is_stalled(), self.campaign.is_drifting()
                except Exception:
                    pass
                head = ("PROGRESS STATE (your own cross-turn record — build on it; do NOT repeat a "
                        "failed hypothesis):")
                if stalled or drifting:
                    # RE-TASKING (L1): prefer the campaign's CONCRETE re-task directive (grounded in
                    # its own recorded mismatch/dead-ends) over a generic "change strategy" nudge.
                    directive = ""
                    rt = getattr(self.campaign, "retask_directive", None)
                    if callable(rt):
                        try:
                            directive = rt() or ""
                        except Exception:
                            directive = ""
                    head = (directive + "\nProgress state:") if directive else (
                        "You appear STALLED or DRIFTING — repeating the same input, or your "
                        "crash keeps missing the described defect. CHANGE STRATEGY: re-localize "
                        "the EXACT described sink and reach it a different way (trace the parse "
                        "path, watch the fault dynamically) instead of refining the same bytes. "
                        "Progress state:")
                self._rec("campaign_context", step=step, stalled=stalled, drifting=drifting)
                messages.append({"role": "user", "content": fence(head + "\n" + summ)})
                st.camp_last = summ
                camp_changed = True

        # AUTO-PUSH escalations — OUTSIDE the campaign block on purpose (see AUTOPUSH_MIN_INTERVAL):
        # ``--campaign`` / ``--specialist`` / ``--strategy-file`` are independent flags, and nesting
        # these two pushes under ``campaign is not None`` meant a specialist-only or playbook-only run
        # never fired them ONCE. ``push_open`` is the throttle and ``want_push`` the trigger:
        #   * WITH a campaign — EXACTLY the previous semantics: gated on the summary having changed
        #     this step (``camp_changed``, the old nesting) and triggered by the campaign's own
        #     stall/drift. The message sequence on the campaign path is therefore unchanged, which the
        #     paid A/B depends on.
        #   * WITHOUT a campaign — there is no summary to key on, so the trigger is the loop's own
        #     grind counters (the CONSTRUCT/MEASURE cadence condition: inspecting without constructing
        #     or measuring), spaced by AUTOPUSH_MIN_INTERVAL. The window is consumed on evaluation so a
        #     quiet hook is not re-entered every step. Both hooks read the campaign only via
        #     ``getattr(camp, …)``, so passing None is safe.
        if self.campaign is not None:
            push_open, want_push = camp_changed, (stalled or drifting)
        else:
            push_open = (step - st.autopush_last >= AUTOPUSH_MIN_INTERVAL
                         and (st.steps_since_construct >= CONSTRUCT_INTERVAL
                              or st.steps_since_test >= MEASURE_INTERVAL))
            want_push = push_open
            if push_open:
                st.autopush_last = step      # consume the window even if the hooks yield nothing

        # PUSH a curated procedure keyed on the current situation (fix 9): the moment the tool would
        # matter most is exactly when a churning agent forgets to call it, so we call it for them.
        # Trusted content → injected UNFENCED; deduped so the same procedure is not repeated.
        if push_open and want_push and self.recall_hook is not None:
            try:
                pb = self.recall_hook(self.campaign, step)
            except Exception as e:   # a broken recall hook must never crash the loop
                self._rec("recall_hook_error", error=f"{type(e).__name__}: {e}")
                pb = None
            if isinstance(pb, str) and pb.strip() and pb != st.pb_last:
                self._rec("playbook_autorecall", step=step)
                messages.append({"role": "user", "content": pb})
                st.pb_last = pb

        # INC-5: ESCALATE to the instrumentation/data-flow specialist. Broader trigger than recall —
        # also fire when the agent is REACHING but never crashing (m5 streak), the sweet spot for
        # runtime data-flow signal — via a duck-typed campaign predicate so the loop stays generic
        # (``getattr`` on a None campaign simply yields no predicate). The hook runs ONE sequential
        # sub-agent on its OWN budget over the candidate ./poc and returns compact runtime constraints;
        # inject them as a user turn (TRUSTED — measured on the vul build — so unfenced, like the
        # recall push), deduped so the same block is never repeated. The hook self-gates on ./poc
        # existence, per-sig dedup, and its own budget, so a spent/duplicate escalation returns None.
        if push_open and self.specialist_hook is not None:
            want_spec = want_push
            if not want_spec:
                reaching = getattr(self.campaign, "is_reaching_uncrashed", None)
                if callable(reaching):
                    try:
                        want_spec = bool(reaching())
                    except Exception:
                        want_spec = False
            if want_spec:
                try:
                    sc = self.specialist_hook(self.campaign, step)
                except Exception as e:   # a broken specialist hook must never crash the loop
                    self._rec("specialist_hook_error", error=f"{type(e).__name__}: {e}")
                    sc = None
                if isinstance(sc, str) and sc.strip() and sc != st.spec_last:
                    self._rec("specialist_push", step=step)
                    messages.append({"role": "user", "content": sc})
                    st.spec_last = sc

    def _cadence_nudges(self, st: LoopState, messages: list[dict], step: int) -> None:
        """The step, repeatable, measure, construct and self-review nudges, in that order.

        AT MOST ONE cadence nudge per step, which is what `nudged_this_step` enforces and the reason
        the measure and construct blocks are adjacent rather than independent: two nudges in one turn
        was measured as noise the agent learns to skim.

        Counters advance here even when the corresponding hook is unwired, so a run that turns a lever
        on mid-flight sees an honest count rather than one that started at zero.
        """
        # Proactive nudge BEFORE the turn: push a stalled agent into the write→test→iterate loop.
        if self.step_nudge is not None and not st.nudged:
            try:
                nudge = self.step_nudge(step, messages)
            except Exception as e:   # a broken nudge must never crash the loop
                self._rec("step_nudge_error", error=f"{type(e).__name__}: {e}", kind="once")
                nudge = None
            if isinstance(nudge, str) and nudge.strip():
                # `kind` discriminates the two emitters of this event type. Without it the firing
                # census cannot tell a ONCE-ONLY lever from an UNCAPPED one — and it labels this row
                # "step_nudge (once-only)", so a repeatable fire would silently inflate a lever whose
                # whole health signal is "it fired at most once".
                self._rec("step_nudge", step=step, text=nudge[:500], kind="once")
                messages.append({"role": "user", "content": nudge})
                st.nudged = True

        # Repeatable nudge — evaluated every step (self-deduping sub-nudges fire once each as their
        # stage becomes relevant). Independent of the once-only `nudged` slot above.
        if self.repeatable_nudge is not None:
            try:
                rnudge = self.repeatable_nudge(step, messages)
            except Exception as e:
                self._rec("step_nudge_error", error=f"{type(e).__name__}: {e}", kind="repeatable")
                rnudge = None
            if isinstance(rnudge, str) and rnudge.strip():
                self._rec("step_nudge", step=step, text=rnudge[:500], kind="repeatable")
                messages.append({"role": "user", "content": rnudge})

        # Measured-iteration cadence (P0c): count this analysis step, then — unlike the once-only
        # step_nudge — REPEAT a measurement directive whenever the agent has gone MEASURE_INTERVAL
        # steps with no fresh test_poc, capped at MEASURE_MAX. Firing resets the counter (≥ one full
        # interval between nudges = min-interval dedup). The counter is reset again to 0 the instant a
        # test_poc result is observed (in the tool loop below), so an agent that measures on its own
        # never triggers it. "commit AND keep analyzing" — never starves a deep-reachability task.
        st.steps_since_test += 1
        nudged_this_step = False                # at most one cadence nudge per step (measure OR construct)
        if (self.measure_nudge is not None and st.steps_since_test >= MEASURE_INTERVAL
                and st.measure_nudges < MEASURE_MAX):
            try:
                mn = self.measure_nudge(st.steps_since_test, step)
            except Exception as e:   # a broken measure nudge must never crash the loop
                self._rec("measure_nudge_error", error=f"{type(e).__name__}: {e}")
                mn = None
            if isinstance(mn, str) and mn.strip():
                st.measure_nudges += 1
                self._rec("measure_nudge", step=step, since=st.steps_since_test, n=st.measure_nudges)
                messages.append({"role": "user", "content": mn})
                st.steps_since_test = 0             # min-interval dedup: need another full interval to re-fire
                nudged_this_step = True

        # CONSTRUCT cadence: on a pure INSPECTION streak (CONSTRUCT_INTERVAL steps of only
        # read/grep/list/run_bash — steps_since_construct resets on any construction/fuzz/test tool
        # below), push the agent to CONSTRUCT a candidate. Capped at CONSTRUCT_MAX, min-interval-deduped
        # (firing resets the counter), and never doubled up with a measure nudge in the same step. The
        # solver's callable self-gates (returns None once a ./poc/./seeds candidate exists), so this
        # only nudges the pre-candidate grind the measure nudge does not reach.
        st.steps_since_construct += 1
        if (not nudged_this_step and self.construct_nudge is not None
                and st.steps_since_construct >= CONSTRUCT_INTERVAL and st.construct_nudges < CONSTRUCT_MAX):
            try:
                cn = self.construct_nudge(st.steps_since_construct, step)
            except Exception as e:   # a broken construct nudge must never crash the loop
                self._rec("construct_nudge_error", error=f"{type(e).__name__}: {e}")
                cn = None
            if isinstance(cn, str) and cn.strip():
                st.construct_nudges += 1
                self._rec("construct_nudge", step=step, since=st.steps_since_construct,
                                    n=st.construct_nudges)
                messages.append({"role": "user", "content": cn})
                st.steps_since_construct = 0        # min-interval dedup: need another full streak to re-fire

        # SELF-REVIEW cadence (Rule 3): every ``self.self_review_interval`` steps, FORCE a metacognition
        # turn — assess goal state, working-vs-churned, whether to change trajectory, and whether a
        # "done"-looking state actually meets the finish criterion. Opt-in per loop (0 = off), so it runs
        # only on solver loops that request it — not the bounded sub-agents — and covers the "done but
        # not concluded" case the campaign retasker cannot see (campaign keys only on test_poc outcomes).
        # Fires at steps INTERVAL, 2·INTERVAL, … but NOT on the final step (max_steps), where the agent
        # can't act on the review before the loop ends — spending the decisive last turn on metacognition
        # would be waste.
        if (self.self_review_interval > 0 and step % self.self_review_interval == 0
                and step != self.max_steps):
            self._rec("self_review", step=step)
            messages.append({"role": "user", "content": render_self_review(step)})

    def _inject_guidance(self, st: "LoopState", messages: list, step: int,
                         full_adv_names: list[str]) -> list[str] | None:
        """Everything the loop pushes INTO the conversation before it sends, and nothing else.

        Eight independent "should the model be told something?" blocks — campaign context, the two
        auto-pushes, playbook, specialist constraints, the step/measure/construct nudges, and the
        advertised-tool rotation. They share only `st`, the message list and the step number, and
        none of them can end the run: the band is free of `return`, `break` and `continue`, which
        is what makes it separable at all.

        Returns the advertised tool names for THIS step, or None to keep the previous set — the
        one value the rest of the iteration reads back.
        """
        self._campaign_and_push(st, messages, step)
        self._cadence_nudges(st, messages, step)


        # Per-step tool advertisement (F4): when a resolver is wired, re-derive the advertised ≤6 slice
        # for THIS step so the tool list rotates with the campaign stage. A resolver that returns None
        # (or raises) leaves the previous advertisement in place — never traps the loop. With no resolver
        # ``tools`` stays the once-computed fixed list, so the default path is byte-for-byte unchanged.
        base_names: list[str] | None = full_adv_names   # the canonical advertised names for THIS step
        if self.tool_names_resolver is not None:
            try:
                resolved = self.tool_names_resolver(step)
            except Exception as e:   # a broken resolver must never crash the loop
                self._rec("tool_resolver_error", step=step, error=f"{type(e).__name__}: {e}")
                resolved = None
            if resolved is not None:
                base_names = list(resolved)
                adv_sig = ",".join(base_names)
                if adv_sig != st.adv_last:
                    self._rec("tools_advertised", step=step, tools=adv_sig)
                    st.adv_last = adv_sig
            else:
                base_names = None                       # resolver returned None → keep previous `tools`
        return base_names

    def _execute_calls(self, st: LoopState, step: int, messages: list[dict],
                       exec_calls: list) -> tuple[AgentResult | None, bool]:
        """Run every tool call this turn requested, append each result, and report whether the turn
        produced crash-PROGRESS. Returns `(early_result, progressed)`.

        `early_result` is not None only for the repeat-breaker, which STOPS the run mid-turn. Bubbling
        it rather than raising keeps `run`'s exits in one place: every way out of the loop is still a
        `return` written in `run` itself, which is what makes that function readable as a state machine.

        `progressed` is returned rather than parked on `st` deliberately. `LoopState` holds what
        survives an ITERATION; this value is born and consumed inside one, and putting it there would
        make a per-turn flag look like loop-carried state to the next reader.

        The four rejection arms come BEFORE `registry.call` and each one records its own journal event,
        because "the tool refused" and "the tool never ran" are different facts about a run. Only the
        executed `else` advances the read-counter — a rejected read must not disarm the enactment
        breaker, which is the loophole the breaker exists to close.
        """
        progressed = False                      # did THIS send yield new crash-progress? (stall-stop, lever ①)
        for tc in exec_calls:
            st.n_calls += 1
            # LEVER 2 — repeat-call circuit-breaker. Count byte-identical consecutive (name,args)
            # calls; ANY change to the signature resets the streak (and the one-shot advisory flag).
            sig = f"{tc.name}:{json.dumps(tc.arguments, sort_keys=True)}"
            if sig == st.repeat_sig:
                st.repeat_n += 1
            else:
                st.repeat_sig, st.repeat_n, st.repeat_advised = sig, 1, False

            # ITEM 1 (SECURITY) — ENFORCE the advertised toolset at EXECUTION, not just at
            # advertisement time. ``run()`` advertises ``openai_tools(self.tool_names)`` but the model
            # can emit ANY tool name; without this guard ``registry.call`` would happily execute an
            # UNADVERTISED tool. When ``tool_names`` is set (a RESTRICTED sub-context — specialist,
            # reproduce sub-loop, verify, oracle), a call to a tool outside that set (write_poc /
            # apply_patch / ask_specialist / git_*) is REJECTED here — never run — so "read + instrument
            # only" is a real capability boundary, not a prompt suggestion the model can step around by
            # naming a tool it was never offered. The rejection is fed back as the tool observation so
            # the model can recover. ``tool_names is None`` = advertise-all = NO restriction: the MAIN
            # solver loop passes None, so its execution path is byte-for-byte unchanged.
            _tool = self.registry.get(tc.name)
            # The enforcement set. With a rotating per-step resolver (F4) the CURRENT advertised slice
            # is only a window onto the wider set the agent may legitimately reach for, so enforce
            # against ``_allowed_union`` (the registry's full registered set) — a tool from a
            # neighbouring stage is ACCEPTED, only a genuinely-unregistered name is rejected. With no
            # resolver this is exactly ``self.tool_names``, so the default path is byte-identical.
            _enforce = self._allowed_union if self.tool_names_resolver is not None else self.tool_names
            if (self._enact_break_after > 0 and st.reads_since_progress >= self._enact_break_after
                    and (tc.name in self._enact_deny
                         or (tc.name == "run_bash" and _is_read_shaped_bash(tc.arguments)))):
                # Enactment breaker (L4): a tripped read tool — OR a read-shaped run_bash (cat/grep/sed, the
                # loophole GLM evaded through) — is REJECTED at execution. Advertisement-drop alone is not
                # authority (the model can still NAME a dropped tool / shell out to `cat`). A rejected call
                # does NOT run and does NOT advance the read-counter (only the executed ``else`` below does),
                # so the breaker HOLDS until a real construct/test re-arms it. A CONSTRUCTION run_bash
                # (writes ./poc/seeds, compiles, or runs a python generator) is NOT read-shaped and runs.
                self._rec("enactment_reject", key=sig, name=tc.name, reads=st.reads_since_progress)
                result = ToolResult(False, error=(
                    f"reads are DISABLED (including `cat`/`grep`/`sed` via run_bash) — you have inspected "
                    f"{st.reads_since_progress} calls without constructing or testing a candidate. Build an "
                    "input NOW: use_corpus / build_emit / emit_struct (or a run_bash that WRITES ./poc, e.g. "
                    "`python3 -c '...struct.pack...' > ./poc`), then test_poc."))
            elif _enforce is not None and tc.name not in _enforce:
                self._rec("tool_rejected", key=sig, name=tc.name)
                _hint = suggest_tool(tc.name, _enforce)   # nearest tool WITHIN the allowed set
                result = ToolResult(False, error=(
                    f"tool {tc.name!r} is not available in this context — you may only call: "
                    f"{', '.join(_enforce)}." + (f" Did you mean {_hint!r}?" if _hint else "")))
            elif _tool is None:
                # Unknown tool: reject with a "did you mean 'X'?" hint (Hermes-inspired, done better —
                # a single nearest suggestion, not just a catalogue re-dump) so a near-miss name
                # ("readFile"→"read_file") self-corrects in one turn instead of guessing.
                _hint = suggest_tool(tc.name, self.registry.names())
                self._rec("tool_unknown", key=sig, name=tc.name)
                result = ToolResult(False, error=(
                    f"unknown tool {tc.name!r}." + (f" Did you mean {_hint!r}?" if _hint else "")
                    + f" Available: {', '.join(self.registry.names())}"))
            elif (_bad := validate_call_args(_tool.args_schema, tc.arguments)) is not None:
                # Valid JSON but WRONG/MISSING args (the real native-FC failure mode Hermes leaves to
                # the handler): hand back ONE precise schema-grounded correction BEFORE dispatch, so the
                # model fixes it next turn instead of decoding a vague "bad args"/TypeError downstream.
                self._rec("tool_args_invalid", key=sig, name=tc.name, detail=_bad)
                result = ToolResult(False, error=f"{tc.name}: {_bad}")
            else:
                result = self.registry.call(tc.name, tc.arguments)
                # P0c: a test_poc call IS a measurement — reset the measure-cadence counter so an agent
                # that measures on its own is never nudged to (only an EXECUTED call is a measurement).
                if tc.name == "test_poc":
                    st.steps_since_test = 0
                # Only a genuine CONSTRUCT-AS-CODE / fuzz tool is PROGRESS toward reaching the sink and
                # resets the cadence. write_poc/apply_patch (hand-writing bytes) are EXCLUDED on purpose
                # — they're the behavior the nudge exists to correct, so a hand-write→test grind that
                # never reaches the sink keeps climbing and keeps getting nudged toward construction.
                if tc.name in CONSTRUCT_PROGRESS_TOOLS:
                    st.steps_since_construct = 0
                # Enactment breaker (L4) read-counter: a genuine test RE-ARMS (reset to 0); any OTHER
                # executed tool (a read, run_bash-cat, write_poc, instrument) EXTENDS the grind. Only
                # executed tools reach here — a rejected read (above) never counts. OFF (break_after=0) →
                # the counter still moves but is never read, so the hot path is behaviourally unchanged.
                # The re-arm additionally requires the call to have produced a REAL MEASUREMENT: naming
                # a re-arm tool is not enough, because `test_poc` with no ./poc (and `fuzz` with no
                # importable helper, and `batch_test` with no candidates) fails INSTANTLY without doing
                # any work — a free disarm, the same loophole class as 3d23765/d4e4db0. A real test that
                # reports `crashed: false` IS a measurement and still re-arms. See _is_enactment_measurement.
                if tc.name in self._enact_rearm and _is_enactment_measurement(result):
                    st.reads_since_progress = 0
                else:
                    st.reads_since_progress += 1
                # Stall-stop progress signal (lever ①): a progress-tool whose OUTCOME CLASS differs from
                # that tool's last outcome is NEW information toward a crash → resets the stall streak. A
                # repeat of the same outcome (incl. a new but non-crashing ./poc that only changes the
                # volatile output window) is NOT progress. Guarded on the lever being ON so the default
                # (lever-off) hot path skips the projection entirely. Only executed tools reach here.
                if self.stall_stop_after > 0 and tc.name in STALL_PROGRESS_TOOLS:
                    _psig = _stall_outcome_sig(result)
                    if st.progress_last.get(tc.name) != _psig:
                        st.progress_last[tc.name] = _psig
                        progressed = True
                # Feed the campaign its cross-turn signal (e.g. a test_poc crash + ./poc signature). The
                # hook is benchmark-specific and lives in the solver; a broken hook must never crash the
                # loop. Only an EXECUTED tool feeds the campaign (a rejected call carries no signal).
                if self.campaign_hook is not None:
                    try:
                        self.campaign_hook(tc.name, tc.arguments, result)
                    except Exception as e:
                        self._rec("campaign_hook_error", error=f"{type(e).__name__}: {e}")
            # Clamp the observation NON-DESTRUCTIVELY: shrink the biggest string values, never the tail
            # of the serialized text, so the envelope stays valid JSON and every scalar verdict field
            # (crash_rate / reliability / precision / sanitizer / crash_count) survives. A result that
            # already fits is serialized byte-for-byte as before. See ``clamp_observation``.
            obs = clamp_observation(result.to_dict(), self.max_obs_chars)
            self._record_source_observation(tc.name, tc.arguments, result, obs)

            # A byte-identical call returns a byte-identical observation — the model is stuck in a
            # no-progress loop the campaign stall-detector (test_poc-only) can't see. First WARN once
            # inside the observation (cheap self-recovery); if it STILL repeats to REPEAT_BREAK_AT,
            # hard-stop like a max_empty streak so the run stops re-billing a dead loop. The break
            # still appends this observation so the journal/history stay consistent.
            if st.repeat_n >= REPEAT_BREAK_AT:
                _log.warning("[%s] repeat-breaker STOPPING run: %s called with identical args %dx",
                             self.role, tc.name, st.repeat_n)
                self._rec("repeat_break", key=sig, n=st.repeat_n)
                messages.append({"role": "tool", "tool_call_id": tc.id, "name": tc.name, "content": obs})
                return self._result("repeat", step, st.n_calls, st.spent,
                                    f"stopped: {tc.name} called with identical args {st.repeat_n}x in a "
                                    f"row with no progress"), progressed
            if st.repeat_n >= REPEAT_ADVISORY_AT and not st.repeat_advised:
                st.repeat_advised = True
                self._rec("repeat_advisory", key=sig, n=st.repeat_n)
                obs = obs + "\n\n" + (
                    f"NOTE: you have called {tc.name} with identical arguments {st.repeat_n} times and it "
                    f"returns the SAME result each time. Change approach — different arguments, a "
                    f"different tool, or finish — or the run will be STOPPED.")

            self._rec("tool_result", key=sig, result=result.to_dict())
            idx = len(messages)
            messages.append({"role": "tool", "tool_call_id": tc.id, "name": tc.name, "content": obs})
            # Remember this call's args (keyed by message INDEX — the history is append-only, so the
            # index is a stable handle) so a later _compact can name what to re-run when it stubs this
            # observation. Capped: read-tool args are tiny; this only guards a pathological write.
            st.obs_args[idx] = json.dumps(tc.arguments, sort_keys=True)[:200]
        return None, progressed


    def _cap_tool_calls(self, res, messages: list[dict], step: int) -> tuple[list, bool]:
        """Bound one degenerate tool-call batch and keep its assistant message protocol-valid.

        Normal batches pass through unchanged. Above the cap, identical calls are deduplicated before
        the unique remainder is capped; the already-appended assistant message is trimmed by the same
        indices so every retained call receives exactly one tool response on the next request.

        Returns ``(calls_to_execute, was_capped)``. The caller owns the post-execution nudge because it
        must be appended after the retained tool responses, not while this decision is made.
        """
        if len(res.tool_calls) <= MAX_TOOLCALLS_PER_TURN:
            return res.tool_calls, False

        sigs = [f"{tc.name}:{json.dumps(tc.arguments, sort_keys=True)}" for tc in res.tool_calls]
        seen: set[str] = set()
        kept_idx: list[int] = []
        for i, sig in enumerate(sigs):
            if sig in seen:
                continue
            seen.add(sig)
            kept_idx.append(i)
            if len(kept_idx) >= MAX_TOOLCALLS_PER_TURN:
                break
        exec_calls = [res.tool_calls[i] for i in kept_idx]
        self._rec("toolcall_cap", step=step, original=len(res.tool_calls),
                  executed=len(exec_calls), unique=len(set(sigs)))

        assistant = messages[-1]
        raw_calls = assistant.get("tool_calls") if isinstance(assistant, dict) else None
        if isinstance(raw_calls, list) and len(raw_calls) == len(res.tool_calls):
            assistant["tool_calls"] = [raw_calls[i] for i in kept_idx]
        return exec_calls, True


    def run(self, goal: str) -> AgentResult:
        """Drive the loop to a terminal state, and give back any budget it was still holding.

        **The `finally` is the whole of this wrapper and it is not defensive tidiness.** The dollar
        guard CLAIMS headroom on the governor before each call (`_unaffordable_next_call`), and that
        governor is SHARED across the sub-loops the separate package fans out. A loop that returns while
        still holding a claim — every terminal path here is a `return`, and there are eleven of them —
        subtracts that claim from the ceiling for the rest of the run, for a call that will never be
        made. Releasing at each of the eleven is the arrangement that goes wrong when a twelfth is
        added; releasing here cannot be forgotten.
        """
        st = LoopState()
        try:
            return self._run(goal, st)
        finally:
            self._release_call(st)

    def _run(self, goal: str, st: LoopState) -> AgentResult:
        tools = self.registry.openai_tools(self.tool_names)
        full_adv_names = [t["function"]["name"] for t in tools]   # canonical no-resolver advertised set (L4 base)
        messages: list = [{"role": "system", "content": self.system},
                          {"role": "user", "content": goal}]
        # The per-LOOP enable state of the step-cadence levers. The run-level ``config`` cannot answer
        # "could this event's loop have fired self_review?" because the answer differs per loop within one
        # run, so it is recorded where it is actually known.
        self._rec("loop_start", max_steps=self.max_steps,
                  self_review_interval=self.self_review_interval,
                  enactment_break_after=self._enact_break_after)
        self._rec("goal", text=goal)

        for step in range(1, self.max_steps + 1):
            stopped = self._budget_stop(st, step)
            if stopped is not None:
                return stopped

            # Stall-triggered early-stop (INC-0 lever ①, opt-in): if this run has gone stall_stop_after
            # productive sends with no NEW progress toward a crash AND has already burned at least
            # stall_stop_min_pressure of its token budget, stop now rather than grinding to the hard cap. OFF
            # by default (stall_stop_after=0). pressure() is 0.0 with no token cap, so the min-pressure gate
            # also makes this inert without a metered budget. See the module STALL_PROGRESS_TOOLS note.
            if self.stall_stop_after > 0 and st.sends_since_progress >= self.stall_stop_after:
                pressure = self.governor.pressure("tokens") if self.governor is not None else 0.0
                if pressure >= self.stall_stop_min_pressure:
                    self._rec("stall_stop", step=step, since_progress=st.sends_since_progress,
                                        pressure=round(pressure, 4))
                    return self._result("stall", step - 1, st.n_calls, st.spent,
                                        f"stopped: {st.sends_since_progress} sends with no progress toward a "
                                        f"crash at {pressure:.0%} of the token budget")

            base_names = self._inject_guidance(st, messages, step, full_adv_names)

            # Enactment circuit-breaker (lever L4): once tripped, DROP the read tools from the advertised set
            # so the model is steered to construct, not read. Recomputed from ``base_names`` each step so a
            # RE-ARM restores the full set (an in-place filter would permanently shrink the no-resolver list).
            # OFF by default (enactment_break_after=0) → base_names carries the exact old advertisement and
            # `tools` is recomputed identically, so this path is byte-for-byte unchanged. Edge-logged.
            deny_active = self._enact_break_after > 0 and st.reads_since_progress >= self._enact_break_after
            if deny_active != st.enact_denied:
                self._rec("enactment_break" if deny_active else "enactment_rearm",
                                    step=step, reads=st.reads_since_progress)
                st.enact_denied = deny_active
            if base_names is not None:
                names = [n for n in base_names if not (deny_active and n in self._enact_deny)]
                tools = self.registry.openai_tools(names)

            # Stale-observation compaction (LEVER 3): at send-time, stub OLD large read observations so
            # this step's re-send of the whole history stops re-billing a step-N read on every later step.
            # THE CONTEXT CURVE, and until 2026-08-21 the whole of this loop's context telemetry was
            # the stub COUNT below. A compaction policy has a threshold, a keep-recent window and a
            # stub size, and none of them is tunable from "it fired 3 times" — while this repository's
            # own measurements put the transcript RE-SEND at the top of the cost table (`tools.py`: one
            # file read 64 times, 206,732 bytes retrieved for 1,479,494 tokens). Measured either side
            # of the compaction so `chars_before - chars_after` is what this call actually reclaimed
            # rather than a number inferred from two unrelated samples.
            #
            # CHARACTERS, not tokens: a tokenizer is a third-party dependency and the core is
            # dependency-free (the maintainers' notes). `shard/telemetry.py` carries the labelled estimate and its
            # divisor travels with the document, so a reader can recompute rather than trust it.
            before_chars = _context_chars(messages)
            compacted = self._compact(messages, st.obs_args)
            after_chars = _context_chars(messages) if compacted else before_chars
            if compacted:
                _log.debug("[%s] step %d: compaction stubbed %d observation(s)",
                           self.role, step, compacted)
                self._rec("context_compacted", step=step, stubbed=compacted,
                          chars_before=before_chars, chars_after=after_chars)
            # Recorded EVERY step, not only when a compaction fires. The question is how fast the
            # transcript grows between them, which is exactly the interval a compaction-only record
            # cannot see.
            self._rec("context_size", step=step, messages=len(messages), chars=after_chars)

            res, hit = self._send_and_bill(st, messages, tools, step)
            if hit:
                return self._meter_stop_result(hit, step, st)
            if not res.ok:
                # An empty-response streak is transient — retry the turn (same messages) rather than
                # killing the attempt. This is an outcome bit from the parser, never a substring in
                # provider-controlled error prose; any other error (bad key, 4xx, hard refusal) is terminal.
                if res.empty_retry_safe and st.empty < self.max_empty:
                    st.empty += 1
                    self._rec("empty_retry", n=st.empty, error=(res.error or "")[:200])
                    continue
                # A transport THROUGHPUT STALL is the same shape of transient as an empty turn, and used to
                # fall straight through to the terminal return below — the measured cost of that is in
                # `max_stall`'s note. Back off longer than the HTTP ladder already did (it is exhausted by
                # now) and re-send the SAME messages, so a recovered turn resumes with no lost context.
                if res.stall_retry_safe and st.stall_retries < self.max_stall:
                    st.stall_retries += 1
                    self._rec("stall_retry", n=st.stall_retries, error=(res.error or "")[:200])
                    self._sleep(self.stall_backoff * st.stall_retries)
                    continue
                self._rec("llm_error", error=res.error)
                return self._result("error", step - 1, st.n_calls, st.spent, res.error)
            st.empty = 0                               # a productive turn resets the streak
            st.stall_retries = 0                       # ...and so does it for the stall streak, so a long task
                                                    # survives repeated ISOLATED dips (the observed pattern)
                                                    # while a SUSTAINED outage still terminates in bounded time
            self._rec("assistant", text=(res.text or "")[:2000],
                                tool_calls=[tc.name for tc in res.tool_calls])

            # ``finish_reason=length`` invalidates the WHOLE turn, including a tool call whose prefix
            # happens to parse. Appending that assistant message leaves an unanswered partial call in
            # the next request; dispatching it lets truncation turn a model's prefix into a side effect.
            # Keep neither. The continuation is bounded, and exhausting the bound is an errored review,
            # never a clean finish over content the provider explicitly said was incomplete.
            if res.finish_reason == "length":
                if st.truncated < self.max_truncated:
                    st.truncated += 1
                    self._rec("truncated_turn", n=st.truncated)
                    messages.append({"role": "user", "content": (
                        "Your previous turn hit the token limit before finishing — continue and emit your "
                        "next tool call.")})
                    continue
                error = f"model hit the token limit {st.truncated + 1} consecutive times"
                self._rec("llm_error", error=error)
                return self._result("error", step, st.n_calls, st.spent, error)

            messages.append(res.raw_message or {"role": "assistant", "content": res.text})

            if not res.tool_calls:
                # No tools requested → the model is finishing. The gate may send it back to work.
                if self.finish_gate is not None:
                    try:
                        reason = self.finish_gate(res.text)
                    except Exception as e:  # a broken gate must never trap the agent
                        self._rec("finish_gate_error", error=f"{type(e).__name__}: {e}")
                        reason = None
                    if reason:
                        self._rec("finish_rejected", reason=str(reason)[:500])
                        messages.append({"role": "user", "content": str(reason)})
                        continue
                self._rec("final", text=(res.text or "")[:4000])
                return self._result("done", step, st.n_calls, st.spent, res.text or "")

            # Bound a degenerate in-turn batch before executing it. The helper also trims the assistant
            # protocol obligations to the retained subset; the nudge stays below, after their results.
            exec_calls, capped_turn = self._cap_tool_calls(res, messages, step)

            st.truncated = 0                           # a productive (tool-emitting) turn resets the streak
            # Execute every requested tool call; feed each back as a role:"tool" result. The turn's
            # own progress verdict comes back with it — see `_execute_calls`.
            early, progressed = self._execute_calls(st, step, messages, exec_calls)
            if early is not None:
                return early

            # If this turn was degeneration-capped, steer the model OUT of the loop. The tool responses for
            # the executed subset are already appended above; add a user nudge (mirrors the repeat_advisory
            # forcing-function) so the model STOPS repeating and commits to ONE next action rather than
            # re-emitting another giant batch. Injected after the tool results so the next turn sees them.
            if capped_turn:
                messages.append({"role": "user", "content": (
                    f"You emitted {len(res.tool_calls)} tool calls in ONE turn — only {len(exec_calls)} "
                    f"were executed; the rest were DROPPED. You appear to be repeating the same action (a "
                    f"degeneration loop). STOP: choose the SINGLE most useful next step and emit just that "
                    f"one tool call.")})

            # Stall-stop bookkeeping (lever ①): a send that produced new crash-progress resets the streak;
            # any other productive send (reads/greps/repeat outcomes) extends it. Evaluated per productive
            # (tool-emitting) send; the finish/empty/truncated paths above ``continue``/return before here.
            st.sends_since_progress = 0 if progressed else st.sends_since_progress + 1

        return self._result("maxsteps", self.max_steps, st.n_calls, st.spent, "reached max steps without finishing")

    def _compact(self, messages: list, obs_args: dict[int, str]) -> int:
        """Stub stale, re-derivable read observations in ``messages`` IN PLACE; return the count newly
        stubbed. Keeps the last ``self._compact_keep_recent`` tool observations verbatim (the TAIL, where a
        just-captured flag lands; defaults to the module ``COMPACT_KEEP_RECENT`` but is an injectable knob —
        INC-0 lever ③); the HEAD (system + goal) is never a ``role:"tool"`` message so it is
        untouched. A tool NOT in ``self._compact_read_tools`` (every crash-signal / oracle verdict) is
        kept verbatim at ANY age or size, as is anything in ``self._compact_never_tools`` (the hard
        invariant). Both sets are injectable (F6): the benchmark default is the module constants; kept
        injectable so a second solver could pass its own read set — today only the benchmark solver does.
        Idempotent — an already-stubbed body (starts with
        ``COMPACT_STUB_PREFIX``) is skipped, so calling this before every send neither re-bills nor
        double-wraps. See the module-level LEVER 3 note for WHY."""
        tool_idxs = [i for i, m in enumerate(messages)
                     if isinstance(m, dict) and m.get("role") == "tool"]
        keep = self._compact_keep_recent
        if len(tool_idxs) <= keep:
            return 0
        n = 0
        for i in tool_idxs[:-keep]:                         # everything older than the live window
            m = messages[i]
            body = m.get("content", "")
            name = m.get("name", "")
            if (not isinstance(body, str) or body.startswith(COMPACT_STUB_PREFIX)
                    or name in self._compact_never_tools or name not in self._compact_read_tools
                    or len(body) <= COMPACT_MIN_CHARS):
                continue
            first_line = body.split("\n", 1)[0][:200]
            m["content"] = (f"{COMPACT_STUB_PREFIX} {name}({obs_args.get(i, '')}) first_line={first_line!r} "
                            f"bytes={len(body)} — elided to reclaim context; re-run the tool to see full.")
            n += 1
        return n

    def _result(self, status: str, steps: int, n_calls: int, tokens: int, final_text: str,
                limit_hit: str = "") -> AgentResult:
        return AgentResult(status=status, final_text=final_text, steps=steps, tool_calls=n_calls,
                           tokens=tokens, journal_path=str(self.journal.path), limit_hit=limit_hit)
