"""Run telemetry — what the run DID, derived from the journal, safe to hand to a third party.

**THE GAP THIS CLOSES.** Before this module a finished run left three artefacts a customer could read
(`shard-report.md`, `shard.sarif`, `bundles/`) and one they could not (`shard_journal.jsonl`, which
carries the model's full reasoning prose and the full body of every tool result — i.e. excerpts of
their own source). Nothing said how long anything took, where the tokens went, or how the context
grew. Measured on a real run of the pinned canary, 2026-08-20:

    18 requests · 140,167 tokens · 450.9 seconds · 3 compactions · 49 steps

and the journal could not attribute one token or one second of that to a step. The whole context
telemetry for that run was three copies of ``{"type": "context_compacted", "stubbed": 1}``.

That matters here more than it would elsewhere, because this repository's own measurements say the
dominant cost term is the TRANSCRIPT RE-SEND: `tools.py` records one file read 64 times in windows six
lines apart, 206,732 bytes retrieved for 1,479,494 tokens. A compaction policy is tunable against a
growth curve and guessable against a count of three.

**DERIVED, NOT RECORDED IN PARALLEL — and that is the load-bearing decision.**

Everything here is a pure function of the journal's events. Nothing in this module is a second
recorder. Three things follow, and each of them is a defect this repository has already paid for
somewhere else:

* **One source of truth.** a maintenance script records the drift class in as many words: a rule
  transcribed a second time is a rule that agrees with the first by construction and then quietly
  stops. Telemetry that recorded its own events would be a second census of the same run, free to
  disagree with the journal about what happened.
* **Redaction happens ONCE.** The alternative is N call sites each remembering not to pass the file
  body, and the one that forgets is discovered by a customer. Here the rule is a single function with
  a default-deny shape, and the maintainers' suite drives a REAL journal through it.
* **It is deterministically testable with no LLM.** A fixture journal in, a document out.

**HONEST ABOUT WHAT IT COULD NOT SEE.** Every summary carries a ``gaps`` list. A journal written before
a field existed, or by a backend that reports no usage, yields an entry there rather than a zero —
the maintainers' notes, a zero indistinguishable from an unknown, which this project has
shipped at least twice (a `marker_refused` column of zeros over runs that wrote no journal; a gate
column that never fired reported as perfectly stable).
"""

from __future__ import annotations

import json
from typing import Any, Iterable

#: The document's shape. Bumped when a consumer would MISREAD an older file, not on every addition —
#: a new optional key is not a breaking change and a renamed one is.
SCHEMA = 1

#: Characters per token, for the ESTIMATE only. A real tokenizer is a third-party dependency and the
#: core is dependency-free by design (the maintainers' notes), so this module reports CHARACTERS as the measured
#: truth and tokens as a labelled estimate beside them. Every estimated field is named ``*_est_tokens``
#: and the divisor travels with the document, so a reader can recompute rather than trust it.
#:
#: 4 is the conventional English/code approximation. It is wrong per-file and adequate for a CURVE,
#: which is what it is for: the shape of context growth, not a bill. The bill comes from the provider's
#: own usage numbers, which are carried separately and unestimated wherever the backend reports them.
CHARS_PER_TOKEN = 4

#: Event fields that carry free text or tool payloads and NEVER appear in a redacted document.
#: A DENYLIST is the wrong shape for this and is deliberately not what the redactor uses — see
#: `_safe_args` and `summarise`, which build up from named fields instead. This tuple exists so the
#: test can assert the values behind these keys are absent from the emitted JSON by SEARCHING for
#: them, which is a check on the outcome rather than on the mechanism.
TEXT_FIELDS: tuple[str, ...] = ("text", "data", "error", "result", "goal", "final")


def _est_tokens(chars: int) -> int:
    return int(chars) // CHARS_PER_TOKEN


def _events(source: Any) -> list[dict]:
    """Journal events from a path, an open file, an iterable of lines, or a list of dicts.

    Tolerant on purpose: a run that was killed leaves a truncated last line, and `json.loads` accepts
    a bare string or number as valid JSON — so a line that parses to a non-dict must be skipped rather
    than reaching `.get` and raising. A maintenance script::marker_refusals` records the same defect
    and the same fix; this is the only other place that parses this file.
    """
    if isinstance(source, (list, tuple)) and (not source or isinstance(source[0], dict)):
        return [e for e in source if isinstance(e, dict)]
    if isinstance(source, (str, bytes)) or hasattr(source, "__fspath__"):
        import pathlib
        try:
            lines: Iterable[str] = pathlib.Path(source).read_text(
                encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return []
    else:
        lines = source
    out: list[dict] = []
    for line in lines:
        try:
            row = json.loads(line)
        except (ValueError, TypeError):
            continue
        if isinstance(row, dict):
            out.append(row)
    return out


def _tool_name(key: str) -> str:
    """``read_file:{"path": "x.py"}`` -> ``read_file``. The name is operational; the arguments are the
    customer's data and are described rather than quoted (see `_safe_args`)."""
    return (key or "").split(":", 1)[0] or "?"


def _safe_args(key: str) -> dict:
    """A tool call's arguments, DESCRIBED rather than quoted: ``{"path": "str[8]"}``.

    **The values are the thing that must not travel.** `read_file`'s `path` is a filename in the
    customer's repository, `grep`'s `pattern` is what we went looking for, and `run`'s `command` is a
    shell line that may quote their source. Names and shapes answer every operational question a log
    is for — which tools ran, with how many arguments, how big — without putting any of it in a file
    the customer may forward to a third-party observability stack.

    A customer who needs the values can retain the full journal on a direct CLI run with
    ``shard diff --journal-path <private-path>``. It never enters ``--out-dir``. This is the artefact
    that is safe by default, not the only artefact.
    """
    _, _, raw = (key or "").partition(":")
    if not raw:
        return {}
    try:
        args = json.loads(raw)
    except ValueError:
        return {"_unparsed": True}
    if not isinstance(args, dict):
        return {"_unparsed": True}
    out = {}
    for name, value in args.items():
        if isinstance(value, bool):
            out[str(name)] = "bool"
        elif isinstance(value, (int, float)):
            out[str(name)] = type(value).__name__          # a number is not content
        else:
            out[str(name)] = f"{type(value).__name__}[{len(str(value))}]"
    return out


def _result_shape(result: Any) -> tuple[bool, int]:
    """``(ok, bytes returned)`` for one tool result, without reading what it said."""
    if not isinstance(result, dict):
        return True, len(str(result or ""))
    ok = bool(result.get("ok", True))
    body = result.get("data")
    size = len(json.dumps(body, default=str)) if body is not None else 0
    size += len(str(result.get("error") or ""))
    return ok, size


def context_curve(events: Iterable[dict]) -> list[dict]:
    """Context size at every step that reported one, plus what each compaction reclaimed.

    **This is the deliverable the count of three could not be.** A compaction policy has a threshold,
    a keep-recent window and a stub size, and none of them is tunable from "it fired 3 times". The
    curve says how fast the transcript grows, whether a compaction actually reclaimed anything, and
    how quickly it grew back — which is the difference between a policy and a guess.

    ``chars`` is measured. ``est_tokens`` is `CHARS_PER_TOKEN` and is labelled everywhere it appears.
    A journal with no `context_size` events yields the compaction rows alone and a gap, never zeros.
    """
    curve: list[dict] = []
    last_chars: int | None = None
    for ev in events:
        kind = ev.get("type")
        if kind == "context_size":
            chars = int(ev.get("chars") or 0)
            row = {"step": ev.get("step"), "messages": ev.get("messages"), "chars": chars,
                   "est_tokens": _est_tokens(chars)}
            last_chars = chars
            curve.append(row)
        elif kind == "context_compacted":
            after = ev.get("chars_after")
            before = ev.get("chars_before", last_chars)
            row = {"step": ev.get("step"), "event": "compaction",
                   "stubbed": ev.get("stubbed"),
                   "chars_before": before, "chars_after": after}
            # RECLAIMED IS ONLY REPORTED WHEN BOTH SIDES WERE MEASURED. An older journal records the
            # stub COUNT and nothing else, and subtracting a missing number to get 0 would say the
            # compaction reclaimed nothing — a confident wrong answer where "not measured" is the
            # truth, which is precisely the trap this module's docstring names.
            if isinstance(before, int) and isinstance(after, int):
                row["reclaimed_chars"] = before - after
                row["reclaimed_est_tokens"] = _est_tokens(before - after)
                last_chars = after
            curve.append(row)
    return curve


def _tool_usage(events: list[dict]) -> dict[str, dict]:
    """The document's `tools` table — per-tool calls, failures, bytes returned, and argument shapes.

    The shapes come from `_safe_args` and keep the FIRST shape seen per argument name: a census of
    how each tool is called, never a record of what it was called with.
    """
    tools: dict[str, dict] = {}
    for ev in events:
        if ev.get("type") != "tool_result":
            continue
        name = _tool_name(ev.get("key", ""))
        ok, size = _result_shape(ev.get("result"))
        row = tools.setdefault(name, {"calls": 0, "failed": 0, "bytes_returned": 0, "args": {}})
        row["calls"] += 1
        row["failed"] += 0 if ok else 1
        row["bytes_returned"] += size
        for arg, shape in _safe_args(ev.get("key", "")).items():
            row["args"].setdefault(arg, shape)
    return tools


def _llm_usage(events: list[dict], gaps: list[str]) -> dict:
    """The document's `llm` section — request, token and latency totals from `llm_request` events.

    Empty when the journal carries no records, with the reason on `gaps`: the missing section IS the
    honest answer. Every derived field appears only when the inputs it needs were reported.
    """
    # PER-REQUEST TOKEN ACCOUNTING, when the journal carries it. `llm_request` is written by the
    # backend wrapper; a journal without it (an older run, or a backend reporting no usage — a
    # self-hosted vLLM, which `cli.py` calls "the guaranteed EU-residency path") produces a GAP rather
    # than a total of zero. A run that cost money and reports 0 tokens is worse than one that says it
    # does not know.
    reqs = [e for e in events if e.get("type") == "llm_request"]
    # NO `requests: 0` WHEN THERE ARE NO RECORDS. The run certainly made requests — it has assistant
    # turns — so a zero would be this module asserting something false about a run it could not see.
    # The gap below says "not measured" instead, which is the true statement.
    llm: dict = {"requests": len(reqs)} if reqs else {}
    if reqs:
        for field in ("input_tokens", "output_tokens", "cached_tokens", "total_tokens"):
            values = [int(r[field]) for r in reqs if isinstance(r.get(field), (int, float))]
            if values:
                llm[field] = sum(values)
        secs = [float(r["seconds"]) for r in reqs if isinstance(r.get("seconds"), (int, float))]
        if secs:
            llm["seconds_total"] = round(sum(secs), 2)
            llm["seconds_slowest"] = round(max(secs), 2)

        # **OUTPUT IS THE SLOW HALF, AND NOTHING REPORTED IT.** Input is prefilled in parallel; output
        # is decoded one token at a time, so a request's wall time tracks what the model WROTE and
        # barely tracks what it read. Without these two fields the totals cannot distinguish a run
        # that read a large context from one that generated a great deal of prose, and those have
        # entirely different fixes.
        #
        # Opened by the arms sweep (`corpora/arms-2026-08-20/`), where the two arms took 88.7 and
        # 31.0 seconds per request — complete separation, exact permutation p = 1/252 — while their
        # TOTAL tokens per request were 10,687 and 9,027, the faster arm using FEWER. Total volume
        # does not explain a 2.9x latency gap; composition would, and no field could say.
        #
        # `output_per_second` IS AN EFFECTIVE RATE AND NOT THE DECODER'S. `seconds` covers queueing
        # and prefill as well as decode, so this is a FLOOR on how fast the endpoint generates. Named
        # and documented that way because quoting it as the decode rate would be the confidently-wrong
        # number this module exists to refuse.
        out_tokens = llm.get("output_tokens")
        if isinstance(out_tokens, int) and reqs:
            llm["output_per_request"] = round(out_tokens / len(reqs), 1)
        if isinstance(out_tokens, int) and secs and sum(secs) > 0:
            llm["output_per_second"] = round(out_tokens / sum(secs), 1)
        token_gaps = sum(r.get("tokens_reported") is False for r in reqs)
        cost_gaps = sum(r.get("cost_reported") is False for r in reqs)
        if token_gaps:
            llm["token_unreported_requests"] = token_gaps
            gaps.append(f"token usage was not reported for {token_gaps} model request(s) — token "
                        "totals are a floor")
        if cost_gaps:
            llm["cost_unreported_requests"] = cost_gaps
            gaps.append(f"cost was not reported for {cost_gaps} model request(s) — dollar totals "
                        "are a floor")
    else:
        gaps.append("no per-request token accounting in this journal (no `llm_request` events) — "
                    "the run's total is in the report's cost line, but it cannot be attributed to a step")
    return llm


def _context_summary(events: list[dict], gaps: list[str]) -> dict:
    """The document's `context` section — compaction count, the growth curve, and the peak.

    The peak cluster appears only when the journal sampled sizes; otherwise the gap on `gaps` says
    the compaction count is known and the curve a policy would be tuned against is not.
    """
    curve = context_curve(events)
    sized = [r for r in curve if isinstance(r.get("chars"), int)]
    compactions = [r for r in curve if r.get("event") == "compaction"]
    context: dict = {"compactions": len(compactions), "curve": curve}
    if sized:
        peak = max(sized, key=lambda r: r["chars"])
        context |= {"peak_chars": peak["chars"], "peak_est_tokens": peak["est_tokens"],
                    "peak_at_step": peak["step"],
                    "peak_messages": peak.get("messages")}
    else:
        gaps.append("no context-size sampling in this journal (no `context_size` events) — the "
                    "compaction COUNT is known and the growth curve that would make a compaction "
                    "policy tunable is not")
    return context


def _run_summary(events: list[dict], gaps: list[str]) -> dict:
    """The document's `run` section — event and turn counts, wall span, and the named fields of the
    four one-shot records (`loop_start`, `simple_proposed`, `simple_adjudicated`, `simple_exec`).

    Copies KNOWN KEYS ONLY, so an old journal omits what it never recorded rather than defaulting
    it — and the two execution gaps at the end exist because that omission is honest but SILENT.
    """
    stamps = [e["ts"] for e in events if isinstance(e.get("ts"), (int, float))]
    steps = [e["step"] for e in events if isinstance(e.get("step"), int)]

    # **`journal_events` AND `model_turns` ARE DIFFERENT NUMBERS AND THE FIRST DRAFT CONFLATED THEM.**
    # The journal's `step` is a monotonic counter over EVERY event it records — tool results, summary
    # rows, compactions — and the loop's `max_steps` bounds MODEL TURNS. Rendering one against the
    # other printed `steps 49 of 40` on the first real journal: a ceiling apparently exceeded by 22%,
    # which is alarming, wrong, and exactly the confidently-wrong number this file's docstring says an
    # instrument must never produce. The loop's unit is the assistant turn, so that is what is counted
    # and that is what `max_steps` is shown against.
    run: dict = {"journal_events": len(events),
                 "model_turns": sum(1 for e in events if e.get("type") == "assistant"),
                 "last_journal_step": max(steps) if steps else 0}
    if len(stamps) > 1:
        run["wall_seconds"] = round(max(stamps) - min(stamps), 2)
    for kind, keys in (("loop_start", ("max_steps",)),
                       ("simple_proposed", ("status",)),
                       ("simple_adjudicated", ("findings", "gate_eligible")),
                       ("simple_exec", ("armed", "calls", "entry_calls", "shell_calls", "network",
                                        "budget", "refused", "exhausted", "spent"))):
        found = next((e for e in events if e.get("type") == kind), None)
        if found is None:
            continue
        bucket = {"loop_start": run, "simple_proposed": run,
                  "simple_adjudicated": run, "simple_exec": None}[kind]
        target = bucket if bucket is not None else {}
        for k in keys:
            if k in found:
                target[k] = found[k]
        # `simple_proposed.count` is CLAIMS PROPOSED, and it arrived here as a bare `count` sitting
        # beside `findings` — two numbers about different things, one of them named after nothing.
        # A claim is what the agent offered; a finding is what adjudication kept.
        if kind == "simple_proposed" and "count" in found:
            run["claims_proposed"] = found["count"]
        if kind == "simple_exec":
            run["execution"] = target

    if "execution" not in run:
        gaps.append("no `simple_exec` record — this run did not report whether the execution tools "
                    "were armed, which is not the same as their being off")
    elif "refused" not in run["execution"]:
        # THE SECOND SILENCE, one field along. A journal from before 2026-08-21 records `calls` and
        # `budget` and cannot say whether the ceiling DENIED anything — and a run cut off
        # mid-verification is exactly the case where that matters, because it is the one that put an
        # unchecked claim on a customer's report. The loop above keeps such a journal honest by
        # omitting the key, which is necessary and not sufficient: omission is SILENT, and a reader
        # asking "did the ceiling bind?" reads silence as "no".
        gaps.append("this journal predates the execution-budget bind signal — it cannot say whether "
                    "the ceiling refused a call, so `budget` and `calls` being equal does NOT mean "
                    "the run was cut short, nor that it was not")
    return run


def _attribute_wall_clock(run: dict, llm: dict, gaps: list[str]) -> None:
    """Writes `run["llm_share"]` — the model's share of the run's wall clock — in place.

    Only when BOTH halves are known; otherwise the reason lands on `gaps`, because a share computed
    from a missing half is a confidently-wrong zero.
    """
    # WHERE THE SECONDS WENT — the model, or this machine. Both halves were already recorded and
    # nothing divided them, so the one question a slow run actually raises could not be answered from
    # the artefact: is the endpoint slow, or is something local eating the run?
    #
    # It decides whether ANY local optimisation is worth doing. Measured over the ten arms samples
    # (`corpora/arms-2026-08-20/`): 8,928 seconds of wall across 168 model requests, 53.1s per
    # request — the endpoint is essentially the entire run, and a maintenance script executes 136 REAL
    # subprocesses in 14s, so local work is under a percent. A lever aimed at CPU there would land at
    # net zero, which this repository has done four times already.
    #
    # ONLY WHEN BOTH HALVES ARE KNOWN. A share computed from a missing numerator is 0.0, which reads
    # as "the model took no time" — the confidently-wrong number this module's docstring forbids.
    wall = run.get("wall_seconds")
    spent = llm.get("seconds_total")
    if isinstance(wall, (int, float)) and isinstance(spent, (int, float)) and wall > 0:
        run["llm_share"] = round(spent / wall, 3)
        # A SHARE ABOVE 1 IS AN INSTRUMENT FAULT, NOT A FAST RUN, and it is reported rather than
        # clamped. The loop is serial and `llm_request` seconds fall inside the journal's own span, so
        # the only ways to exceed it are overlapping requests or a clock that moved. Clamping to 1.0
        # would hide exactly the case a reader needs to distrust.
        if run["llm_share"] > 1.0:
            gaps.append(f"model seconds ({spent:,.0f}) exceed the journal's own span ({wall:,.0f}) — "
                        f"one of the two is wrong, so read neither as the run's cost")
    elif isinstance(wall, (int, float)):
        gaps.append("the split between model time and local time is unknown for this run (no "
                    "per-request seconds), so a slow run cannot be attributed to the endpoint or to "
                    "this machine")


def summarise(source: Any) -> dict:
    """The telemetry document: what the run did, with nothing in it the customer cannot forward.

    Pure. Takes a path, a file, lines, or already-parsed events — the maintainers' suite drives it
    with a REAL journal from a real run, because a fixture that does not look like the real thing tests
    the fixture (a maintenance script::payload_from` learned that the expensive way: both this project's
    measurement scripts shipped a parser that could not read indented JSON, and both their tests passed
    because both fed compact JSON).

    Each section of the document is one helper, and the call order below is the order the `gaps`
    list reports in — a helper that could not see its section appends there instead of inventing a
    zero, so the sequence is part of the artefact and is not free to reorder.
    """
    events = _events(source)
    gaps: list[str] = []
    if not events:
        return {"schema": SCHEMA, "chars_per_token": CHARS_PER_TOKEN, "run": {},
                "gaps": ["the journal was empty or unreadable"]}

    tools = _tool_usage(events)
    llm = _llm_usage(events, gaps)
    context = _context_summary(events, gaps)
    run = _run_summary(events, gaps)
    _attribute_wall_clock(run, llm, gaps)
    return {"schema": SCHEMA, "chars_per_token": CHARS_PER_TOKEN,
            "run": run, "llm": llm, "tools": tools, "context": context, "gaps": gaps}


def render_log(source: Any) -> str:
    """The human-readable operational log — what Shard did, in order, with sizes and timings.

    Same redaction as `summarise`, same source, and deliberately NOT a second traversal with its own
    opinions: it reads the document `summarise` produced plus the event order, so the two artefacts
    cannot disagree about a run.

    It is not `shard-report.md`. That file is about the CODE — what was found and whether it gates.
    This one is about the RUN — what it did, how long it took, where the context went. A reader
    debugging a slow or expensive review has been reaching for a file that does not discuss the run.
    """
    events = _events(source)
    doc = summarise(events)
    if not events:
        return "shard: no journal events — the run wrote nothing, or the file is unreadable.\n"

    out: list[str] = ["=" * 72, "SHARD RUN LOG", "=" * 72]
    run = doc.get("run", {})
    out.append(f"turns {run.get('model_turns', '?')}"
               + (f"/{run['max_steps']}" if "max_steps" in run else "")
               + f"   wall {run.get('wall_seconds', '?')}s"
               + f"   status {run.get('status', '?')}"
               + f"   ({run.get('journal_events', '?')} journal events)")
    llm = doc.get("llm", {})
    if llm.get("requests"):
        total = llm.get("total_tokens")
        out.append(f"llm   {llm['requests']} requests"
                   + (f"   {total:,} tokens" if isinstance(total, int) else "   tokens not reported")
                   + (f"   slowest {llm['seconds_slowest']}s" if "seconds_slowest" in llm else ""))
        # WHERE THE SECONDS WENT, in words, because this is the file somebody opens when a review took
        # too long and the number alone does not tell them which half to go and fix.
        share = run.get("llm_share")
        if isinstance(share, (int, float)):
            pct = share * 100
            verdict = ("waiting on the model endpoint — local speed is not this run's problem"
                       if share >= 0.9 else
                       "split between the endpoint and this machine" if share >= 0.5 else
                       "spent LOCALLY, not waiting on the model — look at this machine first")
            out.append(f"      {pct:.0f}% of the wall clock was {verdict}")
        # WHAT THE MODEL WROTE, which is what it was charged in TIME for. A reader looking at a slow
        # review needs to know whether the endpoint is slow or the agent is verbose, and the totals
        # above cannot tell them apart.
        if "output_per_request" in llm:
            rate = (f" at >={llm['output_per_second']:.0f} output tok/s"
                    if "output_per_second" in llm else "")
            out.append(f"      {llm['output_per_request']:,.0f} output tokens per request{rate}"
                       f"   (output is decoded serially; it is the half that costs wall clock)")
    ex = run.get("execution")
    if ex:
        out.append(f"exec  armed={ex.get('armed')}  {ex.get('calls', 0)} calls "
                   f"({ex.get('entry_calls', 0)} run_entry, {ex.get('shell_calls', 0)} shell)  "
                   f"network={ex.get('network')}")
        # **THE BIND, IN THE FILE A CUSTOMER OPENS WHEN A REVIEW LOOKS WRONG.** The machine document
        # carries `refused` either way; this line exists because a run cut short by the execution
        # ceiling produced claims it REASONED about rather than checked, and a reader deciding whether
        # to trust a non-gate-eligible finding needs that without parsing JSON.
        #
        # Three outcomes, three sentences, because the three states are not two: a journal that cannot
        # say is not a run that was not cut short. Absent -> say the artefact cannot tell; 0 -> say it
        # explicitly, since "the ceiling did not bind" is information a reader wants confirmed rather
        # than inferred from silence; >0 -> name the count and what it costs.
        refused = ex.get("refused")
        if refused is None:
            out.append("      the execution ceiling's bind signal is ABSENT from this run's journal — "
                       "whether it cut the run short is not recorded either way")
        elif refused:
            out.append(f"      CUT SHORT: the execution ceiling refused {refused} call(s). Some claim "
                       f"here was reasoned about rather than checked — treat any finding that is not "
                       f"gate-eligible as unconfirmed. Raising --max-steps raises this budget too")
        elif ex.get("spent"):
            # **THE THIRD STATE, AND ITS ABSENCE WAS THE DEFECT.** `refused == 0` used to select the
            # affirmative sentence below, which is true only if the model would have asked again. It
            # would not: it is handed `executions_left` on every tool result, so it stops at 0 rather
            # than being denied. Measured on a live run — 24 of 24 calls, `refused: 0`, the agent's
            # own last turn opening "I have no tool budget left" at model turn 20 of 40 — and the
            # customer was told the run was complete on all three surfaces.
            out.append(f"      SPENT IN FULL: every one of the {ex.get('budget')} executions was "
                       f"used and none was refused. The model is told how many remain, so it stops "
                       f"asking rather than being denied — treat this as a ceiling that MAY have cut "
                       f"the run short. Raising --max-steps raises this budget too")
        else:
            out.append("      the execution ceiling refused nothing and was not spent in full, so no "
                       "claim here was cut short by it")

    out += ["", "TOOLS", "-" * 72]
    for name, row in sorted(doc.get("tools", {}).items(), key=lambda kv: -kv[1]["calls"]):
        failed = f"  {row['failed']} failed" if row["failed"] else ""
        out.append(f"  {name:<18} {row['calls']:>3} calls   "
                   f"{row['bytes_returned']:>9,} bytes returned{failed}")

    ctx = doc.get("context", {})
    out += ["", "CONTEXT", "-" * 72]
    if "peak_chars" in ctx:
        out.append(f"  peak {ctx['peak_chars']:,} chars (~{ctx['peak_est_tokens']:,} est tokens) "
                   f"at step {ctx['peak_at_step']}")
    out.append(f"  {ctx.get('compactions', 0)} compaction(s)")
    for row in ctx.get("curve", []):
        if row.get("event") != "compaction":
            continue
        reclaimed = row.get("reclaimed_chars")
        out.append(f"    step {row.get('step')}: stubbed {row.get('stubbed')}"
                   + (f", reclaimed {reclaimed:,} chars" if isinstance(reclaimed, int)
                      else ", amount reclaimed NOT MEASURED"))

    if doc.get("gaps"):
        out += ["", "WHAT THIS RUN COULD NOT MEASURE", "-" * 72]
        out += [f"  - {g}" for g in doc["gaps"]]

    out += ["", "=" * 72,
            "Arguments and tool output are described, never quoted: this file is safe to forward.",
            "Direct CLI only: retain a full transcript with "
            "shard diff --journal-path <private-path>.", ""]
    return "\n".join(out)


__all__ = ["CHARS_PER_TOKEN", "SCHEMA", "TEXT_FIELDS", "context_curve", "render_log", "summarise"]
