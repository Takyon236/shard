
from __future__ import annotations

import hashlib
import json
import pathlib
import os
import re
import shlex
import stat
import subprocess
import urllib.parse
from dataclasses import dataclass, fields

from shard.inspectionview import markdown as inspection_markdown
from shard.witness import observed_location

from shard.artefactfs import (atomic_write as _atomic_write,
                              trusted_directory as _trusted_directory)
from shard.target import HARNESS_NAME
from shard.diffscope import prompt_safe, safe_directory_argv
from shard import crashstate

DEFAULT_SARIF_CAP = 500

_EVIDENCE_IN_REPORT = 1200

COMPLETED_STATUSES = frozenset({"done", "audited"})

TRANSPORT_ERROR_ADVICE: dict[str, str] = {
    "auth": "your model endpoint **rejected the credential**. This is not a result about your code: "
            "the run stopped because it could no longer call the model. Check that the secret named by "
            "`api_key_env` is present, unexpired and authorised for the model you asked for",
    "credit": "your model endpoint **refused the call for billing reasons** — an exhausted balance or "
              "quota. The run stopped there, so its counts are a floor and say nothing about your code",
    "rate": "your model endpoint **rate-limited this run** for longer than its retry ladder allows. "
            "Re-running usually succeeds; a scheduled scan that hits this repeatedly is asking the "
            "endpoint for more concurrency than your account is provisioned for",
    "model": "your model endpoint **would not serve the requested model**. Check the `model` input "
             "against the identifiers your provider actually offers — a typo here stops the run "
             "before it reads a single file",
    "stall": "your model endpoint **stopped sending data mid-response** and did not recover within "
             "this run's retry ladder. That is an outage on the inference side, not a fault in your "
             "repository",
    "upstream": "your model endpoint **returned a server error** that outlasted this run's retries. "
                "That is an outage on the inference side, not a fault in your repository",
}


def _advice_sentence(advice: str) -> str:
    plain = advice.replace("**", "")
    opener = plain.split(" ", 1)[0].rstrip(",;:")
    prose = opener.isalpha() and opener.islower()
    return (plain[:1].upper() + plain[1:] if prose else plain) + "."


_SAFE_TOKEN = re.compile(r"[A-Za-z0-9_-][A-Za-z0-9._-]{0,63}")

ANCHOR_DISCLAIMER = (
    "An alert here names the entry point that REPRODUCES the defect, not the line at fault: Shard "
    "resolves a reproduction, not a source location, and a guessed line would be a false positive in "
    "the worst possible place. What the run observed is quoted with the finding.")

ANCHOR_CLAUSE = "filed against the entry point that reproduces it, not the line at fault"


REPORT_ID_DIGITS = 6

UNNUMBERED_REPORT_ID = "0" * REPORT_ID_DIGITS


def report_id(env) -> str:
    raw = str((env or {}).get("GITHUB_RUN_NUMBER") or "").strip()
    if not raw.isdigit():
        return UNNUMBERED_REPORT_ID
    number = int(raw)
    if number <= 0:
        return UNNUMBERED_REPORT_ID
    ident = str(number).zfill(REPORT_ID_DIGITS)
    attempt = str((env or {}).get("GITHUB_RUN_ATTEMPT") or "").strip()
    if attempt.isdigit() and int(attempt) > 1:
        ident = f"{ident}.{int(attempt)}"
    return ident


def is_numbered(ident: str) -> bool:
    return bool(ident) and ident != UNNUMBERED_REPORT_ID


def report_label(ident: str, target: str = "", *, quoted: bool = True) -> str:
    head = f"[Shard-report][{ident or UNNUMBERED_REPORT_ID}]"
    if not target:
        return head
    return f"{head} `{target}`" if quoted else f"{head} {target}"


SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

TOOL_NAME = "Shard"



def _utf8_safe(text: str) -> str:
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return text.encode("utf-8", "replace").decode("utf-8")
    return text


@dataclass(frozen=True)
class Finding:

    rule_id: str
    title: str
    message: str
    gate_eligible: bool
    location: str
    line: int = 1
    rule_title: str = ""
    location_is_harness: bool = False
    location_measured: bool = False
    caller_note: str = ""
    caller_rows: tuple[str, ...] = ()
    attribution: str = "unattributed"
    attribution_reason: str = ""
    witness_refused: str = ""
    signature: str = ""
    sanitizer: str | None = None
    replays: int = 0
    crash_count: int = 0
    doubts: tuple[str, ...] = ()
    poc_path: str | None = None
    poc_bytes: bytes | None = None
    reproduce_command: str = ""
    revision: str = ""
    container_digest: str = ""
    evidence: str = ""
    witness_expectation: str = ""
    witness_marker: str = ""
    witness_entry: str = ""
    witness_controls: tuple[str, ...] = ()
    seq: int = 0

    def __post_init__(self) -> None:
        for spec in fields(self):
            if spec.name == "poc_path":
                continue
            value = getattr(self, spec.name)
            if isinstance(value, str):
                clean: object = _utf8_safe(value)
            elif isinstance(value, tuple):
                clean = tuple(_utf8_safe(v) if isinstance(v, str) else v for v in value)
            else:
                continue
            if clean != value:
                object.__setattr__(self, spec.name, clean)

    @property
    def level(self) -> str:
        return "error" if self.gate_eligible else "note"

    @property
    def crash(self) -> crashstate.CrashState:
        return crashstate.classify(self.evidence, self.sanitizer)

    @property
    def fingerprint(self) -> str:
        if self.signature and _SAFE_TOKEN.fullmatch(self.signature):
            return self.signature
        seed = self.signature or f"{self.rule_id}\x00{self.location}\x00{self.title}"
        return hashlib.sha256(seed.encode()).hexdigest()[:16]


def rank(findings) -> list[Finding]:
    return sorted(findings,
                  key=lambda f: (not f.gate_eligible, -f.crash_count, -f.replays, f.seq, f.fingerprint))


def cap(findings, limit: int = DEFAULT_SARIF_CAP) -> tuple[list[Finding], int]:
    ordered = rank(findings)
    return ordered[:limit], max(0, len(ordered) - limit)


def finding_names(findings) -> list[str]:
    fingerprints = [f.fingerprint for f in findings]
    reserved = set(fingerprints)
    used: set[str] = set()
    next_suffix: dict[str, int] = {}
    names: list[str] = []
    for fingerprint in fingerprints:
        if fingerprint not in used:
            name = fingerprint
        else:
            suffix = next_suffix.get(fingerprint, 2)
            name = f"{fingerprint}-{suffix}"
            while name in reserved or name in used:
                suffix += 1
                name = f"{fingerprint}-{suffix}"
            next_suffix[fingerprint] = suffix + 1
        used.add(name)
        names.append(name)
    return names



def build_sarif(findings, *, limit: int = DEFAULT_SARIF_CAP, status: str = "done") -> dict:
    kept, _dropped = cap(findings, limit)
    by_rule: dict[str, list] = {}
    for f in kept:
        by_rule.setdefault(f.rule_id, []).append(f)
    rules, seen = [], set()
    for f in kept:
        if f.rule_id in seen:
            continue
        seen.add(f.rule_id)
        rule: dict = {
            "id": f.rule_id,
            "name": f.rule_id,
            "shortDescription": {"text": f.rule_title or f.title},
            "defaultConfiguration": {
                "level": "error" if _rule_all_reproduced(by_rule[f.rule_id]) else "note"},
        }
        rule["properties"] = _rule_properties(by_rule[f.rule_id])
        if any(x.location_is_harness for x in by_rule[f.rule_id]):
            rule["fullDescription"] = {"text": ANCHOR_DISCLAIMER}
        rules.append(rule)
    finished = status in COMPLETED_STATUSES
    invocation: dict = {"executionSuccessful": finished}
    if not finished:
        invocation["toolExecutionNotifications"] = [{
            "level": "error",
            "message": {"text": f"Shard stopped before completing this audit (status: {status}). "
                                f"The absence of findings below is not a clean result."},
        }]
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {"driver": {"name": TOOL_NAME, "rules": rules}},
            "invocations": [invocation],
            "results": [_sarif_result(f) for f in kept],
        }],
    }


def _rule_all_reproduced(group) -> bool:
    return all(f.gate_eligible for f in group)


def _rule_properties(group: "list[Finding]") -> dict:
    states = [f.crash for f in group]
    common = set(states[0].tags).intersection(*(set(s.tags) for s in states[1:])) if states else set()
    props: dict = {
        "tags": [tag for tag in states[0].tags if tag in common] if states else [],
        "problem.severity": "error" if _rule_all_reproduced(group) else "recommendation",
        "precision": "very-high" if _rule_all_reproduced(group) else "medium",
    }
    severities = {s.security_severity for s in states if s.security_severity}
    if len(severities) == 1 and len(severities) == len({s.security_severity for s in states}):
        props["security-severity"] = severities.pop()
    return props


_EVIDENCE_IN_SARIF = 300


def _sarif_message(f: Finding) -> str:
    first = (f.evidence or "").strip().splitlines()
    text = f.message if not first else f"{f.message} Observed: {first[0][:_EVIDENCE_IN_SARIF]}"
    if f.location_is_harness:
        text += f" ({ANCHOR_CLAUSE})"
    return text


def _sarif_result(f: Finding) -> dict:
    return {
        "ruleId": f.rule_id,
        "level": f.level,
        "message": {"text": _sarif_message(f)},
        "partialFingerprints": {"shardCrashSignature": f.crash.signature or f.fingerprint},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": urllib.parse.quote(f.location, safe="/")},
                "region": {"startLine": max(1, f.line)},
            },
        }],
    }


def write_sarif(findings, path, *, limit: int = DEFAULT_SARIF_CAP, status: str = "done") -> int:
    kept, dropped = cap(findings, limit)
    pathlib.Path(path).write_text(json.dumps(build_sarif(kept, limit=limit, status=status), indent=2),
                                  encoding="utf-8")
    return dropped



@dataclass(frozen=True)
class RunFacts:

    executions_spent: bool | None = None
    base_ref: str = ""
    files_reviewed: int | None = None
    witness_entry: str = ""
    fail_on: str = ""
    scan: str = ""
    scan_why: str = ""
    target_files: int | None = None
    target_bytes: int | None = None
    target_languages: tuple[str, ...] = ()
    target_truncated: bool = False
    limit_hit: str = ""
    step_flag: str = ""
    error_kind: str = ""
    exec_refused: int | None = None
    exec_calls: int | None = None
    report_id: str = ""
    usd: float | None = None
    tokens: float | None = None
    seconds: float | None = None
    unavailable_levers: tuple[str, ...] = ()
    levers_image_bound: bool | None = None
    stateful: bool | None = None
    inspection: dict | None = None
    library: dict | None = None


def _human_bytes(n: int | None) -> str:
    if not n:
        return ""
    step = 1024.0
    size = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if size < step or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= step
    return f"{size:.1f} GB"


def _language_summary(langs: tuple[str, ...]) -> str:
    if not langs:
        return "no source detected"
    if len(langs) <= 4:
        return ", ".join(langs)
    return ", ".join(langs[:3]) + f", +{len(langs) - 3} more"


def _trust_row(status: str, *, executions_spent: bool | None = None) -> str:
    if status in COMPLETED_STATUSES and executions_spent:
        return (f"**complete status (`{status}`), SPENT EXECUTION BUDGET** — every execution the "
                f"ceiling allowed was used, so this run may have stopped early: **treat any finding "
                f"here that is not gate-eligible as unconfirmed**. Raise `--max-steps`")
    if status in COMPLETED_STATUSES:
        return f"complete run (`{status}`)"
    return (f"**INCOMPLETE (`{status}`) — the counts below are a floor, not a result.** "
            f"A run cut short reports what it happened to reach")


def _duration(seconds: float) -> str:
    seconds = max(0.0, float(seconds))
    if seconds < 60:
        return f"{seconds:.0f}s"
    minutes, secs = divmod(int(round(seconds)), 60)
    if minutes < 60:
        return f"{minutes}m {secs:02d}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes:02d}m"


def _observed(run: RunFacts) -> tuple[str, str] | None:
    if run.exec_calls is None:
        return None
    if run.exec_calls:
        return ("observed",
                f"the agent ran **{run.exec_calls}** command(s) in this checkout while forming these "
                f"claims. That is investigation, not adjudication — a finding is only gate-eligible "
                f"when the row above re-ran it afterwards, against controls")
    return ("observed", "the agent could run code here and **never did**, so every claim below was "
                        "reasoned from reading alone")


def _stopped_by(status: str, run: RunFacts) -> tuple[str, str] | None:
    stopped = run.limit_hit or ("steps" if status == "maxsteps" else "")
    if stopped:
        raise_flag = {"wall_seconds": "--max-minutes", "tokens": "--max-tokens",
                      "usd": "--max-spend-usd", "steps": run.step_flag}.get(stopped, "")
        advice = (f"raise `{raise_flag}` to let it run further" if raise_flag else
                  "and this mode has no argument that raises it, so nothing you could have passed would "
                  "have made this run go further")
        return ("stopped by", f"the **{stopped}** ceiling — {advice}. The other ceilings were not "
                              f"what bound this run")
    if status == "error" and run.error_kind:
        return ("stopped by", TRANSPORT_ERROR_ADVICE.get(
            run.error_kind, f"a transport failure this product does not classify (`{run.error_kind}`)"))
    return None


def _summary_table(findings, *, status: str, run: RunFacts | None,
                   gate_reasons=(), scope_reasons=()) -> list[str]:
    reproduced = sum(1 for f in findings if f.gate_eligible)
    hypotheses = len(findings) - reproduced
    if reproduced:
        verdict = f"**{reproduced} finding(s) with a reproduction attached**"
        if hypotheses:
            verdict += f", {hypotheses} hypothesis(es)"
    elif hypotheses:
        verdict = f"**{hypotheses} hypothesis(es), none reproduced** — nothing here can fail a build"
    else:
        verdict = "**no findings**"

    rows = [("verdict", verdict),
            ("trust", _trust_row(status,
                                 executions_spent=run.executions_spent if run else None))]
    degraded = len(gate_reasons) + len(scope_reasons)
    if degraded:
        rows.append(("caveats", f"**{degraded} — see below.** The run answered less than it looks"))

    run = run or RunFacts()
    if run.target_files is not None:
        least = "≥" if run.target_truncated else ""
        size = f" · {least}{_human_bytes(run.target_bytes)}" if run.target_bytes else ""
        floor = (" — **the walk stopped at its file ceiling, so these are floors**"
                 if run.target_truncated else "")
        rows.append(("repository", f"{least}{run.target_files:,} source file(s){size} · "
                                   f"{_language_summary(run.target_languages)}{floor}"))
    if run.scan:
        incomplete = status not in COMPLETED_STATUSES
        caveat = (" — **this baseline is unfinished, so a later follow-up has nothing sound to be "
                  "measured against; re-run it before relying on one**"
                  if incomplete and run.scan == "initial" else "")
        rows.append(("scan", f"`{run.scan}` — {run.scan_why}{caveat}"))
    stopped_row = _stopped_by(status, run)
    if stopped_row:
        rows.append(stopped_row)
    if run.exec_refused:
        rows.append(("verification cut short",
                     f"the execution budget refused **{run.exec_refused}** call(s), so some claim in "
                     f"this report was reasoned about rather than checked — **treat any finding here "
                     f"that is not gate-eligible as unconfirmed**. The budget is sized from the step "
                     f"ceiling, so raising `--max-steps` raises it too"))
    if run.files_reviewed is not None:
        against = f" against `{run.base_ref}`" if run.base_ref else ""
        rows.append(("scope", f"{run.files_reviewed} changed file(s){against}"))
    if run.fail_on:
        gate = {"none": "`none` — report only, this run could not fail the build",
                "reproduced": "`reproduced` — a demonstrated finding fails the build",
                "new": "`new` — a demonstrated finding this change introduced fails the build",
                }.get(run.fail_on, f"`{run.fail_on}`")
        rows.append(("gate", f"{gate}; {reproduced} gate-eligible"))
    rows.append(("witness", f"`{run.witness_entry}`" if run.witness_entry else
                 "**none declared — nothing in this run could be proven by execution**"))
    observed_row = _observed(run)
    if observed_row:
        rows.append(observed_row)
    if run.unavailable_levers:
        names = ", ".join(f"`{n}`" for n in run.unavailable_levers)
        if run.levers_image_bound is False:
            rows.append(("levers", f"{len(run.unavailable_levers)} not applicable to this target — "
                                   f"{names}. These attach to a PREBUILT vulnerable image, which an "
                                   f"ordinary repository does not carry, so they would not have run "
                                   f"here on any machine. This run took the prepared-harness route, "
                                   f"where your `test_poc.sh` builds the target with this machine's "
                                   f"own toolchain. A larger runner would not change this"))
        elif run.levers_image_bound:
            rows.append(("levers", f"**{len(run.unavailable_levers)} could not run on this machine** — "
                                   f"{names}. This workdir carries a vulnerable image they attach to, "
                                   f"so they would have registered had a docker daemon answered. This "
                                   f"run had less leverage than one with them"))
        else:
            rows.append(("levers", f"{len(run.unavailable_levers)} did not run — {names}. No docker "
                                   f"daemon answered. Whether this target could have used them was "
                                   f"not established"))
    if run.usd is not None or run.tokens is not None or run.seconds is not None:
        cost = []
        if run.usd is not None:
            cost.append(f"${run.usd:,.4f}")
        if run.tokens is not None:
            cost.append(f"{run.tokens:,.0f} tokens")
        if run.seconds is not None:
            cost.append(_duration(run.seconds))
        rows.append(("cost", ", ".join(cost)))

    return _table(rows)


def _table(rows) -> list[str]:
    out = ["| | |", "|---|---|"]
    out += [f"| {name} | {value} |" for name, value in rows]
    return out + [""]


SURVEY_CANDIDATES_IN_REPORT = 20


def _survey_where(ranked) -> str:
    total = len(ranked)
    listed = min(total, SURVEY_CANDIDATES_IN_REPORT)
    where_the_rest_is = (
        "`shard-survey.json`, written beside this report, carries the same ordering under its OWN "
        "larger cap, with each candidate's kind and matched line; read its `omitted` for how many "
        "fell below that one")
    if not listed:
        return "**this report counts; it names no file.** Nothing was ranked"
    if listed == total:
        return f"**all {total} candidate(s) are listed below, with path and line.** {where_the_rest_is}"
    if ranked[listed - 1].rank == ranked[listed].rank:
        return (f"**{listed} of {total} candidates are listed below, with path and line — a SAMPLE, "
                f"not the top of a ranking.** The cut falls inside a tie: the {listed}th and the first "
                f"one left out carry the same rank, so nothing in this block outranks what is missing "
                f"from it, and reading it as *where the attack surface is* would be wrong. "
                f"{where_the_rest_is}")
    return (f"**the {listed} highest-ranked of {total} candidates are listed below, with path and "
            f"line** — a sample; the rank separates them from the {total - listed} not shown. "
            f"{where_the_rest_is}")


def _survey_candidates(ranked) -> list[str]:
    body = "\n".join(f"{r.rank:<11}{r.surface.kind:<16}{prompt_safe(r.surface.path)}:{r.surface.line}"
                     for r in ranked[:SURVEY_CANDIDATES_IN_REPORT])
    fence = _fence_for(body)
    return [fence, body, fence, ""]


def _survey_trust(truncated: bool, partial_files: int) -> str:
    if truncated and partial_files:
        return (f"**TRUNCATED — every count below is a floor.** The scan hit its file ceiling before "
                f"the repository ended, and {partial_files} of the files it did reach were read only "
                f"in part")
    if truncated:
        return ("**TRUNCATED — every count below is a floor.** The scan hit its own limit before the "
                "repository ended")
    if partial_files:
        return (f"**a floor for {partial_files} file(s), complete for the rest.** Those {partial_files} "
                f"were read only in part — past the byte or the per-file candidate ceiling the scan "
                f"stops, so a marker beyond it was never reached rather than absent. The blind spots "
                f"below name both ceilings")
    return "complete scan"


def build_survey_markdown(summary: str, *, target: str = "", truncated: bool = False,
                          report_ident: str = "", ranked=(), partial_files: int = 0,
                          witness_entry: str = "") -> str:
    verdict = ("**survey only — nothing here is a finding.** A survey reads the source and names "
               "candidates; proving one takes a run that can execute something")
    rows = [("verdict", verdict), ("trust", _survey_trust(truncated, partial_files)),
            ("where", _survey_where(ranked)),
            ("witness", f"`{witness_entry}`" if witness_entry else
             "**none declared — nothing in this repository could be proven by execution**")]

    heading = (f"## {report_label(report_ident, target)}" if is_numbered(report_ident)
               else (f"## Shard — `{target}`" if target else "## Shard"))
    out = [heading, ""] + _table(rows)
    fence = _fence_for(summary)
    out += [fence, summary, fence, ""]
    if ranked:
        out += _survey_candidates(ranked)
    if not witness_entry:
        out.append("**To make any of this provable, declare an entry point.** A file at "
                   "`.shard/entry.sh` that Shard may run against one untrusted input, and a "
                   "`.shard/entry.sh.benign/` directory of inputs containing no attack, one per "
                   "branch the entry point can take. Without it every candidate in "
                   "`shard-survey.json` stays a candidate and nothing can fail a build.")
        out.append("")
    return "\n".join(out) + "\n"


def _library_markdown(library: dict | None) -> list[str]:
    if library is None:
        return []
    state = _inline_code(prompt_safe(library["state"]))
    policy = _inline_code(prompt_safe(library["policy"]))
    snapshot = library["snapshot"]
    out = ["### Library", "", f"State: {state}. Policy: {policy}.", "",
           f"Verified snapshot: {_inline_code(str(snapshot)) if snapshot is not None else 'none'}.",
           ""]
    if not library["packs"]:
        return out + ["No accepted packs; the image's built-in baseline was used.", ""]
    out += ["Accepted packs:", ""]
    for pack in library["packs"]:
        label = f'{pack["name"]}@{pack["version"]}'
        label = _inline_code(prompt_safe(label, limit=len(label)))
        digest = str(pack["blob_digest"])
        digest = _inline_code(prompt_safe(digest, limit=len(digest)))
        out.append(f"- {label}: {digest}")
    return out + [""]


def build_markdown(findings, *, status: str, dropped: int = 0, target: str = "",
                   gate_reasons=(), scope_reasons=(), run: RunFacts | None = None,
                   bundle_names: dict[int, str] | None = None) -> str:
    ordered, _capped = cap(findings)
    derived = finding_names(ordered)
    named = [(f, (bundle_names or {}).get(id(f), name))
             for f, name in zip(ordered, derived)]
    reproduced = [pair for pair in named if pair[0].gate_eligible]
    hypotheses = [pair for pair in named if not pair[0].gate_eligible]

    out = [(f"## {report_label(run.report_id, target)}" if run and is_numbered(run.report_id)
            else (f"## Shard — `{target}`" if target else "## Shard")), ""]
    out += _summary_table(findings, status=status, run=run,
                          gate_reasons=gate_reasons, scope_reasons=scope_reasons)
    out += _library_markdown(getattr(run, "library", None))

    for reason in gate_reasons:
        out += [f"> **{reason}**", ""]
    for reason in scope_reasons:
        out += [f"> **{reason}**", ""]

    if run and run.inspection is not None:
        out += inspection_markdown(run.inspection)
    if not ordered:
        out.append(_no_finding_paragraph(status, run.error_kind if run else ""))
        return "\n".join(out) + "\n"

    anchored = [f for f in ordered if f.location_is_harness]
    if anchored:
        where = anchored[0].location or (run.witness_entry if run else "")
        out += [f"> These alerts are filed against `{where}` because it is the entry point that "
                f"reproduces them — **not because the defect is in it**. {ANCHOR_DISCLAIMER}",
                ""]

    for f, name in reproduced:
        out += _finding_block(f, reproduced=True, bundle=name)
    for f, name in hypotheses:
        out += _finding_block(f, reproduced=False, bundle=name)

    if dropped:
        out.append(f"_{dropped} further finding(s) were ranked below the reporting cap and omitted._")
        out.append("")
    return "\n".join(out) + "\n"


def _no_finding_paragraph(status: str, error_kind: str = "") -> str:
    if status in COMPLETED_STATUSES:
        return ("Shard audited this target and produced no reproducing input. That is a statement "
                "about this run, not a proof that the target is free of defects.")
    because = ""
    if status == "error" and error_kind in TRANSPORT_ERROR_ADVICE:
        because = " " + _advice_sentence(TRANSPORT_ERROR_ADVICE[error_kind])
    return (f"Shard did not complete a full audit of this target (`{status}`), and produced no "
            f"reproducing input. Treat this as an incomplete run rather than a clean result.{because}")


_BACKTICKS = re.compile(r"`+")


def _fence_for(*parts: str) -> str:
    longest = max((len(m.group()) for part in parts if part for m in _BACKTICKS.finditer(part)),
                  default=0)
    return "`" * max(3, longest + 1)


def _inline_code(text: str) -> str:
    ticks = "`" * (max((len(m.group()) for m in _BACKTICKS.finditer(text)), default=0) + 1)
    pad = " " if text.startswith("`") or text.endswith("`") else ""
    return f"{ticks}{pad}{text}{pad}{ticks}"


def _quoted(text: str) -> list[str]:
    if not text.strip():
        return []
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    return [f"> {line}" if line.strip() else ">" for line in lines]


def _finding_block(f: Finding, *, reproduced: bool, bundle: str) -> list[str]:
    out = [f"### {prompt_safe(f.title, limit=300)}", ""]
    if f.location:
        out += [f"Location: {_inline_code(f'{prompt_safe(f.location, limit=200)}:{max(1, f.line)}')}",
                ""]
    if reproduced:
        out.append(f"Reproduced **{f.crash_count}/{f.replays}** replays.")
    else:
        out.append("**No reproduction attached.** Informational only; this cannot fail the build.")
    out.append("")
    out += _quoted(f.message)
    out.append("")
    if f.sanitizer:
        fence = _fence_for(f.sanitizer)
        out += [fence, f.sanitizer, fence, ""]
    crash = f.crash
    if crash.parsed:
        classified = [f"Crash state: {_inline_code(prompt_safe(crash.describe(), limit=300))}"]
        if crash.cwe_ids:
            classified.append("Weakness: " + ", ".join(f"CWE-{n}" for n in crash.cwe_ids)
                              + f" · severity {crash.severity} ({crash.security_severity})")
        out += classified + [""]
    if f.evidence:
        shown = f.evidence.strip()
        clipped = len(shown) > _EVIDENCE_IN_REPORT
        body = shown[-_EVIDENCE_IN_REPORT:] if clipped else shown
        fence = _fence_for(body)
        out.append("What the entry point printed:")
        out += ["", fence, body, fence]
        if clipped:
            out.append(f"_Last {_EVIDENCE_IN_REPORT} characters shown._")
        out.append("")
    if f.reproduce_command:
        out += ["Safe acquisition required", "",
                "`reproduce.sh` is the command recorded for this finding, not an independent replay "
                "verifier; do not execute it on a workstation or in a credentialed job. Keep the "
                "bundle with the run that produced it and retain and inspect it as the "
                "version-matched finding-bundle guide shipped with Shard directs; that guide also "
                "states what retention can and cannot establish about the producer and the source "
                "bytes. This build ships no independent replay verifier: stop after acquisition and "
                "do not use this bundle as a gate.", "",
                f"`bundles/{bundle}/` sits beside this report and holds `reproduce.sh`, `input`, "
                f"`output.txt` when captured, and `metadata.json`.", ""]
    if f.caller_note:
        out.append(f"Callers in this repository: {f.caller_note}")
        out.append("")
        if f.caller_rows:
            out += ["```"] + list(f.caller_rows) + ["```", ""]
    if f.doubts:
        out.append("Oracle notes (advisory; these did not affect the verdict):")
        out += [f"- {d}" for d in f.doubts] + [""]
    return out



_FULL_SHA = re.compile(r"[0-9a-f]{40}\Z")


def head_revision(repo) -> str:
    if not repo:
        return ""
    try:
        done = subprocess.run([*safe_directory_argv(repo), "-C", str(repo), "rev-parse", "HEAD"],
                              capture_output=True, text=True, errors="replace", timeout=30)
    except (OSError, subprocess.SubprocessError):
        return ""
    revision = done.stdout.strip()
    return revision if done.returncode == 0 and _FULL_SHA.match(revision) else ""


def _bundle_input_bytes(finding: Finding, require_input: bool) -> bytes | None:
    if require_input and finding.poc_bytes is None:
        raise FileNotFoundError(
            "the demonstrated finding has no immutable reproducing input to attach")
    if finding.poc_bytes is not None:
        return finding.poc_bytes
    if not finding.poc_path:
        return None
    try:
        return pathlib.Path(finding.poc_path).read_bytes()
    except OSError:
        if require_input:
            raise
        return None


def _bundle_metadata(finding: Finding, *, input_present: bool, output_present: bool) -> bytes:
    return json.dumps({
        "rule_id": finding.rule_id,
        "title": finding.title,
        "reproduced": finding.gate_eligible,
        "signature": finding.fingerprint,
        "sanitizer": finding.sanitizer,
        "replays": finding.replays,
        "crash_count": finding.crash_count,
        "container_digest": finding.container_digest,
        "reproduce_command": finding.reproduce_command,
        "input_present": input_present,
        "output_present": output_present,
        "witness_expectation": finding.witness_expectation,
        "witness_marker": finding.witness_marker,
        "witness_entry": finding.witness_entry,
        "witness_controls": list(finding.witness_controls),
        "revision": finding.revision,
        "doubts": list(finding.doubts),
    }, indent=2, sort_keys=True).encode("utf-8")


def _bundle_file_size(dest_fd: int, name: str) -> int:
    flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(name, flags, dir_fd=dest_fd)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise OSError("bundle child is not one regular single-link file")
        return info.st_size
    finally:
        os.close(fd)


def _write_bundle_fd(finding: Finding, dest_fd: int, *,
                     require_input: bool = False) -> dict[str, bytes]:
    source = _bundle_input_bytes(finding, require_input)
    files: dict[str, tuple[bytes, int]] = {}
    if source is not None:
        files["input"] = (source, 0o644)
    if finding.evidence:
        files["output.txt"] = (finding.evidence.encode("utf-8"), 0o644)
    files["metadata.json"] = (
        _bundle_metadata(finding, input_present=source is not None,
                         output_present=bool(finding.evidence)),
        0o644,
    )
    if finding.reproduce_command:
        script = f"#!/bin/sh\n{_shell_comment(finding.title)}\n{finding.reproduce_command}\n"
        files["reproduce.sh"] = (script.encode("utf-8"), 0o755)
    for name, (data, mode) in files.items():
        _atomic_write(dest_fd, name, data, mode=mode)
    for name, (data, _mode) in files.items():
        if _bundle_file_size(dest_fd, name) != len(data):
            raise OSError(f"bundle file {name!r} changed during publication")
    if require_input and "input" not in files:
        raise OSError("the reproduction bundle was written without its required input")
    return {name: data for name, (data, _mode) in files.items()}


def write_bundle(finding: Finding, dest, *, require_input: bool = False) -> pathlib.Path:
    dest = pathlib.Path(dest)
    with _trusted_directory(dest, create=True) as (_held_path, dest_fd):
        _write_bundle_fd(finding, dest_fd, require_input=require_input)
    return dest


def _shell_comment(text: str) -> str:
    return "\n".join(f"# {line}" for line in (text.splitlines() or [""]))




STAGED_INPUT_TOKEN = "./input"

_REPRODUCE_SH = "\n".join((
    'here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd) || exit 2',
    "root=$here",
    'while [ ! -f "$root/$entry" ] && [ "$root" != / ]; do root=$(dirname -- "$root"); done',
    '[ -f "$root/$entry" ] || { echo "shard: $entry is in no directory above $here; unpack this'
    ' bundle inside the repository it was produced from" >&2; exit 2; }',
    '[ -r "$here/input" ] || { echo "shard: the reproducing input is missing from $here" >&2;'
    ' exit 2; }',
    'cd -- "$root" || exit 2',
    'if [ -n "$rev" ]; then',
    '    now=$(git -C "$root" rev-parse HEAD 2>/dev/null)',
    '    [ -n "$now" ] || now="a revision nothing here could read"',
    '    [ "$now" = "$rev" ] || echo "shard: this finding was produced against $rev and this checkout'
    ' is at $now, so a run that shows nothing here may mean the tree moved rather than that the'
    ' defect is gone" >&2',
    "fi",
    'exec bash -- "$root/$entry" "$here/input"',
))



def staged_relative(text: str, input_path: str) -> str:
    if not text or not input_path:
        return text
    root = str(pathlib.Path(input_path).parent)
    if not root or root == "/":
        return text
    for name in ("shard_witness_input", "shard_witness_run"):
        text = text.replace(f"{root}/{name}", STAGED_INPUT_TOKEN)
    return text.replace(f"{root}/", "").replace(root, "")


def _repo_relative(text: str, workdir: pathlib.Path) -> str:
    if not text:
        return text
    root = str(workdir.resolve())
    return text.replace(f"{root}/repo/", "").replace(f"{root}/repo", "").replace(f"{root}/", "")

def _findings(result, workdir: pathlib.Path, setup, *, revision: str) -> list:

    verdict = getattr(result, "verdict", None)
    if verdict is None or not result.solved:
        return []
    harness = setup.fields.get("harness", HARNESS_NAME)
    verdicts = getattr(result, "all_verdicts", None) or [verdict]
    by_signature = getattr(result, "poc_by_signature", None) or {}
    findings = []
    for one in verdicts:
        sanitizer = getattr(one, "sanitizer", None)
        signature = getattr(one, "signature", "")
        poc_bytes = by_signature.get(signature)
        observed = _repo_relative(getattr(one, "evidence", "") or "", workdir)
        sink = observed_location(observed, workdir / "repo", payload=poc_bytes or b"")
        findings.append(Finding(
            rule_id=_rule_id(sanitizer, observed),
            title=_finding_title(sanitizer, signature),
            rule_title=_crash_title(sanitizer),
            location_is_harness=sink is None,
            message=(f"Shard produced an input that crashes this target on {one.crash_count} of "
                     f"{one.replays} replays."),
            evidence=observed,
            gate_eligible=True,
            location=sink[0] if sink else harness,
            line=sink[1] if sink else 1,
            location_measured=sink is not None,
            signature=signature,
            sanitizer=sanitizer,
            replays=one.replays,
            crash_count=one.crash_count,
            doubts=tuple(getattr(one, "doubts", ()) or ()),
            poc_bytes=poc_bytes,
            revision=revision,
            reproduce_command=(f"entry={shlex.quote(harness)}\nrev={shlex.quote(revision)}\n"
                               f"{_REPRODUCE_SH}"),
        ))
    return findings

def _crash_title(sanitizer: str | None) -> str:
    if not sanitizer:
        return "Reproducing input found"
    for kind in ("heap-buffer-overflow", "stack-buffer-overflow", "global-buffer-overflow",
                 "heap-use-after-free", "use-after-poison", "double-free", "memory-leaks",
                 "SEGV", "FPE", "undefined-behavior", "integer-overflow"):
        if kind.lower() in sanitizer.lower():
            return f"{kind} reproduced"
    return "Reproducing input found"

def _finding_title(sanitizer: str | None, signature: str) -> str:
    base = _crash_title(sanitizer)
    if sanitizer or not signature:
        return base
    return f"{base} ({signature[:12]})"

def _rule_id(sanitizer: str | None, evidence: str = "") -> str:
    title = _crash_title(sanitizer)
    slug = title.replace(" reproduced", "").replace(" ", "-").lower()
    if slug == "reproducing-input-found":
        return "shard/reproducing-input"
    access = crashstate.classify(evidence, sanitizer).access
    return f"shard/{slug}-{access.lower()}" if access else f"shard/{slug}"

def _report_id() -> str:

    return report_id(os.environ)


__all__ = [
    "COMPLETED_STATUSES", "DEFAULT_SARIF_CAP", "SARIF_SCHEMA", "SARIF_VERSION", "TOOL_NAME",
    "Finding", "RunFacts", "build_markdown", "build_sarif", "cap", "rank", "write_bundle",
    "write_sarif",
]
