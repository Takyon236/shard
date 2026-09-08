
from __future__ import annotations

import hashlib
import pathlib
import re
import shlex
import tempfile
from dataclasses import dataclass, field, replace

from shard.agentloop import ToolCallingLoop
from shard.budget import BudgetGovernor
from shard.diffscope import HUNK_RADIUS, prompt_safe
from shard.inspection import build as build_inspection
from shard.journal import Journal
from shard.llm import classify_transport_error
from shard.report import _REPRODUCE_SH, Finding, head_revision, staged_relative
from shard.sandbox import ExecState, build_exec_tools, exec_budget, scope_digest
from shard.tools import Tool, ToolContext, ToolRegistry, ToolResult, _grep, _list_dir, _read_file
from shard.witness import (BENIGN_SUFFIX, INHERITED, INTRODUCED, SOURCE_ISOLATION_REFUSAL,
                           UNATTRIBUTED, Witness, WitnessSpec, adjudicate, attribute, bounded_run,
                           controls_digest, entry_digest, observed_location, offered_expectations,
                           self_defeating_marker, witness_contract)
from shard.witnessfs import SnapshotSet, SourceSnapshot

DEFAULT_MAX_STEPS = 40

SYSTEM_TEMPLATE = """You are reviewing a pull request for security defects.

{capability}

Report a defect with `report_finding`. Two tiers, and the difference is not cosmetic:

  * If you can name an input that makes the DECLARED ENTRY POINT misbehave, pass the witness fields.
    After you finish, the runner executes that entry point with your payload and observes what happens.
    Only what it observes counts. You are not consulted.
  * Otherwise report the finding without witness fields. It is emitted as informational and can NEVER
    fail the build. That is a legitimate result, not a failure — say what you found and why you could
    not demonstrate it.

Do not report style, formatting, or anything you have not read the code for. A finding you cannot point
at a line for is not a finding.

When you have nothing further to examine, stop calling tools and say what you covered."""


_CAPABILITY_OFF = """You have READ tools only. You cannot write files, run shells, or author anything."""

_CAPABILITY_ON = """You can read the checkout and you can RUN it. `run` is a shell in the checkout — node, java, ruby,
php, dotnet, gcc, g++, python and git are installed. `outline` maps a file's definitions so you can
read the right part of it. Write only under $SHARD_SCRATCH: changing the checkout is detected and
stops this run from being able to fail the build.

Check before you claim. Do not report behaviour you could have observed and did not."""


@dataclass
class FindingState:

    proposed: list[dict] = field(default_factory=list)

    def record(self, **kw) -> None:
        self.proposed.append(kw)


def witness_payload_bytes(claim: dict) -> bytes:
    text = (claim.get("witness_payload") or "")
    encoded = (claim.get("witness_payload_base64") or "").strip()
    if not encoded:
        return text.encode("utf-8")
    if text:
        raise ValueError("give witness_payload or witness_payload_base64, not both")
    import binascii
    import base64
    try:
        return base64.b64decode("".join(encoded.split()), validate=True)
    except (binascii.Error, ValueError) as e:
        raise ValueError(f"witness_payload_base64 is not valid base64: {e}") from None


def _report_finding(ctx: ToolContext, path: str, line: int, title: str, why: str,
                    witness_expectation: str = "", witness_payload: str = "",
                    witness_marker: str = "", witness_payload_base64: str = "",
                    supersedes: int = 0, *, state: FindingState) -> ToolResult:
    if not title.strip() or not path.strip():
        return ToolResult(False, error="report_finding needs a title and a path")
    safe_path = _repo_relative(ctx, path)
    if safe_path is None:
        return ToolResult(False, error=(
            f"path {path.strip()!r} must be relative to the repository root and inside it"))
    offered = offered_expectations()
    if witness_expectation and witness_expectation not in offered:
        return ToolResult(False, error=f"witness_expectation must be one of {list(offered)}")
    claim = {"witness_payload": witness_payload, "witness_payload_base64": witness_payload_base64}
    try:
        payload = witness_payload_bytes(claim)
    except ValueError as e:
        return ToolResult(False, error=str(e))
    if witness_expectation.strip() == "output_marker":
        if self_defeating := self_defeating_marker(witness_marker.strip(), payload):
            return ToolResult(False, error=(
                f"{self_defeating}. Report the same finding again with a marker taken from the "
                f"program's own output, or with no witness fields at all if there is none."))
    n = len(state.proposed) + 1
    try:
        target = int(supersedes or 0)
    except (TypeError, ValueError):
        return ToolResult(False, error=(
            "supersedes must be the integer handle of one of your earlier report_finding calls"))
    if target and not (1 <= target < n):
        return ToolResult(False, error=(
            f"supersedes={target} is not an earlier handle: pass a handle from 1 to {n - 1} that this "
            f"run already returned to you, or omit it to file a new finding"))
    state.record(path=safe_path, line=max(1, int(line or 1)), title=title.strip(), why=why.strip(),
                 witness_expectation=witness_expectation.strip(),
                 witness_payload=witness_payload, witness_marker=witness_marker.strip(),
                 witness_payload_base64=witness_payload_base64.strip(), supersedes=target)
    return ToolResult(True, data={"recorded": True, "handle": n})


def _repo_relative(ctx: ToolContext, path: str) -> str | None:
    raw = path.strip()
    if pathlib.PurePath(raw).is_absolute():
        return None
    root = pathlib.Path(ctx.engine_root).resolve()
    try:
        resolved = (root / raw).resolve()
        return str(resolved.relative_to(root))
    except (ValueError, OSError):
        return None


def build_simple_registry(ctx: ToolContext, state: FindingState, *,
                          witness_entry: str | None = None,
                          exec_state: "ExecState | None" = None, repo=None,
                          runner=None) -> ToolRegistry:
    import functools

    registry = ToolRegistry(ctx)
    registry.register(Tool(name="read_file", kind="read", description="Read a file from the checkout.",
                           fn=_read_file,
                           args_schema={"path": "str", "offset": "int?", "max_bytes": "int?"}))
    registry.register(Tool(name="grep", kind="read",
                           description="Search the checkout for a regular expression.", fn=_grep,
                           args_schema={"pattern": "str", "path": "str?", "max_matches": "int?"}))
    registry.register(Tool(name="list_dir", kind="read", description="List a directory.",
                           fn=_list_dir, args_schema={"path": "str?"}))

    schema = {"path": "str", "line": "int", "title": "str", "why": "str", "supersedes": "int?"}
    description = ("Report a defect you have read the code for. To correct an earlier report of your "
                   "own, pass supersedes with the handle that report returned; the earlier one is "
                   "withdrawn.")
    if witness_entry:
        schema |= {"witness_expectation": "str?", "witness_payload": "str?", "witness_marker": "str?",
                   "witness_payload_base64": "str?"}
        description += (f" Pass witness_expectation (one of {list(offered_expectations())}) and "
                        f"witness_payload to have {witness_entry} executed against your input after "
                        f"this run ends. If the input needs bytes that are not valid UTF-8 — a magic "
                        f"header, a sentinel byte — pass witness_payload_base64 instead of "
                        f"witness_payload, never both."
                        f" For output_marker: witness_marker must be a string the program's OWN code "
                        f"prints. A marker that appears anywhere inside witness_payload is refused, "
                        f"because an entry point that merely echoed your input would produce it. Do "
                        f"not plant `echo MARKER` in the payload and then look for MARKER."
                        f" Choose a marker you have READ — a literal string in the source. Avoid one "
                        f"whose value you would have to WORK OUT, such as a byte count, a length or a "
                        f"hash: a marker that is off by one demonstrates nothing."
                        f" And your payload must leave the program ALIVE. The runner observes only "
                        f"the entry point's exit status and its output, so an input that kills or "
                        f"hangs it — `kill`, a fork bomb, an infinite loop — destroys the very "
                        f"evidence it was meant to produce. To show command execution, run something "
                        f"whose OUTPUT is distinctive and which you did not write yourself, and let "
                        f"the program finish.")
        if exec_state is not None:
            description += (" You have `run_entry`: execute the entry point on your payload FIRST and "
                            "take the marker from its real output rather than calculating it — a value "
                            "you worked out is a bet you no longer have to make, and run_entry will "
                            "also show you a payload killing the program before you report it.")
    registry.register(Tool(name="report_finding", kind="report", description=description,
                           fn=functools.partial(_report_finding, state=state), args_schema=schema,
                           priority=1))
    if exec_state is not None:
        for tool in build_exec_tools(exec_state, repo=repo if repo is not None else ctx.engine_root,
                                     witness_entry=witness_entry, runner=runner):
            registry.register(tool)
    return registry


MAX_ADJUDICATED = 20

ADJUDICATION_WALL_SECONDS = 1200.0


@dataclass(frozen=True)
class _AdjudicationPlan:
    state: FindingState
    repo: object
    witness_entry: str | None
    baseline_digest: str | None
    runner: object
    workdir: object
    base_repo: object
    tampered: str
    max_witnessed: int
    wall_seconds: float
    clock: object
    snapshots: SnapshotSet
    secret_env_names: tuple[str, ...]


def _adjudication_refusal(tampered: str, snapshot_refusal: str) -> str:
    return tampered or snapshot_refusal


def _isolation_outcome(witness: Witness, attribution: tuple[str, str], located):
    if attribution[1].startswith(SOURCE_ISOLATION_REFUSAL):
        return replace(witness, demonstrated=False, refusal=attribution[1], input_path="",
                       input_bytes=None), None
    return witness, located


def adjudicate_all(state: FindingState, repo, *, witness_entry: str | None,
                   baseline_digest: str | None, runner=None, workdir=None,
                   base_repo=None, tampered: str = "",
                   source_snapshot: SourceSnapshot | None = None,
                   base_snapshot: SourceSnapshot | None = None,
                   max_witnessed: int = MAX_ADJUDICATED,
                   wall_seconds: float = ADJUDICATION_WALL_SECONDS, clock=None,
                   secret_env_names: tuple[str, ...] = ()) -> list[Finding]:
    snapshots = SnapshotSet.prepare(repo, needed=bool(witness_entry), base_repo=base_repo,
                                    source=source_snapshot, base=base_snapshot)
    try:
        plan = _AdjudicationPlan(
            state, repo, witness_entry, baseline_digest, runner, workdir, base_repo, tampered,
            max_witnessed, wall_seconds, clock, snapshots, secret_env_names,
        )
        return _adjudicate_captured(plan)
    finally:
        snapshots.close()


def _adjudicate_captured(plan: _AdjudicationPlan) -> list[Finding]:
    import time as _time

    (state, repo, witness_entry, baseline_digest, runner, workdir, base_repo, tampered,
     max_witnessed, wall_seconds, clock, snapshots, secret_env_names) = (
        plan.state, plan.repo, plan.witness_entry, plan.baseline_digest, plan.runner, plan.workdir,
        plan.base_repo, plan.tampered, plan.max_witnessed, plan.wall_seconds, plan.clock,
        plan.snapshots, plan.secret_env_names,
    )
    runner = runner or bounded_run
    clock = clock or _time.monotonic
    started = clock()
    witnessed = 0
    source_snapshot, base_snapshot = snapshots.source, snapshots.base
    snapshot_refusal = snapshots.refusal(SOURCE_ISOLATION_REFUSAL)
    pristine_repo = snapshots.repository(repo)
    baseline_controls = controls_digest(pristine_repo, witness_entry) if witness_entry else None
    revision = head_revision(repo)

    out: list[Finding] = []
    for ordinal, claim in _surviving_claims(state.proposed):
        corrects = _supersedes_target(claim, ordinal)
        witness = None
        located = None
        attribution = (UNATTRIBUTED, "")
        refusal = _adjudication_refusal(tampered, snapshot_refusal)
        if refusal and claim.get("witness_expectation"):
            out.append(_to_finding(claim, Witness(demonstrated=False,
                                                  expectation=claim["witness_expectation"],
                                                  refusal=refusal),
                                   entry=witness_entry or "", repo=pristine_repo, seq=ordinal,
                                   corrects=corrects, revision=revision))
            continue
        if witness_entry and claim.get("witness_expectation"):
            if ceiling := _adjudication_ceiling(witnessed, clock() - started,
                                                max_witnessed, wall_seconds):
                out.append(_to_finding(claim, Witness(demonstrated=False,
                                                      expectation=claim["witness_expectation"],
                                                      refusal=ceiling),
                                       entry=witness_entry, repo=pristine_repo, seq=ordinal,
                                       corrects=corrects, revision=revision))
                continue
            witnessed += 1
            try:
                payload = witness_payload_bytes(claim)
            except ValueError as e:
                out.append(_to_finding(claim, Witness(demonstrated=False,
                                                      expectation=claim["witness_expectation"],
                                                      refusal=str(e)),
                                       entry=witness_entry, repo=pristine_repo, seq=ordinal,
                                       corrects=corrects, revision=revision))
                continue
            spec = WitnessSpec(entry=witness_entry, expectation=claim["witness_expectation"],
                               payload=payload, marker=claim.get("witness_marker") or "")
            witness = adjudicate(spec, repo, baseline_digest=baseline_digest,
                                 baseline_controls=baseline_controls, runner=runner,
                                 workdir=workdir, source_snapshot=source_snapshot,
                                 secret_env_names=secret_env_names)
            if witness.demonstrated:
                located = observed_location(witness.evidence, repo, payload=spec.payload)
                attribution = attribute(
                    spec, base_repo, runner=runner, workdir=workdir,
                    source_snapshot=base_snapshot, protected_inputs=_protected_candidate(witness, spec),
                    secret_env_names=secret_env_names,
                )
                witness, located = _isolation_outcome(witness, attribution, located)
        out.append(_to_finding(claim, witness, entry=witness_entry or "", located=located,
                               repo=pristine_repo,
                               attribution=attribution, seq=ordinal, corrects=corrects,
                               revision=revision))
    _separate_anchor_collisions(out)
    return out


def _surviving_claims(proposed: list[dict]) -> list[tuple[int, dict]]:
    superseded = {target for ordinal, claim in enumerate(proposed, start=1)
                  if (target := _supersedes_target(claim, ordinal))}
    survivors = []
    seen = set()
    for ordinal, claim in enumerate(proposed, start=1):
        if ordinal in superseded:
            continue
        key = tuple(sorted((name, repr(value)) for name, value in claim.items()))
        if key in seen:
            continue
        seen.add(key)
        survivors.append((ordinal, claim))
    return survivors


def _protected_candidate(witness: Witness, spec: WitnessSpec):
    return (("preserved witness input", pathlib.Path(witness.input_path), spec.payload),)


def _adjudication_ceiling(witnessed: int, elapsed: float, max_witnessed: int,
                          wall_seconds: float) -> str:
    if max_witnessed > 0 and witnessed >= max_witnessed:
        return (f"this run reported more than the {max_witnessed} claims one review will execute a "
                f"witness for, so this one was not adjudicated and cannot gate")
    if wall_seconds > 0 and elapsed >= wall_seconds:
        return (f"the {int(wall_seconds)}s ceiling on post-review adjudication was reached before this "
                f"claim was executed, so it was not adjudicated and cannot gate")
    return ""


def _supersedes_target(claim: dict, ordinal: int) -> int:
    target = claim.get("supersedes") or 0
    return target if isinstance(target, int) and 1 <= target < ordinal else 0


def _separate_anchor_collisions(findings: list[Finding]) -> None:
    groups: dict[str, list[int]] = {}
    for idx, f in enumerate(findings):
        if f.signature:
            groups.setdefault(f.fingerprint, []).append(idx)
    for fingerprint, idxs in groups.items():
        if len(idxs) < 2:
            continue
        sites: dict[tuple[str, int], list[int]] = {}
        for idx in idxs:
            sites.setdefault((findings[idx].location, findings[idx].line), []).append(idx)
        if len(sites) < 2:
            continue
        for site_ordinal, site in enumerate(sorted(sites), start=1):
            salted = hashlib.sha256(
                f"{fingerprint}\x00collision\x00{site_ordinal}".encode()).hexdigest()[:16]
            for idx in sites[site]:
                findings[idx] = replace(findings[idx], signature=salted)


_RULE_TITLES = {
    "fatal_signal": "Demonstrated by a fatal signal from the declared entry point",
    "output_marker": "Demonstrated by an agent-chosen marker absent from a benign control",
    "unhandled_exception": "Demonstrated by an unhandled exception from the declared entry point",
    "hypothesis": "Reported without a demonstration",
}


def _witness_never_judged(witness) -> str:
    if witness is None:
        return ""
    refusal = getattr(witness, "refusal", "") or ""
    if refusal:
        return refusal
    if getattr(witness, "timed_out", False):
        return (getattr(witness, "evidence", "") or "the entry point did not finish") + \
               ", so nothing was adjudicated for this finding"
    return ""


def _to_finding(claim: dict, witness, entry: str = "", located=None, repo=None,
                attribution=(UNATTRIBUTED, ""), *, seq: int = 0, corrects: int = 0,
                revision: str = "") -> Finding:
    demonstrated = bool(witness is not None and witness.demonstrated)
    expectation = claim.get("witness_expectation") or ""
    message = claim.get("why") or claim["title"]
    if witness is None:
        message += "\n\nNo witness was proposed, so this is informational and cannot fail the build."
    elif demonstrated:
        message += (f"\n\nDemonstrated: the declared entry point was executed with the reported input "
                    f"and {expectation} was observed.")
        if attribution[0] == INTRODUCED:
            message += f"\n\nIntroduced by this change: {attribution[1]}."
        elif attribution[0] == INHERITED:
            message += (f"\n\nNOT introduced by this change: {attribution[1]}. It is reported because "
                        f"it is real, and `fail-on: new` will not gate on it.")
        controls = getattr(witness, "controls", ()) or ()
        if len(controls) > 1:
            message += "\n\nChecked against " + ", ".join(controls) + "."
        elif controls:
            message += (f"\n\nChecked against {controls[0]} ONLY. This repository declares no benign "
                        f"control at {entry}{BENIGN_SUFFIX}, and an empty input takes a different "
                        f"branch through most programs — so a marker this program prints during "
                        f"ordinary operation would also have been reported here. Add one benign input "
                        f"per branch, in a directory of that name, to close that.")
    else:
        reason = witness.refusal or getattr(witness, "why_not", "") or (
            f"{expectation or 'the expectation'} was not observed")
        message += f"\n\nWitness NOT demonstrated ({reason}); informational only."

    if corrects:
        message += ("\n\nThis corrects an earlier report from the same run, which has been withdrawn.")

    path, line = claim["path"], int(claim.get("line") or 1)
    if located and located != (path, line):
        message += (f"\n\nLocated at {located[0]}:{located[1]} by the demonstration's own output; the "
                    f"report named {path}:{line}.")
    if located:
        path, line = located

    return Finding(
        rule_id=f"shard/simple-{expectation or 'hypothesis'}",
        title=claim["title"],
        rule_title=_RULE_TITLES.get(expectation or "", "Reported without a demonstration"),
        message=message,
        gate_eligible=demonstrated,
        location=path,
        line=line,
        location_measured=located is not None,
        attribution=attribution[0],
        attribution_reason=attribution[1],
        witness_refused=_witness_never_judged(witness),
        signature=_anchor_signature(repo, path, line) if repo is not None else "",
        replays=1 if witness is not None else 0,
        crash_count=1 if demonstrated else 0,
        poc_path=(getattr(witness, "input_path", "") or None) if witness is not None else None,
        poc_bytes=getattr(witness, "input_bytes", None) if witness is not None else None,
        reproduce_command=(f"entry={shlex.quote(entry)}\nrev={shlex.quote(revision)}\n{_REPRODUCE_SH}"
                           if demonstrated and entry else ""),
        revision=revision,
        evidence=staged_relative((getattr(witness, "evidence", "") or ""),
                                 getattr(witness, "input_path", "")) if witness is not None else "",
        witness_expectation=expectation if demonstrated else "",
        witness_marker=(claim.get("witness_marker") or "") if demonstrated else "",
        witness_entry=entry if demonstrated else "",
        witness_controls=tuple(getattr(witness, "controls", ()) or ()) if demonstrated else (),
        seq=seq,
    )


_ANCHOR_SHAPE = re.compile(r"[A-Za-z_$]")


def _source_anchor(repo, path: str, line: int) -> str:
    try:
        text = (pathlib.Path(repo) / path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    lines = text.splitlines()
    start = min(max(line, 1), len(lines))
    chain: list[str] = []
    indent = _indent_of(lines[start - 1]) if lines else 0
    for i in range(start, 0, -1):
        raw = lines[i - 1]
        if not raw.strip() or not _ANCHOR_SHAPE.match(raw.lstrip()):
            continue
        here = _indent_of(raw)
        if here < indent:
            chain.append(" ".join(raw.split()))
            indent = here
            if here == 0:
                break
    return " | ".join(reversed(chain))


def _indent_of(raw: str) -> int:
    return len(raw) - len(raw.lstrip())


def _anchor_signature(repo, path: str, line: int) -> str:
    anchor = _source_anchor(repo, path, line)
    if not anchor:
        return ""
    return hashlib.sha256(f"shard-anchor-v1\x00{path}\x00{anchor}".encode()).hexdigest()[:16]


@dataclass(frozen=True)
class SimpleRun:

    findings: list[Finding]
    status: str
    limit_hit: str = ""
    exec_refused: int | None = None
    exec_calls: int | None = None

    executions_spent: bool | None = None
    error_kind: str = ""
    inspection: dict | None = None


def run_simple(*, repo, backend, journal: Journal, scope: tuple[str, ...] = (),
               witness_entry: str | None = None, model: str = "glm-5.2",
               max_steps: int = DEFAULT_MAX_STEPS, governor: BudgetGovernor | None = None,
               survey_note: str = "", runner=None, loop_factory=None,
               windows=None, base_repo=None, execution: bool = True,
               secret_env_names: tuple[str, ...] = ()) -> SimpleRun:
    snapshots = SnapshotSet.prepare(repo, needed=True, base_repo=base_repo)
    if snapshots.failure:
        journal.record("simple_snapshot_refused", error=snapshots.failure)
        return SimpleRun(findings=[], status="error", error_kind="", exec_refused=None,
                         exec_calls=None, executions_spent=None)
    args = (repo, backend, journal, scope, witness_entry, model, max_steps, governor, survey_note,
            runner, loop_factory, windows, base_repo, execution, secret_env_names)
    try:
        return _run_simple_captured(args, snapshots)
    finally:
        snapshots.close()


def _run_simple_captured(args, snapshots: SnapshotSet) -> SimpleRun:
    (repo, backend, journal, scope, witness_entry, model, max_steps, governor, survey_note,
     runner, loop_factory, windows, base_repo, execution, secret_env_names) = args
    state = FindingState()
    source_snapshot, base_snapshot = snapshots.source, snapshots.base
    pristine_repo = snapshots.repository(repo)
    ctx = ToolContext(engine_root=pristine_repo, shard_root=pristine_repo,
                      audit_root=pristine_repo,
                      secret_env_names=secret_env_names, immutable_read_roots=True)

    exec_state = (ExecState(scratch=tempfile.mkdtemp(prefix="shard-exec-"),
                            max_calls=exec_budget(max_steps), secret_env_names=secret_env_names,
                            source_snapshot=source_snapshot)
                  if execution else None)
    registry = build_simple_registry(ctx, state, witness_entry=witness_entry,
                                     exec_state=exec_state, repo=pristine_repo, runner=runner)

    baseline = entry_digest(pristine_repo, witness_entry) if witness_entry else None
    watched = (*scope, *witness_contract(repo, witness_entry))
    scope_before = scope_digest(repo, watched)

    factory = loop_factory or ToolCallingLoop
    loop = factory(backend=backend, registry=registry, journal=journal,
                   system=_system(scope, witness_entry, survey_note, windows, execution=execution),
                   model=model,
                   max_steps=max_steps, governor=governor)
    inspection_start = journal.step
    result = loop.run(_goal(scope))
    status = getattr(result, "status", "") or "error"
    limit_hit = getattr(result, "limit_hit", "") or ""
    error_kind = classify_transport_error(getattr(result, "final_text", "") or "") \
        if status == "error" else ""

    ex = exec_state
    journal.record("simple_exec", armed=ex is not None,
                   calls=ex.calls if ex else 0,
                   entry_calls=ex.entry_calls if ex else 0,
                   shell_calls=ex.shell_calls if ex else 0,
                   network=ex.network if ex else "not-armed",
                   budget=ex.max_calls if ex else 0,
                   refused=ex.refused if ex else None,
                   exhausted=ex.exhausted if ex else None,
                   spent=ex.spent if ex else None)

    journal.record("simple_survey", given=bool(survey_note), chars=len(survey_note or ""))

    tampered = ""
    if scope_digest(repo, watched) != scope_before:
        tampered = ("the checkout changed during this run, so nothing observed in it can be "
                    "re-verified; the witness was refused rather than adjudicated")
        journal.record("simple_scope_tampered", scope=len(scope), watched=len(watched))

    journal.record("simple_proposed", count=len(state.proposed), status=status)
    findings = adjudicate_all(state, repo, witness_entry=witness_entry, baseline_digest=baseline,
                              runner=runner, base_repo=base_repo, tampered=tampered,
                              source_snapshot=source_snapshot, base_snapshot=base_snapshot,
                              secret_env_names=secret_env_names)
    journal.record("simple_adjudicated", findings=len(findings),
                   gate_eligible=sum(1 for f in findings if f.gate_eligible))
    exec_facts = ({"exec_refused": exec_state.refused, "exec_calls": exec_state.calls,
                   "executions_spent": exec_state.spent} if exec_state else
                  {"exec_refused": None, "exec_calls": None, "executions_spent": None})
    return SimpleRun(findings=findings, status=status, limit_hit=limit_hit,
                     error_kind=error_kind,
                     inspection=_inspection(journal, inspection_start, scope, pristine_repo, windows),
                     **exec_facts)


def _inspection(journal, start, scope, repo, windows):
    try:
        events = (event for event in journal.events() if event.get("step", 0) > start)
        return build_inspection(scope, events, repo=repo, windows=windows)
    except (OSError, ValueError, TypeError, AttributeError):
        return None


def _system(scope: tuple[str, ...], witness_entry: str | None, survey_note: str,
            windows=None, execution: bool = True) -> str:
    parts = [SYSTEM_TEMPLATE.format(
        capability=_CAPABILITY_ON if execution else _CAPABILITY_OFF)]
    if witness_entry:
        parts.append(f"The declared entry point is {prompt_safe(witness_entry)}. "
                     f"It is read-only to you.")
    else:
        parts.append("No entry point is declared for this repository, so nothing you report can be "
                     "demonstrated. Report what you find as informational and say so.")
    if survey_note:
        parts.append("Known about this codebase already:\n" + survey_note)
    if scope:
        parts.append(_scope_clause(scope, windows))
    return "\n\n".join(parts)


def _scope_clause(scope: tuple[str, ...], windows) -> str:
    windows = windows or {}
    lines = []
    for path in scope[:60]:
        spans = windows.get(path) or ()
        shown = prompt_safe(path)
        if spans:
            where = ", ".join(f"{lo}-{hi}" for lo, hi in spans[:12])
            lines.append(f"  {shown}  (changed around lines {where})")
        else:
            lines.append(f"  {shown}  (changed, but the change added no lines — read it whole)")
    return ("Changed files in this pull request, and where the change is. The ranges include "
            f"{HUNK_RADIUS} lines of context either side; you may still read anything in the "
            "checkout, and should when following what the changed code calls.\n" + "\n".join(lines))


def _goal(scope: tuple[str, ...]) -> str:
    if not scope:
        return ("No changed files were resolved for this pull request. Say so and stop; do not hunt "
                "the whole repository, which is deep mode's job and is not budgeted here.")
    return ("Review the changed files listed in your instructions. Read them, follow what they call, "
            "and report what you find.")


__all__ = [
    "DEFAULT_MAX_STEPS", "SYSTEM_TEMPLATE", "FindingState", "SimpleRun",
    "adjudicate_all", "build_simple_registry", "run_simple", "witness_payload_bytes",
]
