"""The state repository — where understanding accumulates between runs.

the design notes Owner decision, 2026-08-07: *we do not write in the customer's main
repository. The customer creates a dedicated repository which hosts everything from our end, and we
write there.*

    <state-repo>/
      repos/<owner>/<name>/survey.json     the accumulated understanding
      repos/<owner>/<name>/runs/<id>.json  what one run examined, confirmed, and raised unproven

## Why this does not re-open "no control plane"

the maintainers' notes closes it: we build no scheduling, auth, tenancy or storage. We still do not. The state
repository is **the customer's**, in their own organisation, created by them and written by a token they
issue. We operate no service and hold no data. The repository under review is never modified, which also
removes the objection that a security tool opens pull requests against production code.

**This module is NOT what `fail-on: new` uses, and the claim that it was is retired.** An earlier
edition of this docstring asserted it was *"the same mechanism `fail-on: new` needs for baselines
(the integration guide)"* — an answer §10.1 never gave, since §10.1's own preference was code
scanning's alert history. the design notes closed it on 2026-08-11 and chose neither: a finding is
new when the defect sits on a line the pull request introduced, read from the diff, storing nothing.

The reason matters here, because it is about this module's own contract. Making a stored baseline
load-bearing for a GATE would put a build decision on a bookkeeping write, and a pull-request run
writes its own findings before any merge — so pushing the same branch twice would make every finding
"known" and the gate would pass for a branch nobody merged. The rule below survives because state is
not in the gate's path at all.

## The rule that outranks everything else in this module

**A state failure must never fail the build, and must never lose a finding.** The SARIF, the report and
the reproduction bundles are written before anything here is attempted, and they are the deliverable.
State is an enhancement on top. So every function returns a reason string instead of raising, and
`cli` treats a non-empty reason as something to print, never as an exit code.

A security tool that broke a customer's build because a bookkeeping repository was unreachable would not
survive the week, and the whole exit-code contract exists to prevent exactly that class of failure.

## The seam

    path/payload logic     pure, every branch tested from literals
    git                    one function, subprocess, runner injected

Same split as `shard/diffscope.py`, and for the same reason.

## Containment

`slug` reaches this module from a workflow's `github.repository` and from configuration, so it is
untrusted. `_safe_slug` refuses anything that is not `<owner>/<name>` in a conservative character set,
which is what stops a crafted slug writing outside `repos/`. Path construction never concatenates a
caller's string without going through it.

## What it contains, stated plainly

Statements ABOUT the customer's code — paths, symbols, and short source excerpts carried as survey
evidence. That is their code, in their organisation, so no sovereignty claim changes. It must never be
written anywhere else, and nothing in this module sends anything over a network except `git push` to the
remote the customer configured.
"""

from __future__ import annotations

import json
import pathlib
import re
import subprocess
from dataclasses import dataclass, field

# The ONE prompt-rendering boundary, shared with `simple._scope_clause`. It lives beside the C-quote
# decoder in `diffscope` because that decoder is what made these strings dangerous — see its docstring.
from shard.diffscope import prompt_safe

#: `<owner>/<name>`, conservatively. GitHub allows more than this in principle; refusing the exotic
#: cases costs a customer nothing and removes a whole class of path-construction question.
_SLUG = re.compile(r"^[A-Za-z0-9._-]{1,100}/[A-Za-z0-9._-]{1,100}$")

SURVEY_NAME = "survey.json"
RUNS_DIR = "runs"
REPOS_DIR = "repos"

#: A push races another workflow's push on any busy repository. One rebase-and-retry handles the
#: ordinary case; beyond that we report rather than loop, because the findings are already delivered
#: and a retry storm on a bookkeeping write is worse than a missed record.
PUSH_RETRIES = 1

#: The committer of last resort, bot-shaped after the `github-actions[bot]` convention. A container
#: action runs with no git identity anywhere — no repo, global or system config — and there `git
#: commit` fatals with `unable to auto-detect email address (got 'root@<container>.(none)')`, measured
#: 2026-08-11. The dev machines this was built on auto-detect `user@host.domain` and commit fine,
#: which is exactly how a state repository can look green on every laptop and never accumulate a byte
#: in production. The noreply domain routes no mail and names no registered account; these values land
#: in the customer's own state repository's history, so they say what wrote there: shard, not a person.
COMMIT_NAME = "shard[bot]"
COMMIT_EMAIL = "shard[bot]@users.noreply.github.com"


class StateUnavailable(Exception):
    """Only raised by `open_state` for a malformed configuration, which is a caller error.

    Everything else in this module reports instead. This one raises because a bad slug means the caller
    would otherwise write to a path it did not intend, and silently doing nothing would be worse.
    """


@dataclass(frozen=True)
class StateRef:
    """A checked-out state repository, and which repo under review we are reading or writing about.

    Cloning is the ACTION's job, not this module's. By the time anything here runs, the state repository
    is a directory on the runner exactly as the repository under review is.
    """

    root: pathlib.Path
    slug: str

    @property
    def repo_dir(self) -> pathlib.Path:
        return self.root / REPOS_DIR / self.slug

    @property
    def survey_file(self) -> pathlib.Path:
        return self.repo_dir / SURVEY_NAME

    @property
    def runs_dir(self) -> pathlib.Path:
        return self.repo_dir / RUNS_DIR


def open_state(root, slug: str) -> StateRef:
    """Validate and construct. Raises on a malformed slug; see `StateUnavailable`."""
    return StateRef(root=pathlib.Path(root), slug=_safe_slug(slug))


def _safe_slug(slug: str) -> str:
    cleaned = (slug or "").strip().strip("/")
    # An all-dots component is refused as well as `..`. The character class permits ".", and a slug of
    # "./." matches the shape while collapsing `repos/<owner>/<name>` back onto `repos/` — not an
    # escape, but two repositories would then share one survey file, which is a silent data mix.
    dotted = any(set(part) == {"."} for part in cleaned.split("/"))
    if not _SLUG.match(cleaned) or ".." in cleaned or dotted:
        raise StateUnavailable(
            f"{slug!r} is not a <owner>/<name> repository slug; refusing to build a path from it")
    return cleaned


# --- reading ------------------------------------------------------------------------------------------

def load_survey(ref: StateRef) -> tuple[dict | None, str]:
    """The accumulated understanding, or `(None, reason)`.

    A missing file is the FIRST RUN and its reason says so, because "we have never surveyed this
    repository" and "we could not read the survey" lead to different next actions and reporting them
    identically is how a broken state repository looks like a new one forever.
    """
    try:
        return json.loads(ref.survey_file.read_text(encoding="utf-8")), ""
    except FileNotFoundError:
        return None, "no survey recorded yet for this repository"
    except OSError as e:
        return None, f"the survey could not be read: {e}"
    except json.JSONDecodeError as e:
        return None, f"the survey is not valid JSON and was ignored: {e}"


def survey_note(survey: dict | None, *, limit: int = 12) -> str:
    """The prompt fragment a PR run is given: what we already believe about this codebase.

    Capped, and only the candidates that could actually carry proof lead. A note listing everything
    would push the diff itself out of the model's attention, which is the opposite of scoping.

    **EVERY FIELD GOES THROUGH `prompt_safe`, because this lands in the SYSTEM message.** It is the
    second, independent route into the same place as `simple._scope_clause`
    (an internal audit Finding 3) and it is the wider one: `path` comes from a filesystem
    walk over the customer's repository, and the whole dict is JSON reloaded from a state repository, so
    `line`, `kind` and `rank` are whatever that file says — any JSON value, of any length. `blind_spots`
    are our own sentences today and were still unbounded and unescaped, which is a guard that depends on
    a fact about the caller instead of on the data.

    Both routes are rendered by the same function on purpose. Fixing one consumer would have left the
    other, and the next consumer would arrive unguarded; the boundary is "untrusted text becomes prompt
    text", not "this particular string".
    """
    if not survey:
        return ""
    candidates = [c for c in survey.get("candidates", []) if isinstance(c, dict)]
    if not candidates:
        return ""
    lines = [f"  {prompt_safe(c.get('path'))}:{prompt_safe(c.get('line'), limit=20)} — "
             f"{prompt_safe(c.get('kind'), limit=40)} ({prompt_safe(c.get('rank'), limit=20)})"
             for c in candidates[:limit]]
    note = "Candidate surfaces recorded for this repository:\n" + "\n".join(lines)
    if len(candidates) > limit:
        note += f"\n  ... and {len(candidates) - limit} more"
    # The blind spots travel WITH the candidates. A model given only what we found would treat the list
    # as the boundary of what exists, which is the reading `shard/survey.py` refuses to invite.
    spots = [s for s in survey.get("blind_spots", []) if isinstance(s, str)]
    if spots:
        note += "\n\nKnown blind spots:\n" + "\n".join(f"  {prompt_safe(s, limit=300)}" for s in spots[:6])
    return note


# --- writing ------------------------------------------------------------------------------------------

def save_survey(ref: StateRef, payload: dict) -> str:
    """Write the survey. Returns "" on success, or a reason. Never raises."""
    return _write_json(ref.survey_file, payload)


def build_run_record(*, run_id: str, mode: str, status: str, scope, findings,
                     survey_seen: bool) -> dict:
    """What this run examined, confirmed, and raised unproven — the accumulation itself.

    Three separate counts and never one. A run that examined forty files and proved nothing is a
    different fact from a run that examined two, and the design notes is the record of
    what it costs to have only one word for every outcome.

    Findings are stored WITHOUT their message bodies. The bodies are in the report and the bundle; what
    accumulates here is the shape of what we learned, and a state repository that grew a copy of every
    report would be unreadable within a month.
    """
    return {
        "run_id": run_id,
        "mode": mode,
        "status": status,
        "survey_seen": survey_seen,
        "examined": sorted(scope),
        "examined_count": len(scope),
        "confirmed": [_finding_row(f) for f in findings if f.gate_eligible],
        "raised_unproven": [_finding_row(f) for f in findings if not f.gate_eligible],
    }


def _finding_row(finding) -> dict:
    return {
        "rule_id": finding.rule_id,
        "title": finding.title,
        "location": finding.location,
        "line": finding.line,
        "fingerprint": finding.fingerprint,
    }


def append_run(ref: StateRef, record: dict) -> str:
    """Record one run. Returns "" on success, or a reason. Never raises."""
    run_id = str(record.get("run_id") or "").strip()
    if not run_id or "/" in run_id or ".." in run_id:
        return f"refusing to write a run record under id {run_id!r}"
    return _write_json(ref.runs_dir / f"{run_id}.json", record)


def _write_json(path: pathlib.Path, payload: dict) -> str:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    except (OSError, TypeError, ValueError) as e:
        # TypeError/ValueError catch a payload that is not JSON-serialisable, which is a programming
        # error here — but one that must still not take a customer's build down with it.
        return f"could not write {path.name}: {e}"
    return ""


# --- the one impure function ---------------------------------------------------------------------------

def commit_and_push(ref: StateRef, message: str, *, runner=subprocess.run,
                    retries: int = PUSH_RETRIES) -> str:
    """Commit whatever changed and push it. Returns "" on success, or a reason. Never raises.

    Nothing to commit is SUCCESS, not a failure: a PR that changed nothing we track should leave the
    state repository alone, and reporting that as an error would train customers to ignore the line.

    The commit carries a git identity, HERE and not in a workflow step, for the same reason `_argv`
    imports `safe_directory_argv` instead of retyping the flag: one place, in code, so a customer
    wiring their own workflow cannot get a half-configured state repo — and a container action has no
    separate step in which to run `git config` anyway. Precedence is the customer's: any `user.name`
    or `user.email` git already resolves (repo, global or system config) wins untouched, because the
    probe asks git itself. `COMMIT_NAME`/`COMMIT_EMAIL` are supplied per-invocation (`-c`) only for
    the keys nothing configured — the case that, before this, fatally ended every commit a container
    ever attempted. Nothing is written to their configuration.
    """
    root = str(ref.root)
    staged = _git(runner, root, "add", "--", f"{REPOS_DIR}/{ref.slug}")
    if staged:
        return staged

    if not _git_output(runner, root, "diff", "--cached", "--name-only").strip():
        return ""

    identity = _identity_config(runner, root)
    committed = _git(runner, root, "commit", "-m", message, config=identity)
    if committed:
        return committed

    for attempt in range(retries + 1):
        if not _git(runner, root, "push"):
            return ""
        if attempt < retries:
            # A concurrent workflow pushed first. Rebase onto it and try once more; beyond that we
            # report, because the findings are already delivered and a retry storm on a bookkeeping
            # write is worse than a missed record. The rebase REPLAYS the commit, so it needs the
            # same identity the commit did — a bare container would otherwise fatal here instead.
            if _git(runner, root, "pull", "--rebase", config=identity):
                break
    return "the state repository could not be pushed; the findings above were still delivered"


def _identity_config(runner, root: str) -> tuple[str, ...]:
    """`-c` pairs for whichever of `user.name`/`user.email` the customer left unset. Often empty.

    One probe through git's own resolution chain, so what counts as "configured" is exactly what the
    commit would use. A probe failure returns no output and therefore supplies both values — the
    fallback that can only make a commit MORE likely to land, never less.
    """
    found = _git_output(runner, root, "config", "--get-regexp", r"^user\.(name|email)$")
    have = {line.split(None, 1)[0] for line in found.splitlines() if line.strip()}
    config: list[str] = []
    if "user.name" not in have:
        config += ["-c", f"user.name={COMMIT_NAME}"]
    if "user.email" not in have:
        config += ["-c", f"user.email={COMMIT_EMAIL}"]
    return tuple(config)


def _argv(root: str, args, config=()) -> list:
    """Every git command this module runs, with the ownership exception attached.

    The state repository is a SECOND checkout the customer supplies, and a container action runs as root
    while the runner owns both. `diffscope.safe_directory_argv` carries the reasoning and the measured
    failure; the import is here rather than the flag being retyped, because two spellings of a security
    control is the drift class this repository keeps recording. `shard/diffscope.py` owns it because it
    is where the first one was found.

    `config` is more `-c` pairs of the same kind — the commit identity — and it goes BEFORE `-C` with
    the safe.directory flag, where invocation-scoped configuration already lives.
    """
    from shard.diffscope import safe_directory_argv

    return [*safe_directory_argv(root), *config, "-C", root, *args]


def _git(runner, root: str, *args: str, config=()) -> str:
    """Run one git command. Returns "" on success, or a reason."""
    try:
        # errors="replace": git echoes branch names, commit subjects and file paths from the state
        # repository, none of which is guaranteed utf-8. A strict decode raises OUTSIDE this except.
        proc = runner(_argv(root, args, config), capture_output=True, text=True, errors="replace",
                      timeout=120)
    except (OSError, subprocess.SubprocessError) as e:
        return f"git {args[0]} failed: {e}"
    if proc.returncode != 0:
        return f"git {args[0]} failed: {(proc.stderr or '').strip()[:200]}"
    return ""


def _git_output(runner, root: str, *args: str) -> str:
    try:
        # errors="replace" — same reason as `_git` above.
        proc = runner(_argv(root, args), capture_output=True, text=True, errors="replace",
                      timeout=120)
    except (OSError, subprocess.SubprocessError):
        return ""
    return proc.stdout if proc.returncode == 0 else ""


@dataclass
class StateOutcome:
    """What the state write did, for the report and the JSON payload. Never an exit code."""

    attempted: bool = False
    survey_written: bool = False
    run_written: bool = False
    reasons: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.attempted and not self.reasons


__all__ = [
    "COMMIT_EMAIL", "COMMIT_NAME", "PUSH_RETRIES", "REPOS_DIR", "RUNS_DIR", "SURVEY_NAME",
    "StateOutcome", "StateRef", "StateUnavailable",
    "append_run", "build_run_record", "commit_and_push", "load_survey", "open_state",
    "save_survey", "survey_note",
]
