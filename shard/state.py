
from __future__ import annotations

import json
import pathlib
import re
import subprocess
from dataclasses import dataclass, field

from shard.diffscope import prompt_safe

_SLUG = re.compile(r"^[A-Za-z0-9._-]{1,100}/[A-Za-z0-9._-]{1,100}$")

SURVEY_NAME = "survey.json"
RUNS_DIR = "runs"
REPOS_DIR = "repos"

PUSH_RETRIES = 1

COMMIT_NAME = "shard[bot]"
COMMIT_EMAIL = "shard[bot]@users.noreply.github.com"


class StateUnavailable(Exception):
    pass


@dataclass(frozen=True)
class StateRef:

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
    return StateRef(root=pathlib.Path(root), slug=_safe_slug(slug))


def _safe_slug(slug: str) -> str:
    cleaned = (slug or "").strip().strip("/")
    dotted = any(set(part) == {"."} for part in cleaned.split("/"))
    if not _SLUG.match(cleaned) or ".." in cleaned or dotted:
        raise StateUnavailable(
            f"{slug!r} is not a <owner>/<name> repository slug; refusing to build a path from it")
    return cleaned



def load_survey(ref: StateRef) -> tuple[dict | None, str]:
    try:
        return json.loads(ref.survey_file.read_text(encoding="utf-8")), ""
    except FileNotFoundError:
        return None, "no survey recorded yet for this repository"
    except OSError as e:
        return None, f"the survey could not be read: {e}"
    except json.JSONDecodeError as e:
        return None, f"the survey is not valid JSON and was ignored: {e}"


def survey_note(survey: dict | None, *, limit: int = 12) -> str:
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
    spots = [s for s in survey.get("blind_spots", []) if isinstance(s, str)]
    if spots:
        note += "\n\nKnown blind spots:\n" + "\n".join(f"  {prompt_safe(s, limit=300)}" for s in spots[:6])
    return note



def save_survey(ref: StateRef, payload: dict) -> str:
    return _write_json(ref.survey_file, payload)


def build_run_record(*, run_id: str, mode: str, status: str, scope, findings,
                     survey_seen: bool) -> dict:
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
    run_id = str(record.get("run_id") or "").strip()
    if not run_id or "/" in run_id or ".." in run_id:
        return f"refusing to write a run record under id {run_id!r}"
    return _write_json(ref.runs_dir / f"{run_id}.json", record)


def _write_json(path: pathlib.Path, payload: dict) -> str:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    except (OSError, TypeError, ValueError) as e:
        return f"could not write {path.name}: {e}"
    return ""



def commit_and_push(ref: StateRef, message: str, *, runner=subprocess.run,
                    retries: int = PUSH_RETRIES) -> str:
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
            if _git(runner, root, "pull", "--rebase", config=identity):
                break
    return "the state repository could not be pushed; the findings above were still delivered"


def _identity_config(runner, root: str) -> tuple[str, ...]:
    found = _git_output(runner, root, "config", "--get-regexp", r"^user\.(name|email)$")
    have = {line.split(None, 1)[0] for line in found.splitlines() if line.strip()}
    config: list[str] = []
    if "user.name" not in have:
        config += ["-c", f"user.name={COMMIT_NAME}"]
    if "user.email" not in have:
        config += ["-c", f"user.email={COMMIT_EMAIL}"]
    return tuple(config)


def _argv(root: str, args, config=()) -> list:
    from shard.diffscope import safe_directory_argv

    return [*safe_directory_argv(root), *config, "-C", root, *args]


def _git(runner, root: str, *args: str, config=()) -> str:
    try:
        proc = runner(_argv(root, args, config), capture_output=True, text=True, errors="replace",
                      timeout=120)
    except (OSError, subprocess.SubprocessError) as e:
        return f"git {args[0]} failed: {e}"
    if proc.returncode != 0:
        return f"git {args[0]} failed: {(proc.stderr or '').strip()[:200]}"
    return ""


def _git_output(runner, root: str, *args: str) -> str:
    try:
        proc = runner(_argv(root, args), capture_output=True, text=True, errors="replace",
                      timeout=120)
    except (OSError, subprocess.SubprocessError):
        return ""
    return proc.stdout if proc.returncode == 0 else ""


@dataclass
class StateOutcome:

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
