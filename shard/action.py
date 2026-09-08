
from __future__ import annotations

import contextlib
import io
import json
import os
import pathlib
import re

from shard.actionresult import payload_error as _payload_error
from shard.actionhandoff import ActionHandoff as _ActionHandoff
from shard.actionsnapshot import ingest_artefacts as _ingest_artefacts
from shard.gate import EXIT_CONFIG, EXIT_GATED, EXIT_OK, exit_code

MODES = ('survey', 'diff')

INPUTS = (
    'mode', 'model_endpoint', 'model', 'api_key_env', 'max_spend_usd', 'max_minutes', 'max_tokens', 'scan', 'max_steps', 'hunk_radius', 'witness_entry', 'base_ref', 'state_repo', 'slug', 'fail_on', 'out_dir', 'github_token',
)

NOT_A_FLAG = frozenset({'github_token'})

NOT_WIRED: dict[str, str] = {}

MODE_REFUSES: dict[str, dict[str, tuple[str, str]]] = {
    "survey": {
        "model_endpoint": ("", "the survey makes no inference call"),
        "scan": ("", "the survey has no budget for a profile to size"),
        "max_steps": ("", "the survey takes no turns"),
        "hunk_radius": ("", "the survey reads no diff"),
        "state_repo": ("", "the survey writes no state; a diff run is what accumulates there"),
    },
}

_GATE_KEY = {"diff": "gate_eligible", "deep": "reproduced"}

DEFAULT_OUT_DIR = "shard-out"
_ACTION_MODEL_KEY_ENV = "SHARD_ACTION_MODEL_API_KEY"


class ActionInputError(Exception):
    pass


def _input(env, name: str) -> str:
    upper = name.upper()
    for key in ("INPUT_" + upper.replace("_", "-"), "INPUT_" + upper):
        value = (env.get(key) or "").strip()
        if value:
            return value
    return ""


def _opt(argv: list[str], flag: str, value: str) -> None:
    if value:
        argv += [flag, value]


def _ceilings(env, argv: list[str]) -> None:
    for flag, name in (("--max-spend-usd", "max_spend_usd"), ("--max-minutes", "max_minutes"),
                       ("--max-tokens", "max_tokens")):
        _opt(argv, flag, _input(env, name))


def workdir_for(env) -> str:
    root = env.get("RUNNER_TEMP") or "/tmp"
    return str(pathlib.Path(root) / "shard-workdir")


def argv_for(env, *, contained: bool = False) -> list[str]:
    mode = _input(env, "mode") or "diff"
    if mode not in MODES:
        raise ActionInputError(f"mode must be one of {list(MODES)}, not {mode!r}")

    for name, (inert, why) in MODE_REFUSES.get(mode, {}).items():
        value = _input(env, name)
        if value and value != inert:
            raise ActionInputError(
                f"{mode} mode cannot act on the {name!r} input, and it was set to {value!r}: {why}. "
                f"Remove it from this step, or use `mode: diff`, which acts on it")

    argv = [mode, "--repo", env.get("GITHUB_WORKSPACE") or ".",
            "--out-dir", _input(env, "out_dir") or DEFAULT_OUT_DIR]

    _opt(argv, "--slug", _input(env, "slug") or (env.get("GITHUB_REPOSITORY") or ""))

    if mode == "survey":
        _opt(argv, "--witness-entry", _input(env, "witness_entry"))
        return argv + ["--json"]

    _opt(argv, "--model", _input(env, "model"))
    _opt(argv, "--model-endpoint", _input(env, "model_endpoint"))
    requested_key_env = _input(env, "api_key_env")
    _opt(argv, "--api-key-env",
         _ACTION_MODEL_KEY_ENV if contained and requested_key_env else requested_key_env)
    _ceilings(env, argv)
    _opt(argv, "--scan", _input(env, "scan"))
    _opt(argv, "--fail-on", _input(env, "fail_on"))

    if mode == "diff":
        _opt(argv, "--max-steps", _input(env, "max_steps"))
        _opt(argv, "--hunk-radius", _input(env, "hunk_radius"))
        _opt(argv, "--base-ref", _input(env, "base_ref"))
        _opt(argv, "--witness-entry", _input(env, "witness_entry"))
        _opt(argv, "--state-repo", _input(env, "state_repo"))
        _opt(argv, "--run-id", env.get("GITHUB_RUN_ID") or "")
    else:
        argv += ["--workdir", workdir_for(env)]
        _opt(argv, "--harness", _input(env, "harness"))
        _opt(argv, "--memory-file", _input(env, "memory_file"))
        _opt(argv, "--library", _input(env, "library"))
        _opt(argv, "--library-mirror", _input(env, "library_mirror"))

    return argv + ["--json"]


def outputs_for(mode: str, payload: dict) -> dict[str, str]:
    artefacts = payload.get("artefacts") or {}
    bundles = artefacts.get("bundles") or []
    return {
        "status": str(payload.get("status", "done")),
        "findings": str(payload.get("findings", 0)),
        "gate-eligible": str(payload.get(_GATE_KEY.get(mode, ""), 0)),
        "sarif-path": str(artefacts.get("sarif", "")),
        "report-path": str(artefacts.get("report", "")),
        "bundle-path": str(pathlib.Path(bundles[0]).parent) if bundles else "",
        "result-path": str(artefacts.get("result", "")),
        "telemetry-path": str(artefacts.get("telemetry", "")),
        "log-path": str(artefacts.get("log", "")),
    }


def render_outputs(outputs: dict[str, str], *, echo=print) -> str:
    lines, refused = [], []
    for name, value in outputs.items():
        if "\n" in value or "\r" in value:
            refused.append(name)
            continue
        lines.append(f"{name}={value}")
    if refused:
        echo(f"::error::shard: {len(refused)} output(s) carried a newline and were NOT written: "
             f"{', '.join(refused)}. A step reading them sees the empty string; the findings and the "
             f"exit status are unaffected. Check `out_dir`, the only part of a path a workflow gives.")
    return "".join(f"{line}\n" for line in lines)


def run(env=None, *, invoke=None, echo=print, opener=None, handoff_stream=None) -> int:
    env = os.environ if env is None else env
    try:
        handoff = _ActionHandoff.begin(env, stream=handoff_stream)
    except (OSError, ValueError) as error:
        raise ActionInputError(f"authenticated runner handoff failed: {error}") from error

    from shard.cli import main

    try:
        invoke = invoke or main
        argv = argv_for(env, contained=handoff is not None)

        echo(f"::group::{describe(argv, env)}")
        try:
            code = _run(argv, env, invoke=invoke, echo=echo, opener=opener, handoff=handoff)
            if handoff is not None:
                invalid = handoff.seal()
                if invalid:
                    echo(f"shard: {invalid}; no outputs can cross the container boundary")
                    return EXIT_CONFIG
            return code
        finally:
            echo("::endgroup::")
    finally:
        if handoff is not None:
            handoff.discard()


def describe(argv: list[str], env=None) -> str:
    labels = {"--base-ref": "against", "--max-spend-usd": "max $", "--max-tokens": "max tokens",
              "--max-minutes": "max minutes", "--max-steps": "max steps", "--fail-on": "fail-on",
              "--scan": "scan", "--witness-entry": "witness", "--api-key-env": "key from",
              "--model-endpoint": "endpoint"}
    parts = []
    for flag, label in labels.items():
        if flag not in argv:
            continue
        at = argv.index(flag) + 1
        value = argv[at] if at < len(argv) else ""
        if not value:
            continue
        if flag.startswith("--max-") and value in ("0", "0.0", "0.00"):
            continue
        parts.append(f"{label} {value[:12] if flag == '--base-ref' else value}".strip())
    from shard.report import is_numbered, report_id, report_label

    body = f"shard {argv[0] if argv else '?'}" + (" · " + " · ".join(parts) if parts else "")
    ident = report_id(env if env is not None else {})
    if not is_numbered(ident):
        return body
    slug = argv[argv.index("--slug") + 1] if "--slug" in argv else ""
    return f"{report_label(ident, slug, quoted=False)} — {body}"


def _describes_itself(code: int, payload: dict, env, *, echo=print) -> bool:
    status = str(payload.get("status") or "")
    fail_on = _input(env, "fail_on") or "none"
    delivery = (payload.get("artefacts") or {}).get("delivery") or {}
    delivery_failed = (code == EXIT_CONFIG and status == "error" and delivery.get("ok") is False
                       and bool(delivery.get("failed_required")))
    refused_by_gate = code != EXIT_OK and code == exit_code(False, fail_on, status=status)
    if code not in (EXIT_OK, EXIT_GATED) and not refused_by_gate and not delivery_failed:
        echo("shard: the run did not complete; no outputs were written")
        return False
    if delivery_failed:
        echo("shard: the review completed, but a required reproduction bundle could not be delivered. "
             "The outputs below describe the delivery failure; no missing reproduction can gate.")
    elif refused_by_gate:
        echo(f"shard: the review ended `{status}` and `fail_on: {fail_on}` was set, so this step "
             f"reports a configuration failure rather than a pass — a review that did not happen "
             f"cannot clear a gate. The outputs below describe the run.")
    return True


def _write_command_files(env, payload: dict, outputs: dict[str, str], validated: dict[str, bytes],
                         handoff: _ActionHandoff | None, *, echo) -> bool:
    complete = True
    path = env.get("GITHUB_OUTPUT")
    if path:
        rendered = render_outputs(outputs, echo=echo)
        try:
            with open(path, "a", encoding="utf-8") as handle:
                handle.write(rendered)
            if handoff is not None:
                handoff.append_relay("output", rendered.encode("utf-8"))
        except OSError as error:
            complete = False
            echo(f"shard: $GITHUB_OUTPUT could not be written ({error.__class__.__name__}: {error}); "
                 f"the findings are unaffected, but a later step reading these outputs will see "
                 f"nothing")
    else:
        echo("shard: no $GITHUB_OUTPUT; outputs were computed and not written")

    summary_appends: list[bytes] = []
    report = ((payload.get("artefacts") or {}).get("report") or "").strip()
    summary_expected = bool(env.get("GITHUB_STEP_SUMMARY") and report)
    summary_written = write_step_summary(
        env, payload, validated=validated, echo=echo, handoff_appends=summary_appends)
    if summary_expected and not summary_written:
        complete = False
    if handoff is not None and summary_appends:
        handoff.append_relay("summary", summary_appends[0])
    return complete


def _run(argv, env, *, invoke, echo, opener, handoff: _ActionHandoff | None = None) -> int:
    if argv[0] == "deep" and _input(env, "max_steps"):
        echo("shard: deep mode IGNORED max_steps — the solver's step budget is part of its measured "
             "configuration. To bound a deep run use max_spend_usd, max_minutes, max_tokens, or "
             "`scan: followup`.")

    if argv[0] == "survey" and _input(env, "fail_on") not in ("", "none"):
        echo(f"shard: survey mode CANNOT GATE — `fail_on: {_input(env, 'fail_on')}` has nothing here "
             f"that could fire it, because a survey reports candidates and never a finding carrying a "
             f"demonstration. This step passes on every survey; gate the `mode: diff` step instead.")

    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        code = invoke(argv)
    captured = buffer.getvalue()
    if captured:
        echo(captured.rstrip("\n"))

    try:
        payload = json.loads(captured)
    except (ValueError, TypeError):
        echo("shard: the run produced no machine-readable payload; no outputs were written")
        return code

    invalid = _payload_error(argv[0], payload)
    if invalid:
        echo(f"shard: the run produced an incomplete machine-readable payload ({invalid}); "
             "no outputs or delivery actions were written")
        return EXIT_CONFIG

    invalid, validated, payload, handoff_files = _ingest_artefacts(
        argv[0], payload, argv[argv.index("--out-dir") + 1],
        env.get("SHARD_ACTION_SNAPSHOT_ROOT") or env.get("RUNNER_TEMP") or "/tmp")
    if invalid:
        echo(f"shard: the run's machine-readable payload claimed an invalid output artefact ({invalid}); "
             "no outputs or delivery actions were written")
        return EXIT_CONFIG
    if handoff is not None:
        handoff.bind_snapshot(handoff_files)

    if not _describes_itself(code, payload, env, echo=echo):
        return code

    failed = (payload.get("artefacts") or {}).get("failed") or {}
    if failed:
        echo(f"::error::shard: {len(failed)} artefact(s) could not be written and are MISSING from this "
             f"run: {', '.join(sorted(failed))}. The findings themselves are unaffected — what is "
             f"missing is where they were written to.")

    relay_complete = _write_command_files(
        env, payload, outputs_for(argv[0], payload), validated, handoff, echo=echo)
    upload_sarif(env, payload, validated=validated, opener=opener, echo=echo)
    comment_on_pull_request(env, payload, validated=validated, opener=opener, echo=echo)
    if handoff is not None and not relay_complete:
        echo("shard: the authenticated command-file handoff is incomplete; delivery was attempted "
             "but no successful review status can cross the container boundary")
        return EXIT_CONFIG
    return code


COMMENT_MARKER = "<!-- shard:report -->"


def _delivery_bytes(path: str, key: str, validated: dict[str, bytes] | None) -> bytes:
    return validated[key] if validated is not None else pathlib.Path(path).read_bytes()


def comment_on_pull_request(env, payload: dict, *, validated: dict[str, bytes] | None = None,
                            opener=None, echo=print) -> bool:
    token = _input(env, "github_token")
    report = ((payload.get("artefacts") or {}).get("report") or "").strip()
    repo = (env.get("GITHUB_REPOSITORY") or "").strip()
    slug = _input(env, "slug")
    number = _pull_request_number(env)

    if not report:
        return False
    if number is None:
        if (env.get("GITHUB_EVENT_NAME") or "").strip() == "workflow_run":
            echo("shard: this is a `workflow_run` job, which runs on a branch ref and carries no "
                 "pull-request number, so NO COMMENT was posted — `pull-requests: write` and "
                 "`github_token` buy nothing on this trigger. The report is on the job page under "
                 "$GITHUB_STEP_SUMMARY; see the fork section of README.md.")
        return False
    if not token:
        echo("shard: no github_token, so no pull-request comment was posted. Pass "
             "`github_token: ${{ secrets.GITHUB_TOKEN }}` with `permissions: "
             "{pull-requests: write}` — see README.md.")
        return False
    if not repo or (slug and slug != repo):
        echo(f"shard: the review was of {slug or 'another repository'!r} and this pull request "
             f"belongs to {repo or 'nothing this run can name'!r}, so no comment was posted.")
        return False

    try:
        import urllib.request

        api = (env.get("GITHUB_API_URL") or "https://api.github.com").rstrip("/")
        issues = f"{api}/repos/{repo}/issues"
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
                   "X-GitHub-Api-Version": "2022-11-28", "Content-Type": "application/json"}
        send = opener or urllib.request.urlopen

        with send(urllib.request.Request(f"{issues}/{number}/comments?per_page=100",
                                         headers=headers), timeout=60) as response:
            existing = json.loads(response.read().decode())
        mine = [c for c in existing if COMMENT_MARKER in (c.get("body") or "")]

        body = json.dumps({"body": f"{COMMENT_MARKER}\n"
                                  f"{_delivery_bytes(report, 'report', validated).decode('utf-8')}"})
        if mine:
            url, verb = f"{issues}/comments/{mine[-1]['id']}", "PATCH"
        else:
            url, verb = f"{issues}/{number}/comments", "POST"
        with send(urllib.request.Request(url, data=body.encode(), method=verb, headers=headers),
                  timeout=60) as response:
            status = getattr(response, "status", 0)
    except Exception as e:
        echo(f"shard: the pull-request comment failed ({e.__class__.__name__}: {e}); the findings, "
             f"the artefacts and the exit status are unaffected.")
        return False

    if status not in (200, 201):
        echo(f"shard: the pull-request comment was refused ({status}); "
             f"`permissions: {{pull-requests: write}}` is the usual cause.")
        return False
    echo(f"shard: report {'updated on' if mine else 'posted to'} {repo}#{number}.")
    return True


def _pull_request_number(env) -> int | None:
    found = re.match(r"^refs/pull/(\d+)/", env.get("GITHUB_REF") or "")
    return int(found.group(1)) if found else None


SARIF_CATEGORY = "shard"


def upload_sarif(env, payload: dict, *, validated: dict[str, bytes] | None = None,
                 opener=None, echo=print) -> bool:
    token = _input(env, "github_token")
    sarif = ((payload.get("artefacts") or {}).get("sarif") or "").strip()
    repo = (env.get("GITHUB_REPOSITORY") or "").strip()
    sha = (env.get("GITHUB_SHA") or "").strip()
    ref = (env.get("GITHUB_REF") or "").strip()
    slug = _input(env, "slug")

    if not sarif:
        return False
    if slug and repo and slug != repo:
        echo(f"shard: the review was of {slug!r} and this workflow belongs to {repo!r}, so the SARIF "
             f"was NOT uploaded — alerts would attribute another repository's findings to this one, "
             f"against a commit that does not exist here. No token or permission changes this.")
        return False
    if not token:
        echo("shard: no github_token, so the SARIF was NOT uploaded to code scanning and this run "
             "produced no alerts. Pass `github_token: ${{ secrets.GITHUB_TOKEN }}` with "
             "`permissions: {security-events: write}` — see README.md.")
        return False
    if not (repo and sha and ref):
        echo("shard: GITHUB_REPOSITORY, GITHUB_SHA or GITHUB_REF is unset, so there is nothing to "
             "attach a code-scanning upload to; the SARIF is still in the artefacts.")
        return False

    try:
        import base64
        import gzip
        import urllib.request

        body = json.dumps({
            "commit_sha": sha,
            "ref": ref,
            "sarif": base64.b64encode(gzip.compress(
                _delivery_bytes(sarif, "sarif", validated))).decode(),
            "tool_name": SARIF_CATEGORY,
            "checkout_uri": pathlib.Path(env.get("GITHUB_WORKSPACE") or ".").as_uri(),
        }).encode()
        api = (env.get("GITHUB_API_URL") or "https://api.github.com").rstrip("/")
        request = urllib.request.Request(f"{api}/repos/{repo}/code-scanning/sarifs", data=body,
                                         method="POST", headers={
                                             "Authorization": f"Bearer {token}",
                                             "Accept": "application/vnd.github+json",
                                             "X-GitHub-Api-Version": "2022-11-28",
                                             "Content-Type": "application/json"})
        with (opener or urllib.request.urlopen)(request, timeout=60) as response:
            status = getattr(response, "status", 0)
    except Exception as e:
        echo(f"shard: the SARIF upload failed ({e.__class__.__name__}: {e}); the findings, the "
             f"artefacts and the exit status are unaffected, but this run produced no alerts.")
        return False

    if status not in (200, 202):
        echo(f"shard: code scanning answered {status} rather than 202; no alerts were created.")
        return False
    echo(f"shard: SARIF uploaded to {repo} code scanning for {sha}.")
    return True


def write_step_summary(env, payload: dict, *, validated: dict[str, bytes] | None = None,
                       echo=print, handoff_appends: list[bytes] | None = None) -> bool:
    path = env.get("GITHUB_STEP_SUMMARY")
    if not path:
        return False
    report = ((payload.get("artefacts") or {}).get("report") or "").strip()
    if not report:
        echo("shard: no report artefact, so nothing was written to $GITHUB_STEP_SUMMARY")
        return False
    try:
        text = _delivery_bytes(report, "report", validated).decode("utf-8")
        rendered = text if text.endswith("\n") else text + "\n"
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(rendered)
        if handoff_appends is not None:
            handoff_appends.append(rendered.encode("utf-8"))
    except (OSError, UnicodeError, KeyError) as e:
        echo(f"shard: $GITHUB_STEP_SUMMARY could not be written ({e.__class__.__name__}: {e}); the "
             f"findings are unaffected, but this run will not be legible in the Actions UI")
        return False
    return True


__all__ = ["COMMENT_MARKER", "INPUTS", "MODES", "MODE_REFUSES", "NOT_A_FLAG", "NOT_WIRED",
           "SARIF_CATEGORY", "ActionInputError", "argv_for", "comment_on_pull_request", "outputs_for",
           "render_outputs", "run", "upload_sarif", "workdir_for", "write_step_summary"]
