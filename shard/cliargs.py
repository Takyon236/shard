

import argparse
import math

from shard.budget import SCAN_PROFILES
from shard.gate import FAIL_ON_CHOICES


def _ceiling(value: str) -> float:
    try:
        number = float(value)
    except ValueError as e:
        raise argparse.ArgumentTypeError("must be a finite non-negative number") from e
    if not math.isfinite(number) or number < 0:
        raise argparse.ArgumentTypeError("must be a finite non-negative number")
    return number

DEFAULT_MODEL = "glm-5.2"

def _endpoint_args(parser) -> None:
    parser.add_argument("--model-endpoint", default=None,
                        help="an OpenAI-compatible base URL for self-hosted vLLM or Ollama")
    parser.add_argument("--model", default=DEFAULT_MODEL, help="model identifier")
    parser.add_argument("--api-key-env", default=None,
                        help="environment variable holding the endpoint's key")


def _budget_args(parser, *, scan_default: str, max_steps_available: bool = False) -> None:
    parser.add_argument(
        "--max-spend-usd", type=_ceiling, default=0.0,
        help="hard ceiling on inference spend, debited from the price the endpoint reports on every "
             "response. 0 means unmetered. The run stops BEFORE a model call it cannot afford at the "
             "highest price it has already paid this run, so the ceiling holds rather than being "
             "crossed by the call that trips it. Two cases still cross it by at most one call and "
             "neither is knowable in advance: the FIRST call of a run has no observed price behind "
             "it, and a call can be priced above every call before it — no endpoint we support "
             "accepts a spend cap as a request parameter, so a call's real cost arrives with its "
             "response")
    parser.add_argument("--max-minutes", type=_ceiling, default=0.0, help="0 means unmetered")
    parser.add_argument("--max-tokens", type=_ceiling, default=0.0, help="0 means unmetered")
    override_help = ("Explicit --max-tokens and --max-steps values always win over both"
                     if max_steps_available
                     else "An explicit --max-tokens value always wins over both")
    parser.add_argument(
        "--scan", choices=sorted(SCAN_PROFILES), default=scan_default,
        help="which kind of scan this is, and therefore what unset ceilings mean. THIS SETS A "
             "BUDGET, NOT A SCOPE: in diff mode the run reviews exactly the diff whichever you pick. "
             "'initial' is a first look at a target, sized for COVERAGE, because a first scan that "
             "stops early reports a floor rather than a result. 'followup' is every run after that: "
             "the baseline exists, so the run pays for the change rather than for the tree. "
             + override_help)


def build_parser(handlers: dict) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="shard",
        description="Security analysis with a reproducing input attached. Runs in your CI, on your "
                    "model endpoint.")
    sub = parser.add_subparsers(dest="command", required=True)
    for name, handler in handlers.items():
        _DECLARE[name](sub, handler)
    return parser


def _preflight_parser(sub, handler) -> None:
    pre = sub.add_parser("preflight", help="profile a repository; no inference, nearly free")
    pre.add_argument("--repo", default=".", help="path to the checkout")
    pre.add_argument("--workdir", default=None,
                     help="also validate an already-materialised workdir against the contract")
    pre.add_argument("--visibility", default="", choices=["", "public", "private"],
                     help="public or private. Public can be decided here; private remains unknown "
                          "until the operator checks group revenue and contributor count.")
    pre.add_argument("--entry-template", action="store_true",
                     help="print a ready-to-commit .shard/entry.sh for this repository's primary "
                          "language and exit. Redirect it: --entry-template > .shard/entry.sh. It is "
                          "a fixed skeleton, not generated from your code")
    pre.add_argument("--witness-entry", default="",
                     help="the repo-relative entry point your workflow declares, if it is not at a "
                          "conventional path. Preflight checks whether it exists and is runnable, "
                          "because without one NOTHING a run reports can fail a build")
    pre.add_argument("--probe-endpoint", action="store_true",
                     help="spend one probe turn confirming the endpoint supports native tool calling; "
                          "transient transport failures may retry. "
                          "The probe reports an unsupported endpoint before a review begins.")
    _endpoint_args(pre)
    pre.add_argument("--json", action="store_true")
    pre.set_defaults(handler=handler)


def _diff_parser(sub, handler) -> None:
    dif = sub.add_parser("diff", help="review a pull request; the free tier's shipping artefact")
    dif.add_argument("--repo", default=".", help="path to the checkout")
    dif.add_argument("--base-ref", default="HEAD~1", help="what this pull request is measured against")
    dif.add_argument("--witness-entry", default=None,
                     help="repo-relative runnable entry point the customer declared. Without one, "
                          "nothing this run reports can gate the build")
    dif.add_argument("--state-repo", default=None,
                     help="path to the checked-out DEDICATED state repository. Optional: without it "
                          "nothing accumulates between runs")
    dif.add_argument("--slug", default=None, help="<owner>/<name> of the repository under review")
    dif.add_argument("--run-id", default="run", help="identifier for this run's record")
    _endpoint_args(dif)
    _budget_args(dif, scan_default=None, max_steps_available=True)
    dif.add_argument("--fail-on", choices=FAIL_ON_CHOICES, default="none",
                     help="none reports only. reproduced gates on a finding carrying a DEMONSTRATION. "
                          "new gates when a demonstrated defect is attributed to this change: it "
                          "replays against the base when possible, then falls back to changed-line "
                          "attribution with reduced confidence. A hypothesis NEVER gates")
    dif.add_argument("--max-steps", type=int, default=None,
                     help="how many turns the hunt may take. Omit for the measured default, "
                          "simple.DEFAULT_MAX_STEPS — or the higher floor a --scan profile sets, "
                          "which since 2026-08-21 is what `--scan initial` does. This is the FOURTH "
                          "ceiling and until 2026-08-11 "
                          "it was the only one nobody could set: the first real diff this product "
                          "reviewed — 3 files, 71 added lines — used all 40 steps, spent $0.28 of a "
                          "$0.30 allowance and stopped at `maxsteps` with nothing to show. Dollars, "
                          "minutes and tokens were all configurable and none of them was the "
                          "constraint")
    dif.add_argument("--hunk-radius", type=int, default=None,
                     help="lines of context either side of a changed line to name as the change's "
                          "neighbourhood. 0 scopes to whole files, which is what every run before "
                          "2026-08-08 did. Omit for the measured "
                          "default, diffscope.HUNK_RADIUS")
    dif.add_argument("--out-dir", default=None)
    dif.add_argument(
        "--journal-path", default=None,
        help="opt in to retaining the raw run transcript at this path. It contains model reasoning "
             "and source returned by tools, so the path must be outside --out-dir and is never "
             "exposed by the GitHub Action. Without this option, a private temporary journal is "
             "used only to derive redacted telemetry and the run log, then deleted before the "
             "command returns")
    dif.add_argument("--no-execution", action="store_true",
                     help=argparse.SUPPRESS)
    dif.add_argument("--no-survey", action="store_true",
                     help=argparse.SUPPRESS)
    dif.add_argument("--json", action="store_true")
    dif.set_defaults(handler=handler)


def _survey_parser(sub, handler) -> None:
    surv = sub.add_parser("survey", help="what this codebase is and what we might look for; free tier")
    surv.add_argument("--repo", default=".", help="path to the checkout")
    surv.add_argument("--witness-entry", default=None,
                      help="repo-relative runnable entry point the customer declared. Without one, "
                           "every candidate stays a hypothesis")
    surv.add_argument("--out-dir", default=None, help="write shard-survey.json here")
    surv.add_argument("--slug", default=None, help="<owner>/<name> of the repository under review")
    surv.add_argument("--json", action="store_true")
    surv.set_defaults(handler=handler)




def _action_parser(sub, handler) -> None:
    act = sub.add_parser("action", help="run from a GitHub Action's INPUT_* environment")
    act.set_defaults(handler=handler)






_DECLARE = {
    "preflight": _preflight_parser,
    "diff": _diff_parser,
    "survey": _survey_parser,
    "action": _action_parser,
}
