"""Every command-line flag this product accepts, and which handler runs each subcommand.

Split out of `shard/cli.py` on 2026-08-28. That file was 2,545 raw lines and 1,097 code lines
holding seven subcommands, the ceilings, the artefact writers, the terminal rendering and this
parser — `BACKLOG.md` item 2 calls them "three modules wearing one filename" and it was undercounting.
The parser alone was 281 lines and `_build_parser` was 66 statements, which is the largest single
block in the file that decides nothing.

**This is the blocker on a maintenance script --strict`**, and the number is measured rather
than asserted: replaying the last 240 commits that touched `shard/`, the strict freeze would have
gone red on 53.3% of them, and 65 of the 102 module firings behind that are `cli.py` alone.

## What this module is deliberately not allowed to know

**The handlers.** `build_parser` takes them as a mapping and wires them by subcommand name, so
nothing here imports `shard.cli` and there is no cycle to unpick later. The direction is what makes
the surface readable on its own terms: a session asked what `--scan` does opens one file and finds
every flag, every help string, and no control flow at all.

## Why a flat sibling module and not `shard/cli/`

`BACKLOG.md` item 2 proposed a package, to keep the `shard = shard.cli:main` entry point alive. A
sibling module keeps it alive by not touching it, and the package form was measured against the
guards that already exist and REJECTED:

* the maintainers' suite resolves every name in `FREE_MODULES` to `shard/<name>.py` and
  SKIPS what is not a file. `shard/cli/__init__.py` is not a file at that path, so the paid-import
  count — the one guard standing between a nested `from the separate package import ...` and the published
  free artefact — would have passed by not running. That is the exact failure this repository
  recorded on 2026-08-26, when the same guard asserted only that the count was non-zero.
* a maintenance script states that the free package is FLAT and that `FREE_PACKAGES` being
  empty is the statement. A subpackage is a deliberate decision needing its own argument; a sibling
  module needs none, because `FREE_MODULES` is already a list of exactly this shape.

## The three registration points a new module here costs

`FREE_MODULES` (a maintenance script), `PAID_MODULES` (a maintenance script) and the
free-tier module list in the design notes, which the maintainers' suite parses. Two of the
three are not checked by `./.claude/fast-check.sh`, so they are named here rather than left to be
rediscovered.
"""


import argparse

from shard.budget import SCAN_PROFILES
from shard.gate import FAIL_ON_CHOICES
# ON ITS OWN LINE so the free build can remove it. `DEEP_FAIL_ON_CHOICES` is read by `_deep_parser`
# and by nothing else here, and `build_free_tree._drop_orphaned_imports` only rewrites single-name
# `from` imports — a two-name line would survive the drop with one name unused, which is an F401 in
# the published repository's own lint, over code it did not write.

#: The default model, stated once. A LITERAL rather than an import of `SolvePlan.model`, because the
#:
#: It lives beside the `--model` flag it is the default OF, and `shard/cli.py` re-exports it because
#: every caller — the tests, `action.py`'s argv builder — has always read it off `shard.cli`.
#:
#: GLM-5.2 by decision: open weights the customer controls (the maintainers' notes), and the frontier alias this
#: used to name refuses the solver's opening prompt outright — see the design notes, "Found by the
#: FIRST REAL RUN".
DEFAULT_MODEL = "glm-5.2"

def _endpoint_args(parser) -> None:
    """The three flags that name WHOSE endpoint this is. One declaration, three subcommands.

    `--model-endpoint` falling through to `None` is the sovereignty breach this repository leads with
    (`shard/llm.py` `ENDPOINT` is a hardwired openrouter.ai URL), so the flags that select an endpoint
    are the last place to tolerate three near-copies drifting apart.
    """
    parser.add_argument("--model-endpoint", default=None,
                        help="an OpenAI-compatible base URL for self-hosted vLLM or Ollama")
    parser.add_argument("--model", default=DEFAULT_MODEL, help="model identifier")
    parser.add_argument("--api-key-env", default=None,
                        help="environment variable holding the endpoint's key")


def _budget_args(parser, *, scan_default: str) -> None:
    """The three per-run ceilings. Same argument as `_endpoint_args`, and the same drift happened.

    `0` MEANS UNMETERED on all three, and `_budget` (below) depends on that reading — so the sentence
    saying so is not decoration. Before this was one declaration, `deep` carried it and `diff` did not,
    which meant the free tier, the v1 shipping artefact, documented its spend ceiling less well than
    the separate build did.

    `--max-steps` is deliberately NOT here: it is diff-mode only, and `0` on it is refused rather than
    unmetered (`_max_steps`). A flag whose zero means the opposite of these three does not belong in
    the helper that promises they agree.
    """
    parser.add_argument(
        "--max-spend-usd", type=float, default=0.0,
        help="hard ceiling on inference spend, debited from the price the endpoint reports on every "
             "response. 0 means unmetered. The run stops BEFORE a model call it cannot afford at the "
             "highest price it has already paid this run, so the ceiling holds rather than being "
             "crossed by the call that trips it. Two cases still cross it by at most one call and "
             "neither is knowable in advance: the FIRST call of a run has no observed price behind "
             "it, and a call can be priced above every call before it — no endpoint we support "
             "accepts a spend cap as a request parameter, so a call's real cost arrives with its "
             "response")
    parser.add_argument("--max-minutes", type=float, default=0.0, help="0 means unmetered")
    parser.add_argument("--max-tokens", type=float, default=0.0, help="0 means unmetered")
    parser.add_argument(
        "--scan", choices=sorted(SCAN_PROFILES), default=scan_default,
        help="which kind of scan this is, and therefore what unset ceilings mean. THIS SETS A "
             "BUDGET, NOT A SCOPE: in diff mode the run reviews exactly the diff whichever you pick. "
             "'initial' is a first look at a target, sized for COVERAGE, because a first scan that "
             "stops early reports a floor rather than a result. 'followup' is every run after that: "
             "the baseline exists, so the run pays for the change rather than for the tree. An "
             "explicit --max-tokens or --max-steps always wins over both")


def build_parser(handlers: dict) -> argparse.ArgumentParser:
    """The surface for exactly the commands `handlers` supplies a function for.

    Handlers are passed IN rather than imported, which is what keeps this module free of `shard.cli`
    and therefore free of a cycle. Each command's flags are declared by its own function below;
    `_DECLARE` at the foot of this file maps a name to one, and this walks the caller's table.

    **DRIVEN BY THE HANDLERS, and that is what the free build rests on.** a maintenance script
    drops `_cmd_deep`, `_cmd_mirror` and `_cmd_fix` from `shard/cli.py` and their three declarations
    from this module; the commands then do not exist in the emitted parser because nothing supplied a
    handler for them, with no third list of names to keep in step. Before the split the same cut was
    a sweep over statements inside a 200-line `_build_parser` body, keyed on the LOCAL VARIABLE names
    `deep`, `mir` and `fixp` — which would have taken any other local that happened to be spelled
    that way, and which had no way to refuse a paid command nobody had thought to name.

    A handler naming a command this module does not declare raises `KeyError` here, on the first
    invocation, which is loud. The opposite — a declaration nothing dispatches to — is silent, and is
    the correct state in the free artefact; the maintainers' suite asserts the two agree in THIS tree,
    which is the only tree where disagreeing is a defect.
    """
    parser = argparse.ArgumentParser(
        prog="shard",
        description="Security analysis with a reproducing input attached. Runs in your CI, on your "
                    "model endpoint.")
    sub = parser.add_subparsers(dest="command", required=True)
    for name, handler in handlers.items():
        _DECLARE[name](sub, handler)
    return parser


def _preflight_parser(sub, handler) -> None:
    """`preflight` — profile a repository and price it. The onboarding and pricing
    instrument, available on every tier."""
    pre = sub.add_parser("preflight", help="profile a repository; no inference, nearly free")
    pre.add_argument("--repo", default=".", help="path to the checkout")
    pre.add_argument("--workdir", default=None,
                     help="also validate an already-materialised workdir against the contract")
    # SUPPLIED, NOT GUESSED. A checkout does not know whether its origin is public, and the free
    # tier is public + simple — so half the rule is unavailable locally. `free_tier_verdict` answers
    # "unknown" without it, deliberately: a pricing instrument that resolves ambiguity in our own
    # favour is the kind of thing a customer finds out about later.
    pre.add_argument("--visibility", default="", choices=["", "public", "private"],
                     help="public or private. Half of the free-tier rule, and a checkout cannot "
                          "know it; omitted means the verdict is 'unknown' rather than a guess.")
    # THE ENDPOINT PROBE, opt-in. §6c promises preflight refuses a bad endpoint rather than
    # producing a bad run, and it costs ONE request — so it is a flag rather than a default, because
    # a profiling command that quietly spends money is worse than one that has to be asked.
    pre.add_argument("--entry-template", action="store_true",
                     help="print a ready-to-commit .shard/entry.sh for this repository's primary "
                          "language and exit. Redirect it: --entry-template > .shard/entry.sh. It is "
                          "a fixed skeleton, not generated from your code")
    pre.add_argument("--witness-entry", default="",
                     help="the repo-relative entry point your workflow declares, if it is not at a "
                          "conventional path. Preflight checks whether it exists and is runnable, "
                          "because without one NOTHING a run reports can fail a build")
    pre.add_argument("--probe-endpoint", action="store_true",
                     help="spend one request confirming the endpoint supports native tool calling. "
                          "Without it a scan on an incapable endpoint finds nothing and looks clean.")
    _endpoint_args(pre)
    pre.add_argument("--json", action="store_true")
    pre.set_defaults(handler=handler)


def _diff_parser(sub, handler) -> None:
    """`diff` — review a pull request. The free tier and the v1 shipping artefact, and the
    only command carrying the two ablation arms a maintenance script drives."""
    dif = sub.add_parser("diff", help="review a pull request; the free tier and the v1 artefact")
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
    # Diff mode defaults to NO profile, which keeps its unset `--max-tokens` meaning what it has
    # always meant: unmetered. `test_the_free_tier_has_no_invented_token_ceiling` records why —
    # no measurement of a diff-scoped run supports a ceiling, and one invented here would be a
    # number nobody checked, quoted to a customer as a safety property. Both profiles are still
    # offered here; on this mode they are opt-in rather than imposed.
    _budget_args(dif, scan_default=None)
    dif.add_argument("--fail-on", choices=FAIL_ON_CHOICES, default="none",
                     help="none reports only. reproduced gates on a finding carrying a DEMONSTRATION. "
                          "new gates only when a demonstrated finding sits on a line this change "
                          "introduced — derived from the diff in hand, nothing stored. A hypothesis "
                          "NEVER gates")
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
    # ABLATION ARM ONLY — the maintainers' notes arm A, and the same shape the separate package uses for
    # `contract_endpoint`. It reproduces the pre-2026-08-19 toolset (four tools, nothing executable) so
    # that a maintenance script --compare-execution` has a control. Not a customer knob: `README.md`
    # does not document it, and if arm A says execution does not pay, the capability goes and this
    # flag goes with it rather than becoming a permanent option.
    dif.add_argument("--no-execution", action="store_true",
                     help=argparse.SUPPRESS)
    # ABLATION ARM ONLY, same contract as `--no-execution` one line above. It blanks the survey note
    # that `shard/state.py` feeds into the SYSTEM message, so a maintenance script --compare-survey`
    # has a control for the one accumulation mechanism this product already ships.
    #
    # **IT BLANKS THE NOTE AND NOTHING ELSE, and that is the whole design.** The survey is still built
    # and still written to the state repository in both arms, because the arms have to differ in what
    # the MODEL was told and never in what the harness did — the confound `simple._CAPABILITY_OFF`'s
    # first draft shipped, inverted. Skipping the build would also skip the state write, which is a
    # second variable and would make any difference between the arms unattributable.
    dif.add_argument("--no-survey", action="store_true",
                     help=argparse.SUPPRESS)
    dif.add_argument("--json", action="store_true")
    dif.set_defaults(handler=handler)


def _survey_parser(sub, handler) -> None:
    """`survey` — what this codebase is and what we might look for in it. Free tier."""
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
    """`action` — run from a GitHub Action's `INPUT_*` environment. It takes NO flags on
    purpose: its interface is the environment GitHub sets, and a flag here would be a way
    to invoke it that no runner ever will."""
    act = sub.add_parser("action", help="run from a GitHub Action's INPUT_* environment")
    act.set_defaults(handler=handler)






#: WHICH FUNCTION DECLARES EACH COMMAND'S FLAGS. Read by `build_parser`, which declares only the
#: entries the caller handed a handler for.
#:
#: A row here and its handler in `shard/cli.py` are dropped TOGETHER by the free build — the row
#: because its value is a function that left, the function because it is named in
#: `_FREE_EXCLUDED_FUNCTIONS`. That is one rule applied twice rather than two mechanisms, and it is
#: what let `_PAID_PARSER_LOCALS` be deleted.
_DECLARE = {
    "preflight": _preflight_parser,
    "diff": _diff_parser,
    "survey": _survey_parser,
    "action": _action_parser,
}
