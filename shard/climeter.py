"""Every ceiling a run is given, and what it spent against them — the customer-facing half of
`shard/budget.py`.

Fourth cut of the maintainers' backlog item 2. `budget.py` is the MECHANISM: `Budget`, `BudgetGovernor`, the
`ScanProfile` table, the debiting. This is the layer above it that a customer actually touches —
seven flags, the four refusals, and the two payloads that report back.

## Why setting a ceiling and reporting the spend are one job and not two

`_spend`'s own docstring has said it since it was written: *"a ceiling nobody can reconcile against a
reported number is as decorative as a ceiling nothing debits."* Both halves were measured missing on
the same product. The solve path took no token ceiling at all unless one was passed, and `diff`
reported no cost of ANY kind — the ≈$0.29 of the first real run had to be read off OpenRouter's
billing API afterwards. Splitting them into two modules would put the ceiling and the only number
that can check it in two places.

## The four refusals, which are the reason this module is worth finding

`--max-steps 0`, `--attempts 0` and `--max-findings 0` are REFUSED rather than read as unmetered, and
each refusal names why in the message the customer sees. The three other ceilings — dollars, minutes,
tokens — DO read `0` as unmetered, so the asymmetry is the whole point: a run permitted zero steps,
zero passes or zero findings does not run forever, it reviews nothing, reports nothing and exits 0.
That is the green-check-that-reviewed-nothing this repository has now recorded four times, and it
would be offered as a configuration option.

`_refuse_a_token_ceiling_below_the_floor` is the fourth, and it exists because it was got wrong by
hand, on a real run, by somebody who had just spent the day reading the file it was in.
"""



from shard.budget import SCAN_PROFILES, Budget
from shard.gate import ConfigError


#: How far below the caller's measured default a DEEP run's explicit token ceiling may be set — HALF of
#: it. A run may be given less headroom than the measurement had (`SolvePlan.token_cap`, 8,000,000,
#: *"raised from 2M so 200 steps is reachable"*), but not so much less that it cannot reach the behaviour
#: the measurement describes. Expressed as a FRACTION of that default rather than a fixed 4,000,000, so
#: the refusal's "less than half of" is true by construction and the floor tracks the default instead of
#: being a second literal that has to be kept in sync with it.
DEEP_TOKEN_FLOOR_FRACTION = 0.5


def _refuse_a_token_ceiling_below_the_floor(asked: float, default_tokens: float | None) -> None:
    """A deep run may not be handed a ceiling it cannot finish inside. Raises `ConfigError`.

    **This exists because it was got wrong by hand, on a real run, by someone who had just spent the day
    reading this file.** `--max-tokens 2000000` was passed to a live deep run on 2026-08-19 — exactly the
    value `SolvePlan.token_cap`'s own comment records having been RAISED FROM, for the stated reason that
    200 steps were not reachable below it. Nothing objected. The number is pinned as the measured
    configuration by the maintainers' suite, and nothing stopped a CALLER from undercutting it.
    `action.yml` exposes `max_tokens` as a customer input with no floor and no warning, so the same
    mistake is one YAML line away for anybody installing the product.

    **REFUSED, NOT RAISED, and the direction matters.** Silently lifting a ceiling to 4M would spend more
    of the customer's money than they authorised — on their own inference endpoint — which is a worse
    failure than declining to start. `budget.py` already argues that a ceiling is *"mandatory rather than
    advisory"*; a ceiling the product quietly overrides is neither.

    THREE THINGS IT DELIBERATELY DOES NOT TOUCH:

    * **Diff mode.** `_cmd_diff` calls `_budget` with no `default_tokens`, so `default_tokens is None`
      is exactly "this mode has no measured deep ceiling to defend". A real repository's diff run finished on
      402,300 tokens; a 4M floor there would be a floor above the ceiling.
    * **`--scan followup`, whose profile is 400,000 tokens.** That is a MEASURED, named configuration
      for an incremental scan and the whole point of declaring one is that it *"genuinely overrides
      downward"*. So the floor is checked against the EXPLICIT flag, never against the resolved value —
      checking the resolved value would refuse the one downward override the product supports.
    * **`0`.** It is falsy, so it never reaches here; it means "no explicit ceiling" and falls through to
      the profile or the plan's own 8,000,000.
    """
    if default_tokens is None:
        return
    floor = default_tokens * DEEP_TOKEN_FLOOR_FRACTION
    if asked >= floor:
        return
    raise ConfigError(
        f"--max-tokens {asked:,.0f} is below the {floor:,.0f} floor a deep run needs. The "
        f"measured configuration is {default_tokens:,.0f} — raised from 2,000,000 precisely because "
        f"200 steps were not reachable below it — so a run given less than half of that stops at the "
        f"ceiling rather than at an answer, having spent everything it was given. Omit --max-tokens to "
        f"take the measured ceiling, or pass at least {floor:,.0f}. For a deliberately cheap "
        f"incremental run use --scan followup, which is a measured profile rather than a guess.")


def _budget(args, *, default_tokens: float | None = None) -> Budget:
    """`max-spend-usd`, `max-minutes` and `max-tokens`, which is `budget.py` becoming user-facing.

    A per-run ceiling is mandatory rather than advisory: the measured 16x spread across tasks means that
    without one, a weekly deep sweep on a large repository can consume a month of a team's inference
    budget without anybody having agreed to it.

    `default_tokens` is what an UNSET `--max-tokens` means, and it exists because the previous answer
    was `None` — unmetered. `Solve.__init__` falls back to `Budget(tokens=plan.token_cap)` only when no
    governor is supplied and the solve handler always supplies one, so the 8,000,000 that
    the maintainers' suite pins as the measured configuration governed sub-agent loops and nothing
    else — the solve path itself took no token ceiling unless one was passed (the design notes).
    The caller passes the ceiling it can defend: the solve path passes `SolvePlan.token_cap`, which is
    a measured number, and simple mode passes nothing, because no measurement of a diff-scoped run
    supports one and a ceiling invented here would be a number nobody had ever checked against a real
    run.
    """
    profile = _scan_profile(args)
    if args.max_tokens:
        _refuse_a_token_ceiling_below_the_floor(args.max_tokens, default_tokens)
        tokens: float | None = args.max_tokens
    elif profile is None:
        tokens = default_tokens
    elif profile.name == "initial":
        # A FLOOR, not a replacement. "Initial" says *at least* this much, so a mode that already
        # defends a higher measured ceiling keeps it — `SolvePlan.token_cap` is 8,000,000 because 200
        # steps had to be reachable, and the maintainers' suite pins it as the measured
        # configuration. Taking the max means naming a first scan can never REDUCE its coverage, which
        # would be the opposite of what the profile is for.
        tokens = max(profile.max_tokens, default_tokens or 0.0)
    else:
        # A follow-up genuinely overrides downward: that is the entire point of declaring one.
        tokens = profile.max_tokens
    return Budget(
        tokens=tokens,
        usd=args.max_spend_usd if args.max_spend_usd else None,
        wall_seconds=args.max_minutes * 60 if args.max_minutes else None,
    )


def _scan_profile(args):
    """The `--scan` profile in force, or None when the caller has no such flag.

    An EXPLICIT `--max-tokens` always wins over the profile — a customer who names a number gets that
    number. The profile only decides what an unset flag means, which until 2026-08-17 was one ceiling
    for both a first scan and a re-check. See `budget.ScanProfile`.
    """
    return SCAN_PROFILES.get(getattr(args, "scan", "") or "")


def _max_steps(args) -> int:
    """The hunt's step ceiling, defaulting to the measured one.

    `0` IS REFUSED, and that is the whole reason this is a function rather than an argparse default.
    The other three ceilings read `0` as *unmetered*, so a customer copying that convention here would
    write `max_steps: 0` meaning "no limit" — and `agentloop` runs `for step in range(1, max_steps + 1)`,
    so zero steps is not unbounded, it is NO REVIEW AT ALL. That run completes, reports no findings and
    exits 0: the green-check-that-reviewed-nothing this repository has now recorded three times, offered
    as a configuration option. A negative is refused for the same reason.

    There is deliberately no "unmetered" spelling. An unbounded ReAct loop on a customer's runner is the
    thing the ceilings exist to prevent, and `--max-spend-usd` is the ceiling for "let it run".

    **AN UNSET FLAG TAKES THE SCAN PROFILE'S FLOOR, the same precedence `_budget` gives
    `--max-tokens`.** Until 2026-08-21 `--scan initial` raised the token ceiling to 6,000,000 and
    left this at 40, so the profile moved the ceiling that was not binding and left the one that was. A measured run is the measurement: the first real
    customer audit had to pass `--max-steps 200` by hand for a 300-file chunk, and a ceiling the
    operator must know to raise is not a profile — it is a trap with a default.

    The floor is taken with `max()` against the mode's own default, never as a replacement, so naming a
    scan can only ever RAISE the step count. A profile carrying `min_steps=0` — `followup` does — is
    inert by construction rather than by a check that could be dropped.
    """
    if args.max_steps is None:
        from shard.simple import DEFAULT_MAX_STEPS
        profile = _scan_profile(args)
        return max(DEFAULT_MAX_STEPS, profile.min_steps if profile is not None else 0)
    if args.max_steps < 1:
        raise ConfigError(
            f"--max-steps must be at least 1, not {args.max_steps}. Unlike the dollar, minute and "
            f"token ceilings, 0 does NOT mean unmetered here: it means the hunt takes no turns at "
            f"all, and a run that reviewed nothing reports no findings and exits 0. To let a run go "
            f"long, raise --max-spend-usd")
    return args.max_steps






def _scan_payload(args, budget) -> dict:
    """What scan this was and what it was allowed to spend — for the payload and the report.

    Reported rather than implied, because `status: budget` means two different things: on a follow-up
    it is an ordinary stop against a deliberately small ceiling, and on an initial scan it means the
    baseline is INCOMPLETE and every count from it is a floor. A reader cannot tell those apart from
    the status alone, and the whole point of naming the two scans is that they are not the same claim.
    """
    profile = _scan_profile(args)
    return {
        # WHETHER A PROFILE IS IN FORCE AT ALL, as a boolean, because `kind` cannot say it: `"unset"` is
        # a legitimate answer here and reads as a profile name to anything that treats this field as
        # one. The report used to render it as a row and told every diff customer "no scan profile
        # applies to this mode", which is not true — both profiles are offered on diff mode and are
        # opt-in rather than imposed.
        "declared": profile is not None,
        "kind": profile.name if profile else "unset",
        "why": profile.summary if profile else "no profile declared, so this mode's own default ceiling "
                                              "applies — `--scan initial` or `--scan followup` names one",
        "max_tokens": budget.tokens,
        "ceiling_source": "--max-tokens" if args.max_tokens else
                          ("--scan " + profile.name if profile else "mode default"),
    }


def _spend(backend, governor) -> dict:
    """What the run cost, and against which ceilings — the half of a budget that faces the customer.

    Both halves of the design notes and §8: a ceiling nobody can reconcile against a reported
    number is as decorative as a ceiling nothing debits. `deep` reported steps and tokens and never a
    dollar figure; `diff` reported no cost of ANY kind, so the ≈$0.29 of the first real run had to be
    read off OpenRouter's billing API afterwards.

    `usd` is None, never 0.0, when no response this run carried a price. "This run was free" and "this
    endpoint does not price its responses" are different facts, and printing them as the same $0.00 is
    the exact defect class this function was written to close. A backend with no `usage_summary` at all
    (the engine client, a test double) reports None for the same reason.
    """
    usage = getattr(backend, "usage_summary", None)
    usage = usage() if callable(usage) else {}
    priced = int(usage.get("priced_requests", 0) or 0)
    spend = {
        "usd": round(float(usage.get("cost_usd", 0.0) or 0.0), 6) if priced else None,
        "usd_ceiling": governor.budget.usd,
        "tokens_ceiling": governor.budget.tokens,
        "requests": int(usage.get("llm_requests", 0) or 0),
        "priced_requests": priced,
        # **HOW LONG IT TOOK, which this product measured and never reported.** `--max-minutes` is a
        # ceiling, so `budget.py` has tracked `wall_seconds` from the first run — and nothing surfaced
        # it, in any mode, in the payload or the report. That is this function's own opening argument
        # ("a ceiling nobody can reconcile against a reported number is as decorative as a ceiling
        # nothing debits") applied to the one resource it forgot.
        #
        # It is not a secondary number for a CI product: wall-clock is what BLOCKS a customer's
        # pipeline, and it is the first thing anybody asks before putting a gate on a pull request.
        # Both an internal CI workflow and every manual run so far computed it OUTSIDE the product with
        # `date +%s`, which is the tell — an artefact everyone reconstructs by hand is one the product
        # should have written.
        "seconds": round(governor.spent("wall_seconds"), 1),
        "seconds_ceiling": governor.budget.wall_seconds,
    }
    if "token_reported_requests" in usage:
        spend["token_reported_requests"] = int(usage.get("token_reported_requests", 0) or 0)
    return spend
