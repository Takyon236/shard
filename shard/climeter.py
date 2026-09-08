


from shard.budget import SCAN_PROFILES, Budget
from shard.gate import ConfigError


DEEP_TOKEN_FLOOR_FRACTION = 0.5


def _refuse_a_token_ceiling_below_the_floor(asked: float, default_tokens: float | None) -> None:
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
    profile = _scan_profile(args)
    if args.max_tokens:
        _refuse_a_token_ceiling_below_the_floor(args.max_tokens, default_tokens)
        tokens: float | None = args.max_tokens
    elif profile is None:
        tokens = default_tokens
    elif profile.name == "initial":
        tokens = max(profile.max_tokens, default_tokens or 0.0)
    else:
        tokens = profile.max_tokens
    return Budget(
        tokens=tokens,
        usd=args.max_spend_usd if args.max_spend_usd else None,
        wall_seconds=args.max_minutes * 60 if args.max_minutes else None,
    )


def _scan_profile(args):
    return SCAN_PROFILES.get(getattr(args, "scan", "") or "")


def _max_steps(args) -> int:
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
    profile = _scan_profile(args)
    return {
        "declared": profile is not None,
        "kind": profile.name if profile else "unset",
        "why": profile.summary if profile else "no profile declared, so this mode's own default ceiling "
                                              "applies — `--scan initial` or `--scan followup` names one",
        "max_tokens": budget.tokens,
        "ceiling_source": "--max-tokens" if args.max_tokens else
                          ("--scan " + profile.name if profile else "mode default"),
    }


def _spend(backend, governor) -> dict:
    usage = getattr(backend, "usage_summary", None)
    usage = usage() if callable(usage) else {}
    priced = int(usage.get("priced_requests", 0) or 0)
    spend = {
        "usd": round(float(usage.get("cost_usd", 0.0) or 0.0), 6) if priced else None,
        "usd_ceiling": governor.budget.usd,
        "tokens_ceiling": governor.budget.tokens,
        "requests": int(usage.get("llm_requests", 0) or 0),
        "priced_requests": priced,
        "seconds": round(governor.spent("wall_seconds"), 1),
        "seconds_ceiling": governor.budget.wall_seconds,
    }
    if "token_reported_requests" in usage:
        spend["token_reported_requests"] = int(usage.get("token_reported_requests", 0) or 0)
    return spend
