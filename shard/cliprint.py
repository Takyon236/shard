



def _print_profile(payload: dict, profile) -> None:
    print(f"repository   {payload['repo']}")
    print(f"source       {payload['files']} files, {payload['source_bytes'] / 1024:.0f} KiB"
          + ("  (TRUNCATED — counts are a floor)" if payload["truncated"] else ""))
    print(f"languages    {', '.join(f'{k}={v}' for k, v in profile.languages.items()) or 'none'}")
    print(f"build        {', '.join(payload['build_systems']) or 'none detected'}")
    print(f"fuzz         {', '.join(payload['fuzz_harnesses']) or 'no harnesses found'}"
          + ("  (OSS-Fuzz integration present)" if payload["oss_fuzz"] else ""))


def _print_capability(payload: dict) -> None:
    deep = payload["deep"]
    if deep.get("available"):
        print(f"deep mode    {deep.get('headline') or deep['verdict']}")
        if deep.get("reason"):
            for line in deep["reason"].split("\n"):
                print(f"             {line}")
    if deep.get("harness_kinds"):
        print(f"             harness kinds: {', '.join(deep['harness_kinds'])}")
    mach = payload.get("machine")
    if mach:
        mem = f", {mach['memory_gb']} GiB" if mach.get("memory_gb") is not None else ""
        limit = " (CPU quota set)" if mach.get("cpus_are_a_container_limit") else ""
        print(f"this runner  {mach['cpus']} cpu{limit}{mem}, docker "
              f"{'yes' if mach['docker'] else 'NO'}")
        if mach.get("note"):
            print(f"             {mach['note']}")
    runtimes = payload.get("runtimes") or {}
    if runtimes.get("absent"):
        print(f"runtimes     MISSING for {', '.join(runtimes['absent'])} — nothing written in "
              f"{'them' if len(runtimes['absent']) > 1 else 'it'} can be executed here")
        print(f"             {runtimes['note']}")
    elif runtimes.get("probed"):
        found = ", ".join(f"{r['command']}" for r in runtimes["probed"] if r["present"])
        print(f"runtimes     present for every detected language ({found})")
    if runtimes.get("unknown"):
        print(f"             not looked up for: {', '.join(runtimes['unknown'])}")


def _print_gateability(payload: dict) -> None:
    dem = payload["demonstrable"]
    if dem["can_gate"]:
        print(f"can gate     YES — `{dem['entry']}` is runnable, so a reproduced finding fails the build")
        if dem["source"] == "convention":
            print("             it is NOT read by default — declare it as `witness_entry` in the workflow")
    else:
        print("can gate     NO — every finding will be INFORMATIONAL and none can fail the build")
        print(f"             {dem['why']}")
        if dem["source"] == "none":
            print("             start from: shard preflight --repo . --entry-template > .shard/entry.sh")


def _print_endpoint(payload: dict) -> None:
    ep = payload.get("endpoint")
    if not ep:
        return
    print(f"endpoint     {ep['verdict']}")
    obs = ep.get("observed") or {}
    if obs.get("substituted"):
        print(f"             SERVED `{obs['model']}`, NOT the `{obs['requested']}` you asked for")
    elif obs.get("model"):
        print(f"             served by {obs['model']}, as asked")
    elif obs.get("requested") and ep["verdict"] != "unsupported":
        print(f"             asked for {obs['requested']}; this endpoint names no model in its "
              f"replies, so which weights answered is unverifiable from here")
    print(f"             {ep['why'].replace('**', '')}")


def _print_price(payload: dict) -> None:
    cost = payload["cost"]
    print(f"your cost    ${cost['usd_low']:.2f}–${cost['usd_high']:.2f} observed priced lower bound per "
          f"pull-request run, on YOUR inference bill")
    print(f"             ${cost['per_month_at_100_runs']['low']:.0f}–"
          f"${cost['per_month_at_100_runs']['high']:.0f}/month is the same lower-bound extrapolation "
          f"at 100 runs. "
          f"This repository resembles {cost['resembles']}")
    print(f"             {cost['tokens_low']:,}–{cost['tokens_high']:,} tokens a run. "
          f"Later unpriced runs used a median {cost['tokens_median_ratio']}x the tokens; no dollar "
          f"conversion is valid")
    print("             Pull-request runs only; excludes initial scans. Start report-only and calibrate "
          "from your endpoint")
    free = payload["free_tier"]
    print(f"free tier    {free['verdict']} — {free['why']}")
    for need in free["needs"]:
        print(f"             needs {need}")


def _print_preflight(payload: dict, profile) -> None:
    _print_profile(payload, profile)
    _print_capability(payload)
    _print_endpoint(payload)
    _print_gateability(payload)
    _print_price(payload)
    if "workdir" in payload:
        w = payload["workdir"]
        print(f"workdir      {w['verdict']}")
        for reason in w["reasons"]:
            print(f"             {reason}")








def _cost_line(tokens: float, cost: dict) -> str:
    token_reported = cost.get("token_reported_requests")
    if token_reported is None:
        token_reported = cost["requests"] if tokens else 0
    if not token_reported and cost["requests"]:
        parts = ["token count not reported by this endpoint"
                 + (f" (ceiling {cost['tokens_ceiling']:,.0f} could not be enforced)"
                    if cost["tokens_ceiling"] else "")]
    else:
        parts = [f"{tokens:,.0f} tokens" + (f" of {cost['tokens_ceiling']:,.0f}"
                                            if cost["tokens_ceiling"] else " (no token ceiling)")]
        if token_reported < cost["requests"]:
            parts.append(f"token counts on {token_reported} of {cost['requests']} requests — a floor")
    if cost["usd"] is None:
        parts.append("cost not reported by this endpoint" if cost["requests"]
                     else "no inference")
    else:
        parts.append(f"${cost['usd']:.2f}" + (f" of ${cost['usd_ceiling']:.2f}"
                                              if cost["usd_ceiling"] else " (no spend ceiling)"))
        if cost["priced_requests"] < cost["requests"]:
            parts.append(f"priced on {cost['priced_requests']} of {cost['requests']} requests — a floor")
    return ", ".join(parts)
