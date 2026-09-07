"""Rendering a run for a terminal. No decisions, no files — `print` and nothing else.

Third cut of the maintainers' backlog item 2, after `shard/cliargs.py` and `shard/cliemit.py`. The seam is the
one a support session actually navigates by: "the preflight output should also say X" is a question
about this file alone, and it used to mean reading past seven subcommands to find four `print`
blocks scattered through `shard/cli.py` between the functions that decide things.

Everything here takes a PAYLOAD and returns None. The payload is the same dict `--json` prints, so
the two renderings cannot disagree about a number — which is the property the split makes visible
rather than one it introduces.
"""




def _print_profile(payload: dict, profile) -> None:
    """What the repository IS — the walk's own counts, before any judgement about it."""
    print(f"repository   {payload['repo']}")
    print(f"source       {payload['files']} files, {payload['source_bytes'] / 1024:.0f} KiB"
          + ("  (TRUNCATED — counts are a floor)" if payload["truncated"] else ""))
    print(f"languages    {', '.join(f'{k}={v}' for k, v in profile.languages.items()) or 'none'}")
    print(f"build        {', '.join(payload['build_systems']) or 'none detected'}")
    print(f"fuzz         {', '.join(payload['fuzz_harnesses']) or 'no harnesses found'}"
          + ("  (OSS-Fuzz integration present)" if payload["oss_fuzz"] else ""))


def _print_capability(payload: dict) -> None:
    """What THIS build and THIS box can do — that capability's verdict, the runner, the language runtimes.
    Three questions that fail independently: a perfect C target on a runner with no Docker is
    `supported` and still cannot run four of its levers, and a box missing the language runtime
    cannot execute the customer's code at all."""
    deep = payload["deep"]
    # **A BUILD WITH NO SUCH CAPABILITY DOES NOT REPORT ON ONE.** Found by running the shipped image
    # against a real repository on 2026-08-23, which is the only way it could have been found: this is
    # a runtime string, so neither the packaging gates nor the prose redaction can see it. Preflight
    # printed
    #
    # to every customer of an artefact built to contain no trace of that capability — naming it, twice,
    # in the one command people run before they spend anything. `available` is False exactly when the
    # probe found nothing to ask, so the row simply does not exist in that build. Where the capability
    # IS present the row is unchanged, including the honest `unsupported` verdicts.
    if deep.get("available"):
        # The HEADLINE stands in for the bare verdict word when there is one — a buildable cargo-fuzz
        # repository reads "one step away", not "unsupported", though the machine verdict stays
        # unsupported.
        print(f"deep mode    {deep.get('headline') or deep['verdict']}")
        if deep.get("reason"):
            # Per-line indent so a multi-line reason (the cargo-fuzz build command sits on its own
            # line) stays aligned under the column rather than wrapping back to the margin.
            for line in deep["reason"].split("\n"):
                print(f"             {line}")
    if deep.get("harness_kinds"):
        print(f"             harness kinds: {', '.join(deep['harness_kinds'])}")
    # THE BOX, beside the verdict about the REPOSITORY. Printed rather than left in the JSON for the
    # reason §6b gives about the cost band: a number a human never sees is not one, and this is the
    # command a customer runs to check the claim they are being sold on.
    mach = payload.get("machine")
    if mach:
        mem = f", {mach['memory_gb']} GiB" if mach.get("memory_gb") is not None else ""
        limit = " (container limit)" if mach.get("cpus_are_a_container_limit") else ""
        print(f"this runner  {mach['cpus']} cpu{limit}{mem}, docker "
              f"{'yes' if mach['docker'] else 'NO'}")
        if mach.get("note"):
            print(f"             {mach['note']}")
    # CAN THIS BOX EXECUTE THE CUSTOMER'S LANGUAGE AT ALL — the free tier's half of the line above, and
    # it printed nothing until 2026-08-17. A demonstration is the product; a language whose runtime is
    # absent cannot produce one, and the witness only discovered that after a review had been paid for.
    # Printed for the same reason as the cost band: a fact a human never sees is not a fact they have.
    runtimes = payload.get("runtimes") or {}
    if runtimes.get("absent"):
        print(f"runtimes     MISSING for {', '.join(runtimes['absent'])} — nothing written in "
              f"{'them' if len(runtimes['absent']) > 1 else 'it'} can be executed here")
        print(f"             {runtimes['note']}")
    elif runtimes.get("probed"):
        found = ", ".join(f"{r['command']}" for r in runtimes["probed"] if r["present"])
        print(f"runtimes     present for every detected language ({found})")
    if runtimes.get("unknown"):
        # Named rather than counted as fine. `_mode_verdict`'s rule: answer `unknown`, do not guess.
        print(f"             not looked up for: {', '.join(runtimes['unknown'])}")


def _print_gateability(payload: dict) -> None:
    """Whether anything this repository produces can fail a build. Printed ABOVE the money, because
    it decides what the money buys."""
    # CAN ANYTHING HERE FAIL A BUILD — printed ABOVE the money, because it decides what the money buys.
    # A customer reading "your cost $0.02–$0.51" and "runtimes present" reasonably concludes the
    # product will work; without an entry point every finding it returns is informational. That is not
    # a hypothetical: it is what the first paying engagement received, 24 findings and `gate_eligible`
    # 0 on all 13 chunks (a measured run).
    dem = payload["demonstrable"]
    if dem["can_gate"]:
        print(f"can gate     YES — `{dem['entry']}` is runnable, so a reproduced finding fails the build")
        # FOUND BY CONVENTION IS NOT THE SAME AS CONFIGURED. The file exists; nothing reads it unless
        # the workflow names it, so a customer who stops here still gets an informational-only run.
        if dem["source"] == "convention":
            print("             it is NOT read by default — declare it as `witness_entry` in the workflow")
    else:
        print("can gate     NO — every finding will be INFORMATIONAL and none can fail the build")
        print(f"             {dem['why']}")
        # THE BLANK PAGE IS THE BARRIER, not the concept. Naming the limit and leaving the customer to
        # guess the contract is half a fix; the contract has two non-obvious parts (one argument, and
        # an empty payload must be quiet) and both are what people get wrong.
        if dem["source"] == "none":
            print("             start from: shard preflight --repo . --entry-template > .shard/entry.sh")


def _print_endpoint(payload: dict) -> None:
    """The `--probe-endpoint` answer, which cost a real request and was printed nowhere.

    **THE ONE FACT THIS COMMAND EXISTS TO ESTABLISH, AND ONLY `--json` CARRIED IT.** `shard/cli.py`
    sets `payload["endpoint"]` and this file rendered every other key; run as the README documents it
    — `shard preflight --probe-endpoint`, no `--json` — a dead endpoint spent a request, printed not
    one word about itself and exited 0. Measured 2026-09-03 against `http://127.0.0.1:9/v1`: the
    verdict was `unsupported`, and grepping the human output for `unsupported`, `tool calling` and
    `refus` found only the unrelated `the separate capability` row. README.md sends a customer here from the row
    *"the run finds nothing and looks clean"*, which is the failure this product cannot otherwise
    detect: an endpoint without native tool calling completes a run and reports a clean repository.

    Printed ABOVE `can gate` deliberately. Both rows say a run will be worth less than it looks, and
    this one is the stronger claim: without a gateable entry point the findings are informational,
    but without a tool-calling endpoint there are no findings at all.

    The `endpoint` key is absent unless `--probe-endpoint` was passed, so this renders nothing on the
    free profiling path it must not slow down or charge for.
    """
    ep = payload.get("endpoint")
    if not ep:
        return
    print(f"endpoint     {ep['verdict']}")
    obs = ep.get("observed") or {}
    # WHICH WEIGHTS ANSWERED, ABOVE the reason and on its own row, because it is the fact
    # the design notes' "the customer always supplies inference" makes the customer responsible
    # for, and the reason sentence is long enough to bury it. `model` is empty when the provider named
    # nothing — a real answer, and not the same as "it served what you asked", which is what this
    # probe reported until 2026-09-03 by echoing the request back into a key called `observed`.
    # Measured on the wire that day: `api/coding/paas/v4` answers a `glm-5.2` request with `glm-5.3`
    # under HTTP 200, naming the substitute in every SSE chunk, and the probe called it
    # `validated … the configuration this project has measured`.
    if obs.get("substituted"):
        print(f"             SERVED `{obs['model']}`, NOT the `{obs['requested']}` you asked for")
    elif obs.get("model"):
        print(f"             served by {obs['model']}, as asked")
    elif obs.get("requested") and ep["verdict"] != "unsupported":
        # ONLY WHERE A ROUND TRIP ACTUALLY HAPPENED. `unsupported` is every way the exchange failed —
        # refused connection, HTTP error, prose instead of a tool call — and telling a customer whose
        # endpoint was never reached that "it names no model in its replies" invents a reply. The
        # verdict word is written out rather than imported because this module imports nothing: it
        # takes a payload and prints, which is what keeps "the preflight output should also say X" a
        # question about one file.
        print(f"             asked for {obs['requested']}; this endpoint names no model in its "
              f"replies, so which weights answered is unverifiable from here")
    print(f"             {ep['why'].replace('**', '')}")


def _print_price(payload: dict) -> None:
    """What a run costs on the customer's own inference bill, and which tier they are on."""
    # THE MONEY, in the shell output and not only in the JSON. The integration guide makes this
    # the pricing instrument, and a number a human never sees is not one.
    cost = payload["cost"]
    print(f"your cost    ${cost['usd_low']:.2f}–${cost['usd_high']:.2f} observed priced lower bound per "
          f"pull-request run, on YOUR inference bill")
    print(f"             ${cost['per_month_at_100_runs']['low']:.0f}–"
          f"${cost['per_month_at_100_runs']['high']:.0f}/month is the same lower-bound extrapolation "
          f"at 100 runs. "
          f"This repository resembles {cost['resembles']}")
    # THE TOKENS, BESIDE THE DOLLARS. The full dated basis stays in the JSON and customer reference;
    # printing those two paragraphs here made the first no-key onboarding command read like a release
    # note. Keep the facts a customer needs to set a ceiling: the observed bounds, the measured scale of
    # the understatement, and the mode this sample does not cover.
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
    """The whole preflight answer, in the order a reader needs it.

    **THE ORDER IS THE ARGUMENT and it is not alphabetical.** What the repository is, then what this
    build and this box can do with it, then whether anything here can fail a build, then what it
    costs. `can gate` sits above the money deliberately: a customer reading "runtimes present" and
    "$0.02-$0.51" reasonably concludes the product will work, and without an entry point every
    finding it returns is informational. That is not hypothetical — it is what the first paying
    engagement received, 24 findings and `gate_eligible` 0 on all 13 chunks
    (a measured run).

    It was ONE 53-statement body until 2026-08-28, which is over a maintenance script's
    40-statement cap and was grandfathered only because it predated the ratchet. Moving it here made
    it a NEW function, so the cap applied and it split where the SUBJECT changes rather than where a
    line count fell.
    """
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




#: WHICH FUNCTION RUNS EACH SUBCOMMAND — the wiring `shard/cliargs.py` deliberately does not hold.
#:
#: One table rather than seven `set_defaults` lines buried in a 200-line parser body, so "what does
#: this subcommand actually call" is answered by reading four lines. `build_parser` checks this covers
#: `cliargs.COMMANDS` exactly, in BOTH directions: a command with no handler cannot be run, and a
#: handler no command dispatches to is a correct function nothing reaches — the shape the maintainers' notes'
#: standing process rule exists for, found six times in one session on the predecessor repository.




def _cost_line(tokens: float, cost: dict) -> str:
    """`tokens of ceiling, $spent of ceiling` — one line, and every number in it is one we hold."""
    # THE SAME TRI-STATE THE DOLLAR HALF HAS HAD, and it was missing here. "0 tokens" is a measurement;
    # an endpoint that omits `usage` gives us no measurement at all, and printing 0 asserts one. Worse,
    # `--max-tokens` cannot bind against a count that never arrives, so the line stating the ceiling was
    # exactly the line a customer would have used to notice it was inert.
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
            # Partial pricing is stated rather than smoothed over: the figure above is a FLOOR, and a
            # customer reconciling it against a bill needs to know which way it is wrong.
            parts.append(f"priced on {cost['priced_requests']} of {cost['requests']} requests — a floor")
    return ", ".join(parts)
