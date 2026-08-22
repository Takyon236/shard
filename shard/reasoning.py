"""Shared reasoning-elicitation surface — two model-agnostic "think harder" levers that apply to
every autonomous NATIVE-LOOP solve. Today the only solver is the benchmark source-review solver
(`the predecessor project`); the levers are injectable so a future solver reusing ``agentloop.ToolCallingLoop``
picks them up automatically. This module is the ONE place the levers live and the loop is the
enforcement point. Scope note: the compute runway (Rule 1) is enforced unconditionally for every
``ToolCallingLoop`` (solver AND sub-agent); the self-review (Rule 3) is opt-in per loop (the benchmark
solver turns it on, sub-agents leave it off — see below). The CLI ``claude -p`` backend uses the
JSON-action ``ShardLoop`` instead and is out of scope by design (the benchmark runs GLM via native
function-calling; the maintainers' notes scopes these levers to the native loop).

Two levers, both grounded and both DETERMINISTICALLY testable (pure text, no LLM/network):

1. COMPUTE RUNWAY (Rule 1) — a system-prompt directive that forces the model to GENERATE a short reasoning
   runway before every tool call. The mechanism is generation-side, not input-side: "Reading Between the
   Dots: Decoding Hidden Computation across Filler Tokens" (arXiv:2607.03502, Brauer/Verdun/Marks 2026)
   shows a model performs real intermediate computation *through the tokens it emits* — 80-95% of the
   hidden intermediate values were recoverable from the residual stream at the generated filler positions,
   and KV-cache transplants at those positions causally swapped the outputs. The compute lives in what the
   model WRITES, not in filler padded into the prompt it READS. So padding dots into the input buys nothing;
   forcing the model to write a runway before it acts buys the extra forward passes. This also directly
   counters our measured GLM failure mode (a heavy prompt SUPPRESSES GLM's thinking → it jumps to a tool
   call in prose without reasoning; see MEMORY ``glm-tooluse-and-reachability-levers``).
   The exact runway content is a single swappable constant: to A/B a literal-filler variant instead, change
   ``COMPUTE_RUNWAY_DIRECTIVE`` here and nothing else moves.

2. SELF-REVIEW (Rule 3) — a periodic FORCED metacognition turn the loop injects every ``SELF_REVIEW_INTERVAL``
   steps: the agent must stop and assess, in writing, where it stands vs the goal, what has actually moved
   the needle vs what it has repeated without progress, and whether to change trajectory — then act on its
   own conclusion in the same turn. This is the general-agent version of the benchmark-specific campaign
   stall/drift retasking (which keys only on ``test_poc`` outcomes and needs a CampaignState): self-review
   fires on a pure step cadence with no campaign wired, so it also covers the "task looks done but the
   finish criterion is not actually met" case. It never relaxes any finish gate — it only makes the agent
   re-decide.

Pure and dependency-free (imports nothing) so the deterministic suite exercises it with no engine/LLM. The
CADENCE constant (``SELF_REVIEW_INTERVAL``) lives in ``agentloop`` beside ``MEASURE_INTERVAL`` — the loop
that enforces the cadence owns it — while the TEXT lives here so both are edited in the layer that owns them.
"""

from __future__ import annotations

# --- Rule 1: compute runway ------------------------------------------------------------------------
# Stable, DISTINCTIVE substring asserted present in every assembled solver system prompt (both paths) and
# used as the idempotency marker in ``ensure_compute_runway``. It is the directive's own opening clause —
# deliberately a full phrase, not the bare words "compute runway", so a solver prompt that merely mentions
# a compute runway in passing can't false-positive the idempotency check and suppress the real directive.
COMPUTE_RUNWAY_ANCHOR = "THINK BEFORE YOU ACT — the compute runway"

# The directive appended (idempotently) to every ToolCallingLoop system prompt. Generation-side by design
# (see module docstring): it asks the model to WRITE its reasoning before acting, because that written text
# is where the computation actually happens — not the prompt it reads.
COMPUTE_RUNWAY_DIRECTIVE = (
    "\n\nTHINK BEFORE YOU ACT — the compute runway. Before EVERY tool call, first write out your reasoning "
    "as visible text in the SAME turn: (a) restate what the last observation actually told you (grounded in "
    "its bytes, not what you hoped), (b) name the ONE thing this next action is meant to learn or achieve, "
    "and (c) say why this specific tool and these arguments are the right move rather than an alternative. "
    "Reasoning it out in writing first — instead of jumping straight from a long prompt to a tool call — "
    "sharpens the plan and catches the mistake before you spend the call on it; skipping it is the single "
    "most common way a capable agent stalls. A few sentences is enough; do not pad, but never skip it."
)


def ensure_compute_runway(system: str) -> str:
    """Return ``system`` with the compute-runway directive appended, idempotently.

    Idempotent so the loop can enforce it unconditionally even when a solver's own assembly already added it
    (the directive is a floor, not a per-caller responsibility): if ``COMPUTE_RUNWAY_ANCHOR`` is already
    present the string is returned unchanged, so it is never doubled. A falsy/blank system prompt is returned
    as-is (nothing to anchor a solver on — the caller has a bigger problem than the runway)."""
    if not system or not system.strip():
        return system
    if COMPUTE_RUNWAY_ANCHOR in system:
        return system
    return system + COMPUTE_RUNWAY_DIRECTIVE


# --- Rule 3: periodic self-review ------------------------------------------------------------------
# Stable substring asserted present in an injected self-review turn (test anchor + a marker the loop uses to
# avoid double-injecting on the same step).
SELF_REVIEW_ANCHOR = "SELF-REVIEW"


def render_self_review(step: int) -> str:
    """The forced metacognition turn injected every ``SELF_REVIEW_INTERVAL`` steps (see agentloop).

    Trusted loop-authored content (like the nudges), so the loop injects it UNFENCED. It maps 1:1 to the
    four things a stuck-or-drifting autonomous agent must re-decide: where it stands vs the goal, what has
    actually worked vs churned, whether to change trajectory, and — critically — whether a "done"-looking
    state actually meets the finish criterion. It NEVER relaxes a finish gate; it only forces a re-decision."""
    return (
        f"{SELF_REVIEW_ANCHOR} (step {step}) — stop and assess IN WRITING before your next action, then act "
        "on your own conclusion this same turn:\n"
        "1. GOAL STATE: how close are you to the goal, concretely, grounded in your last REAL measurement "
        "(a tool result) — not your plan or your intentions?\n"
        "2. WORKING vs STUCK: what has actually moved the needle, and what have you now repeated more than "
        "once with no new information? Name the dead ends so you do not retry them.\n"
        "3. TRAJECTORY: are you on the right path? If you have made no measurable progress in the last "
        "several steps, CONSIDER whether a different approach would reach the goal faster — and if so, name "
        "it in one line and take its first action. But do NOT abandon a path that is still yielding new "
        "information just because it is slow: some goals legitimately take many steps to reach.\n"
        "4. DONE-CHECK: if the task looks finished, verify the finish criterion is ACTUALLY met by evidence "
        "(not a partial or hoped-for result). If it is not met, keep going; do not stop on an unverified or "
        "unconcluded result.\n"
        "Answer briefly (a few lines), then continue."
    )
