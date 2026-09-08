
from __future__ import annotations

COMPUTE_RUNWAY_ANCHOR = "THINK BEFORE YOU ACT — the compute runway"

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
    if not system or not system.strip():
        return system
    if COMPUTE_RUNWAY_ANCHOR in system:
        return system
    return system + COMPUTE_RUNWAY_DIRECTIVE


SELF_REVIEW_ANCHOR = "SELF-REVIEW"


def render_self_review(step: int) -> str:
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
