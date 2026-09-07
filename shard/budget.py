"""Budget governor — a first-class constraint, not an afterthought.

This session learned the hard way that the localizer subscription rate-limits, and that
cold+warm = 60 benchmark tasks drains the window and starves the warm arm. So Shard tracks
several budgets at once (tokens, dollars, wall-clock, sub-agents, *benchmark task-runs*) and
exposes graceful-degrade hints (warm-only, cheaper model) as it nears a limit.

Pure + dependency-free + unit-testable.
"""

from __future__ import annotations

import math
import threading
import time
from dataclasses import dataclass


class BudgetExceeded(RuntimeError):
    """Raised when a spend would push a metered resource past its hard cap."""

    def __init__(self, resource: str, spent: float, limit: float) -> None:
        super().__init__(f"budget exceeded: {resource} {spent:.4g} > {limit:.4g}")
        self.resource = resource
        self.spent = spent
        self.limit = limit


def _finite_nonnegative(value, label: str) -> None:
    """Reject values that can poison every later ceiling comparison."""
    if isinstance(value, bool):
        raise ValueError(f"{label} must be a finite non-negative number")
    try:
        number = float(value)
    except (TypeError, ValueError) as e:
        raise ValueError(f"{label} must be a finite non-negative number") from e
    if not math.isfinite(number) or number < 0:
        raise ValueError(f"{label} must be a finite non-negative number")


@dataclass
class Budget:
    """Hard caps. ``None`` = unmetered. ``benchmark_task_runs`` meters the EXPENSIVE
    localizer calls specifically — the resource that actually rate-limited us."""

    tokens: float | None = None
    usd: float | None = None
    wall_seconds: float | None = None
    subagents: int | None = None
    benchmark_task_runs: int | None = None
    # fraction-of-limit at which to start degrading (warm-only, cheaper model, fewer agents)
    degrade_at: float = 0.8


@dataclass(frozen=True)
class ScanProfile:
    """A named token ceiling, because the FIRST scan of a repository is not the same job as the next one.

    ## The distinction this encodes

    Until 2026-08-17 every run got one ceiling and it was the same ceiling, so a first look at an
    unknown 260-file repository and a re-check of a three-line change were budgeted identically. Those
    are different jobs:

    **A PROFILE SETS A CEILING AND NEVER A SCOPE.** Said first because the copy that shipped said the
    opposite: `initial`'s help text and its customer-facing summary both claimed *"the whole tree is in
    scope"*, and in diff mode — the tier every customer meets first — what gets reviewed is exactly the
    diff, whatever `--scan` says. `shard-report.md` printed that claim two rows above
    `reviewed | N changed file(s)`, so the artefact contradicted itself on one screen
    (a measured run, found on the first paying engagement). These names choose
    what a run may SPEND establishing its answer. They do not choose what it looks at.

    - **initial** — nothing is known about the target. Every surface is
      unvisited, and the point of the run is COVERAGE. Stopping early here does not produce a smaller
      answer, it produces an unfinished one: a measured run records a deep run that
      returned two findings and `status: budget`, where the honest reading of the count was "a floor",
      not "the result". A first scan that cannot finish cannot establish a baseline for anything after
      it.
    - **followup** — the baseline exists. What changed is small, the prior is strong, and a ceiling that
      would be miserly on a first pass is generous on a re-check. Spending initial-scan money on every
      pull request is how a per-run ceiling becomes a monthly bill nobody agreed to, which is the
      failure `_budget`'s own docstring was written about.

    ## Why 6,000,000 and not the old default

    It is chosen to be larger than any complete run yet measured, not tuned to one, and it was RAISED
    from 4,000,000 by owner decision on 2026-08-17 after the re-run below. The measurements it sits
    above: the first a real repository deep run stopped at 603,200 tokens with work still queued, and the re-run
    reached **2,414,727 and was still working** when a wall stopped it. `SolvePlan.token_cap` has been
    8,000,000 since 200 steps had to be reachable, so 6M sits above every observed run and below that,
    and is still a real cap — "unmetered" is the answer this product refuses to give.

    **No complete first scan of a real repository has been measured yet**, so this is a ceiling chosen
    to be out of the way rather than a number fitted to a distribution. When one completes, that
    measurement should replace this reasoning rather than be added beside it.

    **It is a ceiling, not a target.** A run that finds everything in 200,000 tokens stops at 200,000.
    The number only decides what happens to a run that would otherwise be cut off mid-sweep.
    """

    name: str
    max_tokens: float
    summary: str
    #: How many DISTINCT defects a run under this profile may report.
    #:
    #: **The profile governed only the token ceiling until 2026-08-19, and that made it argue against
    #: itself.** The `initial` reasoning above says the point of a first scan is COVERAGE and that
    #: *"stopping early here does not produce a smaller answer, it produces an unfinished one"* — while
    #: `--max-findings` defaulted to 1 for every profile, which is the earliest possible stop. Measured
    #: the same day: a deep run on a real repository returned `findings: 1, solved: true, status: done` after
    #: 710,264 of its 8,000,000 tokens. It did not run out of anything. It stopped because it had found
    #: one, on a first scan of a 278-file tree, and reported that as a complete result.
    #:
    #: `initial` therefore carries `_SWEEP_BACKSTOP`, not a number chosen as a target: on a first scan
    #: the TOKEN CEILING is what bounds the bill (that is what a ceiling "sized for coverage rather than
    #: for cost" means), and the dry-pass rule is what decides the sweep is finished. The cap only has to
    #: be too high to bind before either of those does.
    #:
    #: `followup` keeps 1, and there it is the right answer rather than an oversight: the baseline
    #: exists, the delta is small, and a re-check that stops at the first reproduction has still told
    #: the customer the thing they needed to know about this change.
    max_findings: int

    #: The FEWEST steps a run under this profile may be given, when no `--max-steps` is named.
    #:
    #: **The profile moved one ceiling and left the binding one alone.** Until 2026-08-21 `initial`
    #: raised the TOKEN floor to 6,000,000 and never touched `max_steps`, which defaults to 40 — so a
    #: profile whose whole summary is "the ceiling is sized for COVERAGE" funded a sweep it then
    #: stopped after forty moves. The two ceilings did not merely differ, they CONTRADICTED each
    #: other: the separate package's `token_cap` carries the comment *"200 steps must be REACHABLE: at 2M
    #: the cap bound at ~40-60 steps"*, so this codebase already sized its token budget around a step
    #: count it never granted.
    #:
    #: Measured on the first real customer audit (a measured run): 13 chunks of a
    #: 1,960-file repository, run at an explicitly-passed `--max-steps 200`, and **every chunk reached
    #: `status=done`** rather than `maxsteps`. That is the evidence for the number — a value a real
    #: engagement ran to completion on — and it is also the evidence for the defect, because the
    #: operator had to know to pass it. A ceiling a customer must discover by hand is not a profile.
    #:
    #: `0` MEANS THIS PROFILE IMPOSES NO FLOOR OF ITS OWN, and it never reads as "unmetered": the
    #: value is consumed through `max()` against the mode's own default, so a zero cannot lower
    #: anything. `followup` carries it because the honest answer there is *the measured default is
    #: already right for a small delta* — and restating that default here would create the
    #: hand-synchronised second copy the 2026-08-20 derivation commit was written to remove.
    min_steps: int = 0


#: A RUNAWAY BACKSTOP, NOT A TARGET, and the distinction is the whole reason this is not `1_000_000`.
#:
#: An initial scan is bounded by two things that are real: its 6,000,000-token ceiling, and
#: `_SWEEP_DRY_PASSES` consecutive passes that surface nothing new. This number exists only so the
#: FINDING COUNT is not a third bound arriving before either of them. It sits far above anything
#: observed — the largest a real repository sweep reported 2 — so if a run ever reaches it, that is a defect in
#: the dry-pass rule or the deduplication and should be read as one rather than raised.
_SWEEP_BACKSTOP = 100

#: THE STEP COUNT THIS CODEBASE ALREADY SIZES ITS TOKEN CEILING AROUND, granted rather than implied.
#:
#: The separate package's `token_cap` was raised to 8,000,000 with the comment *"200 steps must be
#: REACHABLE: at 2M the cap bound at ~40-60 steps"*, and `cli.py`'s token floor refuses a ceiling that
#: would put 200 steps out of reach. Both defend a number that no profile ever handed to the loop.
_INITIAL_STEP_FLOOR = 200

#: A first look at a target nobody has scanned. Coverage matters more than cost.
INITIAL_SCAN = ScanProfile(
    name="initial",
    max_tokens=6_000_000.0,
    # THE STRING A CUSTOMER READS, in `shard-report.md`'s `scan` row. It claimed "the whole tree is in
    # scope" two rows above "reviewed | N changed file(s)" — a self-contradicting artefact, and the
    # false half was ours. What the profile raises is the ALLOWANCE.
    summary="first scan of this target — the ceiling is sized for coverage rather than for cost. It "
            "raises what this run may SPEND, not what it reviews",
    max_findings=_SWEEP_BACKSTOP,
    min_steps=_INITIAL_STEP_FLOOR,
)

#: Every run after the first. The baseline exists; only the delta needs paying for.
FOLLOWUP_SCAN = ScanProfile(
    name="followup",
    max_tokens=400_000.0,
    summary="follow-up scan — a baseline already exists, so this run pays for the change rather than "
            "for the tree",
    max_findings=1,
)

SCAN_PROFILES: dict[str, ScanProfile] = {p.name: p for p in (INITIAL_SCAN, FOLLOWUP_SCAN)}
SCAN_CHOICES: tuple[str, ...] = tuple(SCAN_PROFILES)


class BudgetGovernor:
    """Tracks spend across resources and enforces the caps."""

    _RESOURCES = ("tokens", "usd", "wall_seconds", "subagents", "benchmark_task_runs")

    def __init__(self, budget: Budget, *, now: float | None = None) -> None:
        for resource in self._RESOURCES:
            limit = getattr(budget, resource)
            if limit is not None:
                _finite_nonnegative(limit, f"{resource} budget")
        _finite_nonnegative(budget.degrade_at, "degrade threshold")
        if now is not None and not math.isfinite(float(now)):
            raise ValueError("budget clock origin must be finite")
        self.budget = budget
        self._spent: dict[str, float] = {r: 0.0 for r in self._RESOURCES}
        # Headroom CLAIMED by work in flight and not yet charged. Kept apart from `_spent` on purpose:
        # `spent()` must go on meaning "what this run really cost", which is what the report prints and
        # what a customer reconciles against an invoice. See `reserve`.
        self._reserved: dict[str, float] = {r: 0.0 for r in self._RESOURCES}
        self._start = now if now is not None else time.time()
        # The governor is shared across concurrent sub-loops (orchestrator fan-out), so the
        # read-modify-write in spend() must be serialized — otherwise concurrent spends race and
        # under-count, letting a fan-out quietly overrun its cap.
        self._lock = threading.Lock()

    # --- spend / query ------------------------------------------------------
    def _limit(self, resource: str) -> float | None:
        return getattr(self.budget, resource)

    def spent(self, resource: str) -> float:
        if resource == "wall_seconds":  # time-based, no shared state — no lock needed
            return time.time() - self._start
        # A single dict read is atomic under CPython's GIL, but free-threaded 3.13t has no GIL,
        # so lock for a consistent snapshot; spend() remains the atomic enforcement point.
        with self._lock:
            return self._spent[resource]

    def remaining(self, resource: str) -> float:
        limit = self._limit(resource)
        if limit is None:
            return float("inf")
        return max(0.0, limit - self.spent(resource))

    def can_afford(self, resource: str, amount: float) -> bool:
        _finite_nonnegative(amount, f"{resource} amount")
        limit = self._limit(resource)
        if limit is None:
            return True
        return self.spent(resource) + amount <= limit

    def spend(self, resource: str, amount: float) -> None:
        """Record a spend that HAS ALREADY HAPPENED; raise BudgetExceeded if it crossed the hard cap.

        The commit happens BEFORE the raise, and that ordering is the whole point. Every caller of this
        method meters POST HOC — the loop bills an LLM call only after the provider already charged for
        it. Refusing to record the crossing spend left the ledger claiming 90 of 100 tokens after 140 were
        really spent: ``spent()`` under-reported the very run that blew the cap, ``can_afford()`` kept
        answering True, and a SHARED governor (concurrent fan-out sub-loops) went on admitting work
        against tokens that no longer existed. Those tokens are gone whether or not the ledger likes the
        number; the governor's job is to KNOW that, and then stop the run.

        Overshoot is bounded by one spend: the first amount that crosses the cap is committed and raises,
        after which ``check()``/``can_afford()`` refuse everything. So a budget-terminated run reports
        *slightly over* its cap — which is the truth — instead of exactly at it, which was not.

        For an amount NOT yet spent (a pre-flight reservation: the sub-agent panel, benchmark task-runs)
        use :meth:`try_spend`, which refuses without charging. Committing there would be a phantom charge
        for work that never ran.
        """
        if resource not in self._RESOURCES:
            raise ValueError(f"unknown budget resource: {resource}")
        _finite_nonnegative(amount, f"{resource} spend")
        if resource == "wall_seconds":  # wall time is measured, not spent
            self.check()
            return
        with self._lock:
            new = self._spent[resource] + amount
            self._spent[resource] = new
            limit = self._limit(resource)
            if limit is not None and new > limit:
                raise BudgetExceeded(resource, new, limit)

    def try_spend(self, resource: str, amount: float) -> bool:
        """RESERVE ``amount`` for work not yet done: commit and return True if it fits, else charge
        NOTHING and return False.

        The pre-flight counterpart to :meth:`spend`. Two properties earn it a place: (a) a refusal leaves
        no phantom charge, so a fan-out that never ran does not burn sub-agents; (b) it is ATOMIC where
        ``can_afford()`` followed by ``spend()`` is not — the test and the commit share one acquisition of
        the lock, so concurrent sub-loops cannot both pass the check and jointly overrun the cap.
        """
        if resource not in self._RESOURCES:
            raise ValueError(f"unknown budget resource: {resource}")
        _finite_nonnegative(amount, f"{resource} spend")
        if resource == "wall_seconds":
            # Wall time is measured, never reserved — there is nothing to debit. Report the headroom so
            # a caller can branch on it uniformly.
            return self.can_afford(resource, amount)
        with self._lock:
            new = self._spent[resource] + amount
            limit = self._limit(resource)
            if limit is not None and new > limit:
                return False
            self._spent[resource] = new
            return True

    def reserve(self, resource: str, amount: float) -> bool:
        """Atomically CLAIM headroom for a call that is about to be made. True if it fits.

        **`can_afford()` followed by a call is not a check under concurrency, and that is what this
        replaces.** The dollar ceiling is enforced before a call rather than after it, because the
        provider bills whatever the ledger would have preferred — but the enforcement was a READ
        (`remaining("usd")`) with the spend arriving much later, at the far end of a model round-trip.
        The separate package fans sub-loops out on a thread pool over ONE shared governor, so N loops all
        read the same headroom, all conclude they can afford a call, and all make one. The cap is then
        crossed by up to N calls instead of the one the docstrings account for.

        A reservation is not a spend and is never reported as one. It is headroom that is not available
        to anybody else until the caller `release`s it — which the caller must do on every path,
        including the one where the call raised, or the run starves itself of budget it never used.

        ``wall_seconds`` cannot be reserved: time is measured, not claimed, and there is nothing to
        debit. It answers from live headroom so a caller can branch on all resources uniformly.
        """
        if resource not in self._RESOURCES:
            raise ValueError(f"unknown budget resource: {resource}")
        _finite_nonnegative(amount, f"{resource} reservation")
        if resource == "wall_seconds":
            return self.can_afford(resource, amount)
        with self._lock:
            limit = self._limit(resource)
            if limit is not None and self._spent[resource] + self._reserved[resource] + amount > limit:
                return False
            self._reserved[resource] += amount
            return True

    def release(self, resource: str, amount: float) -> None:
        """Give back headroom claimed by :meth:`reserve`. Never below zero — a double release is a
        caller bug that must not manufacture budget out of arithmetic."""
        if resource not in self._RESOURCES or resource == "wall_seconds":
            return
        _finite_nonnegative(amount, f"{resource} release")
        with self._lock:
            self._reserved[resource] = max(0.0, self._reserved[resource] - amount)

    def settle(self, resource: str, reserved: float, actual: float) -> None:
        """Atomically replace one in-flight reservation with the charge that actually landed.

        Release-then-spend is not equivalent under fan-out: another loop can reserve the temporary
        headroom between those operations and both calls then cross the cap. Keeping both mutations
        under this lock also removes the opposite error—counting the real charge and the stale claim at
        once—which made a concurrent loop stop while affordable money remained.

        The spend commits before ``BudgetExceeded`` is raised, exactly like :meth:`spend`, because the
        provider has already charged it. ``actual == 0`` is still a settlement: the unused claim is
        returned immediately rather than held until the loop's next step.
        """
        if resource not in self._RESOURCES or resource == "wall_seconds":
            raise ValueError(f"resource cannot settle a reservation: {resource}")
        _finite_nonnegative(reserved, f"{resource} reserved settlement")
        _finite_nonnegative(actual, f"{resource} actual settlement")
        with self._lock:
            if reserved > self._reserved[resource]:
                raise ValueError(
                    f"cannot settle {reserved:.4g} of {resource}; only "
                    f"{self._reserved[resource]:.4g} is reserved")
            self._reserved[resource] -= reserved
            new = self._spent[resource] + actual
            self._spent[resource] = new
            limit = self._limit(resource)
            if limit is not None and new > limit:
                raise BudgetExceeded(resource, new, limit)

    def reserved(self, resource: str) -> float:
        """Headroom currently claimed by work in flight. Reported separately from `spent` because they
        are different claims: one is money gone, the other is money somebody expects to spend."""
        if resource == "wall_seconds":
            return 0.0
        with self._lock:
            return self._reserved.get(resource, 0.0)

    def check(self) -> None:
        """Raise if any metered resource is already past its cap (e.g. wall clock)."""
        for r in self._RESOURCES:
            limit = self._limit(r)
            if limit is not None and self.spent(r) > limit:
                raise BudgetExceeded(r, self.spent(r), limit)

    # --- graceful degrade ---------------------------------------------------
    def pressure(self, resource: str) -> float:
        """Fraction of a resource's cap consumed (0..>1). inf-cap → 0."""
        limit = self._limit(resource)
        if limit is None or limit == 0:
            return 0.0
        return self.spent(resource) / limit

    def should_degrade(self) -> bool:
        return any(self.pressure(r) >= self.budget.degrade_at for r in self._RESOURCES)

    def degrade_hints(self) -> list[str]:
        """Concrete, ordered actions to shrink the next iteration's cost. Encodes the
        lessons from this session (warm-only first, then cheaper model, then fewer agents)."""
        hints: list[str] = []
        if self.pressure("benchmark_task_runs") >= self.budget.degrade_at:
            hints.append("benchmark: run WARM-ONLY against an existing cold baseline (halve task-runs)")
            hints.append("benchmark: shrink to a representative cluster, not the full 30")
        if self.pressure("usd") >= self.budget.degrade_at or self.pressure("tokens") >= self.budget.degrade_at:
            hints.append("reasoner: drop sub-agents to Haiku; reserve Opus for the final judge")
        if self.pressure("subagents") >= self.budget.degrade_at:
            hints.append("orchestrator: lower the fan-out width")
        if self.pressure("wall_seconds") >= self.budget.degrade_at:
            hints.append("scope: checkpoint + escalate; defer remaining work to the next run")
        return hints

    def snapshot(self) -> dict:
        return {
            r: {"spent": round(self.spent(r), 4), "limit": self._limit(r),
                "pressure": round(self.pressure(r), 3)}
            for r in self._RESOURCES
        }


# --- Run-health: the degraded-run guard -------------------------------------------------------------
# A benchmark run is a fitness measurement, and its number only means "the solver's capability" if the
# BACKEND actually ran the solver on every task. This session's #1 operational pain was the opposite: the
# fp8 GLM-5.2 provider slow-dripped and FROZE the full-50 run — most tasks died in the transport (idle
# stalls, empty bodies, HTTP 5xx and local transport outcomes), not in the solver. Nothing tallied per-task backend
# outcomes into a run verdict, so such a run reads back as a *clean* low solve-rate — a phantom capability
# gap that misdirects the DIAGNOSE step into "fixing" a solver that never got to try. This tracker closes
# that hole: it separates a genuine MISS (the solver ran, the target didn't fall) from a BACKEND_ERROR (the
# infra died) and refuses to certify a run whose measurement was dominated by infra failure.
#
# The framing is borrowed (over-flag on doubt; a zero-productive run is ALSO invalid; the threshold is a
# knob), but the detection is Shard-native and STRUCTURAL: outcomes key off ``AgentResult.status`` and the
# ``LLMResult`` failure codes, never a text-scrape of provider error prose. Fail-safe DIRECTION is to
# over-flag degraded — a falsely-INVALID run costs a re-run; a falsely-OK run poisons the diagnosis.
#
# Pure + dependency-free + unit-testable — the same bar as BudgetGovernor, and deliberately a SEPARATE
# small class: run-health is a per-run tally, not a metered spend, so entangling it with the governor would
# only blur two unrelated lifecycles.

# The three structural outcome categories. Keyed off signals the loop already produces:
#   solved        — a verified solve (the differential oracle credited a crash).
#   miss          — a genuine done-with-no-crash: the solver ran to a terminal state, the target stood.
#   backend_error — the infra died, not the solver: ``AgentResult.status == "error"`` OR a backend failure
#                   (an ``LLMResult`` with ``ok=False`` after an unretried HTTP/local transport failure).
# ``solved`` and ``miss`` are the PRODUCTIVE outcomes (the solver actually got a fair attempt); a run with
# none of them measured nothing.
_HEALTH_OUTCOMES = ("solved", "miss", "backend_error")
_PRODUCTIVE_OUTCOMES = ("solved", "miss")


def classify_terminal(status: str, retried_ok: bool = False) -> str:
    """Map an ``AgentResult.status`` to a :class:`DegradedRunTracker` outcome.

    STAGED / not yet wired: this is the IN-LOOP mapper (Shard's own ``AgentResult`` vocab), for the
    planned path where the loop's DIAGNOSE step feeds run_health from the journal. The live wiring today
    reads the benchmark results file, whose SCORER vocab differs, so ``tools.py`` maps that directly
    (``_harness_status_outcome``); the two vocabularies are deliberately kept apart, not shared.

    ``status == "error"`` is the loop's own signal that a backend failure (an unretried terminal
    HTTP or local transport result from ``llm.py``) killed the turn — a ``backend_error`` unless
    ``retried_ok`` says the
    transport recovered and the solver still reached a real verdict. Every other terminal status
    (``done`` / ``budget`` / ``maxsteps`` / ``repeat``) means the solver *ran*; without a separate
    crash verdict the conservative reading is a genuine ``miss``. A caller that DOES hold a crash
    verdict should record ``"solved"`` directly rather than route it through here.
    """
    if status == "error" and not retried_ok:
        return "backend_error"
    return "miss"


class DegradedRunTracker:
    """Tally per-task outcomes and refuse to certify a run the backend degraded out from under.

    ``verdict()`` returns ``"INVALID_DEGRADED"`` when either (a) NO productive task was recorded
    (every task backend-died, or nothing ran at all — a zero-task run measured nothing), or (b) the
    ``backend_error`` fraction over ALL recorded tasks reaches ``degrade_threshold``. Otherwise
    ``"OK"``. The direction is fail-safe: over-flag degraded, because a run wrongly stamped INVALID
    just gets re-run, while a degraded run wrongly stamped OK feeds a phantom capability gap into the
    diagnosis.

    ``degrade_threshold`` is the knob (default 0.5 = "half the tasks were infra failures"). It is a
    ``>=`` boundary: at exactly the threshold the run is already INVALID.
    """

    def __init__(self, *, degrade_threshold: float = 0.5) -> None:
        if not 0.0 < degrade_threshold <= 1.0:
            raise ValueError(f"degrade_threshold must be in (0, 1]: {degrade_threshold!r}")
        self.degrade_threshold = degrade_threshold
        self._counts: dict[str, int] = {o: 0 for o in _HEALTH_OUTCOMES}

    def record(self, outcome: str) -> None:
        """Record one task's terminal outcome. Unknown category → ValueError (a caller that invented a
        category is a bug we want loud, not a silently-dropped task that skews the fraction)."""
        if outcome not in self._counts:
            raise ValueError(
                f"unknown run-health outcome: {outcome!r} (expected one of {_HEALTH_OUTCOMES})"
            )
        self._counts[outcome] += 1

    @property
    def total(self) -> int:
        return sum(self._counts.values())

    @property
    def productive(self) -> int:
        """Tasks where the solver got a fair attempt (a real solved/miss verdict)."""
        return sum(self._counts[o] for o in _PRODUCTIVE_OUTCOMES)

    def error_fraction(self) -> float:
        """Fraction of ALL recorded tasks that were backend failures. Zero tasks → 0.0 (the
        zero-productive rule in ``verdict`` is what flags an empty run, not this fraction)."""
        if self.total == 0:
            return 0.0
        return self._counts["backend_error"] / self.total

    def verdict(self) -> str:
        if self.productive == 0:
            return "INVALID_DEGRADED"
        if self.error_fraction() >= self.degrade_threshold:
            return "INVALID_DEGRADED"
        return "OK"

    @property
    def degraded(self) -> bool:
        return self.verdict() == "INVALID_DEGRADED"

    def snapshot(self) -> dict:
        """A verdict + counts view, suitable for stamping onto an aggregate results record."""
        return {
            "verdict": self.verdict(),
            "degraded": self.degraded,
            "total": self.total,
            "productive": self.productive,
            "error_fraction": round(self.error_fraction(), 4),
            "degrade_threshold": self.degrade_threshold,
            "counts": dict(self._counts),
        }
