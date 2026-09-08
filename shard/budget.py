
from __future__ import annotations

import math
import threading
import time
from dataclasses import dataclass


class BudgetExceeded(RuntimeError):

    def __init__(self, resource: str, spent: float, limit: float) -> None:
        super().__init__(f"budget exceeded: {resource} {spent:.4g} > {limit:.4g}")
        self.resource = resource
        self.spent = spent
        self.limit = limit


def _finite_nonnegative(value, label: str) -> None:
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

    tokens: float | None = None
    usd: float | None = None
    wall_seconds: float | None = None
    subagents: int | None = None
    benchmark_task_runs: int | None = None
    degrade_at: float = 0.8


@dataclass(frozen=True)
class ScanProfile:

    name: str
    max_tokens: float
    summary: str
    max_findings: int

    min_steps: int = 0


_SWEEP_BACKSTOP = 100

_INITIAL_STEP_FLOOR = 200

INITIAL_SCAN = ScanProfile(
    name="initial",
    max_tokens=6_000_000.0,
    summary="first scan of this target — the ceiling is sized for coverage rather than for cost. It "
            "raises what this run may SPEND, not what it reviews",
    max_findings=_SWEEP_BACKSTOP,
    min_steps=_INITIAL_STEP_FLOOR,
)

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
        self._reserved: dict[str, float] = {r: 0.0 for r in self._RESOURCES}
        self._start = now if now is not None else time.time()
        self._lock = threading.Lock()

    def _limit(self, resource: str) -> float | None:
        return getattr(self.budget, resource)

    def spent(self, resource: str) -> float:
        if resource == "wall_seconds":
            return time.time() - self._start
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
        if resource not in self._RESOURCES:
            raise ValueError(f"unknown budget resource: {resource}")
        _finite_nonnegative(amount, f"{resource} spend")
        if resource == "wall_seconds":
            self.check()
            return
        with self._lock:
            new = self._spent[resource] + amount
            self._spent[resource] = new
            limit = self._limit(resource)
            if limit is not None and new > limit:
                raise BudgetExceeded(resource, new, limit)

    def try_spend(self, resource: str, amount: float) -> bool:
        if resource not in self._RESOURCES:
            raise ValueError(f"unknown budget resource: {resource}")
        _finite_nonnegative(amount, f"{resource} spend")
        if resource == "wall_seconds":
            return self.can_afford(resource, amount)
        with self._lock:
            new = self._spent[resource] + amount
            limit = self._limit(resource)
            if limit is not None and new > limit:
                return False
            self._spent[resource] = new
            return True

    def reserve(self, resource: str, amount: float) -> bool:
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
        if resource not in self._RESOURCES or resource == "wall_seconds":
            return
        _finite_nonnegative(amount, f"{resource} release")
        with self._lock:
            self._reserved[resource] = max(0.0, self._reserved[resource] - amount)

    def settle(self, resource: str, reserved: float, actual: float) -> None:
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
        if resource == "wall_seconds":
            return 0.0
        with self._lock:
            return self._reserved.get(resource, 0.0)

    def check(self) -> None:
        for r in self._RESOURCES:
            limit = self._limit(r)
            if limit is not None and self.spent(r) > limit:
                raise BudgetExceeded(r, self.spent(r), limit)

    def pressure(self, resource: str) -> float:
        limit = self._limit(resource)
        if limit is None or limit == 0:
            return 0.0
        return self.spent(resource) / limit

    def should_degrade(self) -> bool:
        return any(self.pressure(r) >= self.budget.degrade_at for r in self._RESOURCES)

    def degrade_hints(self) -> list[str]:
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



_HEALTH_OUTCOMES = ("solved", "miss", "backend_error")
_PRODUCTIVE_OUTCOMES = ("solved", "miss")


def classify_terminal(status: str, retried_ok: bool = False) -> str:
    if status == "error" and not retried_ok:
        return "backend_error"
    return "miss"


class DegradedRunTracker:

    def __init__(self, *, degrade_threshold: float = 0.5) -> None:
        if not 0.0 < degrade_threshold <= 1.0:
            raise ValueError(f"degrade_threshold must be in (0, 1]: {degrade_threshold!r}")
        self.degrade_threshold = degrade_threshold
        self._counts: dict[str, int] = {o: 0 for o in _HEALTH_OUTCOMES}

    def record(self, outcome: str) -> None:
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
        return sum(self._counts[o] for o in _PRODUCTIVE_OUTCOMES)

    def error_fraction(self) -> float:
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
        return {
            "verdict": self.verdict(),
            "degraded": self.degraded,
            "total": self.total,
            "productive": self.productive,
            "error_fraction": round(self.error_fraction(), 4),
            "degrade_threshold": self.degrade_threshold,
            "counts": dict(self._counts),
        }
