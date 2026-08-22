"""Shard — autonomous security analysis that runs inside the customer's CI and reports a finding only
when it can attach a reproducing input. See the design notes.

Every public name is resolved LAZILY (PEP 562 module ``__getattr__``) rather than imported when the
package is. This is not a micro-optimisation; it is load-bearing twice over.

**It keeps the core cheap.** Importing ANY submodule runs this file first. In the predecessor repo this
file eagerly re-exported from every submodule including the 6,910-line solver, so
``from the predecessor project import Budget`` — exactly what the external sweep driver does — constructed
the entire solver to reach a dataclass. That is at odds with the dependency-free-core promise in
the maintainers' notes.

**It is the first line of defence for the mode split.** The free image ships simple mode and must
contain nothing of that capability (the design notes, "Protecting the harness"). An eager import
here would put that module in every consumer's import closure, and an ``_EXPORTS`` entry pointing into
the separate package would be a back door around the boundary. `the maintainers' suite` asserts that no
such entry exists.

``__all__`` and ``_EXPORTS`` are the same key set and must stay in sync — `the maintainers' suite`
asserts it. The first touch of a name imports its submodule and caches the value in this module's
globals; ``__getattr__`` is consulted only on a miss, so lookup is free thereafter.
"""

from __future__ import annotations

import importlib

# Public name → the submodule that defines it. This map IS the package's export surface; keep it in
_EXPORTS: dict[str, str] = {
    # core — dependency-free
    "Budget": "budget", "BudgetGovernor": "budget", "BudgetExceeded": "budget",
    "Journal": "journal",
    # reasoner backends — native tool calling is mandatory
    "ClaudeCliBackend": "llm", "NativeClientBackend": "llm", "OpenRouterBackend": "llm",
    "EchoBackend": "llm", "LLMResult": "llm",
    # shared primitives
    "ToolContext": "tools", "ToolRegistry": "tools",
    # the containment floor — deliberately inspectable, per the design notes: the floor is a trust
    # argument, and a trust argument that cannot be read is not one.
    "ScopeManifest": "scope", "is_in_scope": "scope",
    "run_containment_selftest": "containment",
    # retrieval memory — ADVISORY ONLY. Measured at net zero (the design notes); retained, not
    # promoted. Do not add a call site it did not already have.
    "HybridRetriever": "memory", "SessionMemory": "memory", "build_context": "memory",
    "fence": "memory",
}

__all__ = [
    "Budget", "BudgetGovernor", "BudgetExceeded",
    "Journal",
    "ClaudeCliBackend", "NativeClientBackend", "OpenRouterBackend",
    "EchoBackend", "LLMResult",
    "ToolContext", "ToolRegistry",
    "ScopeManifest", "is_in_scope",
    "run_containment_selftest",
    "HybridRetriever", "SessionMemory", "build_context", "fence",
]

__version__ = "0.1.0.dev0"


def __getattr__(name: str):
    """Import the owning submodule on first touch, then cache the value (PEP 562)."""
    submodule = _EXPORTS.get(name)
    if submodule is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(importlib.import_module(f"{__name__}.{submodule}"), name)
    globals()[name] = value      # subsequent lookups hit globals and never reach __getattr__
    return value


def __dir__() -> list[str]:
    """Lazy names live in `_EXPORTS`, not in globals(), so `dir()` must add them back — otherwise
    REPL/IDE completion would show an almost-empty package until something happened to touch it."""
    return sorted(set(globals()) | set(_EXPORTS))
