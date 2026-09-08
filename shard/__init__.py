"""Shard — autonomous security analysis that runs inside the customer's CI and reports a finding only
when it can attach a reproducing input. See the design notes.

Every public name is resolved LAZILY (PEP 562 module ``__getattr__``) rather than imported when the
package is. This is not a micro-optimisation; it is load-bearing twice over.

**It keeps the core cheap.** Importing ANY submodule runs this file first. In the predecessor repo this
file eagerly re-exported from every submodule including the 6,910-line solver, so importing
``Budget`` from that package's `budget` module — exactly what the external sweep driver does —
constructed the entire solver to reach a dataclass. That is at odds with the dependency-free-core promise in
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

# Narrowed at build time to the names this artefact actually carries.
_EXPORTS: dict[str, str] = {
    'Budget': 'budget',
    'BudgetGovernor': 'budget',
    'BudgetExceeded': 'budget',
    'Journal': 'journal',
    'ClaudeCliBackend': 'llm',
    'OpenRouterBackend': 'llm',
    'EchoBackend': 'llm',
    'LLMResult': 'llm',
    'ToolContext': 'tools',
    'ToolRegistry': 'tools',
    'HybridRetriever': 'memory',
    'SessionMemory': 'memory',
    'build_context': 'memory',
    'fence': 'memory',
}

__all__ = [
    'Budget',
    'BudgetGovernor',
    'BudgetExceeded',
    'Journal',
    'ClaudeCliBackend',
    'OpenRouterBackend',
    'EchoBackend',
    'LLMResult',
    'ToolContext',
    'ToolRegistry',
    'HybridRetriever',
    'SessionMemory',
    'build_context',
    'fence',
]

# THE THIRD MANIFEST, AND THE ONLY ONE A CUSTOMER CAN ASK THE ARTEFACT FOR. The two
# `pyproject.toml` files are files in a tree; this is what
# `python -c 'import shard; print(shard.__version__)'` answers inside the action container, which is
# what an issue asking "which version produced this alert" gets answered with. It read `0.1.0.dev0`
# from the W1 port until 2026-09-02 while both manifests read 2.3.0, and it ships verbatim in every
# artefact this project builds.
#
# Nothing in the shipping code READS it — measured by RUNNING the code, not by grepping: the SARIF
# driver carries a name and no version, the result document carries `"tool": "Shard"`, the survey
# payload carries only `markers_pack_version`, there is no `--version` subcommand and no Dockerfile
# sets a LABEL. So the disagreement was never a wrong verdict. It was the artefact giving the one
# answer it had about itself, and giving a wrong one.
#
# THIS COMMENT SHIPS, so it names no development path and no withheld component. The free builder
# deletes a comment line that names either and keeps the rest, which truncates the sentence around
# it: the first draft of this block lost its own last line that way. Bump this in the release commit
# alongside both manifests; the release gate refuses a cut where the three disagree.
__version__ = "4.0.5"


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
