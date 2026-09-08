
from __future__ import annotations

import importlib

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

__version__ = "4.0.7"


def __getattr__(name: str):
    submodule = _EXPORTS.get(name)
    if submodule is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(importlib.import_module(f"{__name__}.{submodule}"), name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(_EXPORTS))
