
from __future__ import annotations

from typing import TypeVar

_T = TypeVar("_T")


def spread(rows: list[tuple[str, _T]], depth: int = 0) -> list[_T]:
    tree: dict[str, list[tuple[str, _T]]] = {}
    for path, item in rows:
        tree.setdefault("".join(path.split("/")[depth:depth + 1]), []).append((path, item))
    sub = {name: [i for _, i in rs] if name == "" else spread(rs, depth + 1)
           for name, rs in tree.items()}
    keyed = [((2 * i + 1) / (2 * len(rs)), name, r) for name, rs in sub.items() for i, r in enumerate(rs)]
    return [t[2] for t in sorted(keyed, key=lambda t: t[:2])]
