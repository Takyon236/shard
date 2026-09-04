"""A pocket-sized settings loader with one real defect, kept to a single page.

The defect is the `eval` inside `load`, marked below. (It said "line 30" until a real review run
pointed out the `eval` was on line 31 — a line number in prose is a fact that drifts every time
somebody adds a comment above it, so this names the function instead.)

It is there for a reason people actually have: the author wanted
`retries = 3` to come back as an integer rather than the string `"3"`, and `eval` is the shortest thing
that does it. That is how this defect gets written in real code — not as carelessness, but as a type
conversion that happens to accept expressions.

Nothing else here is planted. The file is small so that the example is about the WITNESS rather than
about finding a needle.
"""

from __future__ import annotations


def load(text: str) -> dict[str, object]:
    """Parse `key = value` lines into a settings dictionary.

    Blank lines and `#` comments are skipped. Values are converted so that numbers arrive as numbers.
    """
    settings: dict[str, object] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, raw = line.partition("=")
        if not sep:
            continue
        # THE DEFECT. `eval` converts "3" to 3 and "true" to nothing useful, but it also runs whatever
        # else it is given. A settings file is exactly the kind of input that arrives from somewhere
        # other than the author of this line.
        settings[key.strip()] = eval(raw.strip())  # noqa
    return settings
