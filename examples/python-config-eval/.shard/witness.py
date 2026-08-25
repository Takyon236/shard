"""The observation half of this example's entry point. `entry.sh` is what Shard runs; this is what
decides whether anything worth reporting happened.

WHY A SEPARATE FILE. `entry.sh` is a contract — one argument, a quiet branch on empty input, one
`exec`. Keeping the judgement out of it means the shell script stays the shape every entry point has,
and the interesting part is ordinary code in the language of the project.

WHAT IT WATCHES, and why it is not "did eval run". `settings.load` evaluates EVERY value, so an
observation of "eval ran" fires on `retries = 3` as loudly as on an attack — and Shard would refuse
it, correctly, because the benign inputs beside this file reproduce it. A demonstration has to
separate the defect from the feature.

So there are two observations, and they cover the two shapes an attack takes:

  * **The RESULT is not plain data.** `load` is documented to return numbers, strings and containers.
    A module, a function, a class or an instance came from a constructor running.
  * **A dangerous audit event fired.** Some payloads produce perfectly plain data and still do
    something — `__import__("os").system("id")` evaluates to an integer.

**BOTH ARE NEEDED, AND THE AUDIT HOOK ALONE IS NOT ENOUGH — measured.** `sys.addaudithook` does not
raise `import` for a module that is ALREADY in `sys.modules`, and `os` always is. So the classic
payload `x = __import__("os")` fires no event at all: the first version of this file watched only the
hook, ran the documented attack, and observed nothing while exiting 0. That is precisely the silent
witness this product exists to refuse, and it is why every example here is executed by the test suite
rather than read.

NOTHING BUT THE MARKER IS PRINTED. The parsed settings are never echoed: printing attacker text back
is how an entry point ends up "demonstrating" a defect that is only its own echo.
"""

from __future__ import annotations

import datetime
import pathlib
import sys
import types

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import settings  # noqa: E402  — after the path insert, deliberately

#: Yours to choose, and it should be specific enough that nothing else in your output can produce it.
MARKER = "SHARD_SETTINGS_ARBITRARY_CODE"

#: What a settings value is allowed to be. Anything else means a constructor ran.
PLAIN = (type(None), bool, int, float, str, bytes, list, tuple, dict, set, frozenset,
         datetime.date, datetime.datetime)

#: Audit events that mean code beyond arithmetic and literals ran. These catch the payloads whose
#: RESULT is plain — a command's exit status is an integer — and they are the half that would miss the
#: obvious attack on its own. See the module docstring.
DANGEROUS = ("import", "os.system", "subprocess.Popen", "socket.__new__", "open")

_fired: list[str] = []


def _audit(event: str, args: object) -> None:
    if event in DANGEROUS:
        _fired.append(event)


def _foreign(value: object, depth: int = 0) -> bool:
    """Did a constructor run? A bound, because a container can be made to refer to itself."""
    if depth > 6:
        return False
    if isinstance(value, types.ModuleType) or not isinstance(value, PLAIN):
        return True
    if isinstance(value, dict):
        return any(_foreign(k, depth + 1) or _foreign(v, depth + 1) for k, v in value.items())
    if isinstance(value, (list, tuple, set, frozenset)):
        return any(_foreign(item, depth + 1) for item in value)
    return False


def main() -> int:
    text = pathlib.Path(sys.argv[1]).read_text(errors="replace")

    # ARMED AS LATE AS POSSIBLE. Everything above this line — the interpreter starting, this module
    # importing `settings`, reading the payload — raises audit events of its own, and arming earlier
    # would record them and demonstrate nothing but our own start-up.
    sys.addaudithook(_audit)
    try:
        parsed = settings.load(text)
    except Exception:
        # A malformed file is not a finding. The loader rejecting input is the loader working.
        return 0

    if _fired or any(_foreign(value) for value in parsed.values()):
        print(MARKER)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
