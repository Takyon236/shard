"""``python -m shard``. The whole body is a delegation, deliberately.

Keeping this file empty of logic means `shard/cli.py:main` is the single testable entry point and the
one whose import closure the maintainers' suite measures. Anything added here would be code that
runs on the customer's runner and is exercised by no test.
"""

from __future__ import annotations

import sys

from shard.cli import main

if __name__ == "__main__":
    sys.exit(main())
