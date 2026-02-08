"""Deprecated benchmark entry.

Use the unified benchmark instead:
    python examples/evaluate_test_cases.py
"""

from __future__ import annotations

import sys


def main() -> None:
    print(
        "[DEPRECATED] examples/evaluate_ark_accuracy.py is removed.\n"
        "Use: python examples/evaluate_test_cases.py",
        file=sys.stderr,
    )
    raise SystemExit(2)


if __name__ == "__main__":
    main()
