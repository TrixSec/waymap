# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.

"""Clean interrupt handling for Ctrl+C / scan cancellation."""

import sys

from lib.core.state import stop_scan

DEFAULT_INTERRUPT_MESSAGE = "Scan interrupted by user (Ctrl+C). Exiting."


def interrupt_scan() -> None:
    """Signal all running scan workers to stop."""
    stop_scan.set()


def exit_clean(message: str = DEFAULT_INTERRUPT_MESSAGE, code: int = 0) -> None:
    """Stop scans and exit without traceback."""
    interrupt_scan()
    try:
        from lib.ui.display import print_status
        print()
        print_status(message, "warning")
    except Exception:
        print(f"\n{message}")
    sys.exit(code)
