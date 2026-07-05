# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.

"""Clean interrupt handling for Ctrl+C / scan cancellation."""

import sys
import time
import signal

from lib.core.state import stop_scan

DEFAULT_INTERRUPT_MESSAGE = "Scan interrupted by user (Ctrl+C). Exiting."

# Track the last time Ctrl+C was pressed
_last_interrupt_time = 0.0
# How long to wait between presses to consider it a double Ctrl+C
DOUBLE_PRESS_WINDOW = 2.0


def _sigint_handler(signum, frame):
    """Handle SIGINT (Ctrl+C) signal."""
    # Call handle_interrupt which decides whether to exit or skip
    if not handle_interrupt():
        # If we shouldn't exit, just return (skip current step)
        pass


def setup_interrupt_handler():
    """Set up the SIGINT handler for Ctrl+C."""
    signal.signal(signal.SIGINT, _sigint_handler)


def interrupt_scan() -> None:
    """Signal all running scan workers to stop current step."""
    stop_scan.set()


def reset_interrupt() -> None:
    """Reset the interrupt state to continue scanning."""
    global _last_interrupt_time
    _last_interrupt_time = 0.0
    stop_scan.clear()


def handle_interrupt() -> bool:
    """
    Handle Ctrl+C interrupt. Returns True if should exit, False if should continue.
    Implements double Ctrl+C to exit, single Ctrl+C to skip current step.
    """
    global _last_interrupt_time
    current_time = time.time()
    
    try:
        from lib.ui.display import print_status
    except Exception:
        pass
    
    # Check if it's a double press (within DOUBLE_PRESS_WINDOW)
    if current_time - _last_interrupt_time < DOUBLE_PRESS_WINDOW:
        # Double Ctrl+C: exit the program
        exit_clean("Double Ctrl+C pressed. Exiting.", 0)
        return True
    
    # Single Ctrl+C: skip current step
    _last_interrupt_time = current_time
    interrupt_scan()
    try:
        print()
        print_status("Ctrl+C pressed. Skipping current step...", "warning")
        print_status("Press Ctrl+C again within 2 seconds to exit.", "info")
    except Exception:
        print("\nCtrl+C pressed. Skipping current step...")
        print("Press Ctrl+C again within 2 seconds to exit.")
    return False


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
