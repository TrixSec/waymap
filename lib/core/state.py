# Copyright (c) 2026 waymap developers
# See the file 'LICENSE' for copying permission.

"""Global state management - DEPRECATED: Use ScanContext instead."""

import threading
import warnings

# Global stop event for scans - DEPRECATED
# Use ScanContext.stop_event instead
stop_scan = threading.Event()

def _deprecated_global_state():
    """Emit deprecation warning when global state is accessed."""
    warnings.warn(
        "Global state (stop_scan) is deprecated. Use ScanContext.stop_event instead.",
        DeprecationWarning,
        stacklevel=2
    )

# Monkey-patch to warn on access
_original_set = stop_scan.set
_original_clear = stop_scan.clear
_original_is_set = stop_scan.is_set

def _warn_set():
    _deprecated_global_state()
    return _original_set()

def _warn_clear():
    _deprecated_global_state()
    return _original_clear()

def _warn_is_set():
    _deprecated_global_state()
    return _original_is_set()

stop_scan.set = _warn_set
stop_scan.clear = _warn_clear
stop_scan.is_set = _warn_is_set
