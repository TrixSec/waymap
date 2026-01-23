# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.

"""Global state management."""

import threading

# Global stop event for scans
stop_scan = threading.Event()
