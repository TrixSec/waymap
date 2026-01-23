# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.

"""
Legacy Error Handler - Deprecated.

This module is deprecated. Use lib.core.error_handler instead.
Maintained for backward compatibility only.
"""

from lib.core.error_handler import (
    WaymapError,
    ValidationError,
    NetworkError,
    ConfigurationError,
    ScanError,
    validate_url,
    validate_file_path,
    validate_positive_int,
    safe_execute
)

__all__ = [
    'WaymapError',
    'ValidationError',
    'NetworkError',
    'ConfigurationError',
    'ScanError',
    'validate_url',
    'validate_file_path',
    'validate_positive_int',
    'safe_execute'
]

# Deprecated - use lib.core.error_handler
import warnings
warnings.warn(
    "extras.error_handler is deprecated. Use lib.core.error_handler instead.",
    DeprecationWarning,
    stacklevel=2
)