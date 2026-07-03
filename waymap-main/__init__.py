import os
import sys

# Ensure the waymap package directory is in sys.path so internal absolute imports starting with 'lib' work.
pkg_dir = os.path.dirname(os.path.abspath(__file__))
if pkg_dir not in sys.path:
    sys.path.insert(0, pkg_dir)


def _read_version() -> str:
    try:
        from lib.core.config import get_config

        return get_config().VERSION
    except Exception:
        return "0.0.0"


__version__ = _read_version()
