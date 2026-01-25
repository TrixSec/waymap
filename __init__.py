
import importlib


def _read_version() -> str:
    try:
        from waymap.lib.core.config import get_config

        return get_config().VERSION
    except Exception:
        return "0.0.0"


__version__ = _read_version()


try:
    import sys

    if "lib" not in sys.modules:
        sys.modules["lib"] = importlib.import_module("waymap.lib")
except Exception:
    pass
