import json
import os
from typing import Any, Dict, Optional

from lib.core.logger import get_logger
from lib.core.config import get_config

logger = get_logger(__name__)
config = get_config()


def _load_secrets_file() -> Dict[str, Any]:
    path = os.path.join(config.CONFIG_DIR, "secrets.json")
    if not os.path.exists(path):
        return {}

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data
    except Exception as e:
        logger.error(f"Failed to load secrets file: {e}")

    return {}


def _save_secrets_file(data: Dict[str, Any]) -> bool:
    """Save secrets to the secrets file."""
    path = os.path.join(config.CONFIG_DIR, "secrets.json")
    try:
        os.makedirs(config.CONFIG_DIR, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return True
    except Exception as e:
        logger.error(f"Failed to save secrets file: {e}")
        return False


def get_secret(name: str, env_var: Optional[str] = None) -> Optional[str]:
    if env_var:
        v = os.environ.get(env_var)
        if v:
            return v

    data = _load_secrets_file()
    v = data.get(name)
    if isinstance(v, str) and v.strip():
        return v.strip()

    return None


def set_secret(name: str, value: str) -> bool:
    """Set a secret value in the secrets file."""
    data = _load_secrets_file()
    data[name] = value
    return _save_secrets_file(data)
