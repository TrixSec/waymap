# Copyright (c) 2026 waymap developers
# See the file 'LICENSE' for copying permission.

"""Shared injection helpers."""

from functools import lru_cache
from typing import Dict, List, Tuple
from urllib.parse import parse_qs, urlparse

from lib.core.logger import get_logger
from lib.utils.file_utils import load_payloads

logger = get_logger(__name__)


@lru_cache(maxsize=None)
def load_named_payloads(file_path: str, fields: Tuple[str, ...]) -> List[Dict[str, str]]:
    payloads = []
    for line in load_payloads(file_path):
        parts = line.split("::", len(fields) - 1)
        if len(parts) != len(fields):
            logger.warning(f"Malformed payload: {line}")
            continue
        payloads.append(dict(zip(fields, (part.strip() for part in parts))))
    return payloads


def parameter_names(url: str) -> List[str]:
    return list(parse_qs(urlparse(url).query, keep_blank_values=True).keys())
