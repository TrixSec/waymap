# Copyright (c) 2026 waymap developers
# See the file 'LICENSE' for copying permission.

"""Shared SQLi helpers."""

import time
from functools import lru_cache
from typing import Generator, List, Tuple
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import requests

from lib.core import http
from lib.core.config import get_config
from lib.parse.random_headers import generate_random_headers

config = get_config()


def parameter_names(url: str) -> List[str]:
    return list(parse_qs(urlparse(url).query).keys())


def inject_payload(url: str, payload: str) -> Generator[Tuple[str, str], None, None]:
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)

    for param in query_params:
        test_params = query_params.copy()
        test_params[param] = [f"{test_params[param][0]} {payload}"]
        parts = list(parsed_url)
        parts[4] = urlencode(test_params, doseq=True)
        yield urlunparse(parts), param


@lru_cache(maxsize=4096)
def detect_server_info(url: str) -> Tuple[str, str]:
    try:
        response = http.head(url, headers=generate_random_headers(), verify=False, timeout=config.REQUEST_TIMEOUT)
        return response.headers.get("Server", "Unknown"), response.headers.get("X-Powered-By", "Unknown")
    except Exception:
        return "Unknown", "Unknown"


@lru_cache(maxsize=4096)
def baseline_response_time(url: str) -> float:
    try:
        start_time = time.time()
        http.get(url, headers=generate_random_headers(), verify=False, timeout=config.REQUEST_TIMEOUT)
        return time.time() - start_time
    except requests.RequestException:
        return 0.0
