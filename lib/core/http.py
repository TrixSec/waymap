# Copyright (c) 2026 waymap developers
# See the file 'LICENSE' for copying permission.

"""Shared HTTP session helpers."""

from typing import Any
import threading
from collections import defaultdict
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter


_LOCAL = threading.local()
_HOST_LIMITS = defaultdict(lambda: threading.BoundedSemaphore(20))


def get_http_session() -> requests.Session:
    """Return a thread-local requests session with connection pooling."""
    session = getattr(_LOCAL, "session", None)
    if session is None:
        session = requests.Session()
        adapter = HTTPAdapter(pool_connections=100, pool_maxsize=100, max_retries=0)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        _LOCAL.session = session
    return session


def request(method: str, url: str, **kwargs: Any) -> requests.Response:
    host = urlparse(url).netloc or url
    with _HOST_LIMITS[host]:
        return get_http_session().request(method, url, **kwargs)


def get(url: str, **kwargs: Any) -> requests.Response:
    return request("GET", url, **kwargs)


def post(url: str, **kwargs: Any) -> requests.Response:
    return request("POST", url, **kwargs)


def head(url: str, **kwargs: Any) -> requests.Response:
    return request("HEAD", url, **kwargs)


def options(url: str, **kwargs: Any) -> requests.Response:
    return request("OPTIONS", url, **kwargs)
