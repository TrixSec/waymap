# Copyright (c) 2026 waymap developers
# See the file 'LICENSE' for copying permission.

"""Shared HTTP session helpers with enhanced retry logic and connection pooling."""

from typing import Any, Optional
import threading
import time
from collections import defaultdict
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from lib.core.logger import get_logger
from lib.core.config import get_config

logger = get_logger(__name__)
config = get_config()

_LOCAL = threading.local()
_HOST_LIMITS = defaultdict(lambda: threading.BoundedSemaphore(20))


def _create_retry_strategy() -> Retry:
    """Create a retry strategy with exponential backoff."""
    return Retry(
        total=3,  # Total number of retries
        backoff_factor=0.5,  # Exponential backoff factor (0.5s, 1s, 2s)
        status_forcelist=[429, 500, 502, 503, 504],  # Retry on these status codes
        allowed_methods=["HEAD", "GET", "POST", "PUT", "DELETE", "OPTIONS", "TRACE"],
        raise_on_status=False  # Don't raise exception on retry
    )


def get_http_session() -> requests.Session:
    """Return a thread-local requests session with enhanced connection pooling and retry logic."""
    session = getattr(_LOCAL, "session", None)
    if session is None:
        session = requests.Session()
        
        # Create retry strategy
        retry_strategy = _create_retry_strategy()
        
        # Enhanced connection pooling with retry logic
        adapter = HTTPAdapter(
            pool_connections=100,  # Number of connection pools to cache
            pool_maxsize=100,  # Maximum number of connections in pool
            max_retries=retry_strategy,
            pool_block=False  # Don't block when pool is full
        )
        
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # Configure session for persistent connections
        session.headers.update({
            'Connection': 'keep-alive',
            'Keep-Alive': 'timeout=30, max=100'
        })
        
        _LOCAL.session = session
        logger.debug("Created new HTTP session with retry logic and connection pooling")
    
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
