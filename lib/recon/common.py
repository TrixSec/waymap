"""Shared helpers for recon and misconfiguration modules."""

from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Optional
from urllib.parse import urljoin, urlparse

import requests

from lib.core.config import get_config
from lib.core.logger import get_logger
from lib.core.result_manager import ResultManager
from lib.parse.random_headers import generate_random_headers
from lib.ui import print_status

config = get_config()
logger = get_logger(__name__)


def normalize_target(target: str) -> str:
    if not target:
        return ""
    parsed = urlparse(target)
    if not parsed.scheme:
        return f"https://{target.strip('/')}"
    if not parsed.netloc:
        return target
    return f"{parsed.scheme}://{parsed.netloc}"


def get_domain(target: str) -> str:
    parsed = urlparse(normalize_target(target))
    return parsed.netloc or "unknown_domain"


def load_results(domain: str) -> Dict[str, Any]:
    return ResultManager(domain).get_results()


def save_results(domain: str, results: Dict[str, Any]) -> None:
    ResultManager(domain).replace_all(results)


def append_scan_record(
    results: Dict[str, Any],
    scan_key: str,
    record: Dict[str, Any],
    unique_keys: Optional[Iterable[str]] = None,
) -> bool:
    domain = record.get("domain") or record.get("target_domain")
    if domain:
        manager = ResultManager(domain)
        if unique_keys and manager.has_duplicate(scan_key, unique_keys, record):
            return False
        manager.add_finding(scan_key, "", record)
        return True

    if "scans" not in results or not isinstance(results.get("scans"), list):
        results["scans"] = []

    block = None
    for entry in results["scans"]:
        if isinstance(entry, dict) and scan_key in entry:
            block = entry[scan_key]
            break

    if block is None:
        block = []
        results["scans"].append({scan_key: block})

    if unique_keys:
        for existing in block:
            if not isinstance(existing, dict):
                continue
            if all(existing.get(key) == record.get(key) for key in unique_keys):
                return False

    block.append(record)
    return True


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def request_url(
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    timeout: Optional[int] = None,
    allow_redirects: bool = True,
    **kwargs: Any,
) -> Optional[requests.Response]:
    if not url:
        return None

    headers = headers or generate_random_headers()
    try:
        response = requests.request(
            method,
            url,
            headers=headers,
            timeout=timeout or config.REQUEST_TIMEOUT,
            verify=False,
            allow_redirects=allow_redirects,
            **kwargs,
        )
        return response
    except requests.RequestException as e:
        logger.debug(f"Request failed for {url}: {e}")
        return None


def build_url(base_url: str, path: str) -> str:
    if not path.startswith("/"):
        path = f"/{path}"
    return urljoin(base_url.rstrip("/"), path)


def save_and_report(
    domain: str,
    scan_key: str,
    record: Dict[str, Any],
    unique_keys: Optional[Iterable[str]] = None,
    success_message: Optional[str] = None,
) -> None:
    result_manager = ResultManager(domain)

    if unique_keys and result_manager.has_duplicate(scan_key, unique_keys, record):
        return

    result_manager.add_finding(scan_key, "", record)
    if success_message:
        print_status(success_message, "success")
