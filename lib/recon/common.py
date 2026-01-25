"""Shared helpers for recon and misconfiguration modules."""

import json
import os
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import requests

from lib.core.config import get_config
from lib.core.logger import get_logger
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
    session_dir = config.get_domain_session_dir(domain)
    session_file = os.path.join(session_dir, "waymap_full_results.json")
    if os.path.exists(session_file):
        try:
            with open(session_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                return data
        except Exception:
            return {"scans": []}
    return {"scans": []}


def save_results(domain: str, results: Dict[str, Any]) -> None:
    session_dir = config.get_domain_session_dir(domain)
    session_file = os.path.join(session_dir, "waymap_full_results.json")
    try:
        with open(session_file, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=4)
    except Exception as e:
        logger.error(f"Error saving results: {e}")


def append_scan_record(
    results: Dict[str, Any],
    scan_key: str,
    record: Dict[str, Any],
    unique_keys: Optional[Iterable[str]] = None,
) -> bool:
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
    return datetime.utcnow().isoformat()


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
    results = load_results(domain)
    if append_scan_record(results, scan_key, record, unique_keys=unique_keys):
        save_results(domain, results)
        if success_message:
            print_status(success_message, "success")
