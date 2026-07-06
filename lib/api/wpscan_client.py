#!/usr/bin/env python3

import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import requests
from lib.core import http

from lib.core.logger import get_logger

logger = get_logger(__name__)


WPSCAN_API_BASE = "https://wpscan.com/api/v3/"


@dataclass
class WPScanBatchResult:
    raw: Any
    requests: List[str]

    def iter_pairs(self):
        if not isinstance(self.raw, list) or not self.raw:
            return []

        container = self.raw[0]
        if not isinstance(container, dict):
            return []

        responses = container.get("responses")
        if not isinstance(responses, list):
            return []

        pairs = []
        for req, resp in zip(self.requests, responses):
            pairs.append((req, resp))
        return pairs


class WPScanClient:
    def __init__(self, api_token: str, timeout: int = 20):
        if not api_token:
            raise ValueError("WPScan API token is required")
        self.api_token = api_token
        self.timeout = timeout

    def batch(self, requests_list: List[str]) -> WPScanBatchResult:
        if not requests_list:
            return WPScanBatchResult(raw=[], requests=[])

        url = f"{WPSCAN_API_BASE}batch"
        headers = {
            "Authorization": f"Token token={self.api_token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        payload = {"requests": requests_list}

        resp = http.post(url, headers=headers, data=json.dumps(payload), timeout=self.timeout)
        resp.raise_for_status()

        try:
            data = resp.json()
        except json.JSONDecodeError as e:
            logger.error(f"WPScan API returned non-JSON response: {e}")
            raise

        return WPScanBatchResult(raw=data, requests=requests_list)


def build_wordpress_version_path(version: str) -> Optional[str]:
    if not version:
        return None

    cleaned = "".join(ch for ch in version if (ch.isdigit() or ch == "."))
    cleaned = cleaned.strip(".")
    if not cleaned:
        return None

    # WPScan expects dots removed: 5.6.1 -> 561
    version_id = cleaned.replace(".", "")
    if not version_id.isdigit():
        return None

    return f"wordpresses/{version_id}"


def summarize_batch_vulnerabilities(batch_raw: Any) -> Dict[str, int]:
    summary = {
        "wordpress_vulns": 0,
        "plugin_vulns": 0,
        "theme_vulns": 0,
        "total_vulns": 0,
    }

    if not isinstance(batch_raw, list) or not batch_raw:
        return summary

    container = batch_raw[0]
    if not isinstance(container, dict):
        return summary

    responses = container.get("responses")
    if not isinstance(responses, list):
        return summary

    for entry in responses:
        if not isinstance(entry, dict):
            continue

        # wordpress response shape: {"4.9.4": {"vulnerabilities": [...]}}
        for key, value in entry.items():
            if not isinstance(value, dict):
                continue
            vulns = value.get("vulnerabilities")
            if not isinstance(vulns, list):
                continue

            count = len(vulns)
            if key and key[0].isdigit():
                summary["wordpress_vulns"] += count
            else:
                # plugin/theme are slugs, we can't reliably distinguish without knowing request type
                # treat as plugin/theme bucket and let caller label if needed
                summary["plugin_vulns"] += count

    summary["total_vulns"] = summary["wordpress_vulns"] + summary["plugin_vulns"] + summary["theme_vulns"]
    return summary


def count_vulnerabilities_in_response(resp: Any) -> int:
    if not isinstance(resp, dict):
        return 0

    total = 0
    for _, value in resp.items():
        if not isinstance(value, dict):
            continue
        vulns = value.get("vulnerabilities")
        if isinstance(vulns, list):
            total += len(vulns)
    return total
