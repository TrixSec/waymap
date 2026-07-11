#!/usr/bin/env python3
# Copyright (c) 2026 waymap developers
# See the file 'LICENSE' for copying permission.

"""WPScan API batch lookup for known WordPress CVEs.

This module handles the WPScan API integration. It is called by the
consolidated WordPress scanner in profile_wordpress.py when an API
token is available.
"""

import json
import requests
from typing import Any, Dict, List, Optional, Set

from lib.core import http
from lib.api.wpscan_client import (
    WPScanClient,
    build_wordpress_version_path,
    count_vulnerabilities_in_response,
    summarize_batch_vulnerabilities,
)
from lib.core.logger import get_logger
from lib.ui import print_status, print_separator

logger = get_logger(__name__)


def run_wpscan_batch_lookup(
    target_url: str,
    wp_version: Optional[str],
    plugins: Set[str],
    themes: Set[str],
    token: str,
) -> Optional[Dict[str, Any]]:
    """Query WPScan API for known vulnerabilities.

    Args:
        target_url: The WordPress target URL.
        wp_version: Detected WordPress core version (or None).
        plugins: Set of detected plugin slugs.
        themes: Set of detected theme slugs.
        token: WPScan API token.

    Returns:
        Dictionary with vulnerability counts and summary, or None on failure.
    """
    client = WPScanClient(api_token=token)

    request_paths: List[str] = []

    wp_path = build_wordpress_version_path(wp_version or "")
    if wp_path:
        request_paths.append(wp_path)

    for slug in sorted(plugins):
        request_paths.append(f"plugins/{slug}")

    for slug in sorted(themes):
        request_paths.append(f"themes/{slug}")

    if not request_paths:
        print_status("No WordPress version/plugins/themes detected to query WPScan", "warning")
        return None

    print_status(f"Querying WPScan API for {len(request_paths)} item(s)", "info")

    try:
        batch = client.batch(request_paths)
    except requests.HTTPError as e:
        status = getattr(e.response, "status_code", None)
        if status == 401 or status == 403:
            print_status("WPScan API authentication failed (check token)", "error")
            raise
        if status == 429:
            print_status("WPScan API rate limit reached (HTTP 429)", "error")
            raise
        raise

    total = 0
    wp_total = 0
    plugin_total = 0
    theme_total = 0

    for req_path, resp in batch.iter_pairs():
        c = count_vulnerabilities_in_response(resp)
        total += c

        if req_path.startswith("wordpresses/"):
            wp_total += c
        elif req_path.startswith("plugins/"):
            plugin_total += c
        elif req_path.startswith("themes/"):
            theme_total += c

        if c > 0:
            print_status(f"{req_path}: {c} vulnerability(ies)", "success")

    print_separator()
    print_status(
        f"WPScan results: total={total}, wordpress={wp_total}, "
        f"plugins={plugin_total}, themes={theme_total}",
        "info",
    )

    return {
        "request_items": request_paths,
        "counts": {
            "total": total,
            "wordpress": wp_total,
            "plugins": plugin_total,
            "themes": theme_total,
        },
        "summary": summarize_batch_vulnerabilities(batch.raw),
    }
