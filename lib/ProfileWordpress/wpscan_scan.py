#!/usr/bin/env python3

import json
import os
import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

import requests

from lib.api.wpscan_client import (
    WPScanClient,
    build_wordpress_version_path,
    count_vulnerabilities_in_response,
    summarize_batch_vulnerabilities,
)
from lib.core.secrets import get_secret
from lib.core.config import get_config
from lib.core.logger import get_logger
from lib.parse.random_headers import generate_random_headers
from lib.ui import print_header, print_status, print_separator

logger = get_logger(__name__)
config = get_config()


def _get_domain(url: str) -> str:
    return urlparse(url).netloc


def _load_existing_results(domain: str) -> Dict[str, Any]:
    session_dir = config.get_domain_session_dir(domain)
    session_file = os.path.join(session_dir, "waymap_full_results.json")
    if os.path.exists(session_file):
        try:
            with open(session_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                return data
        except Exception:
            return {}
    return {}


def _save_results(domain: str, results: Dict[str, Any]) -> None:
    session_dir = config.get_domain_session_dir(domain)
    session_file = os.path.join(session_dir, "waymap_full_results.json")
    try:
        with open(session_file, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=4)
    except Exception as e:
        logger.error(f"Error saving results: {e}")


def _append_result(results: Dict[str, Any], record: Dict[str, Any]) -> None:
    vuln_key = "wordpress_profile"
    if "scans" not in results or not isinstance(results.get("scans"), list):
        results["scans"] = []

    block = None
    for entry in results["scans"]:
        if isinstance(entry, dict) and vuln_key in entry:
            block = entry[vuln_key]
            break

    if block is None:
        block = []
        results["scans"].append({vuln_key: block})

    block.append(record)


def _extract_wordpress_version(html: str) -> Optional[str]:
    if not html:
        return None

    m = re.search(r"WordPress\s*(\d+(?:\.\d+){1,3})", html, flags=re.IGNORECASE)
    if m:
        return m.group(1)

    return None


def _extract_slugs(html: str) -> Tuple[Set[str], Set[str]]:
    plugins: Set[str] = set()
    themes: Set[str] = set()

    if not html:
        return plugins, themes

    for m in re.finditer(r"/wp-content/plugins/([^/]+)/", html, flags=re.IGNORECASE):
        slug = m.group(1).strip()
        if slug:
            plugins.add(slug)

    for m in re.finditer(r"/wp-content/themes/([^/]+)/", html, flags=re.IGNORECASE):
        slug = m.group(1).strip()
        if slug:
            themes.add(slug)

    return plugins, themes


def run_wpscan_batch_lookup(
    target_url: str,
    wp_version: Optional[str],
    plugins: Set[str],
    themes: Set[str],
    token: str,
) -> None:
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
        return

    print_status(f"Sending WPScan batch request with {len(request_paths)} item(s)", "info")

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
    print_status(f"WPScan results: total={total}, wordpress={wp_total}, plugins={plugin_total}, themes={theme_total}", "info")

    return {
        "request_items": request_paths,
        "counts": {
            "total": total,
            "wordpress": wp_total,
            "plugins": plugin_total,
            "themes": theme_total,
        },
        "summary": summarize_batch_vulnerabilities(batch.raw),
        "raw": batch.raw,
    }


def wpscan_wordpress_vulnerabilities(target_url: str) -> None:
    print_header("WordPress Vulnerability Check (WPScan API)", color="cyan")

    domain = _get_domain(target_url) or "unknown_domain"
    results = _load_existing_results(domain)
    record: Dict[str, Any] = {
        "target": target_url,
        "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "status": "started",
    }

    token = os.environ.get("WPSCAN_API_TOKEN")
    if not token:
        token = get_secret("wpscan_api_token", env_var="WPSCAN_API_TOKEN")
    if not token:
        print_status("WPScan token missing. Provide --wpscan-token or set env WPSCAN_API_TOKEN", "warning")
        record["status"] = "error"
        record["error"] = "missing_wpscan_token"
        _append_result(results, record)
        _save_results(domain, results)
        return

    headers = generate_random_headers()

    try:
        resp = requests.get(target_url, headers=headers, verify=False, timeout=config.REQUEST_TIMEOUT)
        html = resp.text if resp is not None else ""
    except Exception as e:
        logger.error(f"Failed to fetch target for WPScan discovery: {e}")
        print_status(f"Failed to fetch target: {e}", "error")
        record["status"] = "error"
        record["error"] = str(e)
        _append_result(results, record)
        _save_results(domain, results)
        return

    wp_version = _extract_wordpress_version(html)
    plugins, themes = _extract_slugs(html)

    print_status(f"Detected WordPress version: {wp_version or 'unknown'}", "info")
    print_status(f"Detected plugins: {len(plugins)}", "info")
    print_status(f"Detected themes: {len(themes)}", "info")

    record["detected"] = {
        "wordpress_version": wp_version,
        "plugins": sorted(list(plugins)),
        "themes": sorted(list(themes)),
        "plugin_count": len(plugins),
        "theme_count": len(themes),
    }

    try:
        batch_result = run_wpscan_batch_lookup(
            target_url=target_url,
            wp_version=wp_version,
            plugins=plugins,
            themes=themes,
            token=token,
        )
        record["status"] = "ok"
        record["wpscan"] = batch_result
    except Exception as e:
        record["status"] = "error"
        record["error"] = str(e)

    _append_result(results, record)
    _save_results(domain, results)
