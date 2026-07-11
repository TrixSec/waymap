#!/usr/bin/env python3
# Copyright (c) 2026 waymap developers
# See the file 'LICENSE' for copying permission.

"""SerpApi-powered Google dork target discovery module.

Highly optimized and consistent with other waymap modules:
  - Uses stop_scan for graceful cancellation (Ctrl+C)
  - Uses ResultManager for persistence and duplicate check / caching
  - Limits duplicate requests to conserve SerpApi search credits
  - Performs advanced blacklist filtering and validation
"""

import json
import os
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

import requests
from lib.core import http

from lib.core.config import get_config
from lib.core.logger import get_logger
from lib.core.secrets import get_secret
from lib.core.state import stop_scan
from lib.core.result_manager import ResultManager
from lib.ui import print_status, print_header, print_separator

logger = get_logger(__name__)
config = get_config()

SERPAPI_URL = "https://serpapi.com/search"


def _extract_result_links(payload: Dict[str, Any]) -> List[str]:
    """Extract organic search result links from SerpApi response payload."""
    links: List[str] = []
    organic = payload.get("organic_results")
    if isinstance(organic, list):
        for item in organic:
            if isinstance(item, dict):
                link = item.get("link")
                if isinstance(link, str) and link:
                    links.append(link)
    return links


def discover_google_dork(
    query: str,
    api_key: Optional[str] = None,
    limit: Optional[int] = None,
    engine: str = "google",
    timeout: int = 20,
    target: Optional[str] = None,
    output_file: Optional[str] = None,
    max_pages: int = 2,
) -> List[str]:
    """Perform Google dork target discovery using SerpApi.

    Consistent with other modules:
      - Conserves API credits by skipping query if cached in ResultManager
      - Gracefully terminates via stop_scan
      - Saves findings to ResultManager under "dork_discovery"
    """
    print_header("Google Dork Discovery (SerpApi)", color="cyan")

    if not query or not isinstance(query, str):
        raise ValueError("Dork query is required")

    # Resolve domain for ResultManager
    domain = urlparse(target).netloc if target else "dork_discovery"
    result_manager = ResultManager(domain)

    # Cache/Duplicate Check: Conserve SerpApi credits if query already performed
    if result_manager.has_duplicate("dork_discovery", ["query"], {"query": query}):
        print_status("Dork query already executed in previous run.", "info")
        if output_file and os.path.exists(output_file):
            try:
                with open(output_file, "r", encoding="utf-8") as f:
                    cached_urls = [line.strip() for line in f if line.strip()]
                if cached_urls:
                    print_status(f"Loaded {len(cached_urls)} cached URL(s) from: {output_file}", "success")
                    return cached_urls
            except Exception as e:
                logger.debug(f"Failed to read cached dork output file: {e}")

    if not api_key or not isinstance(api_key, str):
        api_key = get_secret("serpapi_api_key", env_var="SERPAPI_API_KEY")
    if not api_key or not isinstance(api_key, str):
        raise ValueError("SerpApi api_key is required. Set SERPAPI_API_KEY env or configure secrets.")

    params = {
        "engine": engine,
        "q": query,
        "api_key": api_key,
        "num": 100,  # Max results per request for credit efficiency
    }

    print_status(f"Query: {query}", "info")
    print_status(f"Engine: {engine}", "info")
    print_status(f"Max pages: {max_pages}", "info")
    print_status("Fetching results from Google via SerpApi...", "info")

    seen: Set[str] = set()
    unique: List[str] = []

    start = 0
    page = 1

    try:
        while not stop_scan.is_set():
            params["start"] = start

            if limit:
                print_status(
                    f"Fetching page {page} (discovered {len(unique)}/{limit})...",
                    "info",
                )
            else:
                print_status(f"Fetching page {page} (discovered {len(unique)})...", "info")

            response = http.get(SERPAPI_URL, params=params, timeout=timeout)
            
            # Handle standard SerpApi errors gracefully
            if response.status_code == 401 or response.status_code == 403:
                print_status("SerpApi authentication failed (check API key)", "error")
                response.raise_for_status()
            elif response.status_code == 429:
                print_status("SerpApi rate limit reached (HTTP 429)", "error")
                response.raise_for_status()
            elif response.status_code != 200:
                print_status(f"SerpApi returned status code {response.status_code}", "error")
                response.raise_for_status()

            try:
                data = response.json()
            except json.JSONDecodeError as e:
                logger.error(f"SerpApi returned non-JSON response: {e}")
                raise

            # Check if there is an error field in the JSON response
            if isinstance(data, dict) and "error" in data:
                error_msg = data.get("error")
                print_status(f"SerpApi Error: {error_msg}", "error")
                break

            links = _extract_result_links(data)
            if not links:
                break

            added_this_page = 0
            for link in links:
                if link in seen:
                    continue
                seen.add(link)
                unique.append(link)
                added_this_page += 1
                if limit and len(unique) >= limit:
                    break

            print_status(
                f"Page {page}: {len(links)} URL(s) returned, +{added_this_page} new, total {len(unique)}",
                "info",
            )

            if limit and len(unique) >= limit:
                break

            if added_this_page == 0:
                break

            start += 100
            page += 1

            if page > max_pages:
                print_status(f"Reached max pages limit ({max_pages})", "info")
                break

    except Exception as e:
        logger.error(f"Dork search failed: {e}")
        print_status(f"Dork search failed: {e}", "error")
        # Return whatever we gathered so far before the exception
        return unique

    if stop_scan.is_set():
        print_status("Dork discovery cancelled by user.", "warning")

    print_status(f"Discovered {len(unique)} URL(s)", "success")

    # Save to ResultManager for caching / consistency
    if unique:
        result_manager.add_finding("dork_discovery", "", {
            "query": query,
            "engine": engine,
            "timestamp": now_iso_timestamp(),
            "discovered_urls_count": len(unique),
        })

    return unique


def now_iso_timestamp() -> str:
    """Get current time in ISO format."""
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


def _load_domain_blacklist() -> Set[str]:
    path = os.path.join(config.CONFIG_DIR, "domain_blacklist.txt")
    if not os.path.exists(path):
        return set()

    blocked: Set[str] = set()
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip().lower()
                if not line:
                    continue
                if line.startswith("#"):
                    continue
                if line.startswith("www."):
                    line = line[4:]
                blocked.add(line)
    except Exception as e:
        logger.error(f"Failed to load domain blacklist: {e}")
        return set()

    return blocked


def _is_blacklisted(hostname: str, blocked: Set[str]) -> bool:
    if not hostname:
        return False

    host = hostname.strip().lower()
    if host.startswith("www."):
        host = host[4:]
    host = host.split(":")[0]

    if host in blocked:
        return True

    for b in blocked:
        if host.endswith(f".{b}"):
            return True

    return False


def save_discovered_urls(urls: List[str], output_file: str) -> str:
    if not output_file:
        raise ValueError("output_file is required")

    output_dir = os.path.dirname(output_file)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    clean: List[str] = []
    seen: Set[str] = set()
    blocked = _load_domain_blacklist()

    for u in urls:
        if not isinstance(u, str):
            continue
        u = u.strip()
        if not u:
            continue
        if "?" not in u or "=" not in u:
            continue
        parsed = urlparse(u)
        if not parsed.scheme or not parsed.netloc:
            continue

        if blocked and _is_blacklisted(parsed.netloc, blocked):
            continue
        if u in seen:
            continue
        seen.add(u)
        clean.append(u)

    with open(output_file, "w", encoding="utf-8") as f:
        for u in clean:
            f.write(f"{u}\n")

    return output_file
