#!/usr/bin/env python3

import json
import os
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

import requests

from lib.core.config import get_config
from lib.core.logger import get_logger
from lib.core.secrets import get_secret
from lib.ui import print_status, print_header

logger = get_logger(__name__)
config = get_config()


SEARCHAPI_URL = "https://www.searchapi.io/api/v1/search"


def _extract_result_links(payload: Dict[str, Any]) -> List[str]:
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
    api_key: str,
    limit: Optional[int] = None,
    engine: str = "google",
    timeout: int = 20,
) -> List[str]:
    print_header("Google Dork Discovery", color="cyan")

    if not query or not isinstance(query, str):
        raise ValueError("Dork query is required")

    if not api_key or not isinstance(api_key, str):
        api_key = get_secret("searchapi_api_key", env_var="SEARCHAPI_API_KEY")
    if not api_key or not isinstance(api_key, str):
        raise ValueError("SearchAPI api_key is required")

    params = {
        "engine": engine,
        "q": query,
        "api_key": api_key,
    }

    print_status(f"Query: {query}", "info")
    print_status("Fetching results from Google...", "info")

    seen: Set[str] = set()
    unique: List[str] = []

    page = 1
    while True:
        params["page"] = page

        response = requests.get(SEARCHAPI_URL, params=params, timeout=timeout)
        response.raise_for_status()

        try:
            data = response.json()
        except json.JSONDecodeError as e:
            logger.error(f"SearchAPI returned non-JSON response: {e}")
            raise

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

        if limit and len(unique) >= limit:
            break

        if added_this_page == 0:
            break

        page += 1

    print_status(f"Discovered {len(unique)} URL(s)", "success")
    return unique


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
