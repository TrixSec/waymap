#!/usr/bin/env python3

import json
import os
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

import requests

from lib.core.logger import get_logger
from lib.ui import print_status, print_header

logger = get_logger(__name__)


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
        raise ValueError("SearchAPI api_key is required")

    params = {
        "engine": engine,
        "q": query,
        "api_key": api_key,
    }

    print_status(f"Query: {query}", "info")
    print_status("Fetching results from SearchAPI...", "info")

    response = requests.get(SEARCHAPI_URL, params=params, timeout=timeout)
    response.raise_for_status()

    try:
        data = response.json()
    except json.JSONDecodeError as e:
        logger.error(f"SearchAPI returned non-JSON response: {e}")
        raise

    links = _extract_result_links(data)

    seen: Set[str] = set()
    unique: List[str] = []
    for link in links:
        if link in seen:
            continue
        seen.add(link)
        unique.append(link)
        if limit and len(unique) >= limit:
            break

    print_status(f"Discovered {len(unique)} URL(s)", "success")
    return unique


def save_discovered_urls(urls: List[str], output_file: str) -> str:
    if not output_file:
        raise ValueError("output_file is required")

    output_dir = os.path.dirname(output_file)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    clean: List[str] = []
    seen: Set[str] = set()

    for u in urls:
        if not isinstance(u, str):
            continue
        u = u.strip()
        if not u:
            continue
        parsed = urlparse(u)
        if not parsed.scheme or not parsed.netloc:
            continue
        if u in seen:
            continue
        seen.add(u)
        clean.append(u)

    with open(output_file, "w", encoding="utf-8") as f:
        for u in clean:
            f.write(f"{u}\n")

    return output_file
