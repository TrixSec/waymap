import os
import re
from typing import List, Optional, Union

import requests
from lib.core import http

from lib.core.config import get_config
from lib.core.logger import get_logger
from lib.parse.random_headers import generate_random_headers
from lib.ui import print_header, print_status, prompt_line
from lib.ProfileWordpress.wpscan_scan import wpscan_wordpress_vulnerabilities

logger = get_logger(__name__)
config = get_config()


def _looks_like_wordpress(target_url: str) -> bool:
    headers = generate_random_headers()

    try:
        resp = http.get(target_url, headers=headers, verify=False, timeout=config.REQUEST_TIMEOUT)
        html = resp.text if resp is not None else ""
        hdrs = resp.headers if resp is not None else {}
    except Exception as e:
        logger.error(f"Failed to fetch target for WordPress detection: {e}")
        return False

    if "wp-content" in html or "wp-includes" in html:
        return True

    gen = str(hdrs.get("X-Generator", ""))
    if "wordpress" in gen.lower():
        return True

    if re.search(r"<meta[^>]+name=['\"]generator['\"][^>]+content=['\"][^'\"]*wordpress", html, flags=re.IGNORECASE):
        return True

    return False


def wordpress_vuln_scan(profile_url: Union[str, List[str]]) -> None:
    print_header("WordPress Vulnerability Profile", color="cyan")

    if isinstance(profile_url, str):
        profile_url = [profile_url]

    print_status(f"Scanning {len(profile_url)} target(s)", "info")

    for url in profile_url:
        try:
            if not _looks_like_wordpress(url):
                no_prompt = os.environ.get("WAYMAP_NO_PROMPT") == "1"
                if no_prompt:
                    print_status(f"WordPress not detected for {url}; skipping", "warning")
                    continue

                choice = prompt_line(f"[?] WordPress not detected for {url}. Continue anyway? [y/N]", "n").lower()
                if choice != "y":
                    print_status("Skipping target", "warning")
                    continue

            wpscan_wordpress_vulnerabilities(url)
        except Exception as e:
            logger.error(f"WordPress vulnerability scan failed for {url}: {e}")
            print_status(f"WordPress vulnerability scan failed: {e}", "error")
