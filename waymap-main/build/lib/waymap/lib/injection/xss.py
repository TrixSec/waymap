# Copyright (c) 2026 waymap developers
# See the file 'LICENSE' for copying permission.

"""XSS Injection Scanner Module."""

import os
import requests
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from lib.core.config import get_config
from lib.core.logger import get_logger
from lib.core.result_manager import ResultManager
from lib.core.state import stop_scan
from lib.ui import print_status, print_header, ask_continue_scanning, prompt_line
from lib.utils import load_payloads
from lib.parse.random_headers import generate_random_headers

config = get_config()
logger = get_logger(__name__)


def load_xss_payloads_from_file(file_path: str) -> List[Dict[str, str]]:
    """Load XSS payloads from a file."""
    payloads = []
    try:
        lines = load_payloads(file_path)
        for line in lines:
            try:
                if '::' in line:
                    name, payload = line.split('::', 1)
                    payloads.append({
                        'name': name.strip(),
                        'payload': payload.strip()
                    })
            except ValueError:
                logger.warning(f"Malformed payload: {line}")
    except Exception as e:
        logger.error(f"Error loading payloads: {e}")
    return payloads


def load_advanced_xss_payloads(file_path: str, level: int) -> List[Dict[str, str]]:
    """Load advanced payloads based on level."""
    all_payloads = load_xss_payloads_from_file(file_path)
    limits = {1: 10, 2: 23, 3: 38, 4: 49, 5: 62, 6: 76, 7: None}
    limit = limits.get(level, None)
    return all_payloads[:limit] if limit else all_payloads


def _build_test_url(base_url: str, param_dict: Dict[str, str], param_key: str, payload: str) -> str:
    test_params = param_dict.copy()
    test_params[param_key] = payload
    query = urlencode(test_params, doseq=False)
    return f"{base_url}?{query}"


def test_xss_payload(url: str, parameter: str, payload: str) -> Dict[str, Any]:
    """Test a single XSS payload."""
    if stop_scan.is_set():
        return {'vulnerable': False}

    headers = generate_random_headers()
    try:
        response = requests.get(
            url,
            params={parameter: payload},
            headers=headers,
            timeout=config.REQUEST_TIMEOUT,
            verify=False
        )

        if payload in response.text:
            return {
                'vulnerable': True,
                'response': response,
                'headers': response.headers
            }
    except requests.RequestException as e:
        if not stop_scan.is_set():
            logger.debug(f"Error testing payload on {url}: {e}")

    return {'vulnerable': False}


def choose_scan_level(no_prompt: bool) -> int:
    """Choose scan level interactively or default."""
    if no_prompt:
        return 3
    while True:
        level = prompt_line("[?] Choose scan level (1-7)")
        if level.isdigit() and 1 <= int(level) <= 7:
            return int(level)
        print_status("Invalid level. Please choose 1-7.", "error")


def _scan_urls_with_payloads(
    urls: List[str],
    payloads: List[Dict[str, str]],
    thread_count: int,
    result_manager: ResultManager,
    no_prompt: bool,
    verbose: bool
) -> None:
    """Helper function to execute scanning logic."""
    detected_tech = None

    with ThreadPoolExecutor(max_workers=thread_count) as executor:
        future_to_url = {}

        for url in urls:
            if stop_scan.is_set():
                break

            print_status(f"Testing URL: {url}", "info")

            parsed = urlparse(url)
            if not parsed.query:
                continue

            base_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, "", parsed.fragment))
            param_dict = {k: v[0] if v else "" for k, v in parse_qs(parsed.query, keep_blank_values=True).items()}

            for payload_entry in payloads:
                if stop_scan.is_set():
                    break

                name = payload_entry['name']
                payload = payload_entry['payload']

                for param_key in param_dict.keys():
                    if stop_scan.is_set():
                        break

                    full_url = _build_test_url(base_url, param_dict, param_key, payload)

                    if result_manager.has_duplicate(
                        "XSS",
                        ["url", "parameter", "payload"],
                        {"url": full_url, "parameter": param_key, "payload": payload},
                        finding_key="Findings",
                    ):
                        if verbose:
                            print_status(f"Skipping already tested: {full_url}", "debug")
                        continue

                    if verbose:
                        print_status(f"Testing {name} on {param_key}", "debug")

                    future = executor.submit(test_xss_payload, base_url, param_key, payload)
                    future_to_url[future] = (full_url, param_key, payload)

        for future in as_completed(future_to_url):
            if stop_scan.is_set():
                break

            try:
                result = future.result()
                full_url, param_key, payload = future_to_url[future]

                if result['vulnerable']:
                    if detected_tech is None:
                        headers = result.get('headers', {})
                        detected_tech = headers.get('X-Powered-By', headers.get('Server', 'Unknown'))
                        print_status(f"Web Technology: {detected_tech}", "info")

                    print_status("Vulnerability Found!", "success")
                    print_status(f"  URL: {full_url}", "info")
                    print_status(f"  Parameter: {param_key}", "info")
                    print_status(f"  Payload: {payload}", "info")

                    logger.log_vulnerability_found("XSS", full_url, f"Param: {param_key}")

                    result_manager.add_finding("XSS", "Findings", {
                        'url': full_url,
                        'parameter': param_key,
                        'payload': payload,
                        'injected': True,
                        'timestamp': datetime.now().isoformat()
                    })

                    if not no_prompt:
                        if not ask_continue_scanning():
                            print_status("Stopping scan...", "warning")
                            stop_scan.set()
                            return

            except Exception as e:
                logger.error(f"Error processing result: {e}")


def perform_xss_scan(
    crawled_urls: List[str],
    thread_count: int = 1,
    no_prompt: bool = False,
    verbose: bool = False
) -> None:
    """Perform XSS scan on a list of URLs."""
    if not crawled_urls:
        print_status("No URLs to scan", "warning")
        return

    stop_scan.clear()
    thread_count = max(1, min(thread_count, config.MAX_THREADS))

    try:
        domain = urlparse(crawled_urls[0]).netloc
    except Exception:
        domain = "unknown_domain"

    result_manager = ResultManager(domain)

    print_header("Basic XSS Scan", color="cyan")
    payload_path = os.path.join(config.DATA_DIR, 'basicxsspayload.txt')
    basic_payloads = load_xss_payloads_from_file(payload_path)

    _scan_urls_with_payloads(crawled_urls, basic_payloads, thread_count, result_manager, no_prompt, verbose)

    if stop_scan.is_set():
        return

    if no_prompt:
        do_advanced = config.DEFAULT_INPUT.lower() == 'y'
    else:
        choice = prompt_line("\nTest XSS Filters Bypass Payload? [y/N] (recommended)", "n").lower()
        do_advanced = choice == 'y'

    if do_advanced:
        print_header("Advanced XSS Scan", color="cyan")
        advanced_file = os.path.join(config.DATA_DIR, 'filtersbypassxss.txt')
        level = choose_scan_level(no_prompt)
        advanced_payloads = load_advanced_xss_payloads(advanced_file, level)

        _scan_urls_with_payloads(crawled_urls, advanced_payloads, thread_count, result_manager, no_prompt, verbose)
