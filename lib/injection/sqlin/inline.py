# Copyright (c) 2026 waymap developers
# See the file 'LICENSE' for copying permission.

"""Inline Query-based SQL Injection Scanner."""

import os
import re
import json
import time
import random
import threading
import requests
from lib.core import http
from functools import lru_cache
from defusedxml import ElementTree as ET
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Tuple, Generator, Optional

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from lib.core.config import get_config
from lib.core.logger import get_logger
from lib.ui import print_status, colored, print_header, print_separator
from lib.parse.random_headers import generate_random_headers
from lib.core.state import stop_scan
from lib.core.result_manager import ResultManager
from lib.injection.sqlin.common import detect_server_info, inject_payload, parameter_names

config = get_config()
logger = get_logger(__name__)

# Track (url, param) pairs that already have findings
# DEPRECATED: Use ScanContext.vulnerable_pairs instead
_found_pairs = set()
_found_lock = threading.Lock()

@lru_cache(maxsize=None)
def parse_inline_tests_from_xml(file_path: str = None) -> List[Dict[str, str]]:
    """Parse inline query-based SQLi test cases from XML."""
    if file_path is None:
        file_path = os.path.join(config.DATA_DIR, "inline_query.xml")
        
    tests = []
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()

        for test in root.findall('test'):
            title = test.find('title').text
            payload_node = test.find('./request/payload')
            payload_template = (payload_node.text or "").strip() if payload_node is not None else ""
            if not payload_template:
                continue
            
            details = test.find('./details')
            dbms = details.find('dbms').text if details is not None and details.find('dbms') is not None else 'Unknown'
            dbms_version = details.find('dbms_version').text if details is not None and details.find('dbms_version') is not None else ''

            tests.append({
                'title': title,
                'payload_template': payload_template,
                'dbms': dbms,
                'dbms_version': dbms_version
            })
    except Exception as e:
        logger.error(f"Error parsing XML {file_path}: {e}")
        
    return tests


def replace_placeholders(template: str, delimiters: Tuple[str, str], rand_numbers: List[int]) -> str:
    """Replace placeholders in the template."""
    replaced_template = (template
                         .replace("[DELIMITER_START]", delimiters[0])
                         .replace("[DELIMITER_STOP]", delimiters[1])
                         .replace("[RANDNUM]", str(rand_numbers[0])))

    for i, rand_num in enumerate(rand_numbers[:5], start=1):
        replaced_template = replaced_template.replace(f"[RANDNUM{i}]", str(rand_num))

    return replaced_template


def make_request(test_url: str, delimiters: Tuple[str, str]) -> Tuple[bool, Optional[str]]:
    """Make request and check for delimiters."""
    try:
        headers = generate_random_headers()
        response = http.get(test_url, headers=headers, verify=False, timeout=config.REQUEST_TIMEOUT)
        
        pattern = re.compile(f"{re.escape(delimiters[0])}(.*?){re.escape(delimiters[1])}")
        match = pattern.search(response.text)
        if match:
            return True, match.group(1).strip()
    except requests.RequestException as e:
        logger.debug(f"Request error: {e}")
    return False, None


def inline_based_sqli(url: str, test: Dict[str, str], thread_count: int, context: Optional['ScanContext'] = None, found_pairs: Optional[set] = None) -> bool:
    """Perform inline query-based SQLi test."""
    # Use context if provided, otherwise fall back to global
    if context is not None:
        stop_event = context.stop_event
        if found_pairs is None:
            found_pairs = context.vulnerable_pairs
    else:
        stop_event = stop_scan
        if found_pairs is None:
            found_pairs = _found_pairs

    delimiters = ('qjkvq', 'qwvkq')
    rand_numbers = [random.randint(1000, 9999) for _ in range(5)]
    payload = replace_placeholders(test['payload_template'], delimiters, rand_numbers)

    for test_url, injected_param in inject_payload(url, payload):
        if stop_event.is_set(): return False
        pair_key = (url, injected_param)
        with _found_lock:
            if pair_key in found_pairs:
                return False
        
        try:
            found, extracted = make_request(test_url, delimiters)
            if found:
                with _found_lock:
                    if pair_key in found_pairs:
                        return False
                    found_pairs.add(pair_key)
                server, technology = detect_server_info(url)

                print_status("Vulnerability Found!", "success")
                print_status(f"  URL: {url}", "info")
                print_status(f"  Parameter: {injected_param}", "info")
                print_status(f"  Payload: {payload}", "info")
                print_status(f"  DBMS: {test['dbms']}", "info")

                vuln_data = {
                    "Vulnerable URL": url,
                    "Injected Parameter": injected_param,
                    "Payload": payload,
                    "Payload Title": test['title'],
                    "DBMS Detected": test['dbms'],
                    "Web Technology": technology,
                    "Server Name": server,
                    "Severity": 10,
                    "Timestamp": datetime.now().isoformat()
                }
                domain = urlparse(url).netloc
                
                # Use context result manager if available
                if context is not None and context.result_store is not None:
                    result_manager = context.result_store
                else:
                    result_manager = ResultManager(domain)
                
                result_manager.add_finding("SQL Injection", "Technique: Inline-Query", vuln_data)
                
                # Add to vulnerable pairs for DB fetching
                if context is not None:
                    context.mark_vulnerable(url, injected_param)
                else:
                    from lib.injection.sqlin.sql import vulnerable_pairs
                    vulnerable_pairs.add((url, injected_param))
                
                return True
        except Exception as e:
            logger.error(f"Error testing {test_url}: {e}")
            
    return False


def process_urls(urls: List[str], thread_count: int, context: Optional['ScanContext'] = None) -> None:
    """Process URLs for inline query-based SQLi."""
    # Use context if provided, otherwise fall back to global
    if context is not None:
        context.vulnerable_pairs.clear()
        stop_event = context.stop_event
    else:
        _found_pairs.clear()
        stop_event = stop_scan
    
    tests = parse_inline_tests_from_xml()
    if not tests:
        print_status("No tests loaded from XML", "error")
        return

    print_header("INLINE QUERY SQLI", color="cyan")
    
    for url in urls:
        params = parameter_names(url)
        if params:
            print_status(f"Testing Inline Query SQLi: {url} (Params: {', '.join(params)})", "info")

    def check_url_test(url_test_tuple):
        url, test = url_test_tuple
        if stop_event.is_set(): return False
        return inline_based_sqli(url, test, thread_count, context)

    tasks = []
    for url in urls:
        for test in tests:
            tasks.append((url, test))

    with ThreadPoolExecutor(max_workers=thread_count) as executor:
        futures = {executor.submit(check_url_test, task): task for task in tasks}
        
        for future in as_completed(futures):
            if stop_event.is_set():
                break
            try:
                if future.result():
                    pass
            except KeyboardInterrupt:
                from lib.core.interrupt import exit_clean
                exit_clean()
            except Exception as e:
                logger.error(f"Error in worker: {e}")
