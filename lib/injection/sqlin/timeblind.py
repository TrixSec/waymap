# Copyright (c) 2026 waymap developers
# See the file 'LICENSE' for copying permission.

"""Time-based Blind SQL Injection Scanner."""

import os
import json
import time
import random
import requests
from lib.core import http
from functools import lru_cache
from defusedxml import ElementTree as ET
from urllib.parse import urlparse, parse_qs
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
from lib.injection.sqlin.common import baseline_response_time, detect_server_info, inject_payload, parameter_names

config = get_config()
logger = get_logger(__name__)

# Track (url, param) pairs that already have findings
# DEPRECATED: Use ScanContext.vulnerable_pairs instead
_found_pairs = set()

@lru_cache(maxsize=None)
def parse_time_blind_tests_from_xml(file_path: str = None) -> List[Dict[str, str]]:
    """Parse time-based SQLi test cases from XML."""
    if file_path is None:
        file_path = os.path.join(config.DATA_DIR, "time_blind.xml")
        
    tests = []
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()

        for test in root.findall('test'):
            title = test.find('title').text
            payload_node = test.find('./request/payload')
            payload_template = payload_node.text if payload_node is not None else ""
            
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

def replace_placeholders(template: str, rand_numbers: int, rand_str: str, sleep_time: int) -> str:
    """Replace placeholders in template."""
    replaced_template = template.replace("[RANDSTR]", rand_str)
    replaced_template = replaced_template.replace("[RANDNUM]", str(rand_numbers))
    replaced_template = replaced_template.replace("[SLEEPTIME]", str(sleep_time))
    return replaced_template

def make_request(test_url: str, baseline_time: float, sleep_time: int) -> bool:
    """Make request and check response time against baseline."""
    try:
        headers = generate_random_headers()
        start_time = time.time()
        request_timeout = int(config.REQUEST_TIMEOUT) + int(sleep_time)
        response = http.get(
            test_url,
            headers=headers,
            verify=False,
            timeout=request_timeout,
        )
        response_time = time.time() - start_time

        # Check if the response is at least (sleep_time - 1) seconds longer than baseline
        baseline_threshold = baseline_time + (sleep_time - 1)
        if response_time > baseline_threshold:
            # Double-check to reduce false positives
            return True
    except requests.RequestException:
        pass
    return False

def time_based_sqli(url: str, test: Dict[str, str], thread_count: int, context: Optional['ScanContext'] = None, found_pairs: Optional[set] = None, failed_baseline_urls: set = None) -> bool:
    """Perform time-based SQLi test."""
    # Use context if provided, otherwise fall back to global
    if context is not None:
        stop_event = context.stop_event
        if found_pairs is None:
            found_pairs = context.vulnerable_pairs
    else:
        stop_event = stop_scan
        if found_pairs is None:
            found_pairs = _found_pairs
    
    rand_numbers = random.randint(1000, 9999)
    rand_str = ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ', k=4))
    sleep_time = random.choice([3, 5, 7, 10]) 

    payload = replace_placeholders(test['payload_template'], rand_numbers, rand_str, sleep_time)

    # Get baseline response time
    baseline_time = baseline_response_time(url)
    if baseline_time == 0.0:
        if failed_baseline_urls is not None and url not in failed_baseline_urls:
            logger.warning(f"Could not get baseline for {url}")
            failed_baseline_urls.add(url)
        return False

    # print_status(f"Testing: {test['title']}", "info")

    for test_url, injected_param in inject_payload(url, payload):
        if stop_event.is_set(): return False
        
        # Skip if we already found a vulnerability for this (url, param) pair
        pair_key = (url, injected_param)
        if pair_key in found_pairs:
            return False

        try:
            if make_request(test_url, baseline_time, sleep_time):
                found_pairs.add(pair_key)
                server, technology = detect_server_info(url)

                print_status("Vulnerability Found!", "success")
                print_status(f"  URL: {url}", "info")
                print_status(f"  Parameter: {injected_param}", "info")
                print_status(f"  Payload: {payload}", "info")

                vuln_data = {
                    "Vulnerable URL": url,
                    "Injected Parameter": injected_param,
                    "Payload": payload,
                    "Payload Title": test['title'],
                    "DBMS Detected": test['dbms'],
                    "Web Technology": technology,
                    "Server Name": server,
                    "Severity": 10,
                    "Timestamp": time.strftime('%Y-%m-%dT%H:%M:%S')
                }
                domain = urlparse(url).netloc
                
                # Use context result manager if available
                if context is not None and context.result_store is not None:
                    result_manager = context.result_store
                else:
                    result_manager = ResultManager(domain)
                
                result_manager.add_finding("SQL Injection", "Technique: Time-Based", vuln_data)
                
                # Add to vulnerable pairs for DB fetching
                if context is not None:
                    context.mark_vulnerable(url, injected_param)
                else:
                    from lib.injection.sqlin.sql import vulnerable_pairs
                    vulnerable_pairs.add(pair_key)
                
                return True
        except Exception as e:
            logger.error(f"Error testing {test_url}: {e}")

    return False

def process_urls(urls: List[str], thread_count: int, context: Optional['ScanContext'] = None) -> None:
    """Process URLs for Time-based SQLi."""
    from lib.core.interrupt import reset_interrupt
    reset_interrupt()
    
    # Use context if provided, otherwise fall back to global
    if context is not None:
        context.vulnerable_pairs.clear()
        stop_event = context.stop_event
        found_pairs = context.vulnerable_pairs
    else:
        _found_pairs.clear()
        stop_event = stop_scan
        found_pairs = _found_pairs
    
    tests = parse_time_blind_tests_from_xml()
    if not tests:
        print_status("No tests loaded from XML", "error")
        return

    print_header("TIME-BASED SQLI", color="cyan")
    
    # Track URLs that have failed baseline check to avoid duplicate warnings
    failed_baseline_urls = set()
    
    # First, show all URLs being tested
    for url in urls:
        params = parameter_names(url)
        if params:
            print_status(f"Testing Time-based SQLi: {url} (Params: {', '.join(params)})", "info")

    def check_url_test(url_test_tuple):
        url, test = url_test_tuple
        if stop_event.is_set(): return False
        # Skip if already failed baseline
        if url in failed_baseline_urls:
            return False
        return time_based_sqli(url, test, thread_count, context=context, found_pairs=found_pairs, failed_baseline_urls=failed_baseline_urls)

    tasks = []
    for url in urls:
        for test in tests:
            tasks.append((url, test))

    total_tasks = len(tasks)
    completed_tasks = 0

    with ThreadPoolExecutor(max_workers=thread_count) as executor:
        futures = {executor.submit(check_url_test, task): task for task in tasks}
        
        for future in as_completed(futures):
            if stop_scan.is_set():
                break
            completed_tasks += 1
            if completed_tasks % 100 == 0 or completed_tasks == total_tasks:
                print_status(f"Progress: {completed_tasks}/{total_tasks}", "info")
            try:
                future.result()
            except KeyboardInterrupt:
                from lib.core.interrupt import exit_clean
                exit_clean()
            except Exception as e:
                logger.error(f"Error in worker: {e}")
