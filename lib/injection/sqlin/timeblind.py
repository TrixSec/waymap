# Copyright (c) 2026 waymap developers
# See the file 'LICENSE' for copying permission.

"""Time-based Blind SQL Injection Scanner."""

import os
import json
import time
import random
import requests
from defusedxml import ElementTree as ET
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Tuple, Generator

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

def inject_payload(url: str, payload: str) -> Generator[Tuple[str, str], None, None]:
    """Inject payload into URL parameters."""
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)

    for param in query_params:
        test_params = query_params.copy()
        test_params[param] = [f"{test_params[param][0]} {payload}"]
        
        from urllib.parse import urlencode, urlunparse
        new_query = urlencode(test_params, doseq=True)
        new_parts = list(parsed_url)
        new_parts[4] = new_query
        test_url = urlunparse(new_parts)
        
        yield test_url, param

def detect_server_info(url: str) -> Tuple[str, str]:
    """Detect server info."""
    try:
        headers = generate_random_headers()
        response = requests.head(url, headers=headers, verify=False, timeout=config.REQUEST_TIMEOUT)
        server = response.headers.get('Server', 'Unknown')
        technology = response.headers.get('X-Powered-By', 'Unknown')
        return server, technology
    except Exception:
        return 'Unknown', 'Unknown'



def make_baseline_request(url: str) -> float:
    """Make a baseline request without payload to get normal response time."""
    try:
        headers = generate_random_headers()
        start_time = time.time()
        requests.get(url, headers=headers, verify=False, timeout=config.REQUEST_TIMEOUT)
        return time.time() - start_time
    except requests.RequestException:
        return 0.0


def make_request(test_url: str, baseline_time: float, sleep_time: int) -> bool:
    """Make request and check response time against baseline."""
    try:
        headers = generate_random_headers()
        start_time = time.time()
        request_timeout = int(config.REQUEST_TIMEOUT) + int(sleep_time)
        response = requests.get(
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

def time_based_sqli(url: str, test: Dict[str, str], thread_count: int, failed_baseline_urls: set = None) -> bool:
    """Perform time-based SQLi test."""
    from lib.injection.sqlin.sql import vulnerable_pairs
    
    rand_numbers = random.randint(1000, 9999)
    rand_str = ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ', k=4))
    sleep_time = random.choice([3, 5, 7, 10]) 

    payload = replace_placeholders(test['payload_template'], rand_numbers, rand_str, sleep_time)

    # Get baseline response time
    baseline_time = make_baseline_request(url)
    if baseline_time == 0.0:
        if failed_baseline_urls is not None and url not in failed_baseline_urls:
            logger.warning(f"Could not get baseline for {url}")
            failed_baseline_urls.add(url)
        return False

    # print_status(f"Testing: {test['title']}", "info")

    for test_url, injected_param in inject_payload(url, payload):
        if stop_scan.is_set(): return False
        
        try:
            if make_request(test_url, baseline_time, sleep_time):
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
                result_manager = ResultManager(domain)
                result_manager.add_finding("SQL Injection", "Technique: Time-Based", vuln_data)
                # Add to vulnerable pairs for DB fetching
                vulnerable_pairs.add((url, injected_param))
                return True
        except Exception as e:
            logger.error(f"Error testing {test_url}: {e}")
            
    return False

def process_urls(urls: List[str], thread_count: int) -> None:
    """Process URLs for Time-based SQLi."""
    tests = parse_time_blind_tests_from_xml()
    if not tests:
        print_status("No tests loaded from XML", "error")
        return

    print_header("TIME-BASED SQLI", color="cyan")
    
    # Track URLs that have failed baseline check to avoid duplicate warnings
    failed_baseline_urls = set()
    
    # First, show all URLs being tested
    for url in urls:
        parsed_url = urlparse(url)
        params = list(parse_qs(parsed_url.query).keys())
        if params:
            print_status(f"Testing Time-based SQLi: {url} (Params: {', '.join(params)})", "info")

    def check_url_test(url_test_tuple):
        url, test = url_test_tuple
        if stop_scan.is_set(): return False
        # Skip if already failed baseline
        if url in failed_baseline_urls:
            return False
        return time_based_sqli(url, test, thread_count, failed_baseline_urls)

    tasks = []
    for url in urls:
        for test in tests:
            tasks.append((url, test))

    with ThreadPoolExecutor(max_workers=thread_count) as executor:
        futures = {executor.submit(check_url_test, task): task for task in tasks}
        
        for future in as_completed(futures):
            if stop_scan.is_set():
                break
            try:
                future.result()
            except KeyboardInterrupt:
                from lib.core.interrupt import exit_clean
                exit_clean()
            except Exception as e:
                logger.error(f"Error in worker: {e}")
