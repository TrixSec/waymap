# Copyright (c) 2026 waymap developers
# See the file 'LICENSE' for copying permission.

"""Inline Query-based SQL Injection Scanner."""

import os
import re
import json
import time
import random
import requests
from defusedxml import ElementTree as ET
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
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


def replace_placeholders(template: str, delimiters: Tuple[str, str], rand_numbers: List[int]) -> str:
    """Replace placeholders in the template."""
    replaced_template = (template
                         .replace("[DELIMITER_START]", delimiters[0])
                         .replace("[DELIMITER_STOP]", delimiters[1])
                         .replace("[RANDNUM]", str(rand_numbers[0])))

    for i, rand_num in enumerate(rand_numbers[:5], start=1):
        replaced_template = replaced_template.replace(f"[RANDNUM{i}]", str(rand_num))

    return replaced_template


def inject_payload(url: str, payload: str) -> Generator[Tuple[str, str], None, None]:
    """Inject payload into URL parameters."""
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)

    for param in query_params:
        test_params = query_params.copy()
        test_params[param] = [f"{test_params[param][0]} {payload}"]
        
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


def make_request(test_url: str, delimiters: Tuple[str, str]) -> Tuple[bool, Optional[str]]:
    """Make request and check for delimiters."""
    try:
        headers = generate_random_headers()
        response = requests.get(test_url, headers=headers, verify=False, timeout=config.REQUEST_TIMEOUT)
        
        pattern = re.compile(f"{re.escape(delimiters[0])}(.*?){re.escape(delimiters[1])}")
        match = pattern.search(response.text)
        if match:
            return True, match.group(1).strip()
    except requests.RequestException as e:
        logger.debug(f"Request error: {e}")
    return False, None


def inline_based_sqli(url: str, test: Dict[str, str], thread_count: int) -> bool:
    """Perform inline query-based SQLi test."""
    from lib.injection.sqlin.sql import vulnerable_pairs

    delimiters = ('qjkvq', 'qwvkq')
    rand_numbers = [random.randint(1000, 9999) for _ in range(5)]
    payload = replace_placeholders(test['payload_template'], delimiters, rand_numbers)

    for test_url, injected_param in inject_payload(url, payload):
        if stop_scan.is_set(): return False
        
        try:
            found, extracted = make_request(test_url, delimiters)
            if found:
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
                result_manager = ResultManager(domain)
                result_manager.add_finding("SQL Injection", "Technique: Inline-Query", vuln_data)
                vulnerable_pairs.add((url, injected_param))
                return True
        except Exception as e:
            logger.error(f"Error testing {test_url}: {e}")
            
    return False


def process_urls(urls: List[str], thread_count: int) -> None:
    """Process URLs for inline query-based SQLi."""
    tests = parse_inline_tests_from_xml()
    if not tests:
        print_status("No tests loaded from XML", "error")
        return

    print_header("INLINE QUERY SQLI", color="cyan")
    
    for url in urls:
        parsed_url = urlparse(url)
        params = list(parse_qs(parsed_url.query).keys())
        if params:
            print_status(f"Testing Inline Query SQLi: {url} (Params: {', '.join(params)})", "info")

    def check_url_test(url_test_tuple):
        url, test = url_test_tuple
        if stop_scan.is_set(): return False
        return inline_based_sqli(url, test, thread_count)

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
                if future.result():
                    pass
            except KeyboardInterrupt:
                from lib.core.interrupt import exit_clean
                exit_clean()
            except Exception as e:
                logger.error(f"Error in worker: {e}")
