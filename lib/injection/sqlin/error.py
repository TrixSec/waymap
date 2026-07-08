# Copyright (c) 2026 waymap developers
# See the file 'LICENSE' for copying permission.

"""Error-based SQL Injection Scanner."""

import os
import re
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
from datetime import datetime

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from lib.core.config import get_config
from lib.core.logger import get_logger
from lib.ui import print_status, colored, print_header, print_separator
from lib.parse.random_headers import generate_random_headers
# Import the shared stop event - DEPRECATED
from lib.core.state import stop_scan
from lib.core.result_manager import ResultManager
from lib.injection.sqlin.common import detect_server_info, inject_payload, parameter_names

config = get_config()
logger = get_logger(__name__)

# Metrics
successful_requests = 0
failed_requests = 0

# Track (url, param) pairs that already have findings
# DEPRECATED: Use ScanContext.vulnerable_pairs instead
_found_pairs = set()

SQL_ERROR_PATTERNS = tuple(re.compile(pattern) for pattern in (
    r"Duplicate entry '.*?' for key",
    r"MySQL server version for the right syntax to use",
    r"You have an error in your SQL syntax",
    r"Unknown column",
    r"Table '\w+' doesn't exist",
    r"Can't find record",
    r"EXTRACTVALUE",
    r"UPDATEXML",
    r"XPATH syntax error",
    r"BIGINT UNSIGNED value is out of range",
    r"ERROR:  syntax error at or near",
    r"pg_query",
    r"column \".*?\" does not exist",
    r"relation \"\w+\" does not exist",
    r"Unclosed quotation mark after the character string",
    r"Incorrect syntax near",
    r"Invalid column name",
    r"Invalid object name",
    r"Microsoft SQL Server",
    r"ODBC SQL Server Driver",
    r"ORA-\d+",
    r"Oracle error",
    r"SQLite error",
    r"unrecognized token",
    r"SQL syntax",
    r"SQL error",
    r"query failed",
    r"syntax error",
))

@lru_cache(maxsize=None)
def parse_error_based_tests_from_xml(file_path: str = None) -> List[Dict[str, str]]:
    """Parse error-based SQLi test cases from XML."""
    if file_path is None:
        file_path = os.path.join(config.DATA_DIR, "error_based.xml")
        
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


def make_request(test_url: str) -> bool:
    """Make request and check for patterns."""
    global successful_requests, failed_requests
    try:
        headers = generate_random_headers()
        response = http.get(test_url, headers=headers, verify=False, timeout=config.REQUEST_TIMEOUT)
        successful_requests += 1

        for pattern in SQL_ERROR_PATTERNS:
            if pattern.search(response.text):
                return True
    except requests.RequestException as e:
        logger.debug(f"Request error: {e}")
        failed_requests += 1
    return False


def error_based_sqli(url: str, test: Dict[str, str], thread_count: int, context: Optional['ScanContext'] = None, found_pairs: Optional[set] = None) -> bool:
    """Perform error-based SQLi test."""
    global successful_requests, failed_requests
    
    # Use context if provided, otherwise fall back to global
    if context is not None:
        stop_event = context.stop_event
        if found_pairs is None:
            found_pairs = context.vulnerable_pairs
    else:
        stop_event = stop_scan
        if found_pairs is None:
            found_pairs = _found_pairs

    delimiters = ('0x716a6b7671', '0x7171766b71')
    rand_numbers = [random.randint(1000, 9999) for _ in range(5)]
    payload = replace_placeholders(test['payload_template'], delimiters, rand_numbers)

    for test_url, injected_param in inject_payload(url, payload):
        if stop_event.is_set(): return False
        
        pair_key = (url, injected_param)
        if pair_key in found_pairs:
            return False

        try:
            if make_request(test_url):
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
                
                result_manager.add_finding("SQL Injection", "Technique: Error-Based", vuln_data)
                
                # Add to vulnerable pairs for DB fetching
                if context is not None:
                    context.mark_vulnerable(url, injected_param)
                else:
                    from lib.injection.sqlin.sql import vulnerable_pairs
                    vulnerable_pairs.add(pair_key)
                
                return True
        except Exception as e:
            logger.error(f"Error testing {test_url}: {e}")
            failed_requests += 1

    return False


def process_urls(urls: List[str], thread_count: int, context: Optional['ScanContext'] = None) -> None:
    """Process URLs for error-based SQLi."""
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
    
    tests = parse_error_based_tests_from_xml()
    if not tests:
        print_status("No tests loaded from XML", "error")
        return

    print_header("ERROR-BASED SQLI", color="cyan")
    
    # First, show all URLs being tested
    for url in urls:
        params = parameter_names(url)
        if params:
            print_status(f"Testing Error-based SQLi: {url} (Params: {', '.join(params)})", "info")

    def check_url_test(url_test_tuple):
        url, test = url_test_tuple
        if stop_event.is_set(): return False
        return error_based_sqli(url, test, thread_count, context=context, found_pairs=found_pairs)

    # Flatten (url, test) pairs for threading
    tasks = []
    for url in urls:
        for test in tests:
            tasks.append((url, test))

    total_tasks = len(tasks)
    completed_tasks = 0

    with ThreadPoolExecutor(max_workers=thread_count) as executor:
        futures = {executor.submit(check_url_test, task): task for task in tasks}
        
        for future in as_completed(futures):
            if stop_event.is_set():
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
