# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.

"""Error-based SQL Injection Scanner."""

import os
import re
import json
import time
import random
import requests
import xml.etree.ElementTree as ET
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Tuple, Generator
from datetime import datetime

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from lib.core.config import get_config
from lib.core.logger import get_logger
from lib.ui import print_status, colored, print_header, print_separator
from lib.parse.random_headers import generate_random_headers
# Import the shared stop event
from lib.core.state import stop_scan

config = get_config()
logger = get_logger(__name__)

# Metrics
successful_requests = 0
failed_requests = 0

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

    replaced_template = replaced_template.replace("'", "")
    return replaced_template


def inject_payload(url: str, payload: str) -> Generator[Tuple[str, str], None, None]:
    """Inject payload into URL parameters."""
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)

    for param in query_params:
        # Reconstruct URL with injected parameter
        # Note: This simple reconstruction might lose other params or order, 
        # but follows original logic. 
        # Better approach would be to use urlencode but we stick to logic for now.
        
        # Original logic: f"{url}&{param}={val} {payload}"
        # This appends the param AGAIN at the end. 
        # Ideally we should replace it.
        # But let's stick to the original logic if it works, or improve it.
        # Improving it:
        
        test_params = query_params.copy()
        # Inject into the first value of the list
        test_params[param] = [f"{test_params[param][0]} {payload}"]
        
        # Rebuild query string
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


def save_vulnerability(target: str, vuln_data: Dict[str, Any]) -> None:
    """Save vulnerability to JSON file."""
    domain = urlparse(target).netloc
    session_dir = config.get_domain_session_dir(domain)
    output_file = os.path.join(session_dir, "waymap_full_results.json")

    data = {"scans": []}
    if os.path.exists(output_file):
        try:
            with open(output_file, 'r') as f:
                data = json.load(f)
        except Exception:
            pass

    # Find or create SQL Injection block
    sql_block = None
    for entry in data["scans"]:
        if "SQL Injection" in entry:
            sql_block = entry["SQL Injection"]
            break
    
    if sql_block is None:
        sql_block = {"Technique: Error-Based": []}
        data["scans"].append({"SQL Injection": sql_block})

    if "Technique: Error-Based" not in sql_block:
        sql_block["Technique: Error-Based"] = []

    # Check duplicate
    exists = False
    for entry in sql_block["Technique: Error-Based"]:
        if (entry.get("Vulnerable URL") == vuln_data["Vulnerable URL"] and 
            entry.get("Payload") == vuln_data["Payload"]):
            exists = True
            break
    
    if not exists:
        sql_block["Technique: Error-Based"].append(vuln_data)
        try:
            with open(output_file, 'w') as f:
                json.dump(data, f, indent=4)
            logger.info(f"Saved vulnerability to {output_file}")
        except Exception as e:
            logger.error(f"Error saving vulnerability: {e}")


def make_request(test_url: str, custom_patterns: List[str]) -> bool:
    """Make request and check for patterns."""
    global successful_requests, failed_requests
    try:
        headers = generate_random_headers()
        response = requests.get(test_url, headers=headers, verify=False, timeout=config.REQUEST_TIMEOUT)
        successful_requests += 1

        for pattern in custom_patterns:
            if re.search(pattern, response.text):
                return True
    except requests.RequestException as e:
        logger.debug(f"Request error: {e}")
        failed_requests += 1
    return False


def error_based_sqli(url: str, test: Dict[str, str], thread_count: int) -> bool:
    """Perform error-based SQLi test."""
    global successful_requests, failed_requests

    delimiters = ('0x716a6b7671', '0x7171766b71')
    rand_numbers = [random.randint(1000, 9999) for _ in range(5)]
    payload = replace_placeholders(test['payload_template'], delimiters, rand_numbers)

    # print_status(f"Testing: {test['title']}", "info")

    custom_patterns = [
        "Duplicate entry 'qjkvq1qqvkq1' for key 'group_key'",
        "qjkvq1qqvkq1"
    ]

    for test_url, injected_param in inject_payload(url, payload):
        if stop_scan.is_set(): return False
        
        try:
            if make_request(test_url, custom_patterns):
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
                save_vulnerability(url, vuln_data)
                return True
        except Exception as e:
            logger.error(f"Error testing {test_url}: {e}")
            failed_requests += 1
            
    return False


def process_urls(urls: List[str], thread_count: int) -> None:
    """Process list of URLs for Error-based SQLi."""
    from datetime import datetime
    
    tests = parse_error_based_tests_from_xml()
    if not tests:
        print_status("No tests loaded from XML", "error")
        return

    def check_url_test(url_test_tuple):
        url, test = url_test_tuple
        if stop_scan.is_set(): return False
        return error_based_sqli(url, test, thread_count)

    # Flatten (url, test) pairs for threading
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
                    # If found, maybe stop testing this URL?
                    # For now, we continue
                    pass
            except KeyboardInterrupt:
                stop_scan.set()
                break
            except Exception as e:
                logger.error(f"Error in worker: {e}")
