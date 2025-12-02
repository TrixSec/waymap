# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.

"""Time-based Blind SQL Injection Scanner."""

import os
import json
import time
import random
import requests
import xml.etree.ElementTree as ET
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
        sql_block = {"Technique: Time-Based": []}
        data["scans"].append({"SQL Injection": sql_block})

    if "Technique: Time-Based" not in sql_block:
        sql_block["Technique: Time-Based"] = []

    # Check duplicate
    exists = False
    for entry in sql_block["Technique: Time-Based"]:
        if (entry.get("Vulnerable URL") == vuln_data["Vulnerable URL"] and 
            entry.get("Payload") == vuln_data["Payload"]):
            exists = True
            break
    
    if not exists:
        sql_block["Technique: Time-Based"].append(vuln_data)
        try:
            with open(output_file, 'w') as f:
                json.dump(data, f, indent=4)
        except Exception as e:
            logger.error(f"Error saving vulnerability: {e}")

def make_request(test_url: str, sleep_time: int) -> bool:
    """Make request and check response time."""
    try:
        headers = generate_random_headers()
        start_time = time.time()
        requests.get(test_url, headers=headers, verify=False, timeout=config.REQUEST_TIMEOUT + sleep_time)
        response_time = time.time() - start_time

        if response_time > (sleep_time - 1):
            # Double check to be sure
            # Ideally we should do multiple checks, but sticking to logic
            return True
    except requests.RequestException:
        pass
    return False

def time_based_sqli(url: str, test: Dict[str, str], thread_count: int) -> bool:
    """Perform time-based SQLi test."""
    rand_numbers = random.randint(1000, 9999)
    rand_str = ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ', k=4))
    sleep_time = random.choice([3, 5, 7, 10]) 

    payload = replace_placeholders(test['payload_template'], rand_numbers, rand_str, sleep_time)

    # print_status(f"Testing: {test['title']}", "info")

    for test_url, injected_param in inject_payload(url, payload):
        if stop_scan.is_set(): return False
        
        try:
            if make_request(test_url, sleep_time):
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
                save_vulnerability(url, vuln_data)
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

    def check_url_test(url_test_tuple):
        url, test = url_test_tuple
        if stop_scan.is_set(): return False
        return time_based_sqli(url, test, thread_count)

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
                stop_scan.set()
                break
            except Exception as e:
                logger.error(f"Error in worker: {e}")
