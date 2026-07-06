# Copyright (c) 2026 waymap developers
# See the file 'LICENSE' for copying permission.

"""SSTI Scanner Module."""

import os
import requests
from lib.core import http
from functools import lru_cache
from datetime import datetime
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from lib.core.config import get_config
from lib.core.logger import get_logger
from lib.core.result_manager import ResultManager
from lib.ui import print_status, colored, print_header, ask_continue_scanning
from lib.injection.common import load_named_payloads
from lib.parse.random_headers import generate_random_headers
from lib.core.state import stop_scan

config = get_config()
logger = get_logger(__name__)

@lru_cache(maxsize=None)
def load_ssti_payloads(file_path: str) -> List[Dict[str, str]]:
    """Load SSTI payloads from a file."""
    return load_named_payloads(file_path, ("name", "payload", "response"))

def test_ssti_payload(url: str, parameter: str, payload: str, expected_response: str) -> Dict[str, Any]:
    """Test a given SSTI payload."""
    if stop_scan.is_set():
        return None

    headers = generate_random_headers()
    try:
        response = http.get(
            url, 
            params={parameter: payload}, 
            headers=headers, 
            timeout=config.REQUEST_TIMEOUT, 
            verify=False
        )
        if expected_response in response.text:
            return {
                'vulnerable': True, 
                'url': url, 
                'parameter': parameter, 
                'payload': payload, 
                'expected_response': expected_response
            }
    except requests.RequestException as e:
        logger.debug(f"Error testing {url}: {e}")

    return None

def perform_ssti_scan(crawled_urls: List[str], thread_count: int = 1, no_prompt: bool = False, verbose: bool = False) -> None:
    """Perform SSTI scanning."""
    stop_scan.clear()
    
    print_header("Server-Side Template Injection Scan", color="cyan")
    
    thread_count = max(1, min(thread_count, config.MAX_THREADS))
    payloads = load_ssti_payloads(os.path.join(config.DATA_DIR, 'sstipayload.txt'))
    
    print_status(f"Scanning {len(crawled_urls)} URLs with {len(payloads)} payloads", "info")

    try:
        for url in crawled_urls:
            if stop_scan.is_set(): break
            
            print_status(f"Testing URL: {url}", "info")
            domain = urlparse(url).netloc
            result_manager = ResultManager(domain)
            
            if '?' not in url:
                if verbose:
                    print_status(f"No parameters in {url}, skipping", "debug")
                continue
                
            base_url, params = url.split('?', 1)
            param_dict = {}
            for param in params.split('&'):
                if '=' in param:
                    key, value = param.split('=', 1)
                    param_dict[key] = value

            with ThreadPoolExecutor(max_workers=thread_count) as executor:
                futures = {}
                for payload_entry in payloads:
                    if stop_scan.is_set(): break
                    
                    name = payload_entry['name']
                    payload = payload_entry['payload']
                    expected_response = payload_entry['response']
                    
                    for param_key in param_dict.keys():
                        if stop_scan.is_set(): break
                        
                        if verbose:
                            print_status(f"Testing {name} on {param_key}", "debug")
                            
                        future = executor.submit(test_ssti_payload, base_url, param_key, payload, expected_response)
                        futures[future] = (base_url, param_key)

                for future in as_completed(futures):
                    if stop_scan.is_set(): break
                    
                    try:
                        result = future.result()
                        if result:
                            print_status("Vulnerability Found!", "success")
                            print_status(f"  URL: {result['url']}", "info")
                            print_status(f"  Parameter: {result['parameter']}", "info")
                            print_status(f"  Payload: {result['payload']}", "info")
                            
                            result_manager.add_finding("SSTI", "", {
                                "url": result['url'],
                                "parameter": result['parameter'],
                                "payload": result['payload'],
                                "expected_response": result['expected_response'],
                                "timestamp": datetime.now().isoformat(),
                            })
                            
                            if not no_prompt:
                                if not ask_continue_scanning():
                                    print_status("Stopping scan...", "warning")
                                    stop_scan.set()
                                    return
                    except Exception as e:
                        logger.error(f"Error in worker: {e}")
                        
        print_status("SSTI Scan completed", "info")

    except KeyboardInterrupt:
        from lib.core.interrupt import exit_clean
        exit_clean()
