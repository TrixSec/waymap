# Copyright (c) 2026 waymap developers
# See the file 'LICENSE' for copying permission.

"""CRLF Injection Scanner Module."""

import os
import requests
from lib.core import http
from functools import lru_cache
from datetime import datetime
from urllib.parse import urlparse
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
def load_crlf_payloads(file_path: str) -> List[Dict[str, str]]:
    """Load CRLF payloads from file."""
    return load_named_payloads(file_path, ("name", "payload", "response"))

def test_crlf_payload(url: str, parameter: str, payload: str, expected_response: str) -> Dict[str, Any]:
    """Test CRLF payload."""
    if stop_scan.is_set():
        return {'vulnerable': False}

    headers = generate_random_headers()
    try:
        response = http.get(
            url, 
            headers=headers, 
            timeout=config.REQUEST_TIMEOUT, 
            verify=False
        )
        header_blob = "\r\n".join(f"{k}: {v}" for k, v in response.headers.items())
        response_text = response.text or ""
        if expected_response in header_blob or expected_response in response_text:
            return {
                'vulnerable': True, 
                'response': response, 
                'url': url,
                'parameter': parameter,
                'payload': payload
            }
    except requests.RequestException as e:
        logger.debug(f"Error testing {url}: {e}")

    return {'vulnerable': False}

def perform_crlf_scan(crawled_urls: List[str], thread_count: int = 1, no_prompt: bool = False, verbose: bool = False) -> None:
    """Perform CRLF injection scan."""
    stop_scan.clear()
    
    print_header("CRLF Injection Scan", color="cyan")
    
    thread_count = max(1, min(thread_count, config.MAX_THREADS))
    payloads = load_crlf_payloads(os.path.join(config.DATA_DIR, 'crlfpayload.txt'))
    
    print_status(f"Scanning {len(crawled_urls)} URLs with {len(payloads)} payloads", "info")

    try:
        for url in crawled_urls:
            if stop_scan.is_set(): break
            
            print_status(f"Testing URL: {url}", "info")
            
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

            domain = urlparse(url).netloc
            result_manager = ResultManager(domain)

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
                            print_status(f"Testing {name} on parameter {param_key}", "debug")

                        test_params = param_dict.copy()
                        test_params[param_key] = payload
                        modified_params = '&'.join([f"{k}={v}" for k, v in test_params.items()])
                        full_url = f"{base_url}?{modified_params}"

                        future = executor.submit(
                            test_crlf_payload, 
                            full_url, 
                            param_key, 
                            payload, 
                            expected_response
                        )
                        futures[future] = (full_url, param_key, payload)

                for future in as_completed(futures):
                    if stop_scan.is_set(): break

                    try:
                        result = future.result()
                        full_url, param_key, payload = futures[future]

                        if result['vulnerable']:
                            print_status("Vulnerability Found!", "success")
                            print_status(f"  URL: {full_url}", "info")
                            print_status(f"  Parameter: {param_key}", "info")
                            print_status(f"  Payload: {payload}", "info")

                            result_manager.add_finding("CRLF Injection", "", {
                                "url": full_url,
                                "parameter": param_key,
                                "payload": payload,
                                "timestamp": datetime.now().isoformat(),
                            })

                            if not no_prompt:
                                if not ask_continue_scanning():
                                    print_status("Stopping scan...", "warning")
                                    stop_scan.set()
                                    return
                    except Exception as e:
                        logger.error(f"Error in worker: {e}")
                        
        print_status("CRLF Scan completed", "info")

    except KeyboardInterrupt:
        from lib.core.interrupt import exit_clean
        exit_clean()
