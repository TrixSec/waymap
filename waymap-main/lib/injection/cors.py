# Copyright (c) 2026 waymap developers
# See the file 'LICENSE' for copying permission.

"""CORS Scanner Module."""

import os
import requests
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
from lib.parse.random_headers import generate_random_headers
from lib.core.state import stop_scan

config = get_config()
logger = get_logger(__name__)

def load_cors_payloads(file_path: str) -> List[Dict[str, str]]:
    """Load CORS payloads from file."""
    payloads = []
    try:
        with open(file_path, 'r') as file:
            for line in file:
                if line.strip():
                    try:
                        name, payload, response = line.strip().split('::')
                        payloads.append({
                            'name': name,
                            'payload': payload,
                            'response': response
                        })
                    except ValueError:
                        logger.warning(f"Malformed payload: {line.strip()}")
    except FileNotFoundError:
        logger.error(f"Payload file not found: {file_path}")
    return payloads

def test_cors_vulnerability(url: str, payload: str, expected_response: str) -> Dict[str, Any]:
    """Test CORS vulnerability."""
    if stop_scan.is_set():
        return {'vulnerable': False}

    headers = generate_random_headers()
    headers['Origin'] = payload
    
    try:
        response = requests.options(
            url, 
            headers=headers, 
            timeout=config.REQUEST_TIMEOUT, 
            verify=False
        )
        cors_header = response.headers.get('Access-Control-Allow-Origin', '')
        if expected_response in cors_header:
            return {
                'vulnerable': True, 
                'response': response, 
                'payload': payload, 
                'url': url
            }
    except requests.RequestException as e:
        logger.debug(f"Error testing {url}: {e}")

    return {'vulnerable': False}

def perform_cors_scan(crawled_urls: List[str], thread_count: int = 1, no_prompt: bool = False, verbose: bool = False) -> None:
    """Perform CORS scan."""
    stop_scan.clear()
    
    print_header("CORS Misconfiguration Scan", color="cyan")
    
    thread_count = max(1, min(thread_count, config.MAX_THREADS))
    payloads = load_cors_payloads(os.path.join(config.DATA_DIR, 'corspayload.txt'))
    
    print_status(f"Scanning {len(crawled_urls)} URLs with {len(payloads)} payloads", "info")

    try:
        for url in crawled_urls:
            if stop_scan.is_set(): break
            
            print_status(f"Testing URL: {url}", "info")
            domain = urlparse(url).netloc
            result_manager = ResultManager(domain)
            found_vulnerability = False
            
            with ThreadPoolExecutor(max_workers=thread_count) as executor:
                futures = {}
                for payload_entry in payloads:
                    if stop_scan.is_set(): break

                    name = payload_entry['name']
                    payload = payload_entry['payload']
                    expected_response = payload_entry['response']

                    if verbose:
                        print_status(f"Testing {name} with payload: {payload}", "debug")

                    future = executor.submit(
                        test_cors_vulnerability, 
                        url, 
                        payload, 
                        expected_response
                    )
                    futures[future] = (url, payload)

                for future in as_completed(futures):
                    if stop_scan.is_set(): break

                    try:
                        result = future.result()
                        url, payload = futures[future]

                        if result['vulnerable']:
                            found_vulnerability = True
                            print_status("Vulnerability Found!", "success")
                            print_status(f"  URL: {result['url']}", "info")
                            print_status(f"  Origin: {payload}", "info")

                            result_manager.add_finding("CORS", "", {
                                "url": result['url'],
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

            if not found_vulnerability and verbose:
                print_status(f"No vulnerabilities found on {url}", "debug")
                
        print_status("CORS Scan completed", "info")

    except KeyboardInterrupt:
        from lib.core.interrupt import exit_clean
        exit_clean()