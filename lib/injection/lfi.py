# Copyright (c) 2026 waymap developers
# See the file 'LICENSE' for copying permission.

"""LFI Scanner Module."""

import os
import json
import requests
import threading
import multiprocessing
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Optional

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from lib.core.config import get_config
from lib.core.logger import get_logger
from lib.ui import print_status, colored, print_header, ask_continue_scanning
from lib.parse.random_headers import generate_random_headers
from lib.core.state import stop_scan
from lib.core.result_manager import ResultManager

config = get_config()
logger = get_logger(__name__)

def extract_parameters(url: str) -> List[str]:
    """Extract parameters from URL."""
    parsed_url = urlparse(url)
    params = parse_qs(parsed_url.query)
    return list(params.keys())

def load_lfi_payloads(file_path: str) -> List[Dict[str, str]]:
    """Load LFI payloads from a file."""
    payloads = []
    try:
        with open(file_path, 'r') as file:
            for line in file:
                if line.strip():
                    try:
                        name, payload, expected_response = line.strip().split('::')
                        payloads.append({
                            'name': name,
                            'payload': payload,
                            'response': expected_response
                        })
                    except ValueError:
                        logger.warning(f"Malformed payload: {line.strip()}")
    except FileNotFoundError:
        logger.error(f"Payload file not found: {file_path}")
    return payloads



def test_lfi_payload(url: str, parameter: str, payload: str, expected_response: str) -> Dict[str, Any]:
    """Test LFI vulnerability with a payload."""
    if stop_scan.is_set():
        return {'vulnerable': False}

    headers = generate_random_headers()
    try:
        response = requests.get(
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
                'payload': payload
            }
    except requests.RequestException as e:
        logger.debug(f"Error testing {url}: {e}")

    return {'vulnerable': False}

def perform_lfi_scan(crawled_urls: List[str], thread_count: int = 1, no_prompt: bool = False, verbose: bool = False) -> None:
    """Perform LFI scan on the given URLs."""
    stop_scan.clear()
    
    print_header("Local File Inclusion Scan", color="cyan")
    
    thread_count = max(1, min(thread_count, config.MAX_THREADS))
    payloads = load_lfi_payloads(os.path.join(config.DATA_DIR, 'lfipayload.txt'))
    
    print_status(f"Scanning {len(crawled_urls)} URLs with {len(payloads)} payloads", "info")

    try:
        for url in crawled_urls:
            if stop_scan.is_set(): break
            
            print_status(f"Testing URL: {url}", "info")
            domain = urlparse(url).netloc
            parameters = extract_parameters(url)

            if not parameters:
                if verbose:
                    print_status(f"No parameters in {url}, skipping", "debug")
                continue

            found_vulnerability = False

            with ThreadPoolExecutor(max_workers=thread_count) as executor:
                futures = {}
                for param in parameters:
                    for payload_entry in payloads:
                        if stop_scan.is_set(): break
                        
                        name = payload_entry['name']
                        payload = payload_entry['payload']
                        expected_response = payload_entry['response']
                        
                        if verbose:
                            print_status(f"Testing {name} on {param}", "debug")

                        future = executor.submit(
                            test_lfi_payload, 
                            url, 
                            param, 
                            payload, 
                            expected_response
                        )
                        futures[future] = (param, payload)

                for future in as_completed(futures):
                    if stop_scan.is_set(): break
                    
                    try:
                        result = future.result()
                        if result['vulnerable']:
                            found_vulnerability = True
                            full_url = result['url']
                            parameter = result['parameter']
                            payload = result['payload']

                            print_status("Vulnerability Found!", "success")
                            print_status(f"  URL: {full_url}", "info")
                            print_status(f"  Parameter: {parameter}", "info")
                            print_status(f"  Payload: {payload}", "info")

                            result_manager = ResultManager(domain)
                            result_manager.add_finding("LFI", "Findings", {
                                "url": full_url,
                                "parameter": parameter,
                                "payload": payload
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
                
        print_status("LFI Scan completed", "info")

    except KeyboardInterrupt:
        from lib.core.interrupt import exit_clean
        exit_clean()
