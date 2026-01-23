# Copyright (c) 2024 waymap developers
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
from lib.ui import print_status, colored, print_header, print_separator
from lib.parse.random_headers import generate_random_headers
from lib.core.state import stop_scan

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

def save_results(domain: str, url: str, parameter: str, payload: str) -> None:
    """Save scan results."""
    session_dir = config.get_domain_session_dir(domain)
    save_path = os.path.join(session_dir, 'waymap_full_results.json')
    
    results = {"scans": []}
    if os.path.exists(save_path):
        try:
            with open(save_path, 'r') as f:
                results = json.load(f)
        except Exception:
            pass
            
    if "scans" not in results or not isinstance(results["scans"], list):
        results["scans"] = []
        
    # Find or create LFI block
    lfi_block = None
    for entry in results["scans"]:
        if "LFI" in entry:
            lfi_block = entry["LFI"]
            break
            
    if lfi_block is None:
        lfi_block = []
        results["scans"].append({"LFI": lfi_block})
        
    # Check duplicate
    for entry in lfi_block:
        if (entry.get("url") == url and 
            entry.get("parameter") == parameter and 
            entry.get("payload") == payload):
            return

    lfi_block.append({
        "url": url,
        "parameter": parameter,
        "payload": payload
    })
    
    try:
        with open(save_path, 'w') as f:
            json.dump(results, f, indent=4)
        print_status(f"Saved to {save_path}", "success")
    except Exception as e:
        logger.error(f"Error saving results: {e}")

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

                            save_results(domain, full_url, parameter, payload)

                            if not no_prompt:
                                choice = input(colored("\n[?] Vulnerability found. Continue scanning? [y/N]: ", 'yellow')).strip().lower()
                                if choice != 'y':
                                    print_status("Stopping scan...", "warning")
                                    stop_scan.set()
                                    return
                    except Exception as e:
                        logger.error(f"Error in worker: {e}")

            if not found_vulnerability and verbose:
                print_status(f"No vulnerabilities found on {url}", "debug")
                
        print_status("LFI Scan completed", "info")

    except KeyboardInterrupt:
        stop_scan.set()
        print_status("Scan interrupted", "warning")
