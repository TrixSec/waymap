# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.

"""CRLF Injection Scanner Module."""

import os
import json
import requests
import threading
from datetime import datetime
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

def load_crlf_payloads(file_path: str) -> List[Dict[str, str]]:
    """Load CRLF payloads from file."""
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
        
    # Find or create CRLF Injection block
    crlf_block = None
    for entry in results["scans"]:
        if "CRLF Injection" in entry:
            crlf_block = entry["CRLF Injection"]
            break
            
    if crlf_block is None:
        crlf_block = []
        results["scans"].append({"CRLF Injection": crlf_block})
        
    # Check duplicate
    for entry in crlf_block:
        if (entry.get("url") == url and 
            entry.get("parameter") == parameter and 
            entry.get("payload") == payload):
            return

    crlf_block.append({
        "url": url,
        "parameter": parameter,
        "payload": payload,
        "timestamp": datetime.now().isoformat()
    })
    
    try:
        with open(save_path, 'w') as f:
            json.dump(results, f, indent=4)
        print_status(f"Saved to {save_path}", "success")
    except Exception as e:
        logger.error(f"Error saving results: {e}")

def test_crlf_payload(url: str, parameter: str, payload: str, expected_response: str) -> Dict[str, Any]:
    """Test CRLF payload."""
    if stop_scan.is_set():
        return {'vulnerable': False}

    headers = generate_random_headers()
    try:
        response = requests.get(
            url, 
            headers=headers, 
            timeout=config.REQUEST_TIMEOUT, 
            verify=False
        )
        if expected_response in response.text:
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

            domain = url.split('/')[2] if len(url.split('/')) > 2 else "unknown"

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

                            save_results(domain, full_url, param_key, payload)

                            if not no_prompt:
                                choice = input(colored("\n[?] Vulnerability found. Continue scanning? [y/N]: ", 'yellow')).strip().lower()
                                if choice != 'y':
                                    print_status("Stopping scan...", "warning")
                                    stop_scan.set()
                                    return
                    except Exception as e:
                        logger.error(f"Error in worker: {e}")
                        
        print_status("CRLF Scan completed", "info")

    except KeyboardInterrupt:
        stop_scan.set()
        print_status("Scan interrupted", "warning")