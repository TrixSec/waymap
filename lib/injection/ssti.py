# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.

"""SSTI Scanner Module."""

import os
import json
import requests
import threading
import multiprocessing
from datetime import datetime
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

def load_ssti_payloads(file_path: str) -> List[Dict[str, str]]:
    """Load SSTI payloads from a file."""
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

def save_results(domain: str, url: str, parameter: str, payload: str, expected_response: str) -> None:
    """Save scan results to JSON file."""
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
        
    # Find or create SSTI block
    ssti_block = None
    for entry in results["scans"]:
        if "SSTI" in entry:
            ssti_block = entry["SSTI"]
            break
            
    if ssti_block is None:
        ssti_block = []
        results["scans"].append({"SSTI": ssti_block})
        
    # Check duplicate
    for entry in ssti_block:
        if (entry.get("url") == url and 
            entry.get("parameter") == parameter and 
            entry.get("payload") == payload):
            return

    ssti_block.append({
        "url": url,
        "parameter": parameter,
        "payload": payload,
        "expected_response": expected_response,
        "timestamp": datetime.now().isoformat()
    })
    
    try:
        with open(save_path, 'w') as f:
            json.dump(results, f, indent=4)
        print_status(f"Saved to {save_path}", "success")
    except Exception as e:
        logger.error(f"Error saving results: {e}")

def test_ssti_payload(url: str, parameter: str, payload: str, expected_response: str) -> Dict[str, Any]:
    """Test a given SSTI payload."""
    if stop_scan.is_set():
        return None

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
                            
                            save_results(domain, result['url'], result['parameter'], result['payload'], result['expected_response'])
                            
                            if not no_prompt:
                                choice = input(colored("\n[?] Vulnerability found. Continue scanning? [y/N]: ", 'yellow')).strip().lower()
                                if choice != 'y':
                                    print_status("Stopping scan...", "warning")
                                    stop_scan.set()
                                    return
                    except Exception as e:
                        logger.error(f"Error in worker: {e}")
                        
        print_status("SSTI Scan completed", "info")

    except KeyboardInterrupt:
        stop_scan.set()
        print_status("Scan interrupted", "warning")
