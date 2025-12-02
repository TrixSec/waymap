# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.

"""XSS Injection Scanner Module."""

import os
import requests
import threading
import json
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse

from lib.core.config import get_config
from lib.core.logger import get_logger
from lib.ui import print_status, print_header, colored
from lib.utils import load_payloads, save_to_file
from lib.parse.random_headers import generate_random_headers

# Initialize configuration and logger
config = get_config()
logger = get_logger(__name__)

# Global stop event
stop_scan = threading.Event()


def load_xss_payloads_from_file(file_path: str) -> List[Dict[str, str]]:
    """Load XSS payloads from a file."""
    payloads = []
    try:
        lines = load_payloads(file_path)
        for line in lines:
            try:
                if '::' in line:
                    name, payload = line.split('::', 1)
                    payloads.append({
                        'name': name.strip(),
                        'payload': payload.strip()
                    })
            except ValueError:
                logger.warning(f"Malformed payload: {line}")
    except Exception as e:
        logger.error(f"Error loading payloads: {e}")
    return payloads


def load_advanced_xss_payloads(file_path: str, level: int) -> List[Dict[str, str]]:
    """Load advanced payloads based on level."""
    all_payloads = load_xss_payloads_from_file(file_path)
    limits = {1: 10, 2: 23, 3: 38, 4: 49, 5: 62, 6: 76, 7: None}
    limit = limits.get(level, None)
    return all_payloads[:limit] if limit else all_payloads


def load_existing_results(domain: str) -> Dict[str, Any]:
    """Load existing scan results."""
    session_dir = config.get_domain_session_dir(domain)
    session_file = os.path.join(session_dir, 'waymap_full_results.json')
    
    if os.path.exists(session_file):
        try:
            with open(session_file, 'r') as file:
                return json.load(file)
        except json.JSONDecodeError:
            logger.error(f"Error decoding JSON from {session_file}")
    return {}


def save_results(domain: str, results: Dict[str, Any]) -> None:
    """Save scan results."""
    session_dir = config.get_domain_session_dir(domain)
    session_file = os.path.join(session_dir, 'waymap_full_results.json')
    
    try:
        with open(session_file, 'w') as file:
            json.dump(results, file, indent=4)
    except Exception as e:
        logger.error(f"Error saving results: {e}")


def test_xss_payload(url: str, parameter: str, payload: str) -> Dict[str, Any]:
    """Test a single XSS payload."""
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
        
        if payload in response.text:
            return {
                'vulnerable': True, 
                'response': response, 
                'headers': response.headers
            }
    except requests.RequestException as e:
        if not stop_scan.is_set():
            logger.debug(f"Error testing payload on {url}: {e}")

    return {'vulnerable': False}


def choose_scan_level(no_prompt: bool) -> int:
    """Choose scan level interactively or default."""
    if no_prompt:
        return 3
    try:
        while True:
            level = input(colored("[?] Choose scan level (1-7): ", 'yellow')).strip()
            if level.isdigit() and 1 <= int(level) <= 7:
                return int(level)
            print_status("Invalid level. Please choose 1-7.", "error")
    except KeyboardInterrupt:
        print_status("Scan interrupted", "warning")
        stop_scan.set()
        return 3


def _scan_urls_with_payloads(
    urls: List[str], 
    payloads: List[Dict[str, str]], 
    thread_count: int, 
    results: Dict[str, Any], 
    domain: str, 
    no_prompt: bool,
    verbose: bool
) -> None:
    """Helper function to execute scanning logic."""
    detected_tech = None
    
    with ThreadPoolExecutor(max_workers=thread_count) as executor:
        future_to_url = {}

        for url in urls:
            if stop_scan.is_set():
                break

            print_status(f"Testing URL: {url}", "info")

            if '?' not in url:
                continue
                
            base_url, params = url.split('?', 1)
            param_dict = {}
            for param in params.split('&'):
                if '=' in param:
                    key, value = param.split('=', 1)
                    param_dict[key] = value

            for payload_entry in payloads:
                if stop_scan.is_set():
                    break

                name = payload_entry['name']
                payload = payload_entry['payload']

                for param_key in param_dict.keys():
                    if stop_scan.is_set():
                        break

                    # Construct full URL for checking duplication
                    test_params = param_dict.copy()
                    test_params[param_key] = payload
                    modified_params = '&'.join([f"{k}={v}" for k, v in test_params.items()])
                    full_url = f"{base_url}?{modified_params}"

                    # Check if already found
                    already_found = False
                    if 'scans' in results and isinstance(results['scans'], list):
                        for entry in results['scans']:
                            if 'xss' in entry:
                                for vuln in entry['xss']:
                                    if (vuln.get('url') == full_url and 
                                        vuln.get('parameter') == param_key and 
                                        vuln.get('payload') == payload):
                                        already_found = True
                                        break
                            if already_found: break
                    
                    if already_found:
                        if verbose:
                            print_status(f"Skipping already tested: {full_url}", "debug")
                        continue

                    if verbose:
                        print_status(f"Testing {name} on {param_key}", "debug")

                    future = executor.submit(test_xss_payload, base_url, param_key, payload)
                    future_to_url[future] = (full_url, param_key, payload)

        # Process results
        for future in as_completed(future_to_url):
            if stop_scan.is_set():
                break

            try:
                result = future.result()
                full_url, param_key, payload = future_to_url[future]

                if result['vulnerable']:
                    if detected_tech is None:
                        headers = result.get('headers', {})
                        detected_tech = headers.get('X-Powered-By', headers.get('Server', 'Unknown'))
                        print_status(f"Web Technology: {detected_tech}", "info")

                    print_status("Vulnerability Found!", "success")
                    print_status(f"  URL: {full_url}", "info")
                    print_status(f"  Parameter: {param_key}", "info")
                    print_status(f"  Payload: {payload}", "info")
                    
                    logger.log_vulnerability_found("XSS", full_url, f"Param: {param_key}")

                    # Save result
                    if 'scans' not in results or not isinstance(results['scans'], list):
                        results['scans'] = []
                    
                    # Find or create XSS block
                    xss_block = None
                    for entry in results['scans']:
                        if 'xss' in entry:
                            xss_block = entry['xss']
                            break
                    
                    if xss_block is None:
                        xss_block = []
                        results['scans'].append({'xss': xss_block})

                    xss_block.append({
                        'url': full_url,
                        'parameter': param_key,
                        'payload': payload,
                        'injected': True,
                        'timestamp': datetime.now().isoformat()
                    })

                    save_results(domain, results)

                    if not no_prompt:
                        choice = input(colored("\n[?] Vulnerability found. Continue scanning? [y/N]: ", 'yellow')).strip().lower()
                        if choice != 'y':
                            print_status("Stopping scan...", "warning")
                            stop_scan.set()
                            return

            except Exception as e:
                logger.error(f"Error processing result: {e}")


def perform_xss_scan(
    crawled_urls: List[str], 
    thread_count: int = 1, 
    no_prompt: bool = False, 
    verbose: bool = False
) -> None:
    """Perform XSS scan on a list of URLs."""
    if not crawled_urls:
        print_status("No URLs to scan", "warning")
        return

    stop_scan.clear()
    thread_count = max(1, min(thread_count, config.MAX_THREADS))
    
    # Extract domain
    try:
        domain = urlparse(crawled_urls[0]).netloc
    except Exception:
        domain = "unknown_domain"
        
    results = load_existing_results(domain)

    # Basic Scan
    print_header("Basic XSS Scan", color="cyan")
    payload_path = os.path.join(config.DATA_DIR, 'basicxsspayload.txt')
    basic_payloads = load_xss_payloads_from_file(payload_path)
    
    _scan_urls_with_payloads(crawled_urls, basic_payloads, thread_count, results, domain, no_prompt, verbose)

    if stop_scan.is_set():
        return

    # Advanced Scan
    if no_prompt:
        do_advanced = config.DEFAULT_INPUT.lower() == 'y'
    else:
        choice = input(colored("\nTest XSS Filters Bypass Payload? [y/N] (recommended): ", 'yellow')).strip().lower()
        do_advanced = choice == 'y'

    if do_advanced:
        print_header("Advanced XSS Scan", color="cyan")
        advanced_file = os.path.join(config.DATA_DIR, 'filtersbypassxss.txt')
        level = choose_scan_level(no_prompt)
        advanced_payloads = load_advanced_xss_payloads(advanced_file, level)
        
        _scan_urls_with_payloads(crawled_urls, advanced_payloads, thread_count, results, domain, no_prompt, verbose)
