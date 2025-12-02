# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.

"""Open Redirect Scanner Module."""

import os
import json
import subprocess
import threading
from datetime import datetime
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Optional

from lib.core.config import get_config
from lib.core.logger import get_logger
from lib.ui import print_status, colored, print_header, print_separator
from lib.parse.random_headers import generate_random_headers
from lib.core.state import stop_scan

config = get_config()
logger = get_logger(__name__)

def load_file_lines(file_path: str) -> List[str]:
    """Load lines from a file."""
    try:
        with open(file_path, 'r') as file:
            return [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        logger.error(f"File not found: {file_path}")
    return []

def replace_last_parameter(url: str, parameter: str, payload: str) -> str:
    """Replace the last parameter in the URL."""
    parsed_url = urlparse(url)
    query = parsed_url.query.split('&')
    query = [param.replace("{payload}", payload) for param in query]
    if query:
        query[-1] = f"{parameter}={payload}"
    new_query = '&'.join(query)
    return f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"

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
        
    # Find or create Open Redirect block
    redirect_block = None
    for entry in results["scans"]:
        if "Open Redirect" in entry:
            redirect_block = entry["Open Redirect"]
            break
            
    if redirect_block is None:
        redirect_block = []
        results["scans"].append({"Open Redirect": redirect_block})
        
    # Check duplicate
    for entry in redirect_block:
        if (entry.get("url") == url and 
            entry.get("parameter") == parameter and 
            entry.get("payload") == payload):
            return

    redirect_block.append({
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

def test_open_redirect_payload(url: str, parameter: str, payload: str, verbose: bool) -> Dict[str, Any]:
    """Test the open redirect payload using curl."""
    if stop_scan.is_set():
        return {'vulnerable': False}

    test_url = replace_last_parameter(url, parameter, payload)
    headers = generate_random_headers()

    try:
        curl_command = [
            "curl", "-L", "-s", "-I", test_url, 
            "-H", f"User-Agent: {headers['User-Agent']}"
        ]
        result = subprocess.run(
            curl_command, 
            capture_output=True, 
            text=True, 
            timeout=config.REQUEST_TIMEOUT
        )

        if result.returncode == 0 and "Location" in result.stdout:
            location = next(
                (line.split(":", 1)[1].strip() for line in result.stdout.splitlines() if "Location" in line), 
                None
            )
            if location:
                if verbose:
                    print_status(f"Vulnerable URL: {test_url}", "success")
                    print_status(f"Redirect URL: {location}", "info")
                    print_status(f"Payload: {payload}", "info")
                    print_status(f"Parameter: {parameter}", "info")

                return {
                    'vulnerable': True, 
                    'url': test_url, 
                    'payload': payload, 
                    'parameter': parameter
                }

    except subprocess.TimeoutExpired:
        logger.debug(f"Timeout testing {test_url}")
    except subprocess.CalledProcessError as e:
        logger.debug(f"Error executing curl: {e}")

    return {'vulnerable': False}

def perform_redirect_scan(crawled_urls: List[str], thread_count: int = 1, no_prompt: bool = False, verbose: bool = False) -> None:
    """Perform open redirect scanning."""
    stop_scan.clear()
    
    print_header("Open Redirect Scan", color="cyan")
    
    thread_count = max(1, min(thread_count, config.MAX_THREADS))
    parameters = load_file_lines(os.path.join(config.DATA_DIR, 'openredirectparameters.txt'))
    payloads = load_file_lines(os.path.join(config.DATA_DIR, 'openredirectpayloads.txt'))
    
    print_status(f"Scanning {len(crawled_urls)} URLs with {len(parameters)} parameters and {len(payloads)} payloads", "info")

    try:
        for url in crawled_urls:
            if stop_scan.is_set(): break
            
            print_status(f"Testing URL: {url}", "info")
            domain = urlparse(url).netloc

            for parameter in parameters:
                if stop_scan.is_set(): break
                
                if verbose:
                    print_status(f"Testing Parameter: {parameter}", "debug")

                with ThreadPoolExecutor(max_workers=thread_count) as executor:
                    futures = {}
                    for payload in payloads:
                        if stop_scan.is_set(): break
                        
                        future = executor.submit(
                            test_open_redirect_payload, 
                            url, 
                            parameter, 
                            payload, 
                            verbose
                        )
                        futures[future] = (parameter, payload)

                    for future in as_completed(futures):
                        if stop_scan.is_set(): break
                        
                        try:
                            result = future.result()
                            if result['vulnerable']:
                                full_url = result['url']
                                param = result['parameter']
                                payload = result['payload']

                                print_status("Vulnerability Found!", "success")
                                print_status(f"  URL: {full_url}", "info")
                                print_status(f"  Parameter: {param}", "info")
                                print_status(f"  Payload: {payload}", "info")

                                save_results(domain, full_url, param, payload)

                                if not no_prompt:
                                    choice = input(colored("\n[?] Vulnerability found. Continue scanning? [y/N]: ", 'yellow')).strip().lower()
                                    if choice != 'y':
                                        print_status("Stopping scan...", "warning")
                                        stop_scan.set()
                                        return
                        except Exception as e:
                            logger.error(f"Error in worker: {e}")

            if stop_scan.is_set(): break
            
        print_status("Open Redirect Scan completed", "info")

    except KeyboardInterrupt:
        stop_scan.set()
        print_status("Scan interrupted", "warning")
