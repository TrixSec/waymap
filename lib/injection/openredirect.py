# Copyright (c) 2026 waymap developers
# See the file 'LICENSE' for copying permission.

"""Open Redirect Scanner Module."""

import os
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any

import requests
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

def test_open_redirect_payload(url: str, parameter: str, payload: str, verbose: bool) -> Dict[str, Any]:
    """Test the open redirect payload using HTTP redirect headers."""
    if stop_scan.is_set():
        return {'vulnerable': False}

    test_url = replace_last_parameter(url, parameter, payload)
    headers = generate_random_headers()

    try:
        response = requests.get(
            test_url,
            headers=headers,
            allow_redirects=False,
            timeout=config.REQUEST_TIMEOUT,
            verify=False,
        )
        location = response.headers.get("Location") or response.headers.get("location")
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
                'parameter': parameter,
                'location': location,
            }

    except requests.RequestException as e:
        logger.debug(f"Error testing {test_url}: {e}")

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
            result_manager = ResultManager(domain)

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
                                if result.get('location'):
                                    print_status(f"  Location: {result['location']}", "info")

                                result_manager.add_finding("Open Redirect", "", {
                                    "url": full_url,
                                    "parameter": param,
                                    "payload": payload,
                                    "location": result.get("location"),
                                })

                                if not no_prompt:
                                    if not ask_continue_scanning():
                                        print_status("Stopping scan...", "warning")
                                        stop_scan.set()
                                        return
                        except Exception as e:
                            logger.error(f"Error in worker: {e}")

            if stop_scan.is_set(): break
            
        print_status("Open Redirect Scan completed", "info")

    except KeyboardInterrupt:
        from lib.core.interrupt import exit_clean
        exit_clean()
