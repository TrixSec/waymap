# Copyright (c) 2026 waymap developers
# See the file 'LICENSE' for copying permission.

"""Command Injection Scanner Module."""

import os
import re
import random
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from defusedxml import ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Optional

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

def get_domain(url: str) -> str:
    """Extract domain from URL."""
    return urlparse(url).netloc

def extract_parameters(url: str) -> List[str]:
    """Extract query parameters."""
    parsed_url = urlparse(url)
    params = parse_qs(parsed_url.query)
    return list(params.keys())

def _build_url_with_param(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [value]
    new_query = urlencode(qs, doseq=True)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

def load_cmdi_errors(xml_file: str) -> Dict[str, List[str]]:
    """Load CMDi error patterns."""
    cmdi_errors = {}
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
        for error in root.findall('error'):
            error_name = error.attrib['value']
            patterns = [pattern.attrib['regexp'] for pattern in error.findall('pattern')]
            cmdi_errors[error_name] = patterns
    except Exception as e:
        logger.error(f"Error loading CMDi errors: {e}")
    return cmdi_errors

def detect_cmdi(response_content: str, cmdi_errors: Dict[str, List[str]]) -> Optional[str]:
    """Detect CMDi error in response."""
    for error_name, patterns in cmdi_errors.items():
        for pattern in patterns:
            if re.search(pattern, response_content, re.IGNORECASE):
                return error_name
    return None

def detect_web_tech(headers: Dict[str, str]) -> str:
    """Detect web technology."""
    return headers.get('x-powered-by', headers.get('server', 'Unknown'))

def test_cmdi_payload(url: str, parameter: str, payload: str, cmdi_errors: Dict[str, List[str]]) -> Dict[str, Any]:
    """Test a single payload."""
    if stop_scan.is_set():
        return {'vulnerable': False}
        
    headers = generate_random_headers()
    test_url = _build_url_with_param(url, parameter, payload)

    try:
        response = requests.get(test_url, headers=headers, timeout=config.REQUEST_TIMEOUT, verify=False)
        cmdi_error = detect_cmdi(response.text, cmdi_errors)
        
        if cmdi_error:
            return {
                'vulnerable': True,
                'cmdi_error': cmdi_error,
                'response': response.text,
                'headers': response.headers,
                'url': test_url,
                'parameter': parameter,
                'payload': payload
            }
    except requests.RequestException as e:
        logger.debug(f"Error testing {test_url}: {e}")

    return {'vulnerable': False}

def perform_cmdi_scan(crawled_urls: List[str], cmdi_payloads: List[str], thread_count: int = 1, no_prompt: bool = False, verbose: bool = False) -> None:
    """Perform Command Injection scan."""
    stop_scan.clear()
    
    print_header("Command Injection Scan", color="cyan")
    
    thread_count = max(1, min(thread_count, config.MAX_THREADS))
    cmdi_errors = load_cmdi_errors(os.path.join(config.DATA_DIR, 'cmdi.xml'))
    detected_tech = None
    
    print_status(f"Scanning {len(crawled_urls)} URLs", "info")

    try:
        for url in crawled_urls:
            if stop_scan.is_set(): break
            
            print_status(f"Testing URL: {url}", "info")
            domain = get_domain(url)
            result_manager = ResultManager(domain)
            parameters = extract_parameters(url)

            if not parameters:
                if verbose:
                    print_status(f"No parameters in {url}, skipping", "debug")
                continue

            found_vulnerability = False
            
            # Limit payloads to random sample of 10 if too many
            payloads_to_test = cmdi_payloads
            if len(cmdi_payloads) > 10:
                payloads_to_test = random.sample(cmdi_payloads, 10)
                if verbose:
                    print_status(f"Selected 10 random payloads from {len(cmdi_payloads)}", "debug")

            with ThreadPoolExecutor(max_workers=thread_count) as executor:
                futures = {}
                for param in parameters:
                    for payload in payloads_to_test:
                        if stop_scan.is_set(): break
                        
                        if verbose:
                            print_status(f"Testing payload on {param}", "debug")
                            
                        future = executor.submit(test_cmdi_payload, url, param, payload, cmdi_errors)
                        futures[future] = (param, payload)

                for future in as_completed(futures):
                    if stop_scan.is_set(): break
                    
                    try:
                        result = future.result()
                        if result['vulnerable']:
                            found_vulnerability = True
                            payload = result['payload']
                            parameter = result['parameter']

                            if not detected_tech:
                                detected_tech = detect_web_tech(result['headers'])
                                print_status(f"Web Technology: {detected_tech}", "info")

                            print_status("Vulnerability Found!", "success")
                            print_status(f"  URL: {result['url']}", "info")
                            print_status(f"  Parameter: {parameter}", "info")
                            print_status(f"  Payload: {payload}", "info")
                            print_status(f"  Error: {result['cmdi_error']}", "info")

                            result_manager.add_finding("Command Injection", "", {
                                "url": result['url'],
                                "parameter": parameter,
                                "payload": payload,
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
                
        print_status("CMDi Scan completed", "info")

    except KeyboardInterrupt:
        from lib.core.interrupt import exit_clean
        exit_clean()
