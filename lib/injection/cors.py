# Copyright (c) 2026 waymap developers
# See the file 'LICENSE' for copying permission.

"""CORS Scanner Module."""

import os
import secrets
import requests
from lib.core import http
from functools import lru_cache
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
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

EVIDENCE_WINDOW = 90


def _domain(url: str) -> str:
    """Extract domain from URL."""
    return urlparse(url).netloc or "unknown_domain"

def _proof_token() -> str:
    """Generate a unique proof token for CORS testing."""
    return f"waymap_cors_{secrets.token_hex(4)}"


def _evidence_snippet(cors_header: str) -> str:
    """Extract evidence snippet from CORS header."""
    if not cors_header:
        return ""
    if len(cors_header) <= EVIDENCE_WINDOW * 2:
        return cors_header
    return cors_header[:EVIDENCE_WINDOW] + "..." + cors_header[-EVIDENCE_WINDOW:]


def _proof_evidence(cors_header: str, expected_response: str, payload: str) -> Dict[str, Any]:
    """Generate proof evidence for CORS vulnerability."""
    expected_in_header = expected_response in cors_header if cors_header else False
    payload_reflected = payload in cors_header if cors_header else False
    allows_credentials = 'true' in cors_header.lower() if cors_header else False
    
    return {
        "confirmed": expected_in_header or payload_reflected,
        "cors_header": cors_header,
        "expected_in_header": expected_in_header,
        "payload_reflected": payload_reflected,
        "allows_credentials": allows_credentials,
        "snippet": _evidence_snippet(cors_header),
    }


@lru_cache(maxsize=None)
def load_cors_payloads(file_path: str) -> List[Dict[str, str]]:
    """Load CORS payloads from file."""
    return load_named_payloads(file_path, ("name", "payload", "response"))

def test_cors_vulnerability(url: str, payload: str, expected_response: str, method: str = "OPTIONS", 
                            baseline_cors_header: str = "") -> Dict[str, Any]:
    """Test CORS vulnerability with proof of concept and false positive prevention."""
    if stop_scan.is_set():
        return {'vulnerable': False}

    # Skip payloads with empty expected responses
    if not expected_response:
        return {'vulnerable': False}

    proof_token = _proof_token()
    headers = generate_random_headers()
    headers['Origin'] = payload
    
    try:
        # Test with different HTTP methods
        if method == "OPTIONS":
            response = http.options(url, headers=headers, timeout=config.REQUEST_TIMEOUT, verify=False)
        elif method == "GET":
            response = http.get(url, headers=headers, timeout=config.REQUEST_TIMEOUT, verify=False)
        elif method == "POST":
            response = http.post(url, headers=headers, timeout=config.REQUEST_TIMEOUT, verify=False)
        else:
            response = http.get(url, headers=headers, timeout=config.REQUEST_TIMEOUT, verify=False)
        
        cors_header = response.headers.get('Access-Control-Allow-Origin', '')
        allow_credentials = response.headers.get('Access-Control-Allow-Credentials', '')
        
        # Strict false positive prevention
        if expected_response in cors_header:
            # Check if the expected response was already in baseline
            if baseline_cors_header and expected_response in baseline_cors_header:
                logger.debug(f"Expected response '{expected_response}' found in baseline CORS header, skipping as false positive")
                return {'vulnerable': False}
            
            # Check if CORS header is identical to baseline
            if cors_header == baseline_cors_header:
                logger.debug(f"CORS header identical to baseline, skipping as false positive")
                return {'vulnerable': False}
            
            # Generate proof evidence
            evidence = _proof_evidence(cors_header, expected_response, payload)
            evidence['allow_credentials'] = allow_credentials.lower() == 'true' if allow_credentials else False
            
            return {
                'vulnerable': True, 
                'response': response, 
                'payload': payload, 
                'url': url,
                'method': method,
                'proof_token': proof_token,
                'cors_header': cors_header,
                'allow_credentials': allow_credentials,
                'evidence': evidence,
                'headers': response.headers,
            }
    except requests.RequestException as e:
        logger.debug(f"Error testing {url}: {e}")

    return {'vulnerable': False}

def perform_cors_scan(crawled_urls: List[str], thread_count: int = 1, no_prompt: bool = False, verbose: bool = False) -> None:
    """Perform CORS scan with proof of concept and false positive prevention."""
    stop_scan.clear()
    
    print_header("CORS Misconfiguration Scan (Enhanced)", color="cyan")
    
    thread_count = max(1, min(thread_count, config.MAX_THREADS))
    payloads = load_cors_payloads(os.path.join(config.DATA_DIR, 'corspayload.txt'))
    methods = ["OPTIONS", "GET", "POST"]
    
    print_status(f"Scanning {len(crawled_urls)} URLs with {len(payloads)} payloads across {len(methods)} HTTP methods", "info")

    # Track tested combinations to avoid duplicates
    tested_combinations = set()

    try:
        for url in crawled_urls:
            if stop_scan.is_set(): break
            
            print_status(f"Testing URL: {url}", "info")
            domain = _domain(url)
            result_manager = ResultManager(domain)
            found_vulnerability = False
            
            # Capture baseline CORS header for false positive prevention
            baseline_cors_header = ""
            try:
                baseline_response = http.options(url, headers=generate_random_headers(), timeout=config.REQUEST_TIMEOUT, verify=False)
                baseline_cors_header = baseline_response.headers.get('Access-Control-Allow-Origin', '')
                if verbose:
                    print_status(f"Captured baseline CORS header: {baseline_cors_header}", "debug")
            except Exception as e:
                logger.debug(f"Failed to capture baseline CORS header: {e}")
            
            with ThreadPoolExecutor(max_workers=thread_count) as executor:
                futures = {}
                for method in methods:
                    for payload_entry in payloads:
                        if stop_scan.is_set(): break

                        name = payload_entry['name']
                        payload = payload_entry['payload']
                        expected_response = payload_entry['response']
                        
                        # Skip if already tested this combination
                        combo_key = (url, method, payload)
                        if combo_key in tested_combinations:
                            continue
                        tested_combinations.add(combo_key)

                        if verbose:
                            print_status(f"Testing {name} with {method} method: {payload}", "debug")

                        future = executor.submit(
                            test_cors_vulnerability, 
                            url, 
                            payload, 
                            expected_response,
                            method,
                            baseline_cors_header
                        )
                        futures[future] = (url, payload, method)

                total_tasks = len(futures)
                completed_tasks = 0
                
                for future in as_completed(futures):
                    if stop_scan.is_set(): break
                    
                    completed_tasks += 1
                    if completed_tasks % 50 == 0 or completed_tasks == total_tasks:
                        print_status(f"Progress: {completed_tasks}/{total_tasks}", "info")

                    try:
                        result = future.result()
                        url, payload, method = futures[future]

                        if result['vulnerable']:
                            # Check for duplicates
                            is_duplicate = result_manager.has_duplicate(
                                "CORS",
                                ["url", "payload", "method"],
                                {"url": url, "payload": payload, "method": method}
                            )
                            
                            if is_duplicate:
                                if verbose:
                                    print_status(f"Skipping already tested: {url} with {method}", "debug")
                                continue
                            
                            found_vulnerability = True
                            print_status("Vulnerability Found!", "success")
                            print_status(f"  URL: {result['url']}", "info")
                            print_status(f"  Method: {result.get('method', 'OPTIONS')}", "info")
                            print_status(f"  Origin: {payload}", "info")
                            print_status(f"  Proof Token: {result.get('proof_token', '')}", "info")
                            
                            cors_header = result.get('cors_header', '')
                            if cors_header:
                                print_status(f"  CORS Header: {cors_header}", "info")
                            
                            allow_credentials = result.get('allow_credentials', '')
                            if allow_credentials:
                                print_status(f"  Allow-Credentials: {allow_credentials}", "info")
                            
                            evidence = result.get('evidence', {})
                            if evidence.get('snippet'):
                                print_status(f"  Evidence: {evidence['snippet']}", "info")
                            
                            confirmations = []
                            if evidence.get('expected_in_header'):
                                confirmations.append('expected response reflected in CORS header')
                            if evidence.get('payload_reflected'):
                                confirmations.append('payload reflected in CORS header')
                            if evidence.get('allow_credentials'):
                                confirmations.append('allows credentials')
                            
                            if confirmations:
                                print_status(f"  Confirmations: {', '.join(confirmations)}", "info")

                            finding_data = {
                                "url": result['url'],
                                "method": result.get('method', 'OPTIONS'),
                                "payload": payload,
                                "proof_token": result.get('proof_token', ''),
                                "poc_url": result['url'],
                                "evidence": evidence,
                                "confirmations": confirmations,
                                "injected": True,
                                "timestamp": datetime.now().isoformat(),
                            }
                            
                            if result.get('cors_header'):
                                finding_data["cors_header"] = result['cors_header']
                            if result.get('allow_credentials'):
                                finding_data["allow_credentials"] = result['allow_credentials']
                            
                            result_manager.add_finding("CORS", "", finding_data)

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
