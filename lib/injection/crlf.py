# Copyright (c) 2026 waymap developers
# See the file 'LICENSE' for copying permission.

"""CRLF Injection Scanner Module with Advanced Detection."""

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


def _params(url: str) -> Dict[str, str]:
    """Extract parameters from URL."""
    return {key: values[0] if values else "" for key, values in parse_qs(urlparse(url).query, keep_blank_values=True).items()}


def _build_url(url: str, param: str, value: str) -> str:
    """Build URL with injected parameter value."""
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [value]
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(qs, doseq=True), parsed.fragment))


def _proof_token() -> str:
    """Generate a unique proof token for CRLF testing."""
    return f"waymap_crlf_{secrets.token_hex(4)}"


def _evidence_snippet(response_text: str, expected_response: str) -> str:
    """Extract evidence snippet from response text."""
    if not expected_response or expected_response not in response_text:
        return ""
    position = response_text.find(expected_response)
    start = max(0, position - EVIDENCE_WINDOW)
    end = min(len(response_text), position + len(expected_response) + EVIDENCE_WINDOW)
    return response_text[start:end].replace("\r", " ").replace("\n", " ").strip()


def _proof_evidence(response_text: str, expected_response: str, baseline_text: str = "", 
                    injected_header: str = "") -> Dict[str, Any]:
    """Generate proof evidence for CRLF vulnerability."""
    expected_in_response = expected_response in response_text
    expected_in_baseline = expected_response in baseline_text if baseline_text else False
    response_changed = response_text != baseline_text if baseline_text else True
    header_injected = bool(injected_header)
    
    return {
        "confirmed": (expected_in_response and not expected_in_baseline and response_changed) or header_injected,
        "expected_response": expected_response,
        "expected_in_response": expected_in_response,
        "expected_in_baseline": expected_in_baseline,
        "response_changed": response_changed,
        "header_injected": header_injected,
        "injected_header": injected_header,
        "snippet": _evidence_snippet(response_text, expected_response),
    }


@lru_cache(maxsize=None)
def load_crlf_payloads(file_path: str) -> List[Dict[str, str]]:
    """Load CRLF payloads from file."""
    return load_named_payloads(file_path, ("name", "payload", "response"))


def test_crlf_payload(url: str, parameter: str, payload: str, expected_response: str, 
                      baseline_headers: str = "", baseline_text: str = "") -> Dict[str, Any]:
    """Test CRLF payload with strict header injection detection and proof of concept."""
    if stop_scan.is_set():
        return {'vulnerable': False}

    # Skip payloads with empty expected responses
    if not expected_response:
        return {'vulnerable': False}

    proof_token = _proof_token()
    headers = generate_random_headers()
    injected_header = ""
    
    try:
        response = http.get(
            url, 
            headers=headers, 
            timeout=config.REQUEST_TIMEOUT, 
            verify=False
        )
        
        # Check for SQL error signatures FIRST (indicates SQL injection, not CRLF)
        # This must be checked before any other detection to avoid false positives
        response_lower = response.text.lower()
        
        # Simple but effective SQL error detection
        if 'you have an error in your sql syntax' in response_lower or \
           'check the manual that corresponds to your' in response_lower:
            logger.debug("SQL error signature found in response, skipping as SQL injection (not CRLF)")
            return {'vulnerable': False}
        
        # Strict CRLF detection: only consider it vulnerable if a new header is actually injected
        # CRLF injection should result in a complete header being added to the response headers
        if ':' in expected_response:
            header_name = expected_response.split(':')[0].strip()
            header_value = expected_response.split(':', 1)[1].strip() if ':' in expected_response else ""
            
            # Check if the header exists in the response
            if header_name in response.headers:
                # Check if this header was NOT in the baseline (newly injected)
                baseline_header_names = [h.split(':')[0].strip() for h in baseline_headers.split('\r\n') if h and ':' in h]
                
                if header_name not in baseline_header_names:
                    logger.debug(f"New header '{header_name}' injected via CRLF - confirmed vulnerability")
                    header_blob = "\r\n".join(f"{k}: {v}" for k, v in response.headers.items())
                    injected_header = f"{header_name}: {response.headers[header_name]}"
                    
                    # Generate proof evidence
                    evidence = _proof_evidence(response.text, expected_response, baseline_text, injected_header)
                    
                    return {
                        'vulnerable': True, 
                        'url': url,
                        'parameter': parameter,
                        'payload': payload,
                        'expected_response': expected_response,
                        'proof_token': proof_token,
                        'injected_header': injected_header,
                        'evidence': evidence,
                        'response': response,
                        'headers': response.headers,
                        'response_snippet': header_blob[:500] if len(header_blob) > 500 else header_blob
                    }
                else:
                    logger.debug(f"Header '{header_name}' exists in baseline, not a new injection")
                    return {'vulnerable': False}
            else:
                logger.debug(f"Header '{header_name}' not found in response headers")
                return {'vulnerable': False}
        else:
            # For non-header expected responses (like body content), check response body
            # This is for XSS via CRLF or response splitting
            if expected_response in response.text:
                # Strict false positive prevention
                if baseline_text:
                    # Check if expected response existed in baseline
                    if expected_response in baseline_text:
                        logger.debug(f"Expected response '{expected_response}' found in baseline body, skipping as false positive")
                        return {'vulnerable': False}
                    
                    # Check if response is identical to baseline
                    if response.text == baseline_text:
                        logger.debug(f"Response body identical to baseline, skipping as false positive")
                        return {'vulnerable': False}
                    
                    # For numeric expected responses, ensure count increased
                    if expected_response.isdigit():
                        baseline_count = baseline_text.count(expected_response)
                        response_count = response.text.count(expected_response)
                        if response_count <= baseline_count:
                            logger.debug(f"Numeric expected response '{expected_response}' not increased, skipping")
                            return {'vulnerable': False}
                    
                    # Additional check: for very short expected responses (3 chars or less), 
                    # require significant response change to avoid false positives
                    if len(expected_response) <= 3:
                        # Calculate response size difference
                        size_diff = abs(len(response.text) - len(baseline_text))
                        if size_diff < 50:  # Response didn't change much
                            logger.debug(f"Response size change too small ({size_diff} chars) for short expected response, skipping")
                            return {'vulnerable': False}
                
                logger.debug(f"Expected response '{expected_response}' found in response body")
                
                # Generate proof evidence
                evidence = _proof_evidence(response.text, expected_response, baseline_text, "")
                
                return {
                    'vulnerable': True, 
                    'url': url,
                    'parameter': parameter,
                    'payload': payload,
                    'expected_response': expected_response,
                    'proof_token': proof_token,
                    'evidence': evidence,
                    'response': response,
                    'headers': response.headers,
                    'response_snippet': response.text[:500] if len(response.text) > 500 else response.text
                }
    except requests.RequestException as e:
        logger.debug(f"Error testing {url}: {e}")

    return {'vulnerable': False}


def perform_crlf_scan(crawled_urls: List[str], thread_count: int = 1, no_prompt: bool = False, verbose: bool = False) -> None:
    """Perform CRLF injection scan with advanced detection."""
    if not crawled_urls:
        print_status("No URLs to scan", "warning")
        return
        
    stop_scan.clear()
    thread_count = max(1, min(thread_count, config.MAX_THREADS))
    print_header("CRLF Injection Scan (Enhanced)", color="cyan")
    print_status(f"Scanning {len(crawled_urls)} URLs", "info")
    
    payloads = load_crlf_payloads(os.path.join(config.DATA_DIR, 'crlfpayload.txt'))
    print_status(f"Loaded {len(payloads)} advanced CRLF payloads", "info")

    # Track tested (url, param, payload) combinations to avoid duplicates
    tested_combinations = set()

    try:
        for url in crawled_urls:
            if stop_scan.is_set(): break
            
            params = _params(url)
            if not params:
                if verbose:
                    print_status(f"No parameters in {url}, skipping", "debug")
                continue
            
            print_status(f"Testing URL: {url}", "info")
            result_manager = ResultManager(_domain(url))
            
            # Capture baseline response for false positive prevention
            baseline_headers = ""
            baseline_text = ""
            try:
                baseline_response = http.get(url, headers=generate_random_headers(), timeout=config.REQUEST_TIMEOUT, verify=False)
                baseline_headers = "\r\n".join(f"{k}: {v}" for k, v in baseline_response.headers.items())
                baseline_text = baseline_response.text or ""
                if verbose:
                    print_status(f"Captured baseline response ({len(baseline_text)} chars)", "debug")
            except Exception as e:
                logger.debug(f"Failed to capture baseline: {e}")

            with ThreadPoolExecutor(max_workers=thread_count) as executor:
                futures = {}
                for param, original in params.items():
                    if result_manager.has_duplicate("CRLF Injection", ["url", "parameter"], {"url": url, "parameter": param}):
                        print_status(f"Skipping parameter '{param}' - CRLF Injection vulnerability already found in previous scan.", "info")
                        continue
                    for payload_entry in payloads:
                        if stop_scan.is_set():
                            break
                        
                        name = payload_entry['name']
                        payload = payload_entry['payload']
                        expected_response = payload_entry['response']
                        
                        # Skip if already tested this combination
                        combo_key = (url, param, payload)
                        if combo_key in tested_combinations:
                            continue
                        tested_combinations.add(combo_key)
                        
                        test_url = _build_url(url, param, payload)
                        
                        if verbose:
                            print_status(f"Testing {name} on {param}", "debug")
                            
                        future = executor.submit(
                            test_crlf_payload, 
                            test_url, 
                            param, 
                            payload, 
                            expected_response,
                            baseline_headers,
                            baseline_text
                        )
                        futures[future] = (param, name)

                for future in as_completed(futures):
                    if stop_scan.is_set(): break
                    
                    try:
                        result = future.result()
                        if result['vulnerable']:
                            print_status("Vulnerability Found!", "success")
                            print_status(f"  URL: {result['url']}", "info")
                            print_status(f"  Parameter: {result['parameter']}", "info")
                            print_status(f"  Payload: {result['payload']}", "info")
                            print_status(f"  Proof Token: {result.get('proof_token', '')}", "info")
                            
                            if result.get('injected_header'):
                                print_status(f"  Injected Header: {result['injected_header']}", "info")
                            
                            evidence = result.get('evidence', {})
                            if evidence.get('snippet'):
                                print_status(f"  Evidence: {evidence['snippet']}", "info")
                            
                            confirmations = []
                            if evidence.get('header_injected'):
                                confirmations.append('new header injected via CRLF')
                            if evidence.get('expected_in_response') and not evidence.get('expected_in_baseline'):
                                confirmations.append('expected response reflected in response body')
                            if evidence.get('response_changed'):
                                confirmations.append('response changed from baseline')
                            
                            if confirmations:
                                print_status(f"  Confirmations: {', '.join(confirmations)}", "info")
                            
                            finding_data = {
                                "url": result['url'],
                                "parameter": result['parameter'],
                                "payload": result['payload'],
                                "proof_token": result.get('proof_token', ''),
                                "poc_url": result['url'],
                                "evidence": evidence,
                                "confirmations": confirmations,
                                "injected": True,
                                "timestamp": datetime.now().isoformat(),
                            }
                            
                            if result.get('injected_header'):
                                finding_data["injected_header"] = result['injected_header']
                            
                            if result.get('response_snippet'):
                                finding_data["response_snippet"] = result['response_snippet']
                            
                            result_manager.add_finding("CRLF Injection", "", finding_data)

                            if not no_prompt:
                                if not ask_continue_scanning():
                                    print_status("Stopping scan...", "warning")
                                    stop_scan.set()
                                    return
                    except Exception as e:
                        logger.error(f"Error in worker: {e}")
                
        print_status("CRLF Scan completed", "info")

    except KeyboardInterrupt:
        from lib.core.interrupt import exit_clean
        exit_clean()
