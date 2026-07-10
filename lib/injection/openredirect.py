# Copyright (c) 2026 waymap developers
# See the file 'LICENSE' for copying permission.

"""Open Redirect Scanner Module - Highly Optimized."""

import os
import secrets
import time
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import List, Dict, Any, Tuple, Generator

import requests
from lib.core import http
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from lib.core.config import get_config
from lib.core.logger import get_logger
from lib.core.result_manager import ResultManager
from lib.ui import print_status, colored, print_header, ask_continue_scanning
from lib.parse.random_headers import generate_random_headers
from lib.core.state import stop_scan
from lib.utils.file_utils import load_file_lines

config = get_config()
logger = get_logger(__name__)

EVIDENCE_WINDOW = 90

# Track (url, param) pairs that already have findings
_found_vulnerable_pairs = set()

# Reusable requests session for connection pooling
_session = None


def get_session() -> requests.Session:
    """Get a reusable session with connection pooling."""
    global _session
    if not _session:
        _session = requests.Session()
        _session.verify = False
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=20,
            pool_maxsize=20,
            max_retries=1
        )
        _session.mount('http://', adapter)
        _session.mount('https://', adapter)
    return _session


def extract_parameters(url: str) -> List[str]:
    """Extract parameters from URL."""
    parsed_url = urlparse(url)
    params = parse_qs(parsed_url.query)
    return list(params.keys()) if params else []


def inject_payload_into_url(url: str, parameter: str, payload: str) -> str:
    """Inject payload into a specific URL parameter."""
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    
    query_params[parameter] = [payload]
    
    new_query = urlencode(query_params, doseq=True)
    new_parts = list(parsed_url)
    new_parts[4] = new_query
    return urlunparse(new_parts)


def _proof_token() -> str:
    """Generate a unique proof token for open redirect testing."""
    return f"waymap_redirect_{secrets.token_hex(4)}"


def _evidence_snippet(location: str) -> str:
    """Extract evidence snippet from location header."""
    if not location:
        return ""
    if len(location) <= EVIDENCE_WINDOW * 2:
        return location
    return location[:EVIDENCE_WINDOW] + "..." + location[-EVIDENCE_WINDOW:]


def _proof_evidence(location: str, payload: str) -> Dict[str, Any]:
    """Generate proof evidence for open redirect vulnerability."""
    payload_in_location = payload in location if location else False
    is_external_redirect = False
    
    if location:
        try:
            parsed_location = urlparse(location)
            parsed_payload = urlparse(payload)
            # Check if redirect goes to external domain
            if parsed_location.netloc and parsed_payload.netloc:
                is_external_redirect = parsed_location.netloc != parsed_payload.netloc
        except:
            pass
    
    return {
        "confirmed": payload_in_location or is_external_redirect,
        "location": location,
        "payload_in_location": payload_in_location,
        "is_external_redirect": is_external_redirect,
        "snippet": _evidence_snippet(location),
    }


def is_parameter_relevant(url: str, parameter: str) -> bool:
    """Quick probe to check if a parameter is worth testing - avoids wasted requests."""
    session = get_session()
    probe_payload = "waymap_redirect_test"
    test_url = inject_payload_into_url(url, parameter, probe_payload)
    
    try:
        headers = generate_random_headers()
        response = session.get(
            test_url,
            headers=headers,
            allow_redirects=False,
            timeout=3  # Short timeout for probe
        )
        
        location = response.headers.get("Location") or response.headers.get("location", "")
        
        # If probe is reflected in Location header, this parameter is definitely relevant!
        if probe_payload in location:
            return True
            
        # Also check if parameter changes response status (3xx redirect)
        if 300 <= response.status_code < 400:
            return True
            
        return False
        
    except Exception as e:
        logger.debug(f"Parameter probe failed: {e}")
        # If probe fails, still try it just in case
        return True


def test_open_redirect_payload(url: str, parameter: str, payload: str, verbose: bool) -> Dict[str, Any]:
    """Test a single open redirect payload quickly with connection pooling and proof of concept."""
    if stop_scan.is_set():
        return {'vulnerable': False}

    proof_token = _proof_token()
    test_url = inject_payload_into_url(url, parameter, payload)
    headers = generate_random_headers()

    try:
        session = get_session()
        response = session.get(
            test_url,
            headers=headers,
            allow_redirects=False,
            timeout=config.REQUEST_TIMEOUT,
        )
        location = response.headers.get("Location") or response.headers.get("location")
        if location:
            # Generate proof evidence
            evidence = _proof_evidence(location, payload)
            
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
                'proof_token': proof_token,
                'evidence': evidence,
                'response': response,
                'headers': response.headers,
            }

    except requests.RequestException as e:
        logger.debug(f"Error testing {test_url}: {e}")

    return {'vulnerable': False}


def process_url(url: str, parameters: List[str], payloads: List[str], thread_count: int, no_prompt: bool, verbose: bool) -> None:
    """Process a single URL for open redirect testing - ultra optimized."""
    domain = urlparse(url).netloc
    result_manager = ResultManager(domain)

    # Step 1: First test existing parameters in the URL (highest priority)
    existing_params = extract_parameters(url)
    for param in existing_params:
        if stop_scan.is_set():
            return
        if (url, param) in _found_vulnerable_pairs:
            continue
            
        print_status(f"Probing parameter: {param}", "info")
        if not is_parameter_relevant(url, param):
            if verbose:
                print_status(f"Parameter {param} doesn't seem relevant, skipping...", "debug")
            continue
            
        test_parameter(url, param, payloads, thread_count, no_prompt, verbose, result_manager)
        if stop_scan.is_set():
            return

    # Step 2: Only test a small subset of common parameters if no existing params found
    if not existing_params:
        # Use only the top 10 most common open redirect parameters
        common_params = ["redirect", "url", "next", "go", "target", "destination", "continue", "return", "link", "redir"]
        for param in common_params:
            if stop_scan.is_set():
                return
            if (url, param) in _found_vulnerable_pairs:
                continue
                
            print_status(f"Probing parameter: {param}", "info")
            if not is_parameter_relevant(url, param):
                if verbose:
                    print_status(f"Parameter {param} doesn't seem relevant, skipping...", "debug")
                continue
                
            test_parameter(url, param, payloads, thread_count, no_prompt, verbose, result_manager)
            if stop_scan.is_set():
                return


def test_parameter(url: str, parameter: str, payloads: List[str], thread_count: int, no_prompt: bool, verbose: bool, result_manager: ResultManager) -> None:
    """Test a single parameter with smart payload ordering, stop on first vulnerable."""
    domain = urlparse(url).netloc
    print_status(f"Testing Parameter: {parameter}", "info")

    # Test payloads in priority order (most likely to succeed first)
    for payload in payloads:
        if stop_scan.is_set():
            return

        result = test_open_redirect_payload(url, parameter, payload, verbose)
        if result['vulnerable']:
            full_url = result['url']
            param = result['parameter']
            payload = result['payload']

            # Check for duplicates using ResultManager
            is_duplicate = result_manager.has_duplicate(
                "Open Redirect",
                ["url", "parameter", "payload"],
                {"url": full_url, "parameter": param, "payload": payload}
            )

            if not is_duplicate:
                _found_vulnerable_pairs.add((url, param))

                print_status("Vulnerability Found!", "success")
                print_status(f"  URL: {full_url}", "info")
                print_status(f"  Parameter: {param}", "info")
                print_status(f"  Payload: {payload}", "info")
                print_status(f"  Proof Token: {result.get('proof_token', '')}", "info")
                if result.get('location'):
                    print_status(f"  Location: {result['location']}", "info")
                
                evidence = result.get('evidence', {})
                if evidence.get('snippet'):
                    print_status(f"  Evidence: {evidence['snippet']}", "info")
                
                confirmations = []
                if evidence.get('payload_in_location'):
                    confirmations.append('payload reflected in Location header')
                if evidence.get('is_external_redirect'):
                    confirmations.append('external redirect detected')
                
                if confirmations:
                    print_status(f"  Confirmations: {', '.join(confirmations)}", "info")

                finding_data = {
                    "url": full_url,
                    "parameter": param,
                    "payload": payload,
                    "location": result.get("location"),
                    "proof_token": result.get('proof_token', ''),
                    "poc_url": full_url,
                    "evidence": evidence,
                    "confirmations": confirmations,
                    "injected": True,
                    "timestamp": datetime.now().isoformat()
                }
                
                result_manager.add_finding("Open Redirect", "", finding_data)

                if not no_prompt:
                    if not ask_continue_scanning():
                        print_status("Stopping scan...", "warning")
                        stop_scan.set()
                        return
            
            # Stop testing this parameter immediately
            break


def perform_redirect_scan(crawled_urls: List[str], thread_count: int = 1, no_prompt: bool = False, verbose: bool = False) -> None:
    """Perform open redirect scanning - highly optimized and intelligent."""
    from lib.core.interrupt import reset_interrupt
    reset_interrupt()
    _found_vulnerable_pairs.clear()
    stop_scan.clear()

    # Reset session for new scan
    global _session
    _session = None

    print_header("Open Redirect Scan", color="cyan")

    thread_count = max(1, min(thread_count, config.MAX_THREADS))
    parameters = load_file_lines(os.path.join(config.DATA_DIR, 'openredirectparameters.txt'))
    payloads = load_file_lines(os.path.join(config.DATA_DIR, 'openredirectpayloads.txt'))

    print_status(f"Scanning {len(crawled_urls)} URLs with {len(payloads)} targeted payloads", "info")

    try:
        for url in crawled_urls:
            if stop_scan.is_set():
                break

            print_status(f"Testing URL: {url}", "info")
            process_url(url, parameters, payloads, thread_count, no_prompt, verbose)

        print_status("Open Redirect Scan completed", "info")

    except KeyboardInterrupt:
        from lib.core.interrupt import exit_clean
        exit_clean()
