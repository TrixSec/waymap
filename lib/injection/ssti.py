# Copyright (c) 2026 waymap developers
# See the file 'LICENSE' for copying permission.

"""SSTI Scanner Module with Enhanced Engine Detection."""

import os
import re
import secrets
import requests
from lib.core import http
from functools import lru_cache
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Set

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

# Template engine signatures based on tplmap analysis
ENGINE_SIGNATURES = {
    'jinja2': [
        r'\{\{.*?\}\}',
        r'\{\%.*?\%\}',
        r'\{#.*?#\}',
        r'__class__',
        r'__mro__',
        r'__subclasses__',
        r'config\.items\(\)',
        r'url_for',
        r'get_flashed_messages',
    ],
    'twig': [
        r'\{\{.*?\}\}',
        r'\{\%.*?\%\}',
        r'\{#.*?#\}',
        r'_self\.env',
        r'_self\.env\.registerUndefinedFilterCallback',
        r'nl2br',
        r'upper',
        r'lower',
    ],
    'smarty': [
        r'\{.*?\}',
        r'\{php.*?\/php\}',
        r'\{\/if\}',
        r'\{\/foreach\}',
        r'\$smarty',
        r'\$smarty\.version',
        r'\$smarty\.template_dir',
    ],
    'freemarker': [
        r'\$\{.*?\}',
        r'<#.*?>',
        r'<#--.*?-->',
        r'<#assign',
        r'<#list',
        r'<#if',
        r'\?c',
        r'\?upper_case',
        r'\?lower_case',
        r'freemarker\.template\.utility\.Execute',
    ],
    'mako': [
        r'\$\{.*?\}',
        r'<%.*?%>',
        r'<%doc>.*?</%doc>',
        r'<%include',
        r'<%def',
        r'context',
        r'self\.',
        r'local\.',
    ],
    'velocity': [
        r'\$\{.*?\}',
        r'#set\(',
        r'#if\(',
        r'#foreach\(',
        r'#end',
        r'\$context',
        r'\$request',
        r'\$response',
    ],
    'erb': [
        r'<%=.*?%>',
        r'<%.*?%>',
        r'<%#.*?%>',
        r'File\.open',
        r'IO\.popen',
        r'eval\(',
        r'system\(',
    ],
    'pug': [
        r'#\{.*?\}',
        r'\.\.\.',
        r'include',
        r'mixin',
        r'block',
    ],
    'nunjucks': [
        r'\{\{.*?\}\}',
        r'\{\%.*?\%\}',
        r'\{#.*?#\}',
        r'context',
        r'env',
        r'filters',
    ],
    'tornado': [
        r'\{\{.*?\}\}',
        r'\{\%.*?\%\}',
        r'\{#.*?#\}',
        r'escape\(',
        r'handler\.',
        r'application\.',
        r'request\.',
    ],
    'dust': [
        r'\{.*?\}',
        r'\{s.*?\}',
        r'\{/s\}',
        r'\{>.*?\}',
        r'\{~s\}',
    ],
    'marko': [
        r'\$\{.*?\}',
        r'<\$.*?\$>',
        r'<@.*?>',
        r'<include',
        r'<for',
    ],
    'slim': [
        r'#\{.*?\}',
        r'=.*?',
        r'div\.',
        r'div#',
    ],
    'ejs': [
        r'<%=.*?%>',
        r'<%.*?%>',
        r'<%-.*?%>',
        r'<%_.*?%>',
    ],
    'java': [
        r'\$\{.*?\}',
        r'T\(java\.lang\.',
        r'T\(java\.util\.',
        r'T\(java\.io\.',
        r'Runtime\.',
        r'ProcessBuilder\.',
    ],
    'razor': [
        r'@\(.*?\)',
        r'@\{.*?\}',
        r'@model',
        r'@Html\.',
        r'@Url\.',
        r'@RenderBody\(\)',
    ],
}


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
    """Generate a unique proof token for SSTI testing."""
    return f"waymap_ssti_{secrets.token_hex(4)}"


def _evidence_snippet(response_text: str, expected_response: str) -> str:
    """Extract evidence snippet from response text."""
    if not expected_response or expected_response not in response_text:
        return ""
    position = response_text.find(expected_response)
    start = max(0, position - EVIDENCE_WINDOW)
    end = min(len(response_text), position + len(expected_response) + EVIDENCE_WINDOW)
    return response_text[start:end].replace("\r", " ").replace("\n", " ").strip()


def _proof_evidence(response_text: str, expected_response: str, baseline_text: str = "") -> Dict[str, Any]:
    """Generate proof evidence for SSTI vulnerability."""
    expected_in_response = expected_response in response_text
    expected_in_baseline = expected_response in baseline_text if baseline_text else False
    response_changed = response_text != baseline_text if baseline_text else True
    
    return {
        "confirmed": expected_in_response and not expected_in_baseline and response_changed,
        "expected_response": expected_response,
        "expected_in_response": expected_in_response,
        "expected_in_baseline": expected_in_baseline,
        "response_changed": response_changed,
        "snippet": _evidence_snippet(response_text, expected_response),
    }


@lru_cache(maxsize=None)
def load_ssti_payloads(file_path: str) -> List[Dict[str, str]]:
    """Load SSTI payloads from a file."""
    return load_named_payloads(file_path, ("name", "payload", "response"))


def detect_engine_from_response(response_text: str, payload: str) -> Set[str]:
    """Detect template engine from response based on signatures."""
    detected_engines = set()
    
    # Check response for engine-specific error messages (reliable indicator)
    error_signatures = {
        'jinja2': ['jinja2', 'jinja', 'template error', 'template syntax error', 'templatenotfound'],
        'twig': ['twig', 'twig error', 'template error', 'twig_'],
        'smarty': ['smarty', 'smarty error', 'template error', 'smarty_internal_'],
        'freemarker': ['freemarker', 'template error', 'freemarker.template'],
        'mako': ['mako', 'template error', 'mako.exceptions'],
        'velocity': ['velocity', 'template error', 'velocityerror'],
        'erb': ['erb', 'ruby template', 'actionview'],
        'java': ['java.lang', 'java.util', 'template error', 'jsp'],
        'razor': ['razor', 'asp.net', 'template error', 'system.web.razor'],
    }
    
    response_lower = response_text.lower()
    for engine, signatures in error_signatures.items():
        for sig in signatures:
            if sig in response_lower:
                detected_engines.add(engine)
                break
    
    # Only check payload reflection if we have error signatures (indicates template processing)
    if detected_engines and payload in response_text:
        # Try to identify engine from reflected payload syntax
        for engine, patterns in ENGINE_SIGNATURES.items():
            for pattern in patterns:
                if re.search(pattern, payload, re.IGNORECASE):
                    detected_engines.add(engine)
                    break
    
    return detected_engines


def test_ssti_payload(url: str, parameter: str, payload: str, expected_response: str, 
                      engine_detection: bool = True, baseline_text: str = "") -> Dict[str, Any]:
    """Test a given SSTI payload with engine detection and strict false positive prevention."""
    if stop_scan.is_set():
        return None

    # Skip payloads with empty or very common expected responses (high false positive rate)
    if not expected_response or expected_response in ["", "test", "TEST", "root:", ""]:
        return None

    proof_token = _proof_token()
    headers = generate_random_headers()
    try:
        response = http.get(
            url, 
            headers=headers, 
            timeout=config.REQUEST_TIMEOUT, 
            verify=False
        )
        
        # Only report if expected response is found
        if expected_response and expected_response in response.text:
            # Strict false positive prevention (tplmap-style)
            if baseline_text:
                # Check if expected response existed in baseline
                if expected_response in baseline_text:
                    logger.debug(f"Expected response '{expected_response}' found in baseline, skipping as false positive")
                    return None
                
                # Check if response is identical to baseline
                if response.text == baseline_text:
                    logger.debug(f"Response identical to baseline, skipping as false positive")
                    return None
                
                # Additional check: for numeric expected responses, ensure they're new in the response
                # and not just part of existing content
                if expected_response.isdigit():
                    # Count occurrences in baseline vs response
                    baseline_count = baseline_text.count(expected_response)
                    response_count = response.text.count(expected_response)
                    if response_count <= baseline_count:
                        logger.debug(f"Numeric expected response '{expected_response}' not increased in response, skipping")
                        return None
            
            detected_engines = detect_engine_from_response(response.text, payload) if engine_detection else set()
            
            # Generate proof evidence
            evidence = _proof_evidence(response.text, expected_response, baseline_text)
            
            return {
                'vulnerable': True, 
                'url': url, 
                'parameter': parameter, 
                'payload': payload, 
                'expected_response': expected_response,
                'proof_token': proof_token,
                'detected_engines': list(detected_engines),
                'evidence': evidence,
                'response': response,
                'headers': response.headers,
                'response_snippet': response.text[:500] if len(response.text) > 500 else response.text
            }
            
    except requests.RequestException as e:
        logger.debug(f"Error testing {url}: {e}")

    return None


def perform_ssti_scan(crawled_urls: List[str], thread_count: int = 1, no_prompt: bool = False, verbose: bool = False) -> None:
    """Perform SSTI scanning with enhanced engine detection."""
    if not crawled_urls:
        print_status("No URLs to scan", "warning")
        return
        
    stop_scan.clear()
    thread_count = max(1, min(thread_count, config.MAX_THREADS))
    print_header("Server-Side Template Injection Scan (Enhanced)", color="cyan")
    print_status(f"Scanning {len(crawled_urls)} URLs", "info")
    
    payloads = load_ssti_payloads(os.path.join(config.DATA_DIR, 'sstipayload.txt'))
    print_status(f"Engine detection enabled for {len(ENGINE_SIGNATURES)} template engines", "info")

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
            detected_engines_for_url = set()
            
            # Capture baseline response for false positive prevention (tplmap-style)
            baseline_text = ""
            try:
                baseline_response = http.get(url, headers=generate_random_headers(), timeout=config.REQUEST_TIMEOUT, verify=False)
                baseline_text = baseline_response.text
                if verbose:
                    print_status(f"Captured baseline response ({len(baseline_text)} chars)", "debug")
            except Exception as e:
                logger.debug(f"Failed to capture baseline: {e}")
            
            with ThreadPoolExecutor(max_workers=thread_count) as executor:
                futures = {}
                for param, original in params.items():
                    if result_manager.has_duplicate("SSTI", ["url", "parameter"], {"url": url, "parameter": param}):
                        print_status(f"Skipping parameter '{param}' - SSTI vulnerability already found in previous scan.", "info")
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
                            
                        future = executor.submit(test_ssti_payload, test_url, param, payload, expected_response, False, baseline_text)
                        futures[future] = (param, name)

                for future in as_completed(futures):
                    if stop_scan.is_set(): break
                    
                    try:
                        result = future.result()
                        if result:
                            print_status("Vulnerability Found!", "success")
                            print_status(f"  URL: {result['url']}", "info")
                            print_status(f"  Parameter: {result['parameter']}", "info")
                            print_status(f"  Payload: {result['payload']}", "info")
                            print_status(f"  Proof Token: {result.get('proof_token', '')}", "info")
                            
                            if result.get('detected_engines'):
                                detected_engines = result['detected_engines']
                                detected_engines_for_url.update(detected_engines)
                                print_status(f"  Detected Engines: {', '.join(detected_engines)}", "success")
                            
                            evidence = result.get('evidence', {})
                            if evidence.get('snippet'):
                                print_status(f"  Evidence: {evidence['snippet']}", "info")
                            
                            print_status("  Confirmations: expected response reflected in response, response changed from baseline", "info")
                            
                            finding_data = {
                                "url": result['url'],
                                "parameter": result['parameter'],
                                "payload": result['payload'],
                                "expected_response": result['expected_response'],
                                "proof_token": result.get('proof_token', ''),
                                "poc_url": result['url'],
                                "evidence": evidence,
                                "confirmations": [
                                    'expected response reflected in response body',
                                    'response changed from baseline',
                                    'expected response not present in baseline',
                                ],
                                "injected": True,
                                "timestamp": datetime.now().isoformat(),
                            }
                            
                            if result.get('detected_engines'):
                                finding_data["detected_engines"] = result['detected_engines']
                            
                            if result.get('response_snippet'):
                                finding_data["response_snippet"] = result['response_snippet']
                            
                            result_manager.add_finding("SSTI", "", finding_data)
                            
                            if not no_prompt:
                                if not ask_continue_scanning():
                                    print_status("Stopping scan...", "warning")
                                    stop_scan.set()
                                    return
                    except Exception as e:
                        logger.error(f"Error in worker: {e}")
            
            # Print summary for this URL
            if detected_engines_for_url:
                print_status(f"URL Summary: Detected {len(detected_engines_for_url)} template engine(s): {', '.join(detected_engines_for_url)}", "success")
                        
        print_status("SSTI Scan completed", "info")

    except KeyboardInterrupt:
        from lib.core.interrupt import exit_clean
        exit_clean()
