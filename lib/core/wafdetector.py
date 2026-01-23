# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.

"""WAF Detection Module."""

import os
import re
import json
import requests
from urllib.parse import urlparse, urlunparse
from typing import Dict, List, Optional

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from lib.core.config import get_config
from lib.core.logger import get_logger
from lib.ui import print_status, colored

config = get_config()
logger = get_logger(__name__)

def load_waf_rules(json_file: str) -> List[Dict]:
    """Load WAF rules from JSON file."""
    try:
        with open(json_file, 'r') as f:
            waf_rules = json.load(f)
        return waf_rules['wafs']
    except Exception as e:
        logger.error(f"Error loading WAF rules: {e}")
        return []

def match_reason(response_reason: str, reason_patterns: List[str]) -> bool:
    """Match reason code from HTTP response with WAF reason patterns."""
    if not reason_patterns:
        return False
    
    for reason_pattern in reason_patterns:
        try:
            if re.search(reason_pattern, response_reason, re.IGNORECASE):
                return True
        except re.error as e:
            logger.error(f"Invalid regex in reason pattern: {reason_pattern}. Error: {e}")
            return False
    return False

def detect_waf(url: str) -> str:
    """Detect WAF/IPS protection on target URL."""
    rules_file = os.path.join(config.DATA_DIR, 'wafsig.json')
    waf_rules = load_waf_rules(rules_file)
    
    if not waf_rules:
        return "Unknown"
    
    session = requests.Session()
    detected_waf = "Unknown"
    
    parsed_url = urlparse(url)
    domain = parsed_url.netloc if parsed_url.netloc else parsed_url.path
    
    print_status(f"Checking if '{domain}' is protected by WAF/IPS", "info")
    
    for payload_name, payload in config.WAFPAYLOADS.items():
        try:
            response = session.get(
                url, 
                params={'q': payload}, 
                timeout=config.REQUEST_TIMEOUT, 
                verify=False
            )
            
            for waf in waf_rules:
                matched_status = False
                matched_additional = False
                
                # Check status patterns
                status_patterns = waf['errors'].get('status', [])
                if status_patterns:
                    for pattern in status_patterns:
                        if re.search(pattern, str(response.status_code), re.IGNORECASE):
                            matched_status = True
                            break
                
                # Check reason patterns
                reason_patterns = waf['errors'].get('reason', [])
                if match_reason(response.reason, reason_patterns):
                    matched_additional = True
                
                # Check header patterns
                header_patterns = waf['errors'].get('header', [])
                for header, value in response.headers.items():
                    for regexp in header_patterns:
                        if re.search(regexp, f"{header}: {value}", re.IGNORECASE):
                            matched_additional = True
                
                # Check content patterns
                content_patterns = waf['errors'].get('content', [])
                for pattern in content_patterns:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        matched_additional = True
                
                # Check cookie patterns
                cookie_patterns = waf['errors'].get('cookie', [])
                for cookie_name, cookie_value in response.cookies.items():
                    cookie_str = f"{cookie_name}={cookie_value}"
                    for pattern in cookie_patterns:
                        if re.search(pattern, cookie_str, re.IGNORECASE):
                            matched_additional = True
                
                # If matched, return WAF name
                if (not status_patterns or matched_status) and matched_additional:
                    detected_waf = waf['name']
                    print_status(f"WAF Detected: {detected_waf}", "critical")
                    return detected_waf
                    
        except requests.RequestException as e:
            logger.debug(f"Error connecting to {url}: {e}")
            continue
        except KeyboardInterrupt:
            print_status("Scan interrupted by user", "warning")
            return detected_waf
    
    return detected_waf

def clean_url(url: str) -> str:
    """Clean and normalize URL."""
    parsed_url = urlparse(url)
    scheme = parsed_url.scheme or "https"
    netloc = parsed_url.netloc or parsed_url.path
    path = "/"
    cleaned_url = urlunparse((scheme, netloc, path, "", "", ""))
    return cleaned_url

def check_wafs(url: str) -> str:
    """Check for WAF protection on URL."""
    cleaned_url = clean_url(url)
    return detect_waf(cleaned_url)
