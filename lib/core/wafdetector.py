# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.

import requests
import re
import json
from colorama import Fore, Style, init
from urllib.parse import urlparse, urlunparse
import os
from termcolor import colored
import sys
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from lib.core.settings import WAFPAYLOADS
init(autoreset=True)

def load_waf_rules(json_file):
    """Loads the WAF rules from a JSON file."""
    with open(json_file, 'r') as f:
        waf_rules = json.load(f)
    return waf_rules['wafs']

def match_reason(response_reason, reason_patterns):
    """Matches the reason code from the HTTP response with the WAF reason patterns."""
    if not reason_patterns:
        return False 
    for reason_pattern in reason_patterns:
        try:
            if re.search(reason_pattern, response_reason, re.IGNORECASE):
                return True
        except re.error as e:
            print(f"{Fore.RED}[ERROR] Invalid regex in reason pattern: {reason_pattern}. Error: {e}")
            return False
    return False

def detect_waf(url):

    rules_file = os.path.join('data', 'wafsig.json')  
    waf_rules = load_waf_rules(rules_file)
    session = requests.Session()
    detected_waf = "Unknown"

    parsed_url = urlparse(url)
    domain = parsed_url.netloc if parsed_url.netloc else parsed_url.path

    print(f"\n\033[42m\033[97m[INFO]\033[0m{Style.RESET_ALL} Checking if the target '{Fore.CYAN}{domain}{Style.RESET_ALL}' is protected by some kind of WAF/IPS\n")

    for payload_name, payload in WAFPAYLOADS.items():
        try:
            response = session.get(url, params={'q': payload}, timeout=10, verify=False)

            for waf in waf_rules:
                matched_status = False
                matched_additional = False

                status_patterns = waf['errors'].get('status', [])
                if status_patterns:
                    for pattern in status_patterns:
                        if re.search(pattern, str(response.status_code), re.IGNORECASE):
                            matched_status = True
                            break

                reason_patterns = waf['errors'].get('reason', [])
                if match_reason(response.reason, reason_patterns):
                    matched_additional = True

                header_patterns = waf['errors'].get('header', [])
                for header, value in response.headers.items():
                    for regexp in header_patterns:
                        if re.search(regexp, f"{header}: {value}", re.IGNORECASE):
                            matched_additional = True

                content_patterns = waf['errors'].get('content', [])
                for pattern in content_patterns:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        matched_additional = True

                cookie_patterns = waf['errors'].get('cookie', [])
                for cookie_name, cookie_value in response.cookies.items():
                    cookie_str = f"{cookie_name}={cookie_value}"
                    for pattern in cookie_patterns:
                        if re.search(pattern, cookie_str, re.IGNORECASE):
                            matched_additional = True

                if (not status_patterns or matched_status) and matched_additional:
                    detected_waf = waf['name']
                    print(
                        f"\n{Fore.GREEN}{Style.BRIGHT}\033[41m[CRITICAL]\033[0m WAF Detected: {detected_waf}{Style.RESET_ALL}"
                    )
                    return detected_waf

        except requests.RequestException as e:
            print(f"{Fore.RED}Error connecting to {url}: {e}{Style.RESET_ALL}")
            continue

        except KeyboardInterrupt:
            print(colored("\n[!] Scan interrupted by user. Exiting cleanly...", 'red'))
            sys.exit(0)
    return detected_waf

def clean_url(url):
    parsed_url = urlparse(url)

    scheme = parsed_url.scheme or "https"
    netloc = parsed_url.netloc or parsed_url.path
    path = "/"  
    cleaned_url = urlunparse((scheme, netloc, path, "", "", ""))
    return cleaned_url

def check_wafs(url):
    cleaned_url = clean_url(url)
    return detect_waf(cleaned_url)
