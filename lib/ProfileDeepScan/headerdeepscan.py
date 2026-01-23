# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.

"""HTTP Headers Deep Scan Module."""

import os
import re
import json
import requests
from urllib.parse import urlparse
from datetime import datetime
from typing import List, Dict, Tuple

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from lib.core.config import get_config
from lib.core.logger import get_logger
from lib.ui import print_status, colored

config = get_config()
logger = get_logger(__name__)

SEVERITY_LEVELS = {
    "Critical": "critical",
    "High": "error",
    "Medium": "warning",
    "Low": "info",
    "Informational": "debug"
}

def fetch_headers(target_url: str) -> Dict[str, str]:
    """Fetch headers from the target URL."""
    try:
        response = requests.get(
            target_url, 
            timeout=config.HEADERS_TIMEOUT, 
            verify=False
        )
        return dict(response.headers)
    except Exception as e:
        logger.error(f"Unable to fetch headers for {target_url}: {e}")
        return {}

def analyze_headers(headers: Dict[str, str], target_url: str) -> List[Tuple[str, str]]:
    """Analyze headers for potential vulnerabilities."""
    results = []
    
    try:
        # Missing security headers
        missing_headers = {
            "Content-Security-Policy": ("Prevents XSS, data injection attacks", "High"),
            "Strict-Transport-Security": ("Enforces HTTPS to prevent MITM", "High"),
            "X-Frame-Options": ("Prevents clickjacking", "Medium"),
            "X-Content-Type-Options": ("Prevents MIME sniffing", "Medium"),
            "Referrer-Policy": ("Controls referrer information", "Low"),
            "Permissions-Policy": ("Controls browser features", "Medium"),
            "Cross-Origin-Resource-Policy": ("Prevents unauthorized resource sharing", "High")
        }
        
        for header, (desc, severity) in missing_headers.items():
            if header not in headers:
                results.append((f"[MISSING] {header} - {desc}", severity))
        
        # Duplicate headers check
        duplicate_headers = [h for h in headers.keys() if list(headers.keys()).count(h) > 1]
        if duplicate_headers:
            results.append((f"[DUPLICATE] Headers: {', '.join(duplicate_headers)}", "Medium"))
        
        # Unusually long headers
        for header, value in headers.items():
            if len(value) > 500:
                results.append((f"[WARNING] Long header: {header}", "Medium"))
        
        # HSTS validation
        if "Strict-Transport-Security" in headers:
            hsts_value = headers["Strict-Transport-Security"]
            if "max-age=" not in hsts_value:
                results.append(("[IMPROPER] HSTS missing max-age directive", "High"))
            if "preload" not in hsts_value:
                results.append(("[IMPROPER] HSTS preload missing", "High"))
        
        # JWT Token detection
        if "Authorization" in headers and "Bearer" in headers["Authorization"]:
            results.append(("[INFO] JWT Token detected. Ensure proper validation", "High"))
        
        # CSP validation
        if "Content-Security-Policy" in headers:
            csp = headers["Content-Security-Policy"]
            if "*" in csp or "unsafe-" in csp:
                results.append(("[IMPROPER] Overly permissive CSP rules", "High"))
        
        # CORS validation
        if "Access-Control-Allow-Origin" in headers:
            if headers["Access-Control-Allow-Origin"] != target_url:
                results.append(("[WARNING] CORS may expose sensitive data", "High"))
        
        # Server identification
        server_software = headers.get("Server", "").lower()
        if "apache" in server_software:
            results.append(("[INFO] Server: Apache. Check for CVEs", "Informational"))
        if "nginx" in server_software:
            results.append(("[INFO] Server: Nginx. Check for CVEs", "Informational"))
        
        # Permissions-Policy validation
        if "Permissions-Policy" in headers:
            if "*" in headers["Permissions-Policy"]:
                results.append(("[IMPROPER] Overly permissive Permissions-Policy", "High"))
        
        # Expect-CT validation
        if "Expect-CT" in headers:
            if "enforce" not in headers["Expect-CT"]:
                results.append(("[IMPROPER] Expect-CT missing enforce directive", "High"))
        
        # X-XSS-Protection validation
        if "X-XSS-Protection" in headers:
            if headers["X-XSS-Protection"] != "1; mode=block":
                results.append(("[IMPROPER] X-XSS-Protection misconfigured", "Medium"))
        
        # X-Content-Type-Options validation
        if "X-Content-Type-Options" in headers:
            if headers["X-Content-Type-Options"] != "nosniff":
                results.append(("[IMPROPER] X-Content-Type-Options misconfigured", "Medium"))
        
        # Referrer-Policy validation
        if "Referrer-Policy" in headers:
            if headers["Referrer-Policy"] not in ["no-referrer", "strict-origin"]:
                results.append(("[IMPROPER] Weak Referrer-Policy", "Medium"))
        
        # X-Frame-Options validation
        if "X-Frame-Options" in headers:
            if headers["X-Frame-Options"] not in ["DENY", "SAMEORIGIN"]:
                results.append(("[IMPROPER] X-Frame-Options misconfigured", "High"))
        
        # Cache-Control validation
        if "Cache-Control" in headers:
            cache_control = headers["Cache-Control"]
            if "no-store" not in cache_control and "private" not in cache_control:
                results.append(("[WARNING] Cache-Control misconfigured", "Medium"))
        
        # Cookie security
        if "Set-Cookie" in headers:
            set_cookie_values = headers.get("Set-Cookie")
            if isinstance(set_cookie_values, str):
                set_cookie_values = [set_cookie_values]
            elif not isinstance(set_cookie_values, list):
                set_cookie_values = []
                
            for cookie in set_cookie_values:
                if "HttpOnly" not in cookie or "Secure" not in cookie:
                    results.append(("[WARNING] Insecure cookie detected", "Medium"))
                    
    except Exception as e:
        logger.error(f"Headers analysis failed: {e}")
        results.append((f"[ERROR] Analysis failed: {e}", "Critical"))
    
    return results

def generate_risk_summary(results: List[Tuple[str, str]]) -> None:
    """Generate a categorized risk report."""
    high = [r for r in results if r[1] == "High"]
    medium = [r for r in results if r[1] == "Medium"]
    low = [r for r in results if r[1] == "Low"]
    informational = [r for r in results if r[1] == "Informational"]
    
    print_status("Risk Summary:", "info")
    print_status(f"- High: {len(high)}", "error")
    print_status(f"- Medium: {len(medium)}", "warning")
    print_status(f"- Low: {len(low)}", "info")
    print_status(f"- Informational: {len(informational)}", "debug")

def save_results(target_url: str, results: List[Tuple[str, str]]) -> None:
    """Save results to JSON file."""
    domain = urlparse(target_url).netloc
    session_dir = config.get_domain_session_dir(domain)
    file_path = os.path.join(session_dir, "waymap_full_results.json")
    
    scan_entry = {
        "type": "Headers Deepscan",
        "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "results": [{"message": msg, "severity": sev} for msg, sev in results]
    }
    
    existing_data = {"scans": []}
    if os.path.exists(file_path):
        try:
            with open(file_path, "r") as f:
                existing_data = json.load(f)
        except json.JSONDecodeError:
            pass
    
    if "scans" not in existing_data or not isinstance(existing_data["scans"], list):
        existing_data["scans"] = []
    
    # Check for duplicates
    for entry in existing_data["scans"]:
        if isinstance(entry, dict) and entry.get("results") == scan_entry["results"]:
            print_status("Duplicate results found. Skipping save.", "info")
            return
    
    existing_data["scans"].append(scan_entry)
    
    try:
        with open(file_path, "w") as f:
            json.dump(existing_data, f, indent=4)
        print_status("Scan results saved successfully.", "success")
    except Exception as e:
        logger.error(f"Error saving results: {e}")

def headersdeepscan(target_url: str) -> None:
    """Perform deep scan on HTTP headers."""
    if not target_url.startswith(("http://", "https://")):
        print_status("Invalid URL. Please include http:// or https://", "error")
        return
    
    print_status(f"Scanning headers for: {target_url}", "info")
    
    headers = fetch_headers(target_url)
    if not headers:
        return
    
    results = analyze_headers(headers, target_url)
    if results:
        print_status("Potential Issues Found:", "warning")
        for message, severity in results:
            level = SEVERITY_LEVELS.get(severity, "info")
            print_status(message, level)
        
        generate_risk_summary(results)
        save_results(target_url, results)
    else:
        print_status("No major issues detected.", "success")
