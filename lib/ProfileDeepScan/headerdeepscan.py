# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.

import os
import requests
from urllib.parse import urlparse
import json
import re
from colorama import Fore, Style, init
from datetime import datetime
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from lib.core.settings import HEADERS_TIMEOUT

init(autoreset=True)

SEVERITY_COLORS = {
    "Critical": Fore.RED,
    "High": Fore.LIGHTRED_EX,
    "Medium": Fore.YELLOW,
    "Low": Fore.LIGHTYELLOW_EX,
    "Informational": Fore.BLUE,
}

def fetch_headers(target_url):
    """Fetch headers from the target URL."""
    try:
        response = requests.get(target_url, timeout=HEADERS_TIMEOUT, verify=False)
        return response.headers
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Unable to fetch headers for {target_url}: {e}")
        return {}

def colorize_message(message, severity, is_for_json=False):
    """Add color to a message based on severity and make it bold."""
    color = SEVERITY_COLORS.get(severity, Fore.WHITE)
    colored_message = f"{color}{Style.BRIGHT}{message}{Style.RESET_ALL}"

    if is_for_json:
        return remove_ansi_escape_codes(colored_message)
    return colored_message

def remove_ansi_escape_codes(text):
    """Remove ANSI escape codes from a string."""
    ansi_escape = re.compile(r'\x1b\[[0-9;]*[mK]')
    return ansi_escape.sub('', text)

def analyze_headers(headers, target_url):
    """Analyze headers for potential vulnerabilities."""
    results = []

    try:
        missing_headers = {
            "Content-Security-Policy": ("Prevents XSS, data injection, and other code execution attacks", "High"),
            "Strict-Transport-Security": ("Enforces HTTPS to prevent MITM attacks", "High"),
            "X-Frame-Options": ("Prevents clickjacking", "Medium"),
            "X-Content-Type-Options": ("Prevents MIME sniffing", "Medium"),
            "Referrer-Policy": ("Controls referrer information", "Low"),
            "Permissions-Policy": ("Controls browser features", "Medium"),
            "Cross-Origin-Resource-Policy": ("Prevents unauthorized resource sharing", "High")
        }
        for header, (desc, severity) in missing_headers.items():
            if header not in headers:
                results.append(colorize_message(f"[MISSING] {header} - {desc} (Severity: {severity})", severity))

        duplicate_headers = [header for header in headers.keys() if list(headers.keys()).count(header) > 1]
        if duplicate_headers:
            results.append(colorize_message(f"[DUPLICATE] Duplicate headers detected: {', '.join(duplicate_headers)} - May cause unexpected behavior (Severity: Medium)", "Medium"))

        for header, value in headers.items():
            if len(value) > 500:
                results.append(colorize_message(f"[WARNING] Unusually long header detected: {header} - May indicate malicious payloads (Severity: Medium)", "Medium"))

        if "Strict-Transport-Security" in headers:
            hsts_value = headers["Strict-Transport-Security"]
            if "max-age=" not in hsts_value:
                results.append(colorize_message("[IMPROPER] HSTS missing max-age directive (Severity: High)", "High"))
            if "preload" not in hsts_value:
                results.append(colorize_message("[IMPROPER] HSTS preload missing (Severity: High)", "High"))

        if "Authorization" in headers and "Bearer" in headers["Authorization"]:
            results.append(colorize_message("[INFO] JWT Token detected in Authorization header. Ensure proper validation (Severity: High)", "High"))

        if "Content-Security-Policy" in headers:
            if "*" in headers["Content-Security-Policy"] or "unsafe-" in headers["Content-Security-Policy"]:
                results.append(colorize_message("[IMPROPER] Overly permissive CSP rules detected (Severity: High)", "High"))

        if "Access-Control-Allow-Origin" in headers and headers["Access-Control-Allow-Origin"] != target_url:
            results.append(colorize_message("[WARNING] CORS policy may expose sensitive data to unauthorized origins (Severity: High)", "High"))

        server_software = headers.get("Server", "").lower()
        if "apache" in server_software:
            results.append(colorize_message("[INFO] Server identified as Apache. Check for Apache-specific CVEs (Severity: Informational)", "Informational"))
        if "nginx" in server_software:
            results.append(colorize_message("[INFO] Server identified as Nginx. Check for Nginx-specific CVEs (Severity: Informational)", "Informational"))

        if "Permissions-Policy" in headers:
            if "*" in headers["Permissions-Policy"]:
                results.append(colorize_message("[IMPROPER] Overly permissive Permissions-Policy detected (Severity: High)", "High"))

        if "Expect-CT" in headers:
            if "enforce" not in headers["Expect-CT"]:
                results.append(colorize_message("[IMPROPER] Expect-CT header missing enforce directive (Severity: High)", "High"))

        if "Clear-Site-Data" in headers:
            results.append(colorize_message("[INFO] Clear-Site-Data header detected. Ensure correct usage on logout (Severity: Low)", "Low"))

        if "X-Permitted-Cross-Domain-Policies" in headers:
            if "none" not in headers["X-Permitted-Cross-Domain-Policies"]:
                results.append(colorize_message("[WARNING] Weak X-Permitted-Cross-Domain-Policies (Severity: Medium)", "Medium"))

        if "X-XSS-Protection" in headers:
            if headers["X-XSS-Protection"] != "1; mode=block":
                results.append(colorize_message("[IMPROPER] X-XSS-Protection header misconfigured (Severity: Medium)", "Medium"))

        if "X-Content-Type-Options" in headers:
            if headers["X-Content-Type-Options"] != "nosniff":
                results.append(colorize_message("[IMPROPER] X-Content-Type-Options header misconfigured (Severity: Medium)", "Medium"))

        if "Referrer-Policy" in headers:
            if headers["Referrer-Policy"] not in ["no-referrer", "strict-origin"]:
                results.append(colorize_message("[IMPROPER] Weak Referrer-Policy header detected (Severity: Medium)", "Medium"))

        if "X-Frame-Options" in headers:
            if headers["X-Frame-Options"] not in ["DENY", "SAMEORIGIN"]:
                results.append(colorize_message("[IMPROPER] X-Frame-Options header misconfigured (Severity: High)", "High"))

        if "Cache-Control" in headers:
            if "no-store" not in headers["Cache-Control"] and "private" not in headers["Cache-Control"]:
                results.append(colorize_message("[WARNING] Cache-Control header misconfigured (Severity: Medium)", "Medium"))

        if "Set-Cookie" in headers:
            set_cookie_values = headers.get("Set-Cookie")
            if isinstance(set_cookie_values, str):
                set_cookie_values = [set_cookie_values]
            elif not isinstance(set_cookie_values, list):
                set_cookie_values = []
            for cookie in set_cookie_values:
                if "HttpOnly" not in cookie or "Secure" not in cookie:
                    results.append(colorize_message("[WARNING] Cookie is not secure (Severity: Medium)", "Medium"))
    except Exception as e:
        results.append(colorize_message(f"[ERROR] Headers Analysis failed: {e}", "Critical"))
    return results

def generate_risk_summary(results):
    """Generate a categorized risk report summarizing high, medium, and low severity issues."""
    high = [r for r in results if "Severity: High" in r]
    medium = [r for r in results if "Severity: Medium" in r]
    low = [r for r in results if "Severity: Low" in r]
    informational = [r for r in results if "Severity: Informational" in r]

    print(colorize_message(f"[INFO] Risk Summary:", "Informational"))
    print(colorize_message(f"- High: {len(high)}", "High"))
    print(colorize_message(f"- Medium: {len(medium)}", "Medium"))
    print(colorize_message(f"- Low: {len(low)}", "Low"))
    print(colorize_message(f"- Informational: {len(informational)}", "Informational"))

def save_results(target_url, results):
    """Save results using flat list-style 'scans' format for compatibility."""
    domain = urlparse(target_url).netloc
    folder = os.path.join("sessions", domain)
    os.makedirs(folder, exist_ok=True)

    file_path = os.path.join(folder, "waymap_full_results.json")

    scan_entry = {
        "type": "Headers Deepscan",
        "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "results": [remove_ansi_escape_codes(result) for result in results]
    }

    if os.path.exists(file_path):
        with open(file_path, "r") as file:
            try:
                existing_data = json.load(file)
            except json.JSONDecodeError:
                existing_data = {}
    else:
        existing_data = {}

    if "scans" not in existing_data or not isinstance(existing_data["scans"], list):
        existing_data["scans"] = []

    for entry in existing_data["scans"]:
        if isinstance(entry, dict) and entry.get("results") == scan_entry["results"]:
            print(colorize_message("[INFO] Duplicate results found. Skipping save.", "Informational"))
            return

    existing_data["scans"].append(scan_entry)

    with open(file_path, "w") as file:
        json.dump(existing_data, file, indent=4)

    print(colorize_message("[INFO] Scan results saved successfully.", "Informational"))


def headersdeepscan(target_url):
    """Performs a deep scan on HTTP headers."""
    if not target_url.startswith("http://") and not target_url.startswith("https://"):
        print(colorize_message("[ERROR] Invalid URL. Please include http:// or https://", "Critical"))
        return

    headers = fetch_headers(target_url)
    if not headers:
        return

    results = analyze_headers(headers, target_url)
    if results:
        print(colorize_message("\n[INFO] Potential Issues Found:", "Informational"))
        for result in results:
            print(result)

        generate_risk_summary(results)
        save_results(target_url, results)
    else:
        print(colorize_message("[INFO] No major issues detected.", "Informational"))
