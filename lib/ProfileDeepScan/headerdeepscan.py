# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.

import os
import requests
from urllib.parse import urlparse
import json
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

def colorize_message(message, severity):
    """Add color to a message based on severity and make it bold."""
    color = SEVERITY_COLORS.get(severity, Fore.WHITE)
    return f"{color}{Style.BRIGHT}{message}{Style.RESET_ALL}"

def analyze_headers(headers, target_url):
    """Analyze headers for potential vulnerabilities."""
    results = []

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

    if "Strict-Transport-Security" in headers:
        if "preload" not in headers["Strict-Transport-Security"]:
            results.append(colorize_message("[IMPROPER] HSTS preload missing (Severity: High)", "High"))

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
        cookies = headers["Set-Cookie"].split(",")
        for cookie in cookies:
            if "HttpOnly" not in cookie or "Secure" not in cookie:
                results.append(colorize_message("[WARNING] Cookie is not secure (Severity: Medium)", "Medium"))

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
    """Save the results to a JSON file with the target domain and timestamp."""
    domain = urlparse(target_url).netloc
    folder = os.path.join("sessions", domain)
    os.makedirs(folder, exist_ok=True)

    scan_data = {
        "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "results": results
    }

    file_path = os.path.join(folder, "headers_deepscan_results.json")

    if os.path.exists(file_path):
        with open(file_path, "r") as file:
            existing_data = json.load(file)
        existing_data.append(scan_data)
        with open(file_path, "w") as file:
            json.dump(existing_data, file, indent=4)
    else:
        with open(file_path, "w") as file:
            json.dump([scan_data], file, indent=4)

def headersdeepscan(target_url):
    
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