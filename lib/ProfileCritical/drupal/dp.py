# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.
# dp.py Critical-risk

import requests
from packaging.version import parse as parse_version
from colorama import Fore, Style
from datetime import datetime
from lib.ProfileCritical.drupal_version import fetch_drupal_version
from lib.core.settings import CVE_DB_URL
from data.cveinfo import CVE_DATACRIT_DRUPAL

def determine_severity(cvss_score):
    """Determine severity based on CVSS v3.x score."""
    if cvss_score == 0.0:
        return "None"
    elif 0.1 <= cvss_score <= 3.9:
        return "Low"
    elif 4.0 <= cvss_score <= 6.9:
        return "Medium"
    elif 7.0 <= cvss_score <= 8.9:
        return "High"
    elif 9.0 <= cvss_score <= 10.0:
        return "Critical"
    return "Unknown"

def fetch_cve_details(cve_id):
    """Fetch CVE details from CVE database."""
    url = CVE_DB_URL.format(cve_id=cve_id)
    response = requests.get(url)
    return response.json() if response.status_code == 200 else {}

def is_vulnerable(version, cve_info):
    """Generic function to check if the version is vulnerable based on CVE info."""
    if version:
        parsed_version = parse_version(version)
        vulnerable_versions = cve_info["vulnerable_version"].split(",")
        
        for v_range in vulnerable_versions:
            v_range = v_range.strip()
            if '-' in v_range: 
                start, end = v_range.split('-')
                if parse_version(start) <= parsed_version <= parse_version(end):
                    return True
            elif parse_version(v_range) == parsed_version:
                return True
    return False

def scan_cve(target_url, cve_id, cve_info):
    """Generic CVE scan function with exception handling for KeyboardInterrupt."""
    try:
        current_time = datetime.now().strftime("%H:%M:%S") 
        print(f"[{Fore.BLUE}{current_time}{Style.RESET_ALL}]::{Fore.GREEN}[Checking]{Style.RESET_ALL}~ {cve_id}")

        print(f"{Style.BRIGHT}{Fore.WHITE}[Testing Target: {target_url}]{Style.RESET_ALL}")

        version = fetch_drupal_version(target_url)
        if version:
            print(f"{Style.BRIGHT}{Fore.CYAN}[i] Detected Drupal version: {version}{Style.RESET_ALL}")
            if is_vulnerable(version, cve_info):
                print(f"{Style.BRIGHT}{Fore.GREEN}[!] Target is vulnerable to {cve_id} ({version}){Style.RESET_ALL}")
                cve_details = fetch_cve_details(cve_id)
                if cve_details:
                    print(f"{Style.BRIGHT}{Fore.CYAN}Summary: {cve_details.get('summary', 'N/A')}{Style.RESET_ALL}")
                    print(f"{Style.BRIGHT}{Fore.CYAN}CVSS Score: {cve_details.get('cvss_score', 'N/A')}{Style.RESET_ALL}")
                    print(f"{Style.BRIGHT}{Fore.CYAN}Severity: {determine_severity(cve_details.get('cvss_score', 0))}{Style.RESET_ALL}")
                print(f"{Style.BRIGHT}{Fore.YELLOW}[!] Recommendation: Update Drupal to a secure version to mitigate {cve_id}.{Style.RESET_ALL}")
            else:
                print(f"{Style.BRIGHT}{Fore.RED}[+] Target is not vulnerable to {cve_id} ({version}).{Style.RESET_ALL}")
        else:
            print(f"{Style.BRIGHT}{Fore.YELLOW}[!] Could not detect Drupal version. Skipping vulnerability checks.{Style.RESET_ALL}")
    except KeyboardInterrupt:
        handle_user_interrupt()

def handle_user_interrupt():
    """Handle user interruption (Ctrl+C) gracefully."""
    print("\n[!] Scan interrupted by user. Options:")
    while True:
        user_input = input(f"{Style.BRIGHT}{Fore.CYAN}Enter 'n' for next target, 'e' to exit, or press Enter to resume: {Style.RESET_ALL}")
        if user_input.lower() == 'n':
            print(f"{Style.BRIGHT}{Fore.GREEN}Skipping to next target...{Style.RESET_ALL}")
            break
        elif user_input.lower() == 'e':
            print(f"{Style.BRIGHT}{Fore.RED}Exiting...{Style.RESET_ALL}")
            exit(0)
        elif user_input == '':
            print(f"{Style.BRIGHT}{Fore.GREEN}Resuming scan...{Style.RESET_ALL}")
            break
        else:
            print(f"{Style.BRIGHT}{Fore.YELLOW}Invalid input. Please try again.{Style.RESET_ALL}")
            continue

def scan_all_cves_for_target(target_url):
    """Scan a target URL against all known CVEs for Drupal."""
    for cve_info in CVE_DATACRIT_DRUPAL:
        scan_cve(target_url, cve_info['cve_id'], cve_info)