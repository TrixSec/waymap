# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.
# wp.py high-risk

import requests
from packaging.version import parse as parse_version
from datetime import datetime
from colorama import Fore, Style
from lib.ProfileCritical.plugin_version import detect_plugin_version
from lib.core.settings import CVE_DB_URL
from data.cveinfo import wphighcves


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


def check_plugin_vulnerability(target_url, plugin_name, vulnerable_version):
    """Check if a plugin is vulnerable based on version."""
    version = detect_plugin_version(target_url, plugin_name)
    if version:
        is_vulnerable = parse_version(version) < parse_version(vulnerable_version)
        return {
            "version": version,
            "is_vulnerable": is_vulnerable
        }
    return None


def handle_cve(target_url, cve_id, plugin_name, vulnerable_version):
    """Central function to check CVE and print relevant info."""
    plugin_check_result = check_plugin_vulnerability(target_url, plugin_name, vulnerable_version)

    if plugin_check_result and plugin_check_result["is_vulnerable"]:
        print(f"{Style.BRIGHT}{Fore.GREEN}Detected version: {plugin_check_result['version']} (Vulnerable){Style.RESET_ALL}")

        cve_details = fetch_cve_details(cve_id)

        if cve_details:
            print(f"{Style.BRIGHT}{Fore.CYAN}Summary: {cve_details.get('summary', 'N/A')}{Style.RESET_ALL}")
            print(f"{Style.BRIGHT}{Fore.CYAN}CVSS Score: {cve_details.get('cvss_score', 'N/A')}{Style.RESET_ALL}")
            print(f"{Style.BRIGHT}{Fore.CYAN}Severity: {determine_severity(cve_details.get('cvss_score', 0))}{Style.RESET_ALL}")
    elif plugin_check_result:
        print(f"{Style.BRIGHT}{Fore.YELLOW}Detected version: {plugin_check_result['version']} (Not vulnerable){Style.RESET_ALL}")


def handle_user_interrupt():
    """
    Handles user interruption (Ctrl+C) with a prompt for action.
    """
    print("\n[!] Process interrupted by user. What would you like to do?")
    while True:
            user_input = input(f"{Style.BRIGHT}{Fore.CYAN}Enter 'n' for next CVE, 'e' to exit, or press Enter to resume: {Style.RESET_ALL}")
            if user_input.lower() == 'n':
                print(f"{Style.BRIGHT}{Fore.GREEN}Continuing with next CVE...{Style.RESET_ALL}")
                break 
            elif user_input.lower() == 'e':
                print(f"{Style.BRIGHT}{Fore.RED}Exiting...{Style.RESET_ALL}")
                exit(0) 
            elif user_input == '':
                print(f"{Style.BRIGHT}{Fore.GREEN}Resuming scan...{Style.RESET_ALL}")
                break 
            else:
                print(f"{Style.BRIGHT}{Fore.YELLOW}Invalid input, please try again.{Style.RESET_ALL}")
                continue
            
def check_vulnerabilities(target_url):
    """Function to check all CVEs."""
    print(f"{Style.BRIGHT}{Fore.WHITE}[Testing: Target: {target_url}]{Style.RESET_ALL}")

    found_vulns = False

    try:
        for cve in wphighcves:
            current_time = datetime.now().strftime("%H:%M:%S")
            print(f"[{Fore.BLUE}{current_time}{Style.RESET_ALL}]::{Fore.GREEN}[Checking]{Style.RESET_ALL}~ {cve['cve_id']}")

            try:
                handle_cve(target_url, cve["cve_id"], cve["plugin_name"], cve["vulnerable_version"])
                plugin_check_result = check_plugin_vulnerability(target_url, cve["plugin_name"], cve["vulnerable_version"])
                if plugin_check_result and plugin_check_result["is_vulnerable"]:
                    found_vulns = True
            except Exception as e:
                continue

    except KeyboardInterrupt:
        handle_user_interrupt()

    if not found_vulns:
        print(f"{Style.BRIGHT}{Fore.WHITE}No vulnerabilities found for any CVEs on {target_url}{Style.RESET_ALL}")
