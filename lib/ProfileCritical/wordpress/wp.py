# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.
# wp.py critical-risk

import requests
from bs4 import BeautifulSoup
from packaging.version import parse as parse_version, InvalidVersion
from packaging.specifiers import SpecifierSet
from datetime import datetime
from colorama import Fore, Style
from lib.ProfileCritical.plugin_version import detect_plugin_version
from lib.core.settings import CVE_DB_URL
from data.cveinfo import wpcves
from lib.parse.random_headers import generate_random_headers
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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


def fetch_plugins(target_url):
    """Fetch all plugins used on the WordPress site by parsing HTML for plugin paths."""
    headers = generate_random_headers()
    try:
        response = requests.get(target_url, headers=headers, verify=False)
        if response.status_code != 200:
            print(f"Failed to fetch the page: {target_url}")
            return []

        soup = BeautifulSoup(response.text, 'html.parser')

        plugin_paths = set()
        for tag in soup.find_all(['link', 'script'], {'href': True, 'src': True}):
            attr_value = tag.get('href') or tag.get('src')
            if '/wp-content/plugins/' in attr_value:
                plugin_name = attr_value.split('/wp-content/plugins/')[1].split('/')[0]
                plugin_paths.add(plugin_name)

        return list(plugin_paths)

    except Exception as e:
        print(f"Error fetching plugins")
        return []

def check_plugin_vulnerability(target_url, plugin_name, vulnerable_version):
    """Check if a plugin is vulnerable based on version and version constraints."""
    version = detect_plugin_version(target_url, plugin_name)
    if version:
        try:
            if any(op in vulnerable_version for op in ['<', '>', '=', '<=', '>=']):
                spec = SpecifierSet(vulnerable_version)
                is_vulnerable = parse_version(version) in spec
            else:
                is_vulnerable = parse_version(version) < parse_version(vulnerable_version)
            
            return {
                "version": version,
                "is_vulnerable": is_vulnerable
            }
        except InvalidVersion:
            print(f"Invalid version format for plugin {plugin_name}: {vulnerable_version}")
            return None
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
    """Handles user interruption (Ctrl+C) with a prompt for action."""
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
    """Function to check CVEs for matching plugins."""
    print(f"{Style.BRIGHT}{Fore.WHITE}[Testing: Target: {target_url}]{Style.RESET_ALL}")

    found_vulns = False

    try:
        plugins = fetch_plugins(target_url)
        print(f"{Style.BRIGHT}{Fore.CYAN}Plugins found on site: {', '.join(plugins)}{Style.RESET_ALL}")
        
        matched_plugins = [cve for cve in wpcves if cve["plugin_name"] in plugins]

        if not matched_plugins:
            print(f"{Style.BRIGHT}{Fore.YELLOW}No matching plugins found in CVE database.{Style.RESET_ALL}")
            return

        print(f"{Style.BRIGHT}{Fore.GREEN}Plugins matching CVE database:{Style.RESET_ALL}")
        for plugin in matched_plugins:
            print(f"- {plugin['plugin_name']}")

        for cve in matched_plugins:
            current_time = datetime.now().strftime("%H:%M:%S")
            print(f"[{Fore.BLUE}{current_time}{Style.RESET_ALL}]::{Fore.GREEN}[Checking]{Style.RESET_ALL}~ {cve['cve_id']} for plugin {cve['plugin_name']}")

            try:
                handle_cve(target_url, cve["cve_id"], cve["plugin_name"], cve["vulnerable_version"])
                plugin_check_result = check_plugin_vulnerability(target_url, cve["plugin_name"], cve["vulnerable_version"])
                if plugin_check_result and plugin_check_result["is_vulnerable"]:
                    found_vulns = True
            except Exception as e:
                print(f"{Style.BRIGHT}{Fore.RED}Error while checking {cve['cve_id']}: {str(e)}{Style.RESET_ALL}")
                continue

    except KeyboardInterrupt:
        handle_user_interrupt()

    if not found_vulns:
        print(f"{Style.BRIGHT}{Fore.WHITE}No vulnerabilities found for any CVEs on {target_url}{Style.RESET_ALL}")
