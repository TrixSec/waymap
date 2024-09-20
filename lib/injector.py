import requests
import os
import re
import xml.etree.ElementTree as ET
from termcolor import colored
import random
from urllib.parse import urlparse, parse_qs, urlunparse, urlencode
import signal

# Global flags
interrupted = False
continue_scanning_flag = True

# Signal handler for user interruption (Ctrl+C)
def signal_handler(sig, frame):
    global interrupted
    interrupted = True
    print("\n[•] Scan interrupted by user. Exiting cleanly...")

# Directory paths for payloads, user-agents, and errors
data_dir = os.path.join(os.getcwd(), 'data')
session_dir = os.path.join(os.getcwd(), 'session')

# Load payloads from files
def load_payloads(file_path):
    with open(file_path, 'r') as f:
        return [line.strip() for line in f.readlines() if line.strip()]

# Load user agents from ua.txt
def load_user_agents():
    ua_file = os.path.join(data_dir, 'ua.txt')
    return load_payloads(ua_file)

# Load DBMS error patterns from errors.xml
def load_errors_xml(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()
    error_dict = {}
    for dbms in root.findall('dbms'):
        dbms_name = dbms.attrib['value']
        errors = [error.attrib['regexp'] for error in dbms.findall('error')]
        error_dict[dbms_name] = errors
    return error_dict

# Match DBMS based on error patterns
def match_dbms(response_text, error_dict):
    for dbms_name, errors in error_dict.items():
        for error_regex in errors:
            if re.search(error_regex, response_text):
                return dbms_name
    return None

# Detect web technologies from headers
def detect_web_technology(response):
    server_header = response.headers.get('Server', 'Unknown')
    powered_by = response.headers.get('X-Powered-By', 'Unknown')
    return server_header, powered_by

# Function to inject payload into a URL's parameters
def test_injection(url, headers, payloads, error_dict, printed_servers):
    global continue_scanning_flag
    if not continue_scanning_flag:
        return False

    # Ensure payloads is a list
    if not isinstance(payloads, list):
        print(colored(f"[×] Invalid payloads format for URL: {url}", 'red'))
        return False

    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)

    for param in query_params:
        for payload in random.sample(payloads, min(10, len(payloads))):
            if not continue_scanning_flag:
                return False

            modified_params = query_params.copy()
            modified_params[param] = payload
            modified_query = urlencode(modified_params, doseq=True)

            test_url = urlunparse(parsed_url._replace(query=modified_query))
            try:
                response = requests.get(test_url, headers=headers)

                # Detect web technology based on headers
                server_header, powered_by = detect_web_technology(response)
                if (url not in printed_servers) and powered_by != 'Unknown' and not interrupted:
                    print(colored(f'[•] Web Server: {server_header}', 'cyan'))
                    print(colored(f'[•] Powered By: {powered_by}', 'cyan'))
                    printed_servers.add(url)

                # Check for DBMS error patterns specific for command injection
                cmd_error_dict = {'Command Injection': error_dict['Command Injection']}
                dbms_name = match_dbms(response.text, cmd_error_dict)
                if dbms_name and not interrupted:
                    print_vulnerable_url(test_url, param, payload, dbms_name)
                    return True

            except requests.RequestException as e:
                if not interrupted:
                    print(colored(f"[×] Error occurred: {e}", 'red'))

    return False

# Pretty print for vulnerable URL
def print_vulnerable_url(url, param, payload, dbms_name):
    if not interrupted:
        print(colored(f'[★] Vulnerable URL found: {url}', 'white', attrs=['bold']))
        print(f"[•] Parameter: {param}")
        print(f"[•] Payload: {payload}")
        print(colored(f"[•] Backend DBMS: {dbms_name}", 'cyan'))

# Pretty print for non-vulnerable URL
def print_non_vulnerable_url(url):
    if not interrupted:
        print(colored(f'[-] No vulnerability found in: {url}', 'white'))

# Main injection logic
# Main injection logic
def inject_payloads(urls, sql_payloads, cmdi_payloads, user_agents):
    global continue_scanning_flag
    headers = {'User-Agent': random.choice(user_agents)}

    # Load error dictionaries
    sql_error_dict = load_errors_xml(os.path.join(data_dir, 'errors.xml'))
    cmd_error_dict = load_errors_xml(os.path.join(data_dir, 'cmdi.xml'))

    printed_servers = set()  # Track printed server info

    for count, url in enumerate(urls, start=1):
        if interrupted or not continue_scanning_flag:
            break

        if "?" in url and "=" in url:
            print(colored(f'[•] Testing URL: {url}', 'light_yellow'))

            # Test for SQL Injection vulnerabilities
            if test_injection(url, headers, sql_payloads, sql_error_dict, printed_servers):
                print(colored(f'[★] SQL Injection vulnerability detected!', 'red'))
                continue_scanning_flag = continue_scanning()
                if not continue_scanning_flag or interrupted:
                    break

            # Test for Command Injection vulnerabilities
            if test_injection(url, headers, cmdi_payloads, cmd_error_dict, printed_servers):
                print(colored(f'[×] Command Injection vulnerability detected!', 'red'))
                continue_scanning_flag = continue_scanning()
                if not continue_scanning_flag or interrupted:
                    break

            if not interrupted:
                print_non_vulnerable_url(url)
        else:
            if not interrupted:
                print(colored(f'[×] Skipping invalid URL: {url}', 'yellow'))

# Ask the user if they want to continue scanning
def continue_scanning():
    while True:
        user_input = input(colored("[?] Do you want to continue scanning other URLs? (y/n): ", 'yellow'))
        if user_input.lower() == 'n':
            return False
        elif user_input.lower() == 'y':
            return True
        else:
            if not interrupted:
                print(colored("[×] Invalid input. Please enter 'y' or 'n'.", 'red'))

# Example usage (URLs from session):
if __name__ == "__main__":
    session_files = os.listdir(session_dir)
    urls = []
    for file in session_files:
        with open(os.path.join(session_dir, file), 'r') as f:
            urls.extend(f.read().splitlines())
    sql_payloads = load_payloads(os.path.join(data_dir, 'sqlipayload.txt'))
    cmdi_payloads = load_payloads(os.path.join(data_dir, 'cmdipayload.txt'))
    user_agents = load_user_agents()

    inject_payloads(urls, sql_payloads, cmdi_payloads, user_agents)

# Register signal handler for graceful interruption
signal.signal(signal.SIGINT, signal_handler)