import requests
import os
import re
import xml.etree.ElementTree as ET
from termcolor import colored
import random
from urllib.parse import urlparse, parse_qs, urlunparse, urlencode

# Directory paths for payloads, user-agents, and errors
data_dir = '/waymap/data/'
session_dir = '/waymap/session/'

# Load payloads from files
def load_payloads(file_path):
    with open(file_path, 'r') as f:
        return [line.strip() for line in f.readlines()]

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

# Function to match DBMS based on error patterns
def match_dbms(response_text, error_dict):
    for dbms_name, errors in error_dict.items():
        for error_regex in errors:
            if re.search(error_regex, response_text):
                return dbms_name
    return None

# Function to inject payload into a URL's parameters
def test_injection(url, headers, payloads, error_dict):
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)

    for param in query_params:
        for payload in random.sample(payloads, 10):  # Randomly select 10 payloads
            modified_params = query_params.copy()
            modified_params[param] = payload
            modified_query = urlencode(modified_params, doseq=True)

            test_url = urlunparse(parsed_url._replace(query=modified_query))
            response = requests.get(test_url, headers=headers)

            if match_dbms(response.text, error_dict):  # Check if any DBMS error matches
                print_vulnerable_url(test_url)
                return True  # Stop testing further if vulnerable

    return False

# Pretty print for vulnerable URL
def print_vulnerable_url(url):
    print(colored(f'[★] Vulnerable URL found: {url}', 'white', attrs=['bold']))

# Pretty print for non-vulnerable URL
def print_non_vulnerable_url(url):
    print(colored(f'[-] No vulnerability found in: {url}', 'white'))

# Main injection logic
def inject_payloads(urls, sql_payloads, cmdi_payloads, user_agents):
    headers = {'User-Agent': random.choice(user_agents)}
    error_dict = load_errors_xml(os.path.join(data_dir, 'errors.xml'))  # Load error patterns once

    for url in urls:
        if "?" in url and "=" in url:
            print(colored(f'[•] Testing URL: {url}', 'white'))

            if test_injection(url, headers, sql_payloads, error_dict):
                print(colored(f'[★] SQL Injection vulnerability detected!', 'red'))
            elif test_injection(url, headers, cmdi_payloads, error_dict):
                print(colored(f'[×] Command Injection vulnerability detected!', 'red'))
            else:
                print_non_vulnerable_url(url)

# Example usage:
if __name__ == "__main__":
    urls = [...]  # Load crawled URLs from the crawler
    sql_payloads = load_payloads(os.path.join(data_dir, 'sqlipayload.txt'))
    cmdi_payloads = load_payloads(os.path.join(data_dir, 'cmdipayload.txt'))
    user_agents = load_user_agents()

    inject_payloads(urls, sql_payloads, cmdi_payloads, user_agents)
