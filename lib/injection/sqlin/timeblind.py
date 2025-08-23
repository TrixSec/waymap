# Copyright (c) 2024-2025 waymap developers
# # See the file 'LICENSE' for copying permission.
# timeblind.py 

import os
import json
import requests
import random
import time
import xml.etree.ElementTree as ET
from urllib.parse import urlparse, parse_qs
from colorama import Fore, Style
from lib.parse.random_headers import generate_random_headers
from lib.injection.sqlin.sql import abort_all_tests

successful_requests = 0
failed_requests = 0

headers = generate_random_headers()


def parse_time_blind_tests_from_xml(file_path="data/time_blind.xml"):
    """Parse time-based SQLi test cases from XML."""
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


def replace_placeholders(template, rand_numbers, rand_str, sleep_time):
    """Replace placeholders in the template with random values."""
    replaced_template = template.replace("[RANDSTR]", rand_str)
    replaced_template = replaced_template.replace("[RANDNUM]", str(rand_numbers))
    replaced_template = replaced_template.replace("[SLEEPTIME]", str(sleep_time))
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
        data["scans"].append({"SQL Injection": {"Technique: Time-Based": []}})

    sql_injection_block = next((entry["SQL Injection"] for entry in data["scans"] if "SQL Injection" in entry), None)
    time_based_block = sql_injection_block.get("Technique: Time-Based", [])

    for entry in time_based_block:
        if entry["Vulnerable URL"] == vuln_data["Vulnerable URL"] and entry["Payload"] == vuln_data["Payload"]:
            return  

    time_based_block.append(vuln_data)
    sql_injection_block["Technique: Time-Based"] = time_based_block

    with open(output_file, 'w') as file:
        json.dump(data, file, indent=4)

    print(f"\n{Style.BRIGHT}[{Fore.YELLOW}Vulnerability saved to JSON{Style.RESET_ALL}] {output_file}")


def time_based_sqli(url, test, thread_count):
    """Perform time-based SQL injection testing."""
    global successful_requests, failed_requests

    rand_numbers = random.randint(1000, 9999)
    rand_str = ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ', k=4))  # 4-character alphanumeric string
    sleep_time = random.choice([3, 5, 7, 10]) 

    payload = replace_placeholders(test['payload_template'], rand_numbers, rand_str, sleep_time)

    current_time = time.strftime('%H:%M:%S', time.localtime())
    print(f"{Style.BRIGHT}[{Fore.BLUE}{current_time}{Style.RESET_ALL}] [{Fore.GREEN}Testing{Style.RESET_ALL}]: {Fore.CYAN}{test['title']}{Style.RESET_ALL}")

    for test_url, injected_param in inject_payload(url, payload):
        try:
            if make_request(test_url, sleep_time):
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


def make_request(test_url, sleep_time):
    """Make a request and check for response time to confirm time-based blind SQLi."""
    global successful_requests, failed_requests
    try:
        start_time = time.time()
        response = requests.get(test_url, headers=headers, verify=False)
        response_time = time.time() - start_time
        successful_requests += 1

        if response_time > (sleep_time - 1) and response_time < (sleep_time + 1):
            print(f"{Style.BRIGHT}{Fore.GREEN}[+] Time-Based Blind SQLi Detected!{Style.RESET_ALL}")
            print(f"{Fore.CYAN}Response Time: {Fore.WHITE}{response_time:.2f}s")
            return True
    except requests.RequestException as e:
        print(f"{Style.BRIGHT}{Fore.RED}[!] Request error: {e}{Style.RESET_ALL}")
        failed_requests += 1
    return False


def process_urls(urls, thread_count):
    global abort_all_tests
    for url in urls:
        if abort_all_tests:
            break

        try:
            if any(time_based_sqli(url, test, thread_count) for test in parse_time_blind_tests_from_xml()): 
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
