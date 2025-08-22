# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.

import random
import requests
import re
import os
from urllib.parse import urlparse, parse_qs
import json
import multiprocessing
from termcolor import colored
from xml.etree import ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from lib.parse.random_headers import generate_random_headers
from lib.core.settings import DEFAULT_THREADS
from lib.core.settings import MAX_THREADS
from lib.core.settings import DEFAULT_INPUT 


data_dir = os.path.join(os.getcwd(), 'data')

def get_domain(url):
    """ Extract domain from URL for organizing output storage """
    return urlparse(url).netloc

def extract_parameters(url):
    """ Extract query parameters from the URL """
    parsed_url = urlparse(url)
    params = parse_qs(parsed_url.query)
    return list(params.keys())  

def load_json(file_path):
    """ Load existing JSON file, ensuring no data loss """
    if os.path.exists(file_path):
        try:
            with open(file_path, 'r') as file:
                return json.load(file)
        except json.JSONDecodeError:
            return {} 
    return {}


def save_results(domain, url, parameter, payload, vuln_type):
    """ Save new vulnerabilities while preserving previous results """

    save_path = f"sessions/{domain}/waymap_full_results.json"
    os.makedirs(os.path.dirname(save_path), exist_ok=True)

    results = load_json(save_path)

    if "scans" not in results:
        results["scans"] = {}

    if vuln_type not in results["scans"]:
        results["scans"][vuln_type] = []

    existing_entries = results["scans"][vuln_type]
    for entry in existing_entries:
        if entry["url"] == url and entry["parameter"] == parameter and entry["payload"] == payload:
            return  

    results["scans"][vuln_type].append({
        "url": url,
        "parameter": parameter,
        "payload": payload
    })

    with open(save_path, 'w') as file:
        json.dump(results, file, indent=4)

    print(colored(f"[✓] Saved: {save_path}", 'cyan'))


def load_cmdi_errors(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()
    cmdi_errors = {}
    for error in root.findall('error'):
        error_name = error.attrib['value']
        patterns = [pattern.attrib['regexp'] for pattern in error.findall('pattern')]
        cmdi_errors[error_name] = patterns
    return cmdi_errors


def detect_cmdi(response_content, cmdi_errors):
    for error_name, patterns in cmdi_errors.items():
        for pattern in patterns:
            if re.search(pattern, response_content, re.IGNORECASE):
                return error_name
    return None


def detect_web_tech(headers):
    if 'x-powered-by' in headers:
        return headers['x-powered-by']
    elif 'server' in headers:
        return headers['server']
    return 'Unknown'


def test_cmdi_payload(url, parameter, payload, cmdi_errors):
    """ Test if a payload is vulnerable for a specific parameter in a URL """
    headers = generate_random_headers()
    test_url = url.replace(f"{parameter}=", f"{parameter}={payload}")

    try:
        response = requests.get(test_url, headers=headers, timeout=10, verify=False)
        response_content = response.text

        cmdi_error = detect_cmdi(response_content, cmdi_errors)
        if cmdi_error:
            return {
                'vulnerable': True,
                'cmdi_error': cmdi_error,
                'response': response_content,
                'headers': response.headers,
                'url': test_url,
                'parameter': parameter,
                'payload': payload
            }

    except requests.RequestException as e:
        print(colored(f"[×] Error testing payload on {test_url}: {e}", 'red'))

    return {'vulnerable': False}


def perform_cmdi_scan(crawled_urls, cmdi_payloads, thread_count, no_prompt):
    if thread_count is None:
        thread_count = DEFAULT_THREADS  

    cpu_count = multiprocessing.cpu_count()
    thread_count = max(1, min(thread_count, cpu_count * 2, MAX_THREADS))

    cmdi_errors = load_cmdi_errors(os.path.join(data_dir, 'cmdi.xml'))
    detected_tech = None

    try:
        for url in crawled_urls:
            print(colored(f"\n[•] Testing URL: {url}", 'yellow'))

            domain = get_domain(url)
            parameters = extract_parameters(url)

            if not parameters:
                print(colored(f"[×] No parameters found in {url}, skipping...", 'red'))
                continue

            found_vulnerability = False

            with ThreadPoolExecutor(max_workers=thread_count) as executor:
                futures = {
                    executor.submit(test_cmdi_payload, url, param, payload, cmdi_errors): (param, payload)
                    for param in parameters for payload in random.sample(cmdi_payloads, 10)
                }

                for future in as_completed(futures):
                    result = future.result()

                    if result['vulnerable']:
                        found_vulnerability = True
                        payload = result['payload']
                        parameter = result['parameter']

                        if not detected_tech:
                            detected_tech = detect_web_tech(result['headers'])
                            print(colored(f"[•] Web Technology: {detected_tech or 'Unknown'}", 'magenta'))

                        print(colored(f"[★] Vulnerable URL: {result['url']}", 'white', attrs=['bold']))
                        print(colored(f"[•] Injected Parameter: {parameter}", 'green'))
                        print(colored(f"[•] Payload Used: {payload}", 'blue'))
                        print(colored(f"[•] Command Injection Error Pattern: {result['cmdi_error']}", 'red'))

                        save_results(domain, result['url'], parameter, payload, "Command Injection")

                        if not no_prompt:
                            while True:
                                user_input = input(colored("\n[?] Vulnerable URL found. Do you want to continue testing other URLs? (y/n): ", 'yellow')).strip().lower()
                                if user_input in ['y', 'n']:
                                    break
                                print(colored("[×] Invalid input. Please enter 'y' or 'n'.", 'red'))

                            if user_input == 'n':
                                print(colored("[•] Stopping further scans as per user's decision.", 'red'))
                                return
                        else:
                            user_input = DEFAULT_INPUT
                            if user_input == 'n':
                                print(colored("[•] Stopping further scans as per default value (n).", 'red'))
                                return
                            else:
                                print(colored("[•] Continuing to scan as per default value (y).", 'green'))

                if not found_vulnerability:
                    print(colored(f"[×] No vulnerabilities found on: {url}", 'red'))

    except KeyboardInterrupt:
        print(colored("\n[!] Scan interrupted by user. Exiting cleanly...", 'red'))
