# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.

import random
import requests
import re
import os
import logging
import multiprocessing
from termcolor import colored
from xml.etree import ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from lib.core.settings import DEFAULT_THREADS
from lib.core.settings import MAX_THREADS
from lib.core.settings import DEFAULT_INPUT 


data_dir = os.path.join(os.getcwd(), 'data')

logging.basicConfig(filename='cmdi_scan.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

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

def test_cmdi_payload(url, payload, user_agent, cmdi_errors):
    headers = {'User-Agent': user_agent}
    try:
        response = requests.get(url, headers=headers, timeout=10, verify=False)
        response_content = response.text

        cmdi_error = detect_cmdi(response_content, cmdi_errors)
        if cmdi_error:
            return {'vulnerable': True, 'cmdi_error': cmdi_error, 'response': response_content, 'headers': response.headers}

    except requests.RequestException as e:
        print(colored(f"[×] Error testing payload on {url}: {e}", 'red'))

    return {'vulnerable': False}

def perform_cmdi_scan(crawled_urls, cmdi_payloads, user_agents, thread_count, no_prompt):
    if thread_count is None:
        thread_count = DEFAULT_THREADS  

    cpu_count = multiprocessing.cpu_count()
    thread_count = max(1, min(thread_count, cpu_count * 2, MAX_THREADS))

    cmdi_errors = load_cmdi_errors(os.path.join(data_dir, 'cmdi.xml'))
    detected_tech = None
    user_decision = None

    try:
        for url in crawled_urls:
            print(colored(f"\n[•] Testing URL: {url}", 'yellow'))

            payloads_to_test = random.sample(cmdi_payloads, 10)
            found_vulnerability = False

            with ThreadPoolExecutor(max_workers=thread_count) as executor:
                futures = {executor.submit(test_cmdi_payload, f"{url}{payload}", payload, random.choice(user_agents), cmdi_errors): payload for payload in payloads_to_test}

                for future in as_completed(futures):
                    result = future.result()

                    if result['vulnerable']:
                        found_vulnerability = True

                        if not detected_tech:
                            detected_tech = detect_web_tech(result['headers'])
                            print(colored(f"[•] Web Technology: {detected_tech or 'Unknown'}", 'magenta'))

                        payload = futures[future]
                        print(colored(f"[★] Vulnerable URL found: {url}", 'white', attrs=['bold']))
                        print(colored(f"[•] Payload: {payload}", 'green'))
                        print(colored(f"[•] Command Injection Error Pattern: {result['cmdi_error']}", 'blue'))

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