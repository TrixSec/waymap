# Copyright (c) 2024 waymap developers 
# See the file 'LICENSE' for copying permission.

import random
import requests
import os
from datetime import datetime
from termcolor import colored
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import threading

data_dir = os.path.join(os.getcwd(), 'data')

stop_scan = threading.Event()

def load_crlf_payloads(file_path):
    """Load CRLF payloads from the given file."""
    payloads = []
    try:
        with open(file_path, 'r') as file:
            for line in file:
                if line.strip():
                    try:
                        name, payload, response = line.strip().split('::')
                        payloads.append({
                            'name': name,
                            'payload': payload,
                            'response': response
                        })
                    except ValueError:
                        print(colored(f"[×] Malformed payload in the file: {line.strip()}", 'red'))
    except FileNotFoundError:
        print(colored(f"[×] Payload file not found at: {file_path}", 'red'))
    return payloads

def test_crlf_payload(url, parameter, payload, expected_response, user_agent):
    """Test a CRLF payload on the given URL."""
    if stop_scan.is_set():
        return {'vulnerable': False}

    headers = {'User-Agent': user_agent}
    try:
        response = requests.get(url, headers=headers, timeout=10, verify=False)
        response_content = response.text
        time.sleep(random.uniform(1, 3))  

        if expected_response in response_content:
            return {'vulnerable': True, 'response': response, 'url': url}
    except requests.RequestException as e:
        if not stop_scan.is_set():
            print(colored(f"[×] Error testing payload on {url}: {e}", 'red'))

    return {'vulnerable': False}

def perform_crlf_scan(crawled_urls, user_agents, verbose=False):
    """Perform CRLF injection scanning on the given crawled URLs."""
    payloads = load_crlf_payloads(os.path.join(data_dir, 'crlfpayload.txt'))

    use_threads = input(colored("[?] Do you want to use threads for scanning? (y/n, press Enter for default [n]): ", 'yellow')).strip().lower()

    max_threads = 1  
    if use_threads == 'y':
        max_threads = int(input(colored("[?] How many threads do you want to use (1-10)? ", 'yellow', attrs=['bold'])))
        max_threads = min(max_threads, 10) 

    try:
        for url in crawled_urls:
            if stop_scan.is_set():
                break

            print(colored(f"\n[•] Testing URL: {url}", 'yellow'))

            base_url = url.split('?')[0]
            params = url.split('?')[1] if '?' in url else ''
            param_dict = {param.split('=')[0]: param.split('=')[1] for param in params.split('&')} if params else {}

            with ThreadPoolExecutor(max_workers=1) as executor:
                future_to_payload = {}
                for payload_entry in payloads:
                    if stop_scan.is_set():
                        break

                    name = payload_entry['name']
                    payload = payload_entry['payload']
                    expected_response = payload_entry['response']

                    for param_key in param_dict.keys():
                        if stop_scan.is_set():
                            break

                        timestamp = datetime.now().strftime("%H:%M:%S")

                        if verbose:
                            print(f"[{colored(timestamp, 'blue')}] [Info]: Testing {name} on parameter {param_key}")

                        user_agent = random.choice(user_agents)
                        test_params = param_dict.copy()
                        test_params[param_key] = payload

                        modified_params = '&'.join([f"{k}={v}" for k, v in test_params.items()])
                        full_url = f"{base_url}?{modified_params}"

                        future = executor.submit(test_crlf_payload, full_url, param_key, payload, expected_response, user_agent)
                        future_to_payload[future] = (full_url, param_key, payload)

                for future in as_completed(future_to_payload):
                    if stop_scan.is_set():
                        break

                    result = future.result()
                    full_url, param_key, payload = future_to_payload[future]

                    if result['vulnerable']:
                        print(colored(f"[★] Vulnerable URL found: {full_url}", 'white', attrs=['bold']))
                        print(colored(f"[•] Vulnerable Parameter: {param_key}", 'green'))
                        print(colored(f"[•] Payload: {payload}", 'green'))

                        user_input = input(colored("\n[?] Vulnerable URL found. Do you want to continue testing other URLs? (y/n): ", 'yellow')).strip().lower()
                        if user_input == 'n':
                            print(colored("[•] Stopping further scans as per user's decision.", 'red'))
                            stop_scan.set()  
                            break

        else:
            for url in crawled_urls:
                if stop_scan.is_set():
                    break

                print(colored(f"\n[•] Testing URL: {url}", 'yellow'))

                base_url = url.split('?')[0]
                params = url.split('?')[1] if '?' in url else ''
                param_dict = {param.split('=')[0]: param.split('=')[1] for param in params.split('&')} if params else {}

                for payload_entry in payloads:
                    if stop_scan.is_set():
                        break

                    name = payload_entry['name']
                    payload = payload_entry['payload']
                    expected_response = payload_entry['response']

                    for param_key in param_dict.keys():
                        if stop_scan.is_set():
                            break

                        timestamp = datetime.now().strftime("%H:%M:%S")

                        if verbose:
                            print(f"[{colored(timestamp, 'blue')}] [Info]: Testing {name} on parameter {param_key}")

                        user_agent = random.choice(user_agents)
                        test_params = param_dict.copy()
                        test_params[param_key] = payload

                        modified_params = '&'.join([f"{k}={v}" for k, v in test_params.items()])
                        full_url = f"{base_url}?{modified_params}"

                        result = test_crlf_payload(full_url, param_key, payload, expected_response, user_agent)

                        if result['vulnerable']:
                            print(colored(f"[★] Vulnerable URL found: {full_url}", 'white', attrs=['bold']))
                            print(colored(f"[•] Vulnerable Parameter: {param_key}", 'green'))
                            print(colored(f"[•] Payload: {payload}", 'green'))

                            user_input = input(colored("\n[?] Vulnerable URL found. Do you want to continue testing other URLs? (y/n): ", 'yellow')).strip().lower()
                            if user_input == 'n':
                                print(colored("[•] Stopping further scans as per user's decision.", 'red'))
                                stop_scan.set() 
                                break

    except KeyboardInterrupt:
        print(colored("\n[!] Scan interrupted by user. Exiting cleanly...", 'red'))
        stop_scan.set()

