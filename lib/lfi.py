# Copyright (c) 2024 waymap developers 
# See the file 'LICENSE' for copying permission

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

def load_lfi_payloads(file_path):
    payloads = []
    try:
        with open(file_path, 'r') as file:
            for line in file:
                if line.strip():
                    try:
                        name, payload, expected_response = line.strip().split('::')
                        payloads.append({
                            'name': name,
                            'payload': payload,
                            'response': expected_response
                        })
                    except ValueError:
                        print(colored(f"[×] Malformed payload in the file: {line.strip()}", 'red'))
    except FileNotFoundError:
        print(colored(f"[×] Payload file not found at: {file_path}", 'red'))
    return payloads

def test_lfi_payload(url, parameter, payload, expected_response, user_agent):
    if stop_scan.is_set():
        return {'vulnerable': False}

    headers = {'User-Agent': user_agent}
    try:
        response = requests.get(url, params={parameter: payload}, headers=headers, timeout=10)
        response_content = response.text
        time.sleep(random.randint(1, 3))

        if expected_response in response_content:
            return {'vulnerable': True, 'response': response, 'headers': response.headers}
    except requests.RequestException as e:
        if not stop_scan.is_set():
            print(colored(f"[×] Error testing payload on {url}: {e}", 'red'))

    return {'vulnerable': False}

def perform_lfi_scan(crawled_urls, user_agents, verbose=False):
    payloads = load_lfi_payloads(os.path.join(data_dir, 'lfipayload.txt'))
    detected_tech = None

    use_threads = input(colored("[?] Do you want to use threads for scanning? (y/n, press Enter for default [n]): ", 'yellow')).strip().lower()

    try:
        if use_threads == 'y':
            with ThreadPoolExecutor(max_workers=5) as executor:
                future_to_url = {}
                for url in crawled_urls:
                    if stop_scan.is_set():
                        break

                    print(colored(f"\n[•] Testing URL: {url}", 'yellow'))

                    base_url = url.split('?')[0]
                    params = url.split('?')[1] if '?' in url else ''

                    param_dict = {}
                    if params:
                        for param in params.split('&'):
                            try:
                                key, value = param.split('=')
                                param_dict[key] = value
                            except ValueError:
                                print(colored(f"[×] Malformed parameter in URL: {url}", 'red'))
                                continue

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

                            future = executor.submit(test_lfi_payload, full_url, param_key, payload, expected_response, user_agent)
                            future_to_url[future] = full_url

                for future in as_completed(future_to_url):
                    if stop_scan.is_set():
                        break

                    result = future.result()
                    full_url = future_to_url[future]

                    if result['vulnerable']:
                        if detected_tech is None:
                            detected_tech = result['headers'].get('X-Powered-By', result['headers'].get('Server', 'Unknown'))
                            print(colored(f"[•] Web Technology: {detected_tech or 'Unknown'}", 'magenta'))

                        print(colored(f"[★] Vulnerable URL found: {full_url}", 'white', attrs=['bold']))
                        print(colored(f"[•] Vulnerable Parameter: {param_key}", 'green'))
                        print(colored(f"[•] Payload: {payload}", 'green'))
                        print(colored(f"[•] Expected Response: {expected_response}", 'blue'))

                        user_input = input(colored("\n[?] Vulnerable URL found. Do you want to continue testing other URLs? (y/n): ", 'yellow')).strip().lower()
                        if user_input == 'n':
                            print(colored("[•] Stopping further scans as per user's decision.", 'red'))
                            stop_scan.set()  
                            break
                        break

        else:
            for url in crawled_urls:
                if stop_scan.is_set():
                    break

                print(colored(f"\n[•] Testing URL: {url}", 'yellow'))

                base_url = url.split('?')[0]
                params = url.split('?')[1] if '?' in url else ''

                param_dict = {}
                if params:
                    for param in params.split('&'):
                        try:
                            key, value = param.split('=')
                            param_dict[key] = value
                        except ValueError:
                            print(colored(f"[×] Malformed parameter in URL: {url}", 'red'))
                            continue

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

                        result = test_lfi_payload(full_url, param_key, payload, expected_response, user_agent)

                        if result['vulnerable']:
                            if detected_tech is None:
                                detected_tech = result['headers'].get('X-Powered-By', result['headers'].get('Server', 'Unknown'))
                                print(colored(f"[•] Web Technology: {detected_tech or 'Unknown'}", 'magenta'))

                            print(colored(f"[★] Vulnerable URL found: {full_url}", 'white', attrs=['bold']))
                            print(colored(f"[•] Vulnerable Parameter: {param_key}", 'green'))
                            print(colored(f"[•] Payload: {payload}", 'green'))
                            print(colored(f"[•] Expected Response: {expected_response}", 'blue'))

                            user_input = input(colored("\n[?] Vulnerable URL found. Do you want to continue testing other URLs? (y/n): ", 'yellow')).strip().lower()
                            if user_input == 'n':
                                print(colored("[•] Stopping further scans as per user's decision.", 'red'))
                                stop_scan.set()  
                                break
                            break

    except KeyboardInterrupt:
        print(colored("\n[!] Scan interrupted by user. Exiting cleanly...", 'red'))
        stop_scan.set()
