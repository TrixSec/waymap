# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.

import requests
import os
from datetime import datetime
from termcolor import colored
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from lib.parse.random_headers import generate_random_headers
from lib.core.settings import DEFAULT_THREADS
from lib.core.settings import MAX_THREADS
from lib.core.settings import DEFAULT_INPUT 

data_dir = os.path.join(os.getcwd(), 'data')

stop_scan = threading.Event()

def load_xss_payloads(file_path):
    payloads = []
    try:
        with open(file_path, 'r') as file:
            for line in file:
                if line.strip():
                    try:
                        name, payload = line.strip().split('::')
                        payloads.append({
                            'name': name,
                            'payload': payload
                        })
                    except ValueError:
                        print(colored(f"[×] Malformed payload in the file: {line.strip()}", 'red'))
    except FileNotFoundError:
        print(colored(f"[×] Payload file not found at: {file_path}", 'red'))
    return payloads

def load_advanced_xss_payloads(file_path, level):
    payloads = []
    try:
        with open(file_path, 'r') as file:
            for line in file:
                if line.strip():
                    try:
                        name, payload = line.strip().split('::')
                        payloads.append({
                            'name': name,
                            'payload': payload
                        })
                    except ValueError:
                        print(colored(f"[×] Malformed payload in the file: {line.strip()}", 'red'))

        if level == 1:
            return payloads[:10]
        elif level == 2:
            return payloads[:23]
        elif level == 3:
            return payloads[:38]
        elif level == 4:
            return payloads[:49]
        elif level == 5:
            return payloads[:62]
        elif level == 6:
            return payloads[:76]
        elif level == 7:
            return payloads

    except FileNotFoundError:
        print(colored(f"[×] Payload file not found at: {file_path}", 'red'))

    return payloads

def test_xss_payload(url, parameter, payload):
    if stop_scan.is_set():
        return {'vulnerable': False}

    headers = generate_random_headers()
    try:
        response = requests.get(url, params={parameter: payload}, headers=headers, timeout=10, verify=False)
        response_content = response.text

        if payload in response_content:
            return {'vulnerable': True, 'response': response, 'headers': response.headers}
    except requests.RequestException as e:
        if not stop_scan.is_set():
            print(colored(f"[×] Error testing payload on {url}: {e}", 'red'))

    return {'vulnerable': False}

def choose_scan_level(no_prompt):
    if no_prompt:
        return 3  
    try:
        while True:
            level = input(colored("[?] Choose scan level (1-7): ", 'yellow')).strip()
            if level.isdigit() and 1 <= int(level) <= 7:
                return int(level)
            else:
                print(colored("[×] Invalid level. Please choose a number between 1 and 7.", 'red'))
    except KeyboardInterrupt:
        print(colored("\n[!] Scan interrupted by user. Exiting...", 'red'))
        stop_scan.set()

def perform_xss_scan(crawled_urls, thread_count, no_prompt, verbose=False,):
    if thread_count is None:
        thread_count = DEFAULT_THREADS  

    thread_count = max(1, min(thread_count, MAX_THREADS))

    basic_payloads = load_xss_payloads(os.path.join(data_dir, 'basicxsspayload.txt'))
    detected_tech = None

    try:
        with ThreadPoolExecutor(max_workers=thread_count) as executor:
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

                for payload_entry in basic_payloads:
                    if stop_scan.is_set():
                        break

                    name = payload_entry['name']
                    payload = payload_entry['payload']

                    for param_key in param_dict.keys():
                        if stop_scan.is_set():
                            break

                        timestamp = datetime.now().strftime("%H:%M:%S")

                        if verbose:
                            print(f"[{colored(timestamp, 'blue')}] [Info]: Testing {name} on parameter {param_key}")

                        test_params = param_dict.copy()
                        test_params[param_key] = payload

                        modified_params = '&'.join([f"{k}={v}" for k, v in test_params.items()])
                        full_url = f"{base_url}?{modified_params}"

                        future = executor.submit(test_xss_payload, full_url, param_key, payload)
                        future_to_url[future] = (full_url, param_key)

            for future in as_completed(future_to_url):
                if stop_scan.is_set():
                    break

                result = future.result()
                full_url, param_key = future_to_url[future]

                if result['vulnerable']:
                    if detected_tech is None:
                        detected_tech = result['headers'].get('X-Powered-By', result['headers'].get('Server', 'Unknown'))
                        print(colored(f"[•] Web Technology: {detected_tech or 'Unknown'}", 'magenta'))

                    print(colored(f"[★] Vulnerable URL found: {full_url}", 'white', attrs=['bold']))
                    print(colored(f"[•] Vulnerable Parameter: {param_key}", 'green'))
                    print(colored(f"[•] Payload: {payload}", 'green'))

                    if no_prompt:
                        user_input = DEFAULT_INPUT 
                    else:
                        user_input = input(colored("\n[?] Vulnerable URL found. Do you want to continue testing other URLs? (y/n): ", 'yellow')).strip().lower()
                    
                    if user_input == 'n':
                        print(colored("[•] Stopping further scans as per user's decision.", 'red'))
                        stop_scan.set()
                        return
                    break

        if no_prompt:
            advanced_scan_choice = DEFAULT_INPUT
        else:
            advanced_scan_choice = input(colored("[?] Do you want to Test XSS Filters Bypass Payload (y/n)(recommended): ", 'yellow')).strip().lower()
        
        if advanced_scan_choice == 'y':
            advanced_file_path = os.path.join(data_dir, 'filterbypassxss.txt')
            advanced_payloads = load_advanced_xss_payloads(advanced_file_path, choose_scan_level(no_prompt))

            with ThreadPoolExecutor(max_workers=thread_count) as executor:
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

                    for payload_entry in advanced_payloads:
                        if stop_scan.is_set():
                            break

                        name = payload_entry['name']
                        payload = payload_entry['payload']

                        for param_key in param_dict.keys():
                            if stop_scan.is_set():
                                break

                            timestamp = datetime.now().strftime("%H:%M:%S")

                            if verbose:
                                print(f"[{colored(timestamp, 'blue')}] [Info]: Testing {name} on parameter {param_key}")

                            test_params = param_dict.copy()
                            test_params[param_key] = payload

                            modified_params = '&'.join([f"{k}={v}" for k, v in test_params.items()])
                            full_url = f"{base_url}?{modified_params}"

                            future = executor.submit(test_xss_payload, full_url, param_key, payload)
                            future_to_url[future] = (full_url, param_key)

                for future in as_completed(future_to_url):
                    if stop_scan.is_set():
                        break

                    result = future.result()
                    full_url, param_key = future_to_url[future]

                    if result['vulnerable']:
                        if detected_tech is None:
                            detected_tech = result['headers'].get('X-Powered-By', result['headers'].get('Server', 'Unknown'))
                            print(colored(f"[•] Web Technology: {detected_tech or 'Unknown'}", 'magenta'))

                        print(colored(f"[★] Vulnerable URL found: {full_url}", 'white', attrs=['bold']))
                        print(colored(f"[•] Vulnerable Parameter: {param_key}", 'green'))
                        print(colored(f"[•] Payload: {payload}", 'green'))

                        if no_prompt:
                            user_input = DEFAULT_INPUT
                        else:
                            user_input = input(colored("\n[?] Vulnerable URL found. Do you want to continue testing other URLs? (y/n): ", 'yellow')).strip().lower()
                        
                        if user_input == 'n':
                            print(colored("[•] Stopping further scans as per user's decision.", 'red'))
                            stop_scan.set()
                            return
                        break

    except KeyboardInterrupt:
        print(colored("\n[!] Scan interrupted by user. Exiting...", 'red'))
        stop_scan.set()