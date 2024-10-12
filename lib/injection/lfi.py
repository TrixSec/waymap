# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.

import random
import requests
import os
from datetime import datetime
import logging
import multiprocessing
import threading
from termcolor import colored
from concurrent.futures import ThreadPoolExecutor, as_completed
from lib.core.settings import DEFAULT_THREADS, MAX_THREADS  

data_dir = os.path.join(os.getcwd(), 'data')

logging.basicConfig(filename='lfi_scan.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

stop_scan = threading.Event()

def log_error(url, error):
    logging.error(f"Error testing payload on {url}: {error}")

def load_lfi_payloads(file_path):
    """Load LFI payloads from the given file."""
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
    """Test an LFI payload on the given URL."""
    if stop_scan.is_set():
        return {'vulnerable': False}

    headers = {'User-Agent': user_agent}
    try:
        response = requests.get(url, params={parameter: payload}, headers=headers, timeout=10, verify=False)
        if expected_response in response.text:
            return {'vulnerable': True, 'response': response, 'headers': response.headers}
    except requests.RequestException as e:
        if not stop_scan.is_set():
            print(colored(f"[×] Error testing payload on {url}: {e}", 'red'))
            log_error(url, e)

    return {'vulnerable': False}

def perform_lfi_scan(crawled_urls, user_agents, thread_count, verbose=False):
    """Perform LFI scanning on the given crawled URLs with the specified number of threads."""
    if thread_count is None:
        thread_count = DEFAULT_THREADS  

    cpu_count = multiprocessing.cpu_count()
    thread_count = max(1, min(thread_count, cpu_count * 2, MAX_THREADS))

    payloads = load_lfi_payloads(os.path.join(data_dir, 'lfipayload.txt'))

    try:
        for url in crawled_urls:
            if stop_scan.is_set():
                break

            print(colored(f"\n[•] Testing URL: {url}", 'yellow'))

            with ThreadPoolExecutor(max_workers=thread_count) as executor:
                future_to_payload = {}
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

                        user_agent = random.choice(user_agents)

                        if verbose:
                            timestamp = datetime.now().strftime("%H:%M:%S")
                            print(f"[{colored(timestamp, 'blue')}] [Info]: Testing {name} on parameter {param_key}")

                        test_params = param_dict.copy()
                        test_params[param_key] = payload

                        modified_params = '&'.join([f"{k}={v}" for k, v in test_params.items()])
                        full_url = f"{base_url}?{modified_params}"

                        future = executor.submit(test_lfi_payload, full_url, param_key, payload, expected_response, user_agent)
                        future_to_payload[future] = (full_url, param_key)

                for future in as_completed(future_to_payload):
                    if stop_scan.is_set():
                        break

                    result = future.result()
                    full_url, param_key = future_to_payload[future]

                    if result['vulnerable']:
                        print(colored(f"[★] Vulnerable URL found: {full_url}", 'white', attrs=['bold']))
                        print(colored(f"[•] Vulnerable Parameter: {param_key}", 'green'))
                        print(colored(f"[•] Payload: {payload}", 'green'))
                        print(colored(f"[•] Expected Response: {expected_response}", 'blue'))

                        while True:
                            user_input = input(colored("\n[?] Vulnerable URL found. Do you want to continue testing other URLs? (y/n): ", 'yellow')).strip().lower()
                            if user_input in ['y', 'n']:
                                break
                            print(colored("[×] Invalid input. Please enter 'y' or 'n'.", 'red'))

                        if user_input == 'n':
                            print(colored("[•] Stopping further scans as per user's decision.", 'red'))
                            stop_scan.set()
                            break

    except KeyboardInterrupt:
        print(colored("\n[!] Scan interrupted by user. Exiting cleanly...", 'red'))
        stop_scan.set()


