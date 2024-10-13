# Copyright (c) 2024 waymap developers 
# See the file 'LICENSE' for copying permission.

import random
import requests
import os
import multiprocessing
import logging
from datetime import datetime
import threading
from termcolor import colored
from concurrent.futures import ThreadPoolExecutor, as_completed
from lib.core.settings import DEFAULT_THREADS
from lib.core.settings import MAX_THREADS
from lib.core.settings import DEFAULT_INPUT 

data_dir = os.path.join(os.getcwd(), 'data')

logging.basicConfig(filename='ssti_scan.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

stop_scan = threading.Event()

def load_ssti_payloads(file_path):
    """Load SSTI payloads from a file."""
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

def test_ssti_payload(url, parameter, payload, expected_response, user_agent):
    if stop_scan.is_set():
        return {'vulnerable': False}

    headers = {'User-Agent': user_agent}
    try:
        response = requests.get(url, params={parameter: payload}, headers=headers, timeout=10, verify=False)
        response_content = response.text
        if expected_response in response_content:
            return {'vulnerable': True, 'response': response_content, 'headers': response.headers}
    except requests.RequestException as e:
        print(colored(f"[×] Error testing payload on {url}: {e}", 'red'))

    return {'vulnerable': False}

def perform_ssti_scan(crawled_urls, user_agents, thread_count, no_prompt, verbose=False):
    if thread_count is None:
        thread_count = DEFAULT_THREADS  

    cpu_count = multiprocessing.cpu_count()
    thread_count = max(1, min(thread_count, cpu_count * 2, MAX_THREADS))

    payloads = load_ssti_payloads(os.path.join(data_dir, 'sstipayload.txt'))
    detected_tech = None

    try:
        for url in crawled_urls:
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

            with ThreadPoolExecutor(max_workers=thread_count) as executor:
                futures = {}
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
                        test_params = param_dict.copy()
                        test_params[param_key] = payload

                        modified_params = '&'.join([f"{k}={v}" for k, v in test_params.items()])
                        full_url = f"{base_url}?{modified_params}"

                        future = executor.submit(test_ssti_payload, full_url, param_key, payload, expected_response, user_agent)
                        futures[future] = full_url

                    if verbose:
                        timestamp = datetime.now().strftime("%H:%M:%S")
                        print(f"[{colored(timestamp, 'blue')}] [Info]: Testing {name} with payload: {payload}")


                for future in as_completed(futures):
                    result = future.result()
                    full_url = futures[future]

                    if result['vulnerable']:
                        if not detected_tech:
                            detected_tech = result['headers'].get('X-Powered-By', result['headers'].get('Server', 'Unknown'))
                            print(colored(f"[•] Web Technology: {detected_tech or 'Unknown'}", 'magenta'))

                        print(colored(f"[★] Vulnerable URL found: {full_url}", 'white', attrs=['bold']))
                        print(colored(f"[•] Payload: {payload}", 'green'))
                        print(colored(f"[•] Expected Response: {expected_response}", 'blue'))

                        if no_prompt:  
                            user_input = DEFAULT_INPUT
                        else:
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

