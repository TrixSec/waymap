# Copyright (c) 2024 waymap developers 
# See the file 'LICENSE' for copying permission.

import random
import requests
import os
from datetime import datetime
from termcolor import colored
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from lib.core.settings import DEFAULT_THREADS
from lib.core.settings import MAX_THREADS
from lib.core.settings import DEFAULT_INPUT 

data_dir = os.path.join(os.getcwd(), 'data')

stop_scan = threading.Event()

def load_open_redirect_payloads(file_path):
    """Load open redirect payloads from the given file."""
    payloads = []
    try:
        with open(file_path, 'r') as file:
            for line in file:
                if line.strip():
                    try:
                        name, payload = line.strip().split('::')
                        payloads.append({'name': name, 'payload': payload})
                    except ValueError:
                        print(colored(f"[×] Malformed payload in the file: {line.strip()}", 'red'))
    except FileNotFoundError:
        print(colored(f"[×] Payload file not found at: {file_path}", 'red'))
    return payloads

def test_open_redirect_payload(url, parameter, payload, user_agent):
    """Test the open redirect payload on the given URL."""
    if stop_scan.is_set():
        return {'vulnerable': False}

    headers = {'User-Agent': user_agent}
    full_url = f"{url.split('?')[0]}?{parameter}={payload}"
    
    try:
        response = requests.get(full_url, headers=headers, allow_redirects=True, timeout=10, verify=False)
        if response.status_code in [200, 301, 302, 303, 307, 308]:
            redirected_url = response.url
            if redirected_url != full_url:
                return {'vulnerable': True, 'redirected_url': redirected_url}
    except requests.RequestException as e:
        if not stop_scan.is_set():
            print(colored(f"[×] Error testing payload on {full_url}: {e}", 'red'))

    return {'vulnerable': False}

def perform_redirect_scan(crawled_urls, user_agents, thread_count, no_prompt, verbose=False):
    """Perform open redirect scanning on the given crawled URLs."""
    if thread_count is None:
        thread_count = DEFAULT_THREADS  

    payloads = load_open_redirect_payloads(os.path.join(data_dir, 'openredirectpayloads.txt'))
    detected_tech = None

    thread_count = max(1, min(thread_count, MAX_THREADS))

    try:
        for url in crawled_urls:
            if stop_scan.is_set():
                break

            print(colored(f"\n[•] Testing URL: {url}", 'yellow'))

            with ThreadPoolExecutor(max_workers=thread_count) as executor:
                future_to_payload = {}
                for payload_entry in payloads:
                    if stop_scan.is_set():
                        break

                    name = payload_entry['name']
                    payload = payload_entry['payload']

                    for param_key in url.split('?')[1].split('&'):
                        if stop_scan.is_set():
                            break

                        param_key = param_key.split('=')[0]
                        timestamp = datetime.now().strftime("%H:%M:%S")

                        if verbose:
                            print(f"[{colored(timestamp, 'blue')}] [Info]: Testing {name} on parameter {param_key}")

                        user_agent = random.choice(user_agents)
                        future = executor.submit(test_open_redirect_payload, url, param_key, payload, user_agent)
                        future_to_payload[future] = (url, name)

                for future in as_completed(future_to_payload):
                    if stop_scan.is_set():
                        break

                    result = future.result()
                    full_url, name = future_to_payload[future]

                    if result['vulnerable']:
                        if detected_tech is None:
                            detected_tech = result['redirected_url'] 
                            print(colored(f"[•] Detected Technology: {detected_tech or 'Unknown'}", 'magenta'))

                        print(colored(f"[★] Vulnerable URL found: {full_url}", 'white', attrs=['bold']))
                        print(colored(f"[•] Redirected URL: {result['redirected_url']}", 'blue'))

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
