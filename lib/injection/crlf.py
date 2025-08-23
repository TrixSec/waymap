# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.

import requests
import json
import os
from datetime import datetime
from termcolor import colored # type: ignore
from concurrent.futures import ThreadPoolExecutor, as_completed
from lib.parse.random_headers import generate_random_headers
from lib.core.settings import DEFAULT_THREADS
from lib.core.settings import MAX_THREADS
from lib.core.settings import DEFAULT_INPUT 

import threading

data_dir = os.path.join(os.getcwd(), 'data')

stop_scan = threading.Event()

def load_results(domain):
    """Load existing results from a session's JSON file or create a new one."""
    results_path = os.path.join('sessions', domain, 'waymap_full_results.json')
    if os.path.exists(results_path):
        try:
            with open(results_path, 'r') as file:
                return json.load(file)
        except json.JSONDecodeError:
            print(colored(f"[×] Error parsing the JSON file for domain {domain}, starting fresh.", 'red'))
    else:
        os.makedirs(os.path.dirname(results_path), exist_ok=True)
        return {'scans': {}, 'CRLF Injection': {}} 

def save_results(domain, results):
    """Save results to the session's JSON file."""
    results_path = os.path.join('sessions', domain, 'waymap_full_results.json')
    try:
        with open(results_path, 'w') as file:
            json.dump(results, file, indent=4)
    except IOError as e:
        print(colored(f"[×] Failed to save results for {domain}: {e}", 'red'))

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

def test_crlf_payload(url, parameter, payload, expected_response):
    """Test a CRLF payload on the given URL."""
    if stop_scan.is_set():
        return {'vulnerable': False}

    headers = generate_random_headers()
    try:
        response = requests.get(url, headers=headers, timeout=10, verify=False)
        response_content = response.text

        if expected_response in response_content:
            return {'vulnerable': True, 'response': response, 'url': url}
    except requests.RequestException as e:
        if not stop_scan.is_set():
            print(colored(f"[×] Error testing payload on {url}: {e}", 'red'))

    return {'vulnerable': False}

def perform_crlf_scan(crawled_urls, thread_count, no_prompt, verbose=False):
    if thread_count is None:
        thread_count = DEFAULT_THREADS  

    payloads = load_crlf_payloads(os.path.join(data_dir, 'crlfpayload.txt'))

    thread_count = max(1, min(thread_count, MAX_THREADS))

    try:
        for url in crawled_urls:
            if stop_scan.is_set():
                break

            print(colored(f"\n[•] Testing URL: {url}", 'yellow'))

            base_url = url.split('?')[0]
            params = url.split('?')[1] if '?' in url else ''
            param_dict = {param.split('=')[0]: param.split('=')[1] for param in params.split('&')} if params else {}

            domain = url.split('/')[2] 
            results = load_results(domain)  

            vulnerability_type = 'CRLF Injection'

            if vulnerability_type not in results:
                results[vulnerability_type] = {}

            with ThreadPoolExecutor(max_workers=thread_count) as executor:
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

                        if url in results['scans'] and param_key in results['scans'][url] and payload in results['scans'][url][param_key]:
                            continue

                        test_params = param_dict.copy()
                        test_params[param_key] = payload

                        modified_params = '&'.join([f"{k}={v}" for k, v in test_params.items()])
                        full_url = f"{base_url}?{modified_params}"

                        future = executor.submit(test_crlf_payload, full_url, param_key, payload, expected_response)
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

                        if url not in results['scans']:
                            results['scans'][url] = {}

                        if param_key not in results['scans'][url]:
                            results['scans'][url][param_key] = {}

                        results['scans'][url][param_key][payload] = {
                            'vulnerable': True,
                            'payload': payload
                        }

                        if full_url not in results[vulnerability_type]:
                            results[vulnerability_type][full_url] = []
                        results[vulnerability_type][full_url].append({
                            'parameter': param_key,
                            'payload': payload
                        })

                        save_results(domain, results)

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