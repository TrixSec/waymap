# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.

import requests
import os
import json
import multiprocessing
import threading
from datetime import datetime
from termcolor import colored
from concurrent.futures import ThreadPoolExecutor, as_completed
from lib.parse.random_headers import generate_random_headers
from lib.core.settings import DEFAULT_THREADS
from lib.core.settings import MAX_THREADS
from lib.core.settings import DEFAULT_INPUT

data_dir = os.path.join(os.getcwd(), 'data')
stop_scan = threading.Event()

def load_results(domain):
    results_path = os.path.join('sessions', domain, 'waymap_full_results.json')
    if os.path.exists(results_path):
        try:
            with open(results_path, 'r') as file:
                return json.load(file)
        except json.JSONDecodeError:
            print(colored(f"[×] Error parsing the JSON file for domain {domain}, starting fresh.", 'red'))
    else:
        os.makedirs(os.path.dirname(results_path), exist_ok=True)
        return {'scans': {}}
    
def save_results(domain, results):
    results_path = os.path.join('sessions', domain, 'waymap_full_results.json')
    try:
        with open(results_path, 'w') as file:
            json.dump(results, file, indent=4)
    except IOError as e:
        print(colored(f"[×] Failed to save results for {domain}: {e}", 'red'))

def load_cors_payloads(file_path):
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

def test_cors_vulnerability(url, payload, expected_response):
    if stop_scan.is_set():
        return {'vulnerable': False}

    headers = generate_random_headers()
    headers['Origin'] = payload
    
    try:
        response = requests.options(url, headers=headers, timeout=10, verify=False)
        cors_header = response.headers.get('Access-Control-Allow-Origin', '')
        if expected_response in cors_header:
            return {'vulnerable': True, 'response': response, 'payload': payload, 'url': url}
    except requests.RequestException as e:
        if not stop_scan.is_set():
            print(colored(f"[×] Error testing payload on {url}: {e}", 'red'))

    return {'vulnerable': False}

def perform_cors_scan(crawled_urls, thread_count, no_prompt, verbose=False):
    if thread_count is None:
        thread_count = DEFAULT_THREADS  

    cpu_count = multiprocessing.cpu_count()
    thread_count = max(1, min(thread_count, cpu_count * 2, MAX_THREADS))

    payloads = load_cors_payloads(os.path.join(data_dir, 'corspayload.txt'))

    try:
        for url in crawled_urls:
            if stop_scan.is_set():
                break

            print(colored(f"\n[•] Testing URL: {url}", 'yellow'))

            found_vulnerability = False
            domain = url.split('/')[2] 
            results = load_results(domain) 

            print(colored("\n[•] Checking for CORS vulnerabilities...", 'blue'))
            with ThreadPoolExecutor(max_workers=thread_count) as executor:
                future_to_payload = {}
                for payload_entry in payloads:
                    if stop_scan.is_set():
                        break

                    name = payload_entry['name']
                    payload = payload_entry['payload']
                    expected_response = payload_entry['response']

                    if url in results['scans'] and payload in results['scans'][url]:
                        continue

                    if verbose:
                        timestamp = datetime.now().strftime("%H:%M:%S")
                        print(f"[{colored(timestamp, 'blue')}] [Info]: Testing {name} with payload: {payload}")

                    future = executor.submit(test_cors_vulnerability, url, payload, expected_response)
                    future_to_payload[future] = (url, payload)

                for future in as_completed(future_to_payload):
                    if stop_scan.is_set():
                        break

                    result = future.result()
                    url, payload = future_to_payload[future]

                    if result['vulnerable']:
                        found_vulnerability = True
                        print(colored(f"[★] Vulnerable URL found: {result['url']}", 'white', attrs=['bold']))
                        print(colored(f"[•] Vulnerable Origin: {payload}", 'green'))

                        if url not in results['scans']:
                            results['scans'][url] = {}
                        results['scans'][url][payload] = {
                            'vulnerable': True,
                            'response': result['response'].text,
                            'payload': result['payload']
                        }

                        print(colored(f"[•] Payload Used: {payload}", 'cyan'))

                        save_results(domain, results)

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
        stop_scan.set()