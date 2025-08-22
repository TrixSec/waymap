# Copyright (c) 2024 waymap developers 
# See the file 'LICENSE' for copying permission.

import requests
import os
import multiprocessing
import json
from urllib.parse import urlparse
from datetime import datetime
import threading
from termcolor import colored
from concurrent.futures import ThreadPoolExecutor, as_completed
from lib.parse.random_headers import generate_random_headers
from lib.core.settings import DEFAULT_THREADS
from lib.core.settings import MAX_THREADS
from lib.core.settings import DEFAULT_INPUT 

data_dir = os.path.join(os.getcwd(), 'data')
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
                        payloads.append({'name': name, 'payload': payload, 'response': response})
                    except ValueError:
                        print(colored(f"[×] Malformed payload in file: {line.strip()}", 'red'))
    except FileNotFoundError:
        print(colored(f"[×] Payload file not found: {file_path}", 'red'))
    return payloads

def get_output_path(url):
    """Get JSON output path for a given domain."""
    domain = urlparse(url).netloc
    session_dir = os.path.join('sessions', domain)
    os.makedirs(session_dir, exist_ok=True)
    return os.path.join(session_dir, 'waymap_full_results.json')

def load_existing_results(file_path):
    """Load existing results from JSON file, handling errors gracefully."""
    if os.path.exists(file_path):
        try:
            with open(file_path, 'r') as f:
                return json.load(f)
        except json.JSONDecodeError:
            return {}
    return {}

def save_results(file_path, results):
    """Save scan results to JSON file."""
    try:
        with open(file_path, 'w') as f:
            json.dump(results, f, indent=4)
    except Exception as e:
        print(colored(f"[×] Error saving results: {e}", 'red'))

def is_already_scanned(existing_results, vuln_type, url, parameter, payload):
    """Check if a specific URL, parameter, and payload have already been scanned under the correct vulnerability type."""
    if "scans" in existing_results and vuln_type in existing_results["scans"]:
        for entry in existing_results["scans"][vuln_type]:
            if entry["url"] == url and entry["parameter"] == parameter and entry["payload"] == payload:
                return True
    return False

def test_ssti_payload(url, parameter, payload, expected_response):
    """Test a given SSTI payload on the URL."""
    if stop_scan.is_set():
        return None

    headers = generate_random_headers()
    try:
        response = requests.get(url, params={parameter: payload}, headers=headers, timeout=10, verify=False)
        if expected_response in response.text:
            return {'vulnerable': True, 'url': url, 'parameter': parameter, 'payload': payload, 'expected_response': expected_response}
    except requests.RequestException as e:
        print(colored(f"[×] Error testing payload on {url}: {e}", 'red'))

    return None

def perform_ssti_scan(crawled_urls, thread_count, no_prompt, verbose=False):
    """Perform SSTI scanning across multiple URLs."""
    if thread_count is None:
        thread_count = DEFAULT_THREADS

    thread_count = max(1, min(thread_count, multiprocessing.cpu_count() * 2, MAX_THREADS))
    payloads = load_ssti_payloads(os.path.join(data_dir, 'sstipayload.txt'))

    try:
        for url in crawled_urls:
            output_file = get_output_path(url)
            existing_results = load_existing_results(output_file)

            if "scans" not in existing_results:
                existing_results["scans"] = {}

            if "SSTI" not in existing_results["scans"]:
                existing_results["scans"]["SSTI"] = []

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

                        test_params = param_dict.copy()
                        test_params[param_key] = payload

                        modified_params = '&'.join([f"{k}={v}" for k, v in test_params.items()])
                        full_url = f"{base_url}?{modified_params}"

                        if is_already_scanned(existing_results, "SSTI", full_url, param_key, payload):
                            print(colored(f"[!] Skipping already scanned: {full_url}", 'cyan'))
                            continue

                        future = executor.submit(test_ssti_payload, full_url, param_key, payload, expected_response)
                        futures[future] = full_url

                        if verbose:
                            timestamp = datetime.now().strftime("%H:%M:%S")
                            print(f"[{colored(timestamp, 'blue')}] Testing {name} with payload: {payload}")

                for future in as_completed(futures):
                    result = future.result()
                    full_url = futures[future]

                    if result:
                        print(colored(f"[★] Vulnerable URL found: {full_url}", 'white', attrs=['bold']))
                        print(colored(f"[•] Parameter: {result['parameter']}", 'green'))
                        print(colored(f"[•] Payload: {result['payload']}", 'yellow'))
                        print(colored(f"[•] Expected Response: {result['expected_response']}", 'blue'))

                        existing_results["scans"]["SSTI"].append({
                            "url": result["url"],
                            "parameter": result["parameter"],
                            "payload": result["payload"],
                            "expected_response": result["expected_response"]
                        })

                        save_results(output_file, existing_results)

                        if no_prompt:
                            user_input = DEFAULT_INPUT
                        else:
                            while True:
                                user_input = input(colored("\n[?] Continue scanning other URLs? (y/n): ", 'yellow')).strip().lower()
                                if user_input in ['y', 'n']:
                                    break
                                print(colored("[×] Invalid input. Enter 'y' or 'n'.", 'red'))

                        if user_input == 'n':
                            print(colored("[•] Stopping further scans.", 'red'))
                            stop_scan.set()
                            break

    except KeyboardInterrupt:
        print(colored("\n[!] Scan interrupted by user. Exiting cleanly...", 'red'))
        stop_scan.set()
