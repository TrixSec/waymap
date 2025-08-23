# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.
#boolean.py 

import requests
import os
import json
from urllib.parse import urlparse, parse_qs
import multiprocessing
import threading
from termcolor import colored # type: ignore
from concurrent.futures import ThreadPoolExecutor, as_completed
from lib.parse.random_headers import generate_random_headers
from lib.core.settings import DEFAULT_THREADS
from lib.core.settings import MAX_THREADS
from lib.core.settings import DEFAULT_INPUT 

data_dir = os.path.join(os.getcwd(), 'data')
stop_scan = threading.Event()


def extract_parameters(url):
    """ Extract parameters from the URL """
    parsed_url = urlparse(url)
    params = parse_qs(parsed_url.query)
    return list(params.keys()) 


def get_domain(url):
    """ Extract domain for structured output storage """
    return urlparse(url).netloc


def load_json(file_path):
    """ Load existing JSON file safely, handling errors """
    if os.path.exists(file_path):
        try:
            with open(file_path, 'r') as file:
                return json.load(file)
        except json.JSONDecodeError:
            return {} 
    return {}


def save_results(domain, url, parameter, payload, vuln_type):
    """ Save new findings while preserving previous results """
    save_path = f"sessions/{domain}/waymap_full_results.json"
    os.makedirs(os.path.dirname(save_path), exist_ok=True)

    results = load_json(save_path)

    if "scans" not in results:
        results["scans"] = {}

    if vuln_type not in results["scans"]:
        results["scans"][vuln_type] = []

    existing_entries = results["scans"][vuln_type]
    for entry in existing_entries:
        if entry["url"] == url and entry["parameter"] == parameter and entry["payload"] == payload:
            return  

    results["scans"][vuln_type].append({
        "url": url,
        "parameter": parameter,
        "payload": payload
    })

    with open(save_path, 'w') as file:
        json.dump(results, file, indent=4)

    print(colored(f"[✓] Saved: {save_path}", 'cyan'))


def load_lfi_payloads(file_path):
    """ Load LFI payloads from a file """
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
                        print(colored(f"[×] Malformed payload in file: {line.strip()}", 'red'))
    except FileNotFoundError:
        print(colored(f"[×] Payload file not found: {file_path}", 'red'))
    return payloads


def test_lfi_payload(url, parameter, payload, expected_response):
    """ Test LFI vulnerability with a payload on a specific parameter """
    if stop_scan.is_set():
        return {'vulnerable': False}

    headers = generate_random_headers()
    try:
        response = requests.get(url, params={parameter: payload}, headers=headers, timeout=10, verify=False)
        if expected_response in response.text:
            return {'vulnerable': True, 'url': url, 'parameter': parameter, 'payload': payload}

    except requests.RequestException as e:
        if not stop_scan.is_set():
            print(colored(f"[×] Error testing {url}: {e}", 'red'))

    return {'vulnerable': False}


def perform_lfi_scan(crawled_urls, thread_count, no_prompt):
    """ Perform LFI scan on the given URLs with specified threads """
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

            domain = get_domain(url)
            parameters = extract_parameters(url)

            if not parameters:
                print(colored(f"[×] No parameters found in {url}, skipping...", 'red'))
                continue

            found_vulnerability = False
            existing_results = load_json(f"sessions/{domain}/waymap_full_results.json")

            with ThreadPoolExecutor(max_workers=thread_count) as executor:
                futures = {
                    executor.submit(test_lfi_payload, url, param, payload_entry['payload'], payload_entry['response']): (param, payload_entry['payload'])
                    for param in parameters for payload_entry in payloads
                }

                for future in as_completed(futures):
                    result = future.result()

                    if result['vulnerable']:
                        full_url = result['url']
                        parameter = result['parameter']
                        payload = result['payload']

                        if any(entry['url'] == full_url and entry['parameter'] == parameter and entry['payload'] == payload
                               for entry in existing_results.get("scans", {}).get("LFI", [])):
                            print(colored(f"[!] Already recorded, skipping: {full_url}", 'cyan'))
                            continue

                        found_vulnerability = True

                        print(colored(f"[★] Vulnerable URL: {full_url}", 'white', attrs=['bold']))
                        print(colored(f"[•] Injected Parameter: {parameter}", 'green'))
                        print(colored(f"[•] Payload Used: {payload}", 'blue'))

                        save_results(domain, full_url, parameter, payload, "LFI")

                        if not no_prompt:
                            while True:
                                user_input = input(colored("\n[?] Continue testing other URLs? (y/n): ", 'yellow')).strip().lower()
                                if user_input in ['y', 'n']:
                                    break
                                print(colored("[×] Invalid input. Enter 'y' or 'n'.", 'red'))

                            if user_input == 'n':
                                print(colored("[•] Stopping further scans as per user's decision.", 'red'))
                                stop_scan.set()
                                return
                        else:
                            user_input = DEFAULT_INPUT
                            if user_input == 'n':
                                print(colored("[•] Stopping scans as per default setting.", 'red'))
                                stop_scan.set()
                                return
                            else:
                                print(colored("[•] Continuing scan as per default setting.", 'green'))

                if not found_vulnerability:
                    print(colored(f"[×] No vulnerabilities found on: {url}", 'red'))

    except KeyboardInterrupt:
        print(colored("\n[!] Scan interrupted. Exiting...", 'red'))
        stop_scan.set()