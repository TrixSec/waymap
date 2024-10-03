# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.

import random
import requests
import os
from datetime import datetime
from termcolor import colored
import threading
import signal

data_dir = os.path.join(os.getcwd(), 'data')
stop_scan = threading.Event()

def signal_handler(sig, frame):
    print(colored("\n[!] Scan interrupted by user. Stopping...", 'red'))
    stop_scan.set()

signal.signal(signal.SIGINT, signal_handler)

def load_cors_payloads(file_path):
    payloads = []
    try:
        with open(file_path, 'r') as file:
            for line in file:
                if line.strip():
                    try:
                        name, payload, response = line.strip().split('::')
                        payloads.append({'name': name, 'payload': payload, 'response': response})
                    except ValueError:
                        print(colored(f"[×] Malformed payload in the file: {line.strip()}", 'red'))
    except FileNotFoundError:
        print(colored(f"[×] Payload file not found at: {file_path}", 'red'))
    return payloads

def test_cors_vulnerability(url, payload, expected_response, user_agent):
    if stop_scan.is_set():
        return {'vulnerable': False}
    
    headers = {'Origin': payload, 'User-Agent': user_agent}
    
    try:
        response = requests.options(url, headers=headers, timeout=10)
        cors_header = response.headers.get('Access-Control-Allow-Origin', '')
        if expected_response in cors_header:
            return {'vulnerable': True, 'response': response, 'payload': payload, 'url': url}
    except requests.RequestException as e:
        if not stop_scan.is_set():
            print(colored(f"[×] Error testing payload on {url}: {e}", 'red'))

    return {'vulnerable': False}

def perform_cors_scan(crawled_urls, user_agents, verbose=False):
    payloads = load_cors_payloads(os.path.join(data_dir, 'corspayload.txt'))

    use_threads = input(colored("[?] Do you want to use threads for scanning? (y/n, press Enter for default [n]): ", 'yellow')).strip().lower()
    max_threads = 1

    if use_threads == 'y':
        while True:
            try:
                max_threads = int(input(colored("[?] How many threads do you want to use (1-10)? ", 'yellow')))
                if 1 <= max_threads <= 10:
                    break
                else:
                    print(colored("[×] Please enter a valid number between 1 and 10.", 'red'))
            except ValueError:
                print(colored("[×] Please enter a valid number.", 'red'))

    if use_threads == 'n' or max_threads == 1:
        for url in crawled_urls:
            if stop_scan.is_set():
                break

            print(colored(f"\n[•] Testing URL: {url}", 'yellow'))

            for payload_entry in payloads:
                if stop_scan.is_set():
                    break

                name = payload_entry['name']
                payload = payload_entry['payload']
                expected_response = payload_entry['response']

                timestamp = datetime.now().strftime("%H:%M:%S")

                if verbose:
                    print(f"[{colored(timestamp, 'blue')}] [Info]: Testing {name}")

                user_agent = random.choice(user_agents)
                result = test_cors_vulnerability(url, payload, expected_response, user_agent)
                
                if result['vulnerable']:
                    print(colored(f"[★] Vulnerable URL found: {result['url']}", 'white', attrs=['bold']))
                    print(colored(f"[•] Vulnerable Origin: {payload}", 'green'))
                    print(colored(f"[•] Expected Response: {result['payload']}", 'green'))

                    user_input = input(colored("\n[?] Vulnerable URL found. Do you want to continue testing other URLs? (y/n): ", 'yellow')).strip().lower()
                    if user_input == 'n':
                        print(colored("[•] Stopping further scans as per user's decision.", 'red'))
                        stop_scan.set()
                        break

    else:
        threads = []
        for url in crawled_urls:
            if stop_scan.is_set():
                break

            print(colored(f"\n[•] Testing URL: {url}", 'yellow'))

            for payload_entry in payloads:
                if stop_scan.is_set():
                    break

                name = payload_entry['name']
                payload = payload_entry['payload']
                expected_response = payload_entry['response']

                timestamp = datetime.now().strftime("%H:%M:%S")

                if verbose:
                    print(f"[{colored(timestamp, 'blue')}] [Info]: Testing {name}")

                user_agent = random.choice(user_agents)

                thread = threading.Thread(target=thread_target, args=(url, payload, expected_response, user_agent))
                threads.append(thread)
                thread.start()

        for thread in threads:
            thread.join()

def thread_target(url, payload, expected_response, user_agent):
    """Thread target function to test CORS vulnerability and print results immediately."""
    result = test_cors_vulnerability(url, payload, expected_response, user_agent)
    if result['vulnerable']:
        print(colored(f"[★] Vulnerable URL found: {result['url']}", 'white', attrs=['bold']))
        print(colored(f"[•] Vulnerable Origin: {payload}", 'green'))
        print(colored(f"[•] Expected Response: {result['payload']}", 'green'))

        user_input = input(colored("\n[?] Vulnerable URL found. Do you want to continue testing other URLs? (y/n): ", 'yellow')).strip().lower()
        if user_input == 'n':
            print(colored("[•] Stopping further scans as per user's decision.", 'red'))
            stop_scan.set()


