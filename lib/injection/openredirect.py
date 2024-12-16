# Copyright (c) 2024 waymap developers 
# See the file 'LICENSE' for copying permission.

import os
import subprocess
from datetime import datetime
from termcolor import colored
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from lib.parse.random_headers import generate_random_headers
from lib.core.settings import DEFAULT_THREADS, MAX_THREADS

data_dir = os.path.join(os.getcwd(), 'data')
stop_scan = threading.Event()

def load_file_lines(file_path):
    """Load lines from a given file."""
    try:
        with open(file_path, 'r') as file:
            return [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        print(colored(f"[×] File not found: {file_path}", 'red'))
    return []

def replace_last_parameter(url, parameter, payload):
    """Replace the last parameter in the URL with the given parameter and payload."""
    parsed_url = urlparse(url)
    query = parsed_url.query.split('&')
    query = [param.replace("{payload}", payload) for param in query]
    if query:
        query[-1] = f"{parameter}={payload}"
    new_query = '&'.join(query)
    return f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"

def test_open_redirect_payload(url, parameter, payload, verbose):
    """Test the open redirect payload on the given URL using curl."""
    if stop_scan.is_set():
        return {'vulnerable': False}
    
    test_url = replace_last_parameter(url, parameter, payload)
    try:
        curl_command = ["curl", "-L", "-s", "-I", test_url]
        result = subprocess.run(curl_command, capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0 and "Location" in result.stdout:
            location = next((line.split(":", 1)[1].strip() for line in result.stdout.splitlines() if "Location" in line), None)
            if location:
                if verbose:
                    print(colored(f"[>>>] Vulnerability Details:", 'cyan'))
                    print(colored(f"  [-] Vulnerable URL: {test_url}", 'green'))
                    print(colored(f"  [-] Redirect URL: {location}", 'yellow'))
                    print(colored(f"  [-] Payload: {payload}", 'yellow'))
                    print(colored(f"  [-] Parameter: {parameter}", 'yellow'))
                    print(colored(f"  [•] Redirected to: {location}", 'blue'))
                return {'vulnerable': True, 'url': test_url, 'payload': payload, 'parameter': parameter}
    except subprocess.TimeoutExpired:
        print(colored(f"[×] Timeout while testing URL: {test_url}", 'red'))
    except subprocess.CalledProcessError as e:
        print(colored(f"[×] Error executing curl: {e}", 'red'))
    
    return {'vulnerable': False}

def perform_redirect_scan(crawled_urls, thread_count=None, no_prompt=False, verbose=False):
    """Perform open redirect scanning on the given crawled URLs."""
    thread_count = thread_count or DEFAULT_THREADS
    thread_count = max(1, min(thread_count, MAX_THREADS))
    parameters = load_file_lines(os.path.join(data_dir, 'openredirectparameters.txt'))
    payloads = load_file_lines(os.path.join(data_dir, 'openredirectpayloads.txt'))

    try:
        for url in crawled_urls:
            if stop_scan.is_set():
                break
            print(colored(f"\n[•] Testing URL: {url}", 'yellow'))

            for parameter in parameters:
                if stop_scan.is_set():
                    break

                print(colored(f"[{datetime.now().strftime('%H:%M:%S')}]", 'blue') +
                      colored(" [INFO] ") + f"Testing Parameter: {parameter}", flush=True)

                with ThreadPoolExecutor(max_workers=thread_count) as executor:
                    future_to_payload = {
                        executor.submit(test_open_redirect_payload, url, parameter, payload, verbose): (parameter, payload)
                        for payload in payloads
                    }

                    for future in as_completed(future_to_payload):
                        if stop_scan.is_set():
                            break

                        result = future.result()

                        if result['vulnerable']:
                            print(colored(f"\n[★] Vulnerability Found! Parameter: {parameter}, Payload: {result['payload']}", 'green', attrs=['bold']))
                            stop_scan.set()
                            print(colored(f"[•] Stopping further scans for this URL as vulnerability is found.", 'red'))
                            break

            if stop_scan.is_set():
                break

    except KeyboardInterrupt:
        print(colored("\n[!] Scan interrupted by user. Exiting cleanly...", 'red'))
        stop_scan.set()
