# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.

import requests
import os
import json
from urllib.parse import urljoin, urlparse
from colorama import Fore, Style, init
from datetime import datetime
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import signal
import sys
from tqdm import tqdm 
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from lib.core.settings import FUZZER_THREADS
from lib.core.settings import FUZZER_TIMEOUT
from lib.parse.random_headers import generate_random_headers

init(autoreset=True)

shutdown_requested = False
results = []
target_url = ""

def correct_url(url):
    """Ensure the URL is correctly formatted."""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url

def load_wordlist(file_name):
    """Load wordlist from a file."""
    try:
        with open(file_name, "r") as file:
            return [line.strip() for line in file.readlines()]
    except FileNotFoundError:
        print(f"{Fore.RED}[ERROR] Wordlist file '{file_name}' not found.")
        exit(1)

def fetch_directory(url):
    """Check if a directory exists."""
    global shutdown_requested
    if shutdown_requested:
        return False, None 

    try:
        headers = generate_random_headers()
        response = requests.get(url, timeout=FUZZER_TIMEOUT, allow_redirects=True, verify=False, headers=headers)
        if response.status_code in [200, 301, 302]:
            return True, response.url
        return False, None
    except requests.RequestException:
        return False, None

def save_results(target_url, results):
    """Save results to a JSON file with the target domain and timestamp."""
    domain = urlparse(target_url).netloc
    folder = os.path.join("sessions", domain)
    os.makedirs(folder, exist_ok=True)
    output_file = os.path.join(folder, "deepscan_dirfuzz_results.json")

    scan_data = {
        "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "results": results
    }

    if os.path.exists(output_file):
        with open(output_file, "r") as file:
            existing_data = json.load(file)
        existing_data.append(scan_data)
        with open(output_file, "w") as file:
            json.dump(existing_data, file, indent=4)
    else:
        with open(output_file, "w") as file:
            json.dump([scan_data], file, indent=4)


def signal_handler(sig, frame):
    """Handle the signal interrupt to terminate all threads immediately."""
    global shutdown_requested
    shutdown_requested = True
    print(f"\n{Fore.YELLOW}{Style.BRIGHT}[WARNING] Keyboard interruption detected. Saving results and exiting...{Style.RESET_ALL}")
    
    save_results(target_url, results)
    sys.exit(0)

def dirfuzz(target_url):
    global results  

    start_time = time.perf_counter() 

    target_url = correct_url(target_url)

    print(f"{Fore.CYAN}[INFO] Starting directory fuzzing for: {Fore.WHITE}{Style.BRIGHT}{target_url}{Style.RESET_ALL}")

    data_dir = "data"
    wordlist_file1 = os.path.join(data_dir, "waymap_dirfuzzlist.txt")
    wordlist_file2 = os.path.join(data_dir, "waymap_dirfuzzlist2.txt")

    wordlist1 = load_wordlist(wordlist_file1)
    wordlist2 = load_wordlist(wordlist_file2)

    wordlist = wordlist1 + wordlist2

    checked_dirs = set()

    signal.signal(signal.SIGINT, signal_handler)

    with tqdm(total=len(wordlist), desc="Fuzzing Directories...", ncols=100, dynamic_ncols=True, bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed} < {remaining}, {rate_fmt}]") as pbar:
        with ThreadPoolExecutor(max_workers=FUZZER_THREADS) as executor:
            futures = {}
            for word in wordlist:
                dir_url = urljoin(target_url, word)
                if dir_url not in checked_dirs:
                    checked_dirs.add(dir_url)
                    futures[executor.submit(fetch_directory, dir_url)] = word

            for future in as_completed(futures):
                if shutdown_requested:
                    break  

                word = futures[future]
                try:
                    found, redirected_url = future.result()
                    if found:
                        result = {
                            "word": word,
                            "url": redirected_url or urljoin(target_url, word)
                        }
                        results.append(result)
                        print(
                            f"{Fore.GREEN}{Style.BRIGHT}[POSSIBLE] Sensitive Directory: {Style.RESET_ALL}{Fore.WHITE}{Style.BRIGHT}{result['url']}{Style.RESET_ALL}"
                        )
                except Exception as e:
                    print(f"{Fore.RED}[ERROR] Error processing {word}: {e}")

                pbar.update(1)  

    if results:
        print(f"\n{Fore.YELLOW}{Style.BRIGHT}[WARNING] Found {len(results)} potential sensitive directories.{Style.RESET_ALL}")
    else:
        print(f"\n{Fore.GREEN}{Style.BRIGHT}[INFO] No sensitive directories found.{Style.RESET_ALL}")

    save_results(target_url, results)

    end_time = time.perf_counter()
    elapsed_time = end_time - start_time
    print(f"\n{Fore.CYAN}{Style.BRIGHT}[INFO] Total Time Taken: {elapsed_time:.2f} seconds{Style.RESET_ALL}")
