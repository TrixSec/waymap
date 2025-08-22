# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.

import requests
import os
import json
from urllib.parse import urljoin, urlparse
from colorama import Fore, Style
from threading import Lock
from datetime import datetime
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import signal
from tqdm import tqdm 
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from lib.core.settings import FUZZER_THREADS
from lib.core.settings import FUZZER_TIMEOUT
from lib.parse.random_headers import generate_random_headers

# Global variables
shutdown_requested = False
checked_urls = set()
checked_urls_lock = Lock()
temp_file_path = None
current_results = []

def get_results_file(domain):
    """Returns the path for the results JSON file."""
    session_dir = os.path.join("sessions", domain)
    os.makedirs(session_dir, exist_ok=True)
    return os.path.join(session_dir, "waymap_full_results.json")

def get_temp_file(domain):
    """Returns path for temporary progress file."""
    return os.path.join("sessions", domain, "dirfuzz_progress.tmp")

def load_existing_results(domain):
    """Loads existing results with proper format validation."""
    file_path = get_results_file(domain)
    if not os.path.exists(file_path):
        return {"scans": []}
    
    try:
        with open(file_path, "r") as file:
            data = json.load(file)
            if not isinstance(data.get("scans", []), list):
                data["scans"] = []
            return data
    except (json.JSONDecodeError, FileNotFoundError):
        return {"scans": []}

def load_checked_urls(domain):
    """Load already checked URLs from temp file."""
    global checked_urls, temp_file_path
    temp_file_path = get_temp_file(domain)
    if os.path.exists(temp_file_path):
        try:
            with open(temp_file_path, "r") as f:
                return set(line.strip() for line in f if line.strip())
        except Exception:
            return set()
    return set()

def save_checked_urls():
    """Save checked URLs to temp file."""
    if temp_file_path:
        with checked_urls_lock:
            with open(temp_file_path, "w") as f:
                f.writelines(f"{url}\n" for url in checked_urls)

def save_results(target_url, scan_type, results):
    """Saves results with duplicate checking."""
    domain = urlparse(target_url).netloc
    file_path = get_results_file(domain)
    
    existing_data = load_existing_results(domain)
    existing_entries = set()
    
    for scan in existing_data.get("scans", []):
        if scan.get("type") == "Directory Fuzzing":
            for entry in scan.get("results", []):
                existing_entries.add((entry.get("url"), entry.get("word")))
    
    unique_results = [
        res for res in results 
        if (res["url"], res["word"]) not in existing_entries
    ]
    
    if not unique_results:
        print(f"{Fore.YELLOW}[INFO] No new directories to save.{Style.RESET_ALL}")
        return
    
    scan_entry = {
        "type": scan_type,
        "scan_date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "results": unique_results
    }

    existing_data["scans"].append(scan_entry)
    
    with open(file_path, "w") as file:
        json.dump(existing_data, file, indent=4)
    
    if temp_file_path and os.path.exists(temp_file_path):
        os.remove(temp_file_path)
    
    print(f"{Fore.GREEN}[INFO] Saved {len(unique_results)} new directories.{Style.RESET_ALL}")

def record_directory(target_url, word, final_url):
    """Records a directory finding."""
    return {
        "url": final_url,
        "word": word,
        "status": "Discovered",
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

def correct_url(url):
    """Ensure the URL is correctly formatted."""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url

def load_wordlist(file_name):
    """Load wordlist from a file."""
    try:
        with open(file_name, "r") as file:
            return [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        print(f"{Fore.RED}[ERROR] Wordlist file '{file_name}' not found.")
        exit(1)

def fetch_directory(url, word):
    """Check if a directory exists with thread-safe tracking."""
    global shutdown_requested, checked_urls
    
    if shutdown_requested:
        return False, None, word
    
    with checked_urls_lock:
        if url in checked_urls:
            return False, None, word
        checked_urls.add(url)
    
    try:
        headers = generate_random_headers()
        response = requests.get(
            url,
            headers=headers,
            timeout=FUZZER_TIMEOUT,
            allow_redirects=False,
            verify=False
        )
        if response.status_code in [200, 301, 302, 403, 401]:
            return True, response.url, word
        return False, None, word
    except requests.RequestException:
        return False, None, word
    finally:
        save_checked_urls()

def signal_handler(sig, frame):
    """Handle keyboard interrupts gracefully."""
    global shutdown_requested
    shutdown_requested = True
    print(f"\n{Fore.YELLOW}[WARNING] Keyboard interrupt detected. Saving progress...{Style.RESET_ALL}")
    if current_results:
        save_results(globals().get('target_url', ''), "Directory Fuzzing (Partial)", current_results)

def dirfuzz(target_url):
    """Main directory fuzzing function with all requested features."""
    global shutdown_requested, checked_urls, current_results
    
    start_time = time.time()
    target_url = correct_url(target_url)
    domain = urlparse(target_url).netloc
    current_results = []
    
    globals()['target_url'] = target_url
    
    checked_urls = load_checked_urls(domain)
    
    print(f"{Fore.CYAN}[INFO] Starting directory fuzzing for: {target_url}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[INFO] Resuming from {len(checked_urls)} already checked URLs{Style.RESET_ALL}")

    wordlists = [
        os.path.join("data", "waymap_dirfuzzlist.txt"),
        os.path.join("data", "waymap_dirfuzzlist2.txt")
    ]
    
    wordlist = []
    for wl in wordlists:
        try:
            wordlist.extend(load_wordlist(wl))
        except FileNotFoundError as e:
            print(f"{Fore.RED}{e}{Style.RESET_ALL}")
            return

    signal.signal(signal.SIGINT, signal_handler)

    with tqdm(total=len(wordlist), desc="Fuzzing Directories...") as pbar:
        with ThreadPoolExecutor(max_workers=FUZZER_THREADS) as executor:
            futures = []
            for word in wordlist:
                if shutdown_requested:
                    break
                dir_url = urljoin(target_url, word)
                futures.append(executor.submit(fetch_directory, dir_url, word))

            for future in as_completed(futures):
                if shutdown_requested:
                    break

                try:
                    exists, final_url, word = future.result()
                    if exists:
                        result = record_directory(target_url, word, final_url or urljoin(target_url, word))
                        current_results.append(result)
                        print(f"{Fore.GREEN}[+] Found directory: {result['url']}{Style.RESET_ALL}")
                except Exception as e:
                    print(f"{Fore.RED}[ERROR] Processing {word}: {str(e)[:100]}{Style.RESET_ALL}")
                finally:
                    pbar.update(1)

    save_results(target_url, "Directory Fuzzing", current_results)
    
    elapsed = time.time() - start_time
    print(f"\n{Fore.CYAN}[INFO] Found {len(current_results)} directories in {elapsed:.2f} seconds{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[INFO] Total checked URLs: {len(checked_urls)}{Style.RESET_ALL}")