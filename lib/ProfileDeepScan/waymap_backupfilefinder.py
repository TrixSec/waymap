# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.

import os
import requests
import json
import queue as Queue
from urllib.parse import urlparse
from threading import Lock
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style, init
import signal
import sys
from datetime import datetime
from lib.waymapcrawlers.backup_crawler import start_crawl
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from lib.core.settings import BACKUP_TIMEOUT
from lib.parse.random_headers import generate_random_headers

init(autoreset=True)
# Global variables
lock = Lock()
stop_threads = False
total_checked = 0
results_queue = Queue.Queue()
temp_file_path = None

def get_results_file(domain):
    """Returns the path for the results JSON file."""
    session_dir = os.path.join("sessions", domain)
    os.makedirs(session_dir, exist_ok=True)
    return os.path.join(session_dir, "waymap_full_results.json")

def get_temp_file(domain):
    """Returns path for temporary progress file."""
    return os.path.join("sessions", domain, "backup_scan_progress.tmp")

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
    global temp_file_path
    temp_file_path = get_temp_file(domain)
    if os.path.exists(temp_file_path):
        try:
            with open(temp_file_path, "r") as f:
                return set(line.strip() for line in f if line.strip())
        except Exception:
            return set()
    return set()

def save_checked_urls(checked_urls):
    """Save checked URLs to temp file."""
    global temp_file_path
    if temp_file_path:
        with lock:
            with open(temp_file_path, "w") as f:
                f.writelines(f"{url}\n" for url in checked_urls)

def save_results(target_url, scan_type, results):
    """Saves results with duplicate checking."""
    domain = urlparse(target_url).netloc
    file_path = get_results_file(domain)
    
    existing_data = load_existing_results(domain)
    existing_entries = set()
    
    for scan in existing_data.get("scans", []):
        if scan.get("type") == "Backup File Scan":
            for entry in scan.get("results", []):
                existing_entries.add(entry.get("url"))
    
    unique_results = [
        res for res in results 
        if res["url"] not in existing_entries
    ]
    
    if not unique_results:
        print(f"{Fore.YELLOW}[INFO] No new backup files to save.{Style.RESET_ALL}")
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
        try:
            os.remove(temp_file_path)
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Failed to remove temp file: {e}{Style.RESET_ALL}")
    
    print(f"{Fore.GREEN}[INFO] Saved {len(unique_results)} new backup files.{Style.RESET_ALL}")

def record_backup(url, status):
    """Records a backup file finding."""
    return {
        "url": url,
        "status": status,
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

def read_crawled_urls(file_path):
    """Read URLs from the specified file and filter directory-like URLs."""
    if not os.path.exists(file_path):
        print(f"{Fore.RED}[!] File not found: {file_path}{Style.RESET_ALL}")
        return []

    directory_urls = []
    with open(file_path, "r") as f:
        for line in f.readlines():
            url = line.strip()
            if url and urlparse(url).path.endswith('/'):  
                directory_urls.append(url)

    if not directory_urls:
        print(f"{Fore.YELLOW}[!] No directory-like URLs found in {file_path}{Style.RESET_ALL}")
    return directory_urls

def extract_target_domain(url):
    """Extract the target domain from a given URL."""
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        if not domain:
            raise ValueError("Invalid URL")
        return domain
    except Exception as e:
        print(f"{Fore.RED}[!] Error extracting domain from URL: {url}\n{e}{Style.RESET_ALL}")
        return None

def generate_backup_urls(url, extensions):
    """Generate potential backup file URLs from a base URL."""
    parsed_url = urlparse(url)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
    path_parts = parsed_url.path.strip('/').split('/')
    backup_urls = []

    for i in range(len(path_parts)):
        current_path = '/'.join(path_parts[:i + 1])
        for ext in extensions:
            backup_urls.append(f"{base_url}/{current_path}{ext}")

    return backup_urls

def test_backup_url(backup_url, checked_urls):
    """Test if a backup URL exists."""
    global total_checked, stop_threads
    
    if stop_threads or backup_url in checked_urls:
        return None
    
    try:
        headers = generate_random_headers()
        response = requests.head(backup_url, timeout=BACKUP_TIMEOUT, verify=False, headers=headers)
        
        with lock:
            total_checked += 1
            print(f"\r{Fore.CYAN}[Info] Total URLs Checked: {total_checked}{Style.RESET_ALL}", end="")

        if response.status_code == 200:
            result = record_backup(backup_url, "Found")
            print(f"\n{Fore.GREEN}[+] Found backup file: {backup_url}{Style.RESET_ALL}")
            return result
        elif response.status_code == 403:
            result = record_backup(backup_url, "Forbidden")
            print(f"\n{Fore.YELLOW}[+] Forbidden backup file: {backup_url}{Style.RESET_ALL}")
            return result
    except requests.exceptions.RequestException:
        pass
    
    return None

def find_backup_files(target_url, threads=20):
    """Scan for backup files using URLs from crawl2.txt."""
    global stop_threads, total_checked
    
    domain = urlparse(target_url).netloc
    session_path = f"sessions/{domain}/crawl2.txt"
    checked_urls = load_checked_urls(domain)
    backup_extensions = [".zip", ".tar.gz", ".bak", ".old", ".7z"]
    current_results = []
    
    urls = read_crawled_urls(session_path)
    if not urls:
        print(f"{Fore.RED}[!] No valid URLs to process in {session_path}{Style.RESET_ALL}")
        return []

    print(f"{Fore.CYAN}[Backup Files Finder] Scanning for backup files...{Style.RESET_ALL}")

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = []
        for url in urls:
            backup_urls = generate_backup_urls(url, backup_extensions)
            for backup_url in backup_urls:
                futures.append(executor.submit(
                    test_backup_url, 
                    backup_url, 
                    checked_urls, 
                    load_existing_results(domain),
                    target_url
                ))
                checked_urls.add(backup_url)

        try:
            for future in as_completed(futures):
                if stop_threads:
                    break
                result = future.result()
                if result:
                    current_results.append(result)
        except KeyboardInterrupt:
            print(f"\n{Fore.RED}[!] Scanning interrupted! Saving progress...{Style.RESET_ALL}")
            stop_threads = True

    save_checked_urls(checked_urls)
    return current_results

def handle_exit():
    """Handle cleanup and save progress on program exit."""
    global stop_threads
    stop_threads = True
    print(f"\n{Fore.RED}[!] Program terminated! Saving progress...{Style.RESET_ALL}")
    sys.exit(0)

def backupfiles(target_url):
    """Main backup file scanning function."""
    signal.signal(signal.SIGINT, handle_exit)
    
    domain = extract_target_domain(target_url)
    if not domain:
        print(f"{Fore.RED}[!] Unable to start the scan due to invalid target URL.{Style.RESET_ALL}")
        return

    print(f"{Fore.CYAN}[+] Target domain: {domain}{Style.RESET_ALL}")
    
    session_dir = f"sessions/{domain}"
    os.makedirs(session_dir, exist_ok=True)

    crawl_file = os.path.join(session_dir, "crawl2.txt")
    if os.path.exists(crawl_file):
        os.remove(crawl_file)

    try:
        start_crawl(target_url)
        results = find_backup_files(target_url)
        
        if results:
            save_results(target_url, "Backup File Scan", results)
        
        print("\n==== Scan Results Summary ====")
        print(f"{Style.BRIGHT}{Fore.CYAN}⇨ Total URLs Checked: {total_checked}{Style.RESET_ALL}")
        found = len([r for r in results if r["status"] == "Found"])
        forbidden = len([r for r in results if r["status"] == "Forbidden"])
        print(f"{Style.BRIGHT}{Fore.GREEN}⇨ Backup Files Found: {found}{Style.RESET_ALL}")
        print(f"{Style.BRIGHT}{Fore.YELLOW}⇨ Forbidden Backup Files: {forbidden}{Style.RESET_ALL}")
        print("==== End of Scan ====")

    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Process interrupted! Saving progress...{Style.RESET_ALL}")
