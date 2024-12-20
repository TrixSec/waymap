# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.

import os
import requests
import json
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

lock = Lock()

stop_threads = False
total_checked = 0


def read_crawled_urls(file_path):
    """
    Read URLs from the specified file and filter directory-like URLs.
    """
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
    """
    Extract the target domain from a given URL.
    """
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        if not domain:
            raise ValueError("Invalid URL")
        return domain
    except Exception as e:
        print(f"{Fore.RED}[!] Error extracting domain from URL: {url}\n{e}{Style.RESET_ALL}")
        return None


def find_backup_files(target_domain, threads=20):
    """
    Scan for backup files using URLs from crawl2.txt.
    """
    global stop_threads, total_checked

    session_path = f"sessions/{target_domain}/crawl2.txt"
    output_file = f"sessions/{target_domain}/deepscan_backfiles_results.json"

    os.makedirs(f"sessions/{target_domain}", exist_ok=True)

    urls = read_crawled_urls(session_path)
    if not urls:
        print(f"{Fore.RED}[!] No valid URLs to process in {session_path}{Style.RESET_ALL}")
        return

    backup_extensions = [".zip", ".tar.gz", ".bak", ".old", ".7z"]

    print(f"{Fore.CYAN}[Backup Files Finder] Scanning for backup files...{Style.RESET_ALL}")

    if os.path.exists(output_file):
        with open(output_file, "r") as out_file:
            output_data = json.load(out_file)
    else:
        output_data = []

    checked_urls = set()

    def generate_backup_urls(url):
        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        path_parts = parsed_url.path.strip('/').split('/')
        backup_urls = []

        for i in range(len(path_parts)):
            current_path = '/'.join(path_parts[:i + 1])
            for ext in backup_extensions:
                backup_urls.append(f"{base_url}/{current_path}{ext}")

        return backup_urls

    def test_backup_url(backup_url):
        global stop_threads, total_checked
        if backup_url in checked_urls:
            return 
        checked_urls.add(backup_url)

        try:
            headers = generate_random_headers()
            response = requests.head(backup_url, timeout=BACKUP_TIMEOUT, verify=False, headers=headers)
            with lock:
                total_checked += 1
                print(f"\r{Fore.CYAN}[Info] Total URLs Checked: {total_checked}{Style.RESET_ALL}", end="")

            if response.status_code == 200:
                with lock:
                    print(f"\n{Fore.GREEN}{Style.BRIGHT}[Possible] Backup File Found: {backup_url}{Style.RESET_ALL}")
                    output_data.append({
                        "url": backup_url,
                        "status": "Found",
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    })
            elif response.status_code == 403:
                print(f"\n{Fore.YELLOW}{Style.BRIGHT}[Possible] Forbidden Backup File Found: {backup_url}{Style.RESET_ALL}")
                output_data.append({
                    "url": backup_url,
                    "status": "Forbidden",
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                })
        except requests.exceptions.RequestException as e:
            pass 

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = []
        for url in urls:
            backup_urls = generate_backup_urls(url)
            for backup_url in backup_urls:
                futures.append(executor.submit(test_backup_url, backup_url))

        try:
            for future in as_completed(futures):
                if stop_threads:
                    break
        except KeyboardInterrupt:
            print(f"\n{Fore.RED}[!] Scanning interrupted! Saving progress...{Style.RESET_ALL}")
            stop_threads = True

    with open(output_file, "w") as out_file:
        json.dump(output_data, out_file, indent=4)

    print(f"\n{Fore.CYAN}[+] Scan completed! Results saved to {output_file}{Style.RESET_ALL}")


def start_backup_scan(target_url):
    """
    Start the backup scan process by initializing the crawler and scanning for backup files.
    """
    global stop_threads

    target_domain = extract_target_domain(target_url)
    if not target_domain:
        print(f"{Fore.RED}[!] Unable to start the scan due to invalid target URL.{Style.RESET_ALL}")
        return

    print(f"{Fore.CYAN}[+] Target domain extracted: {target_domain}{Style.RESET_ALL}")

    session_dir = f"sessions/{target_domain}"
    os.makedirs(session_dir, exist_ok=True)

    crawl_file = os.path.join(session_dir, "crawl2.txt")
    if os.path.exists(crawl_file):
        os.remove(crawl_file)

    try:
        start_crawl(target_url)

        find_backup_files(target_domain)

    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Process interrupted! Saving progress...{Style.RESET_ALL}")
        stop_threads = True


def handle_exit(signal_received, frame):
    """
    Handle cleanup and save progress on program exit.
    """
    global stop_threads
    stop_threads = True
    print(f"\n{Fore.RED}[!] Program terminated! Saving progress...{Style.RESET_ALL}")
    sys.exit(0)


def backupfiles(target_url):
    signal.signal(signal.SIGINT, handle_exit)
    start_backup_scan(target_url)