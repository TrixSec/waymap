# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.

import os
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor
from queue import Queue
import threading
import time
import signal
import sys
from lib.core.settings import VALID_EXTENSIONS, MAX_THREADS

RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
CYAN = "\033[36m"

visited_urls = set()
lock = threading.Lock()
js_files = set()
shutdown_flag = threading.Event() 
queue = Queue()

def save_js_link(js_url, filename):
    """Save JavaScript link to file and update live counter."""
    global js_files
    with lock:
        if js_url not in js_files:
            js_files.add(js_url)
            with open(filename, "a") as file:
                file.write(js_url + "\n")
            print(f"{CYAN}{BOLD}\rUnique JS files saved: {len(js_files)}{RESET}", end="")

def is_same_domain(base_url, target_url):
    """Check if the target URL belongs to the same domain as the base URL."""
    base_domain = urlparse(base_url).netloc
    target_domain = urlparse(target_url).netloc
    return base_domain == target_domain

def is_valid_extension(url):
    """Check if the URL has a valid extension."""
    parsed_url = urlparse(url)
    return parsed_url.path.endswith(VALID_EXTENSIONS)

def crawl_js_links(url, base_url, filename):
    """Crawl a page and extract JavaScript links."""
    global visited_urls

    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, "html.parser")

            script_tags = soup.find_all("script", src=True)
            for tag in script_tags:
                js_url = tag["src"]
                if not js_url.startswith("http"):
                    js_url = urljoin(url, js_url)
                if js_url.endswith(".js"):
                    save_js_link(js_url, filename)

            for anchor in soup.find_all("a", href=True):
                sub_url = anchor["href"]
                full_url = urljoin(url, sub_url)

                if is_same_domain(base_url, full_url) and is_valid_extension(full_url):
                    with lock:
                        if full_url not in visited_urls:
                            visited_urls.add(full_url)
                            queue.put(full_url)
    except requests.exceptions.RequestException as e:
        print(f"{YELLOW}{BOLD}Error fetching URL {url}: {e}{RESET}")

def worker(base_url, filename):
    """Worker function for concurrent crawling."""
    while not queue.empty() and not shutdown_flag.is_set():
        try:
            url = queue.get(timeout=1)
            crawl_js_links(url, base_url, filename)
            queue.task_done()
        except Exception:
            break 

def signal_handler(sig, frame):
    """Handle keyboard interruption (Ctrl+C)."""
    print(f"\n{RED}{BOLD}Keyboard interruption detected! Stopping all threads...{RESET}")
    shutdown_flag.set()  
    save_output(output_file)
    sys.exit(0)

def save_output(filename):
    """Save all discovered JavaScript links before exiting."""
    with open(filename, "w") as file:
        for js_url in js_files:
            file.write(js_url + "\n")
    print(f"\n{GREEN}{BOLD}Output saved to '{filename}'.{RESET}")

def check_internet():
    """Check internet connection by pinging google.com."""
    while True:
        try:
            requests.get("https://www.google.com", timeout=5)
            return True
        except requests.exceptions.RequestException:
            print(f"{RED}{BOLD}No internet connection. Retrying in 5 seconds...{RESET}")
            time.sleep(5)

def start_crawl(base_url):
    """Initialize and start the crawling process."""
    global queue, visited_urls, js_files, output_file

    domain = urlparse(base_url).netloc
    output_dir = os.path.join("sessions", domain)
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, "crawl3.txt")

    open(output_file, "w").close()

    signal.signal(signal.SIGINT, signal_handler)

    check_internet()

    queue = Queue()
    queue.put(base_url)
    visited_urls = {base_url}
    js_files = set()

    print(f"{BLUE}{BOLD}Crawling started...{RESET}")
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        threads = [executor.submit(worker, base_url, output_file) for _ in range(10)]
        try:
            for future in threads:
                future.result() 
        except KeyboardInterrupt:
            signal_handler(None, None)

    print(f"\n{GREEN}{BOLD}Crawling completed! Unique JS files saved to '{output_file}'.{RESET}")
