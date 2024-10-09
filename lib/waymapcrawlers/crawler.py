# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import time
import sys
import os
import threading
import signal
from lib.core.settings import CRAWLING_EXCLUDE_EXTENSIONS

visited_urls = set()
all_urls = []
valid_urls = []
total_urls = 0
valid_url_count = 0

REQUEST_TIMEOUT = 10

BOLD = '\033[1m'
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
MAGENTA = '\033[95m'
CYAN = '\033[96m'
RESET = '\033[0m'

lock = threading.Lock()

stop_crawl = False
def handle_interrupt(signal, frame):
    global stop_crawl
    stop_crawl = True
    print(f"\n{RED}{BOLD}[×] Crawling interrupted. Saving results...{RESET}")

signal.signal(signal.SIGINT, handle_interrupt)

def get_domain_dir(base_domain):
    """Create and return the directory for the given base domain."""
    domain_dir = os.path.join(os.getcwd(), 'sessions', base_domain)
    os.makedirs(domain_dir, exist_ok=True)
    return domain_dir

def get_crawl_file_path(base_domain):
    """Return the path for the crawl file of the given base domain."""
    return os.path.join(get_domain_dir(base_domain), 'crawl.txt')

def load_crawled_urls(base_domain):
    """Load previously crawled URLs from the crawl file."""
    crawl_file = get_crawl_file_path(base_domain)
    if os.path.exists(crawl_file):
        with open(crawl_file, 'r') as file:
            return set(line.strip() for line in file.readlines())
    return set()

def save_crawled_urls(base_domain, urls):
    """Append crawled URLs to the crawl file."""
    crawl_file = get_crawl_file_path(base_domain)
    with open(crawl_file, 'a') as file:
        for url in urls:
            file.write(f"{url}\n")

def remove_crawl_file(base_domain):
    """Remove the crawl file for re-crawling."""
    crawl_file = get_crawl_file_path(base_domain)
    if os.path.exists(crawl_file):
        os.remove(crawl_file)
        print(f"\n{GREEN}[•] Removed {crawl_file} as user is re-crawling a previously crawled URL.{RESET}")

def crawl_url(url, base_domain, next_urls_to_crawl):
    """Crawl a single URL and extract valid links."""
    global total_urls, valid_url_count
    if stop_crawl:
        return

    try:
        headers = {"User-Agent": "Mozilla/5.0"}  
        response = requests.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True, verify=False, headers=headers)
        final_url = response.url

        parsed_final_url = urlparse(final_url)
        if parsed_final_url.netloc != base_domain or should_skip_url(final_url):
            return

        soup = BeautifulSoup(response.text, 'html.parser')
        links = soup.find_all('a')

        for link in links:
            href = link.get('href')
            if href:
                full_url = urljoin(final_url, href)

                with lock:
                    visited_urls.add(full_url)
                    all_urls.append(full_url) 
                    total_urls += 1

                if is_valid_url(full_url) and is_within_domain(full_url, base_domain) and has_query_parameters(full_url):
                    with lock:
                        valid_urls.append(full_url)
                        valid_url_count += 1

                with lock:
                    sys.stdout.write(f"\r{BOLD}{YELLOW}[•] Total URLs crawled: {total_urls} | Valid URLs: {valid_url_count}{RESET}")
                    sys.stdout.flush()

                next_urls_to_crawl.append(full_url)  

    except requests.RequestException:
        pass 

def should_skip_url(url):
    """Determine if the URL should be skipped based on its extension."""
    return any(url.lower().endswith(ext) for ext in CRAWLING_EXCLUDE_EXTENSIONS)

def crawl_worker(urls_to_crawl, base_domain, next_urls_to_crawl):
    """Worker function for crawling URLs in a separate thread."""
    for url in urls_to_crawl:
        crawl_url(url, base_domain, next_urls_to_crawl)

def crawl(urls_to_crawl, depth, max_depth, base_domain, num_threads):
    """Crawl the given URLs up to a specified depth."""
    global total_urls
    if depth > max_depth or stop_crawl:
        return

    total_urls = 0
    print(f"\n{BOLD}{BLUE}[•] Crawling depth: {depth}{RESET}")
    next_urls_to_crawl = []

    if num_threads > 1:
        thread_list = []
        for i in range(num_threads):
            urls_chunk = urls_to_crawl[i::num_threads]
            thread = threading.Thread(target=crawl_worker, args=(urls_chunk, base_domain, next_urls_to_crawl))
            thread_list.append(thread)
            thread.start()

        for thread in thread_list:
            thread.join()
    else:
        crawl_worker(urls_to_crawl, base_domain, next_urls_to_crawl)

    scanable_urls_at_depth = len(next_urls_to_crawl)
    print(f"\n{BOLD}{CYAN}[•] Found {scanable_urls_at_depth} scanable URLs at depth {depth}. Moving to depth {depth + 1}...{RESET}")

    if next_urls_to_crawl and depth < max_depth:
        time.sleep(1)
        crawl(next_urls_to_crawl, depth + 1, max_depth, base_domain, num_threads)

def is_valid_url(url):
    """Check if the given URL is valid."""
    parsed = urlparse(url)
    return bool(parsed.netloc) and bool(parsed.scheme)

def has_query_parameters(url):
    """Check if the URL contains query parameters."""
    return any(symbol in url for symbol in ['?', '&', '='])

def is_within_domain(url, base_domain):
    """Check if the URL belongs to the base domain."""
    return urlparse(url).netloc == base_domain

def run_crawler(start_url, max_depth):
    """Main function to run the crawler."""
    global total_urls, valid_url_count
    total_urls = 0
    valid_url_count = 0
    visited_urls.clear()
    all_urls.clear()
    valid_urls.clear()

    parsed_start_url = urlparse(start_url)
    base_domain = parsed_start_url.netloc

    previously_crawled = load_crawled_urls(base_domain)

    if start_url in previously_crawled:
        remove_crawl_file(base_domain)

    use_threads = input(f"{BOLD}{CYAN}Do you want to enable multi-threading? (y/n): {RESET}").strip().lower() == 'y'

    num_threads = 1
    if use_threads:
        while True:
            try:
                num_threads = int(input(f"{BOLD}{MAGENTA}How many threads do you want to use? (max 10): {RESET}"))
                if 1 <= num_threads <= 10:
                    break
                else:
                    print(f"{RED}[×] Please choose a number between 1 and 10.{RESET}")
            except ValueError:
                print(f"{RED}[×] Please enter a valid number.{RESET}")

    try:
        crawl([start_url], 1, max_depth, base_domain, num_threads)

    finally:
        save_crawled_urls(base_domain, valid_urls)
        print(f"\n{GREEN}[•] Crawling stopped. Total URLs found: {total_urls}, Valid URLs saved: {len(valid_urls)}.{RESET}")

    return valid_urls
