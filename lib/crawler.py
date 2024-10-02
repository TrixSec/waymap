# Copyright (c) 2024 waymap developers 
# See the file 'LICENSE' for copying permission

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import time
import sys
import os
import threading
import signal

visited_urls = set()
valid_urls = []
total_urls = 0

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

stop_crawling = False

def get_domain_dir(base_domain):
    domain_dir = os.path.join(os.getcwd(), 'sessions', base_domain)
    if not os.path.exists(domain_dir):
        os.makedirs(domain_dir)
    return domain_dir

def get_crawl_file_path(base_domain):
    domain_dir = get_domain_dir(base_domain)
    return os.path.join(domain_dir, 'crawl.txt')

def load_crawled_urls(base_domain):
    crawl_file = get_crawl_file_path(base_domain)
    if os.path.exists(crawl_file):
        with open(crawl_file, 'r') as file:
            return set(line.strip() for line in file.readlines())
    return set()

def save_crawled_urls(base_domain, urls):
    crawl_file = get_crawl_file_path(base_domain)
    with open(crawl_file, 'a') as file:
        for url in urls:
            file.write(f"{url}\n")

def remove_crawl_file(base_domain):
    crawl_file = get_crawl_file_path(base_domain)
    if os.path.exists(crawl_file):
        os.remove(crawl_file)
        print(f"\n{GREEN}[•] Removed {crawl_file} as user is re-crawling a previously crawled URL.{RESET}")

def signal_handler(sig, frame):
    global stop_crawling
    stop_crawling = True
    print(f"\n\n{RED}[×] Keyboard interruption detected. Stopping the crawling process...{RESET}")

signal.signal(signal.SIGINT, signal_handler)

def crawl_url(url, base_domain, next_urls_to_crawl):
    global total_urls, stop_crawling
    if stop_crawling:
        return

    try:
        response = requests.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
        final_url = response.url

        parsed_final_url = urlparse(final_url)
        if parsed_final_url.netloc != base_domain:
            return  

        soup = BeautifulSoup(response.text, 'html.parser')
        links = soup.find_all('a')

        for link in links:
            href = link.get('href')
            if href:
                full_url = urljoin(final_url, href)

                if is_valid_url(full_url) and full_url not in visited_urls and is_within_domain(full_url, base_domain) and has_query_parameters(full_url):
                    with lock: 
                        visited_urls.add(full_url)
                        valid_urls.append(full_url)
                        total_urls += 1

                    sys.stdout.write(f"\r{BOLD}{YELLOW}[•] URLs crawled: {total_urls}{RESET}")
                    sys.stdout.flush()

                    next_urls_to_crawl.append(full_url)  

    except requests.RequestException as e:
        print(f"\n{RED}{BOLD}[×] Error crawling {url}: {e}{RESET}")

def crawl_worker(urls_to_crawl, base_domain, next_urls_to_crawl):
    global stop_crawling
    for url in urls_to_crawl:
        if stop_crawling:
            return
        crawl_url(url, base_domain, next_urls_to_crawl)

def crawl(urls_to_crawl, depth, max_depth, base_domain, num_threads):
    global total_urls, stop_crawling
    if depth > max_depth or stop_crawling:
        return

    total_urls = 0

    print(f"\n{BOLD}{BLUE}[•] Crawling depth: {depth}{RESET}")  
    next_urls_to_crawl = []  

    scanable_urls_at_depth = 0

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

    if stop_crawling:
        return

    scanable_urls_at_depth = len(next_urls_to_crawl)

    print(f"\n[•] Found {scanable_urls_at_depth} scanable URLs at depth {depth}. Moving to depth {depth + 1}...")

    if next_urls_to_crawl and depth < max_depth:
        time.sleep(1)  
        crawl(next_urls_to_crawl, depth + 1, max_depth, base_domain, num_threads)

def is_valid_url(url):
    parsed = urlparse(url)
    return bool(parsed.netloc) and bool(parsed.scheme)

def has_query_parameters(url):
    return any(symbol in url for symbol in ['?', '&', '='])

def is_within_domain(url, base_domain):
    return urlparse(url).netloc == base_domain

def run_crawler(start_url, max_depth):
    global total_urls, stop_crawling
    total_urls = 0
    stop_crawling = False
    visited_urls.clear()
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

    except KeyboardInterrupt:
        stop_crawling = True

    finally:
        save_crawled_urls(base_domain, valid_urls)
        print(f"\n{GREEN}[•] Crawling stopped. {len(valid_urls)} URLs saved.{RESET}")

    return valid_urls
