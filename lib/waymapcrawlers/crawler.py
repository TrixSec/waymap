# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import time
import sys
import os
import threading
import urllib3
from lib.parse.random_headers import generate_random_headers
from lib.core.settings import CRAWLING_EXCLUDE_EXTENSIONS, DEFAULT_THREADS, MAX_THREADS, DEFAULT_INPUT

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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
CYAN = '\033[96m'
RESET = '\033[0m'

lock = threading.Lock()
crawl_done = threading.Event()

def get_domain_dir(base_domain):
    domain_dir = os.path.join(os.getcwd(), 'sessions', base_domain)
    os.makedirs(domain_dir, exist_ok=True)
    return domain_dir

def get_crawl_file_path(base_domain):
    return os.path.join(get_domain_dir(base_domain), 'crawl.txt')

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

def is_language_related(url):
    language_related_keywords = ['ln=', 'lang=', 'locale=', 'nl=']
    parsed_url = urlparse(url)
    query_params = parsed_url.query
    for keyword in language_related_keywords:
        if keyword in query_params:
            return True
    return False

def crawl_url(url, base_domain, next_urls_to_crawl):
    global total_urls, valid_url_count

    try:
        headers = generate_random_headers()
        response = requests.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True, verify=False, headers=headers)
        final_url = response.url

        parsed_final_url = urlparse(final_url)
        if parsed_final_url.netloc != base_domain or should_skip_url(final_url):
            return

        if is_language_related(final_url):
            return

        soup = BeautifulSoup(response.text, 'html.parser')
        links = soup.find_all('a')

        for link in links:
            href = link.get('href')
            if href:
                full_url = urljoin(final_url, href)

                if full_url not in visited_urls and not should_skip_url(full_url):
                    with lock:
                        visited_urls.add(full_url)
                        all_urls.append(full_url)
                        total_urls += 1

                    if is_language_related(full_url):
                        continue

                    if is_valid_url(full_url) and is_within_domain(full_url, base_domain) and has_query_parameters(full_url):
                        with lock:
                            valid_urls.append(full_url)
                            valid_url_count += 1
                            save_valid_url(base_domain, full_url)  

                    with lock:
                        sys.stdout.write(f"\r{BOLD}{YELLOW}[•] Total URLs crawled: {total_urls} | Valid URLs: {valid_url_count}{RESET}")
                        sys.stdout.flush()

                    next_urls_to_crawl.append(full_url)

    except requests.RequestException:
        pass

def save_valid_url(base_domain, url):
    if is_language_related(url):
        return
    
    crawl_file = get_crawl_file_path(base_domain)
    with open(crawl_file, 'a') as file:
        file.write(f"{url}\n")

def should_skip_url(url):
    return any(url.lower().endswith(ext) for ext in CRAWLING_EXCLUDE_EXTENSIONS)

def crawl_worker(urls_to_crawl, base_domain, next_urls_to_crawl):
    for url in urls_to_crawl:
        crawl_url(url, base_domain, next_urls_to_crawl)

def crawl(urls_to_crawl, depth, max_depth, base_domain, num_threads):
    global total_urls
    if depth > max_depth:
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
    parsed = urlparse(url)
    return bool(parsed.netloc) and bool(parsed.scheme)

def has_query_parameters(url):
    return any(symbol in url for symbol in ['?', '&', '='])

def is_within_domain(url, base_domain):
    return urlparse(url).netloc == base_domain

def run_crawler(start_url, max_depth, thread_count, no_prompt):
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

    if no_prompt:
        use_threads = DEFAULT_INPUT.lower() == 'y'
    else:
        use_threads = input(f"{BOLD}{CYAN}Do you want to enable multi-threading? (y/n): {RESET}").strip().lower() == 'y'

    if use_threads and thread_count is not None:
        num_threads = min(thread_count, MAX_THREADS)
    else:
        num_threads = 1

    try:
        crawl([start_url], 1, max_depth, base_domain, num_threads)
        crawl_done.set()
    except KeyboardInterrupt:
        print(f"\n{RED}[!] Crawling interrupted by user.{RESET}")
    finally:
        save_crawled_urls(base_domain, valid_urls)
        print(f"\n{GREEN}[•] Crawling stopped. Total URLs found: {total_urls}, Valid URLs saved: {len(valid_urls)}.{RESET}")

    return valid_urls