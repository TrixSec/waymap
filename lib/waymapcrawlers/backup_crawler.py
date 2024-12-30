# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import re
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from queue import Queue
from threading import Lock
from colorama import Fore, Style, init
import signal
import sys
from lib.core.settings import BACKUP_CRAWLER_THREADS
from lib.core.settings import DISSALLOWED_EXT
from lib.core.settings import VALID_EXTENSIONS
from lib.parse.random_headers import generate_random_headers

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

init(autoreset=True)

unique_urls = set()
queue = Queue()

lock = Lock()

output_file = None
stop_threads = False
saved_count = 0  


def is_valid_url_to_crawl(url, base_domain):
    """
    Validate the URL for crawling based on specified rules.
    """
    parsed_url = urlparse(url)
    path = parsed_url.path

    valid_extensions = VALID_EXTENSIONS
    if not path.endswith(valid_extensions):
        return False

    if parsed_url.netloc != base_domain:
        return False

    return True


def is_valid_url_to_save(url, base_domain):
    """
    Validate the URL for saving based on specified rules.
    """
    parsed_url = urlparse(url)
    path = parsed_url.path

    disallowed_extensions = DISSALLOWED_EXT
    if any(ext in path for ext in disallowed_extensions):
        return False

    if re.fullmatch(r"[\d\W]+", path.strip("/")):
        return False

    if parsed_url.netloc != base_domain:
        return False

    return True


def save_url(url):
    """
    Save the URL to the output file and increment the counter.
    """
    global output_file, saved_count
    with lock:
        with open(output_file, "a") as f:
            f.write(url + "\n")
        saved_count += 1


def print_counters():
    """
    Print the live count of saved URLs.
    """
    with lock:
        print(
            f"{Fore.GREEN}{Style.BRIGHT}Unique URLs Found: {len(unique_urls)}, "
            f"Saved to File: {saved_count}{Style.RESET_ALL}",
            end="\r",
        )


def crawl_worker(base_domain):
    """
    Worker function to process the URL queue.
    """
    global stop_threads
    while not queue.empty() and not stop_threads:
        url = queue.get()
        try:
            headers = generate_random_headers()
            response = requests.get(url, timeout=10, verify=False, headers=headers)
            if response.status_code != 200:
                queue.task_done()
                continue

            soup = BeautifulSoup(response.text, "html.parser")

            for tag in soup.find_all("a", href=True):
                absolute_url = urljoin(url, tag["href"])
                absolute_url = absolute_url.split("#")[0]

                with lock:
                    if absolute_url in unique_urls:
                        continue
                    unique_urls.add(absolute_url)

                if is_valid_url_to_save(absolute_url, base_domain):
                    save_url(absolute_url)

                if is_valid_url_to_crawl(absolute_url, base_domain):
                    queue.put(absolute_url)

                print_counters()

        except requests.exceptions.RequestException:
            pass 
        finally:
            queue.task_done()


def crawl(start_url, threads):
    """
    Start the crawling process with concurrent threading.
    """
    global unique_urls, output_file, stop_threads

    parsed_start_url = urlparse(start_url)
    base_domain = parsed_start_url.netloc

    session_dir = f"sessions/{base_domain}"
    os.makedirs(session_dir, exist_ok=True)

    output_file = os.path.join(session_dir, "crawl2.txt")

    queue.put(start_url)
    unique_urls.add(start_url)

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [
            executor.submit(crawl_worker, base_domain) for _ in range(threads)
        ]
        try:
            for future in as_completed(futures):
                if stop_threads:
                    break
        except KeyboardInterrupt:
            print(f"\n{Fore.RED}{Style.BRIGHT}Crawling interrupted! Saving progress...{Style.RESET_ALL}")
            stop_threads = True

        queue.join()


def handle_exit(signal_received, frame):
    """
    Handle cleanup and save progress on program exit.
    """
    global stop_threads
    stop_threads = True
    print(f"\n{Fore.RED}{Style.BRIGHT}Program terminated! Saving progress...{Style.RESET_ALL}")

def start_crawl(start_url):
    signal.signal(signal.SIGINT, handle_exit)

    while True:
        try:
            threads = BACKUP_CRAWLER_THREADS
            if threads > 0:
                break
        except ValueError:
            print(f"{Fore.RED}Invalid input! Please enter a valid number.{Style.RESET_ALL}")

    if not start_url.startswith(("http://", "https://")):
        print(f"{Fore.RED}Invalid URL. Please include http:// or https://{Style.RESET_ALL}")

        return  

    print(f"{Fore.YELLOW}Crawling started...{Style.RESET_ALL}")

    crawl(start_url, threads)

    print(f"\n{Fore.CYAN}{Style.BRIGHT}Crawling completed! Results saved to sessions/{urlparse(start_url).netloc}/crawl2.txt{Style.RESET_ALL}")
