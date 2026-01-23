# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.

"""Web Crawler Module."""

import os
import sys
import time
import threading
import requests
from typing import List, Set, Optional
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import urllib3

from lib.core.config import get_config
from lib.core.logger import get_logger
from lib.ui import print_status, print_header, colored
from lib.utils import is_valid_url, has_query_parameters, is_within_domain
from lib.parse.random_headers import generate_random_headers

# Disable warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

config = get_config()
logger = get_logger(__name__)

class WaymapCrawler:
    def __init__(self, base_url: str, max_depth: int = 2, thread_count: int = 1):
        self.start_url = base_url
        self.max_depth = max_depth
        self.thread_count = thread_count
        self.base_domain = urlparse(base_url).netloc
        
        # State
        self.visited_urls: Set[str] = set()
        self.all_urls: List[str] = []
        self.valid_urls: List[str] = []
        self.total_urls = 0
        self.valid_url_count = 0
        
        # Synchronization
        self.lock = threading.Lock()
        self.stop_event = threading.Event()

    def get_crawl_file_path(self) -> str:
        """Get path to crawl results file."""
        return os.path.join(config.get_domain_session_dir(self.base_domain), 'crawl.txt')

    def load_previous_crawl(self) -> Set[str]:
        """Load previously crawled URLs."""
        crawl_file = self.get_crawl_file_path()
        if os.path.exists(crawl_file):
            try:
                with open(crawl_file, 'r') as f:
                    return set(line.strip() for line in f.readlines())
            except Exception as e:
                logger.error(f"Error loading crawl file: {e}")
        return set()

    def save_valid_url(self, url: str) -> None:
        """Save a valid URL to file."""
        if self._is_language_related(url):
            return
            
        crawl_file = self.get_crawl_file_path()
        try:
            with open(crawl_file, 'a') as f:
                f.write(f"{url}\n")
        except Exception as e:
            logger.error(f"Error saving URL: {e}")

    def _is_language_related(self, url: str) -> bool:
        """Check if URL is language related."""
        keywords = ['ln=', 'lang=', 'locale=', 'nl=']
        query = urlparse(url).query
        return any(k in query for k in keywords)

    def _should_skip_url(self, url: str) -> bool:
        """Check if URL should be skipped based on extension."""
        return any(url.lower().endswith(ext) for ext in config.CRAWLING_EXCLUDE_EXTENSIONS)

    def crawl_url(self, url: str, next_urls: List[str]) -> None:
        """Crawl a single URL."""
        if self.stop_event.is_set():
            return

        try:
            headers = generate_random_headers()
            response = requests.get(
                url, 
                timeout=config.REQUEST_TIMEOUT, 
                allow_redirects=True, 
                verify=False, 
                headers=headers
            )
            final_url = response.url
            
            # Check domain scope
            if urlparse(final_url).netloc != self.base_domain or self._should_skip_url(final_url):
                return

            if self._is_language_related(final_url):
                return

            soup = BeautifulSoup(response.text, 'html.parser')
            links = soup.find_all('a')

            for link in links:
                href = link.get('href')
                if not href:
                    continue
                    
                full_url = urljoin(final_url, href)

                if full_url not in self.visited_urls and not self._should_skip_url(full_url):
                    with self.lock:
                        if full_url in self.visited_urls:
                            continue
                        self.visited_urls.add(full_url)
                        self.all_urls.append(full_url)
                        self.total_urls += 1

                    if self._is_language_related(full_url):
                        continue

                    # Check if it's a target for scanning (has params)
                    if (is_valid_url(full_url) and 
                        is_within_domain(full_url, self.base_domain) and 
                        has_query_parameters(full_url)):
                        
                        with self.lock:
                            self.valid_urls.append(full_url)
                            self.valid_url_count += 1
                            self.save_valid_url(full_url)

                    # Update progress
                    with self.lock:
                        sys.stdout.write(f"\r{colored('[•]', 'yellow')} Total: {self.total_urls} | Valid: {self.valid_url_count}")
                        sys.stdout.flush()

                    next_urls.append(full_url)

        except requests.RequestException:
            pass
        except Exception as e:
            logger.debug(f"Error crawling {url}: {e}")

    def _crawl_worker(self, urls: List[str], next_urls: List[str]) -> None:
        """Worker thread function."""
        for url in urls:
            if self.stop_event.is_set():
                break
            self.crawl_url(url, next_urls)

    def _process_depth(self, urls: List[str], depth: int) -> None:
        """Process a single depth level."""
        if depth > self.max_depth or not urls:
            return

        print_status(f"Crawling depth: {depth}", "info")
        next_urls = []

        if self.thread_count > 1 and len(urls) > 1:
            threads = []
            chunk_size = max(1, len(urls) // self.thread_count)
            chunks = [urls[i:i + chunk_size] for i in range(0, len(urls), chunk_size)]
            
            for chunk in chunks:
                t = threading.Thread(target=self._crawl_worker, args=(chunk, next_urls))
                t.start()
                threads.append(t)
            
            for t in threads:
                t.join()
        else:
            self._crawl_worker(urls, next_urls)

        print() # Newline after progress
        print_status(f"Found {len(next_urls)} URLs at depth {depth}", "success")

        if next_urls and depth < self.max_depth:
            time.sleep(1)
            self._process_depth(next_urls, depth + 1)

    def start(self, no_prompt: bool = False) -> List[str]:
        """Start the crawling process."""
        print_header("Starting Crawler")
        
        # Check previous crawl
        previous = self.load_previous_crawl()
        if self.start_url in previous:
            # Clear previous if re-crawling start URL
            try:
                os.remove(self.get_crawl_file_path())
                print_status("Removed previous crawl data", "info")
            except OSError:
                pass

        # Threading prompt
        use_threads = False
        if no_prompt:
            use_threads = config.DEFAULT_INPUT.lower() == 'y'
        else:
            choice = input(colored("Enable multi-threading? [y/N]: ", 'cyan')).strip().lower()
            use_threads = choice == 'y'

        self.thread_count = min(self.thread_count, config.MAX_THREADS) if use_threads else 1

        try:
            self._process_depth([self.start_url], 1)
        except KeyboardInterrupt:
            print_status("Crawling interrupted", "warning")
            self.stop_event.set()
        finally:
            print_status(f"Crawling finished. Total: {self.total_urls}, Valid: {len(self.valid_urls)}", "success")
            
        return self.valid_urls

# Legacy wrapper for backward compatibility
def run_crawler(start_url: str, max_depth: int, thread_count: int, no_prompt: bool) -> List[str]:
    crawler = WaymapCrawler(start_url, max_depth, thread_count)
    return crawler.start(no_prompt)