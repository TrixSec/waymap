# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.

"""JavaScript File Crawler Module."""

import os
import requests
import signal
import sys
import threading
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor
from queue import Queue
from typing import Set

from lib.core.config import get_config
from lib.core.logger import get_logger
from lib.ui import print_status, colored

config = get_config()
logger = get_logger(__name__)

class JSCrawler:
    """JavaScript file crawler with thread-safe state management."""
    
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.base_domain = urlparse(base_url).netloc
        
        # State
        self.visited_urls: Set[str] = set()
        self.js_files: Set[str] = set()
        self.queue = Queue()
        self.lock = threading.Lock()
        self.shutdown_flag = threading.Event()
        
        # Output
        session_dir = config.get_domain_session_dir(self.base_domain)
        self.output_file = os.path.join(session_dir, "crawl3.txt")
        
        # Initialize empty file
        open(self.output_file, "w").close()
    
    def is_same_domain(self, target_url: str) -> bool:
        """Check if URL belongs to same domain."""
        target_domain = urlparse(target_url).netloc
        return self.base_domain == target_domain
    
    def is_valid_extension(self, url: str) -> bool:
        """Check if URL has valid extension."""
        parsed_url = urlparse(url)
        return parsed_url.path.endswith(config.VALID_EXTENSIONS)
    
    def save_js_link(self, js_url: str) -> None:
        """Save JavaScript link to file."""
        with self.lock:
            if js_url not in self.js_files:
                self.js_files.add(js_url)
                try:
                    with open(self.output_file, "a") as file:
                        file.write(js_url + "\n")
                    print_status(f"Unique JS files saved: {len(self.js_files)}", "info", end="\r")
                except Exception as e:
                    logger.error(f"Error saving JS link: {e}")
    
    def crawl_js_links(self, url: str) -> None:
        """Crawl a page and extract JavaScript links."""
        try:
            response = requests.get(url, timeout=config.REQUEST_TIMEOUT, verify=False)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, "html.parser")
                
                # Extract script tags
                script_tags = soup.find_all("script", src=True)
                for tag in script_tags:
                    js_url = tag["src"]
                    if not js_url.startswith("http"):
                        js_url = urljoin(url, js_url)
                    if js_url.endswith(".js"):
                        self.save_js_link(js_url)
                
                # Extract anchor links
                for anchor in soup.find_all("a", href=True):
                    sub_url = anchor["href"]
                    full_url = urljoin(url, sub_url)
                    
                    if self.is_same_domain(full_url) and self.is_valid_extension(full_url):
                        with self.lock:
                            if full_url not in self.visited_urls:
                                self.visited_urls.add(full_url)
                                self.queue.put(full_url)
        except requests.exceptions.RequestException as e:
            logger.debug(f"Error fetching {url}: {e}")
    
    def worker(self) -> None:
        """Worker function for concurrent crawling."""
        while not self.queue.empty() and not self.shutdown_flag.is_set():
            try:
                url = self.queue.get(timeout=1)
                self.crawl_js_links(url)
                self.queue.task_done()
            except Exception:
                break
    
    def start(self) -> None:
        """Start the crawling process."""
        self.queue.put(self.base_url)
        self.visited_urls.add(self.base_url)
        
        print_status("Crawling started...", "info")
        
        with ThreadPoolExecutor(max_workers=config.MAX_THREADS) as executor:
            threads = [executor.submit(self.worker) for _ in range(10)]
            try:
                for future in threads:
                    future.result()
            except KeyboardInterrupt:
                print_status("Keyboard interruption detected! Stopping...", "warning")
                self.shutdown_flag.set()
        
        print_status(f"Crawling completed! JS files saved to {self.output_file}", "success")

def start_crawl(base_url: str) -> None:
    """Initialize and start the JS crawling process."""
    crawler = JSCrawler(base_url)
    crawler.start()
