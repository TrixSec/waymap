# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.

"""Backup File Crawler Module."""

import os
import re
import signal
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from queue import Queue
from threading import Lock
from typing import Set

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from lib.core.config import get_config
from lib.core.logger import get_logger
from lib.ui import print_status, colored
from lib.parse.random_headers import generate_random_headers

config = get_config()
logger = get_logger(__name__)

class BackupCrawler:
    """Backup file crawler with thread-safe state management."""
    
    def __init__(self, start_url: str, threads: int = None):
        self.start_url = start_url
        self.threads = threads or config.BACKUP_CRAWLER_THREADS
        self.base_domain = urlparse(start_url).netloc
        
        # State
        self.unique_urls: Set[str] = set()
        self.queue = Queue()
        self.lock = Lock()
        self.stop_threads = False
        self.saved_count = 0
        
        # Output
        session_dir = config.get_domain_session_dir(self.base_domain)
        self.output_file = os.path.join(session_dir, "crawl2.txt")
        
    def is_valid_url_to_crawl(self, url: str) -> bool:
        """Validate URL for crawling."""
        parsed_url = urlparse(url)
        path = parsed_url.path
        
        if not path.endswith(config.VALID_EXTENSIONS):
            return False
            
        if parsed_url.netloc != self.base_domain:
            return False
            
        return True
    
    def is_valid_url_to_save(self, url: str) -> bool:
        """Validate URL for saving."""
        parsed_url = urlparse(url)
        path = parsed_url.path
        
        if any(ext in path for ext in config.DISSALLOWED_EXT):
            return False
            
        if re.fullmatch(r"[\d\W]+", path.strip("/")):
            return False
            
        if parsed_url.netloc != self.base_domain:
            return False
            
        return True
    
    def save_url(self, url: str) -> None:
        """Save URL to file."""
        with self.lock:
            try:
                with open(self.output_file, "a") as f:
                    f.write(url + "\n")
                self.saved_count += 1
            except Exception as e:
                logger.error(f"Error saving URL: {e}")
    
    def print_counters(self) -> None:
        """Print live count."""
        with self.lock:
            print_status(
                f"Unique URLs: {len(self.unique_urls)}, Saved: {self.saved_count}", 
                "info", 
                end="\r"
            )
    
    def crawl_worker(self) -> None:
        """Worker function to process queue."""
        while not self.queue.empty() and not self.stop_threads:
            url = self.queue.get()
            try:
                headers = generate_random_headers()
                response = requests.get(
                    url, 
                    timeout=config.REQUEST_TIMEOUT, 
                    verify=False, 
                    headers=headers
                )
                
                if response.status_code != 200:
                    self.queue.task_done()
                    continue
                
                soup = BeautifulSoup(response.text, "html.parser")
                
                for tag in soup.find_all("a", href=True):
                    absolute_url = urljoin(url, tag["href"])
                    absolute_url = absolute_url.split("#")[0]
                    
                    with self.lock:
                        if absolute_url in self.unique_urls:
                            continue
                        self.unique_urls.add(absolute_url)
                    
                    if self.is_valid_url_to_save(absolute_url):
                        self.save_url(absolute_url)
                    
                    if self.is_valid_url_to_crawl(absolute_url):
                        self.queue.put(absolute_url)
                    
                    self.print_counters()
                    
            except requests.exceptions.RequestException:
                pass
            finally:
                self.queue.task_done()
    
    def start(self) -> None:
        """Start the crawling process."""
        self.queue.put(self.start_url)
        self.unique_urls.add(self.start_url)
        
        print_status("Crawling started...", "info")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [
                executor.submit(self.crawl_worker) 
                for _ in range(self.threads)
            ]
            try:
                for future in as_completed(futures):
                    if self.stop_threads:
                        break
            except KeyboardInterrupt:
                print_status("Crawling interrupted! Saving progress...", "warning")
                self.stop_threads = True
            
            self.queue.join()
        
        print_status(f"Crawling completed! Results saved to {self.output_file}", "success")

def start_crawl(start_url: str) -> None:
    """Start backup file crawling."""
    if not start_url.startswith(("http://", "https://")):
        print_status("Invalid URL. Please include http:// or https://", "error")
        return
    
    crawler = BackupCrawler(start_url)
    crawler.start()
