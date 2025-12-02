# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.

"""Backup File Finder Module."""

import os
import json
import signal
import requests
from urllib.parse import urlparse
from threading import Lock
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Set, Tuple, Optional
import queue as Queue

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from lib.core.config import get_config
from lib.core.logger import get_logger
from lib.ui import print_status
from lib.waymapcrawlers.backup_crawler import start_crawl
from lib.parse.random_headers import generate_random_headers

config = get_config()
logger = get_logger(__name__)

class BackupFileFinder:
    """Backup file discovery with progress tracking."""
    
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.domain = urlparse(target_url).netloc
        
        # State
        self.checked_urls: Set[str] = set()
        self.current_results: List[Dict] = []
        self.stop_threads = False
        self.total_checked = 0
        self.lock = Lock()
        
        # Files
        session_dir = config.get_domain_session_dir(self.domain)
        self.results_file = os.path.join(session_dir, "waymap_full_results.json")
        self.temp_file = os.path.join(session_dir, "backup_scan_progress.tmp")
        self.crawl_file = os.path.join(session_dir, "crawl2.txt")
        
        # Load previous progress
        self.checked_urls = self._load_checked_urls()
    
    def _load_checked_urls(self) -> Set[str]:
        """Load previously checked URLs."""
        if os.path.exists(self.temp_file):
            try:
                with open(self.temp_file, "r") as f:
                    return set(line.strip() for line in f if line.strip())
            except Exception as e:
                logger.error(f"Error loading checked URLs: {e}")
        return set()
    
    def _save_checked_urls(self) -> None:
        """Save checked URLs to temp file."""
        with self.lock:
            try:
                with open(self.temp_file, "w") as f:
                    f.writelines(f"{url}\n" for url in self.checked_urls)
            except Exception as e:
                logger.error(f"Error saving checked URLs: {e}")
    
    def _save_results(self) -> None:
        """Save results to JSON file."""
        existing_data = {"scans": []}
        if os.path.exists(self.results_file):
            try:
                with open(self.results_file, "r") as f:
                    existing_data = json.load(f)
            except json.JSONDecodeError:
                pass
        
        if "scans" not in existing_data or not isinstance(existing_data["scans"], list):
            existing_data["scans"] = []
        
        # Check for duplicates
        existing_entries = set()
        for scan in existing_data.get("scans", []):
            if scan.get("type") == "Backup File Scan":
                for entry in scan.get("results", []):
                    existing_entries.add(entry.get("url"))
        
        unique_results = [
            res for res in self.current_results
            if res["url"] not in existing_entries
        ]
        
        if not unique_results:
            print_status("No new backup files to save.", "info")
            return
        
        scan_entry = {
            "type": "Backup File Scan",
            "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "results": unique_results
        }
        
        existing_data["scans"].append(scan_entry)
        
        try:
            with open(self.results_file, "w") as f:
                json.dump(existing_data, f, indent=4)
            
            # Remove temp file
            if os.path.exists(self.temp_file):
                os.remove(self.temp_file)
            
            print_status(f"Saved {len(unique_results)} new backup files.", "success")
        except Exception as e:
            logger.error(f"Error saving results: {e}")
    
    def _read_crawled_urls(self) -> List[str]:
        """Read URLs from crawl file."""
        if not os.path.exists(self.crawl_file):
            logger.error(f"File not found: {self.crawl_file}")
            return []

        directory_urls = []
        with open(self.crawl_file, "r") as f:
            for line in f.readlines():
                url = line.strip()
                if url and urlparse(url).path.endswith('/'):
                    directory_urls.append(url)

        if not directory_urls:
            logger.warning(f"No directory-like URLs found in {self.crawl_file}")
        return directory_urls
    
    def _generate_backup_urls(self, url: str, extensions: List[str]) -> List[str]:
        """Generate potential backup file URLs."""
        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        path_parts = parsed_url.path.strip('/').split('/')
        backup_urls = []

        for i in range(len(path_parts)):
            current_path = '/'.join(path_parts[:i + 1])
            for ext in extensions:
                backup_urls.append(f"{base_url}/{current_path}{ext}")

        return backup_urls
    
    def _test_backup_url(self, backup_url: str) -> Optional[Dict]:
        """Test if a backup URL exists."""
        if self.stop_threads or backup_url in self.checked_urls:
            return None
        
        try:
            headers = generate_random_headers()
            response = requests.head(
                backup_url, 
                timeout=config.BACKUP_TIMEOUT, 
                verify=False, 
                headers=headers
            )
            
            with self.lock:
                self.total_checked += 1
                print_status(f"Total URLs Checked: {self.total_checked}", "info", end="\r")

            if response.status_code == 200:
                print_status(f"Found backup file: {backup_url}", "success")
                return {
                    "url": backup_url,
                    "status": "Found",
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }
            elif response.status_code == 403:
                print_status(f"Forbidden backup file: {backup_url}", "warning")
                return {
                    "url": backup_url,
                    "status": "Forbidden",
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }
        except requests.exceptions.RequestException:
            pass
        
        return None
    
    def _signal_handler(self, sig, frame) -> None:
        """Handle keyboard interrupts."""
        self.stop_threads = True
        print_status("Scanning interrupted! Saving progress...", "warning")
        if self.current_results:
            self._save_results()
    
    def find_backup_files(self, threads: int = 20) -> None:
        """Scan for backup files."""
        backup_extensions = [".zip", ".tar.gz", ".bak", ".old", ".7z"]
        
        urls = self._read_crawled_urls()
        if not urls:
            print_status(f"No valid URLs to process in {self.crawl_file}", "error")
            return

        print_status("Scanning for backup files...", "info")

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = []
            for url in urls:
                backup_urls = self._generate_backup_urls(url, backup_extensions)
                for backup_url in backup_urls:
                    futures.append(executor.submit(self._test_backup_url, backup_url))
                    self.checked_urls.add(backup_url)

            try:
                for future in as_completed(futures):
                    if self.stop_threads:
                        break
                    result = future.result()
                    if result:
                        self.current_results.append(result)
            except KeyboardInterrupt:
                print_status("Scanning interrupted! Saving progress...", "warning")
                self.stop_threads = True

        self._save_checked_urls()
    
    def start(self) -> None:
        """Start backup file scanning."""
        print_status(f"Target domain: {self.domain}", "info")
        
        # Remove old crawl file
        if os.path.exists(self.crawl_file):
            os.remove(self.crawl_file)

        # Set up signal handler
        signal.signal(signal.SIGINT, self._signal_handler)

        try:
            # Start crawling
            start_crawl(self.target_url)
            
            # Find backup files
            self.find_backup_files()
            
            # Save results
            if self.current_results:
                self._save_results()
            
            # Print summary
            print_status("=== Scan Results Summary ===", "info")
            print_status(f"Total URLs Checked: {self.total_checked}", "info")
            found = len([r for r in self.current_results if r["status"] == "Found"])
            forbidden = len([r for r in self.current_results if r["status"] == "Forbidden"])
            print_status(f"Backup Files Found: {found}", "success")
            print_status(f"Forbidden Backup Files: {forbidden}", "warning")
            print_status("=== End of Scan ===", "info")

        except KeyboardInterrupt:
            print_status("Process interrupted! Saving progress...", "warning")

def backupfiles(target_url: str) -> None:
    """Perform backup file scanning."""
    finder = BackupFileFinder(target_url)
    finder.start()
