# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.

"""Directory Fuzzing Module."""

import os
import json
import time
import signal
import requests
from urllib.parse import urljoin, urlparse
from threading import Lock
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Set, Tuple, Optional
from tqdm import tqdm

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from lib.core.config import get_config
from lib.core.logger import get_logger
from lib.ui import print_status
from lib.parse.random_headers import generate_random_headers

config = get_config()
logger = get_logger(__name__)

class DirectoryFuzzer:
    """Directory fuzzing with state management and progress tracking."""
    
    def __init__(self, target_url: str):
        self.target_url = self._correct_url(target_url)
        self.domain = urlparse(self.target_url).netloc
        
        # State
        self.checked_urls: Set[str] = set()
        self.current_results: List[Dict] = []
        self.shutdown_requested = False
        self.lock = Lock()
        
        # Files
        session_dir = config.get_domain_session_dir(self.domain)
        self.results_file = os.path.join(session_dir, "waymap_full_results.json")
        self.temp_file = os.path.join(session_dir, "dirfuzz_progress.tmp")
        
        # Load previous progress
        self.checked_urls = self._load_checked_urls()
    
    def _correct_url(self, url: str) -> str:
        """Ensure URL is correctly formatted."""
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        return url
    
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
    
    def _save_results(self, scan_type: str) -> None:
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
            if scan.get("type") == "Directory Fuzzing":
                for entry in scan.get("results", []):
                    existing_entries.add((entry.get("url"), entry.get("word")))
        
        unique_results = [
            res for res in self.current_results
            if (res["url"], res["word"]) not in existing_entries
        ]
        
        if not unique_results:
            print_status("No new directories to save.", "info")
            return
        
        scan_entry = {
            "type": scan_type,
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
            
            print_status(f"Saved {len(unique_results)} new directories.", "success")
        except Exception as e:
            logger.error(f"Error saving results: {e}")
    
    def _load_wordlist(self, file_name: str) -> List[str]:
        """Load wordlist from file."""
        try:
            with open(file_name, "r") as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            logger.error(f"Wordlist file '{file_name}' not found.")
            return []
    
    def _fetch_directory(self, url: str, word: str) -> Tuple[bool, Optional[str], str]:
        """Check if a directory exists."""
        if self.shutdown_requested:
            return False, None, word
        
        with self.lock:
            if url in self.checked_urls:
                return False, None, word
            self.checked_urls.add(url)
        
        try:
            headers = generate_random_headers()
            response = requests.get(
                url,
                headers=headers,
                timeout=config.FUZZER_TIMEOUT,
                allow_redirects=False,
                verify=False
            )
            if response.status_code in [200, 301, 302, 403, 401]:
                return True, response.url, word
            return False, None, word
        except requests.RequestException:
            return False, None, word
        finally:
            self._save_checked_urls()
    
    def _signal_handler(self, sig, frame) -> None:
        """Handle keyboard interrupts."""
        self.shutdown_requested = True
        print_status("Keyboard interrupt detected. Saving progress...", "warning")
        if self.current_results:
            self._save_results("Directory Fuzzing (Partial)")
    
    def start(self) -> None:
        """Start directory fuzzing."""
        start_time = time.time()
        
        print_status(f"Starting directory fuzzing for: {self.target_url}", "info")
        print_status(f"Resuming from {len(self.checked_urls)} already checked URLs", "info")
        
        # Load wordlists
        wordlists = [
            os.path.join(config.DATA_DIR, "waymap_dirfuzzlist.txt"),
            os.path.join(config.DATA_DIR, "waymap_dirfuzzlist2.txt")
        ]
        
        wordlist = []
        for wl in wordlists:
            words = self._load_wordlist(wl)
            if words:
                wordlist.extend(words)
        
        if not wordlist:
            print_status("No wordlists loaded. Aborting.", "error")
            return
        
        # Set up signal handler
        signal.signal(signal.SIGINT, self._signal_handler)
        
        # Fuzzing with progress bar
        with tqdm(total=len(wordlist), desc="Fuzzing Directories") as pbar:
            with ThreadPoolExecutor(max_workers=config.FUZZER_THREADS) as executor:
                futures = []
                for word in wordlist:
                    if self.shutdown_requested:
                        break
                    dir_url = urljoin(self.target_url, word)
                    futures.append(executor.submit(self._fetch_directory, dir_url, word))
                
                for future in as_completed(futures):
                    if self.shutdown_requested:
                        break
                    
                    try:
                        exists, final_url, word = future.result()
                        if exists:
                            result = {
                                "url": final_url or urljoin(self.target_url, word),
                                "word": word,
                                "status": "Discovered",
                                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                            }
                            self.current_results.append(result)
                            print_status(f"Found directory: {result['url']}", "success")
                    except Exception as e:
                        logger.error(f"Error processing {word}: {e}")
                    finally:
                        pbar.update(1)
        
        self._save_results("Directory Fuzzing")
        
        elapsed = time.time() - start_time
        print_status(f"Found {len(self.current_results)} directories in {elapsed:.2f}s", "success")
        print_status(f"Total checked URLs: {len(self.checked_urls)}", "info")

def dirfuzz(target_url: str) -> None:
    """Perform directory fuzzing on target URL."""
    fuzzer = DirectoryFuzzer(target_url)
    fuzzer.start()