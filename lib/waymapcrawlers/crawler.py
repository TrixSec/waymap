# Copyright (c) 2026 waymap developers
# See the file 'LICENSE' for copying permission.

"""Web Crawler Module - Two-Layer Architecture."""

import os
import sys
import threading
import requests
from lib.core import http
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Set, Optional
from urllib.parse import urljoin, urlparse
import urllib3

from lib.core.config import get_config
from lib.core.logger import get_logger
from lib.ui import print_status, print_header, prompt_line, colored
from lib.utils import is_valid_url, has_query_parameters, is_within_domain
from lib.discovery.engine import DiscoveryEngine
from lib.discovery.models import DiscoveryResults
from lib.ai.discovery_agent import DiscoveryAgent
from lib.events.bus import get_event_bus
from lib.events.events import DiscoveryEvent, ScanStartEvent, ScanEndEvent, ProgressEvent

# Disable warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

config = get_config()
logger = get_logger(__name__)

class WaymapCrawler:
    def __init__(self, base_url: str, max_depth: int = 2, thread_count: int = 1, use_ai: bool = True):
        self.start_url = base_url
        self.max_depth = max_depth
        self.thread_count = thread_count
        self.use_ai = use_ai
        self.base_domain = urlparse(base_url).netloc
        
        # Two-layer architecture
        self.discovery_engine: Optional[DiscoveryEngine] = None
        self.discovery_agent: Optional[DiscoveryAgent] = None
        self.discovery_results: Optional[DiscoveryResults] = None
        
        # State (for backward compatibility)
        self.visited_urls: Set[str] = set()
        self.all_urls: List[str] = []
        self.valid_urls: List[str] = []
        self.total_urls = 0
        self.valid_url_count = 0
        
        # Synchronization
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        
        # Event bus
        self.event_bus = get_event_bus()

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
            response = http.get(
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

            content_type = response.headers.get("Content-Type", "")
            if content_type and "html" not in content_type.lower():
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
                        
                        # Emit discovery event for parameterized URLs
                        params = list(urlparse(full_url).query.split('&'))
                        event = DiscoveryEvent(
                            url=full_url,
                            source="crawler",
                            method="link_extraction",
                            depth=depth if hasattr(self, '_current_depth') else 0,
                            parent_url=url,
                            parameters=params
                        )
                        self.event_bus.publish(event)

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

        self._current_depth = depth  # Track depth for event emission
        print_status(f"Crawling depth: {depth}", "info")
        
        # Emit progress event
        progress_event = ProgressEvent(
            phase="crawling",
            current=depth,
            total=self.max_depth,
            message=f"Crawling depth {depth}"
        )
        self.event_bus.publish(progress_event)
        
        next_urls = []

        if self.thread_count > 1 and len(urls) > 1:
            with ThreadPoolExecutor(max_workers=self.thread_count) as executor:
                futures = [executor.submit(self.crawl_url, url, next_urls) for url in urls]
                for future in as_completed(futures):
                    if self.stop_event.is_set():
                        break
                    try:
                        future.result()
                    except Exception as e:
                        logger.debug(f"Error in crawler worker: {e}")
        else:
            self._crawl_worker(urls, next_urls)

        print() # Newline after progress
        print_status(f"Found {len(next_urls)} URLs at depth {depth}", "success")

        if next_urls and depth < self.max_depth:
            self._process_depth(next_urls, depth + 1)

    def start(self, no_prompt: bool = False) -> List[str]:
        """Start the crawling process using two-layer architecture."""
        print_header("Starting Crawler")
        
        # Emit scan start event
        start_event = ScanStartEvent(
            target=self.start_url,
            scan_types=["crawl"]
        )
        self.event_bus.publish(start_event)
        
        # Check previous crawl
        previous = self.load_previous_crawl()
        if self.start_url in previous:
            # Clear previous if re-crawling start URL
            try:
                os.remove(self.get_crawl_file_path())
                print_status("Removed previous crawl data", "info")
            except OSError:
                pass

        # Threading: honor configured thread_count when prompts are disabled
        use_threads = False
        if no_prompt:
            use_threads = self.thread_count > 1
        else:
            choice = prompt_line("Enable multi-threading? [y/N]", "n").lower()
            use_threads = choice == 'y'

        self.thread_count = min(self.thread_count, config.MAX_THREADS) if use_threads else 1

        # AI: ask if AI should be used for analysis
        use_ai = self.use_ai
        if not no_prompt and use_ai:
            choice = prompt_line("Enable AI analysis for prioritization? [y/N]", "n").lower()
            use_ai = choice == 'y'

        import time
        crawl_start_time = time.time()
        
        try:
            # Layer 1: Fast deterministic discovery
            print_status("Layer 1: Starting high-speed discovery engine", "info")
            self.discovery_engine = DiscoveryEngine(
                self.start_url,
                max_depth=self.max_depth,
                thread_count=self.thread_count
            )
            self.discovery_engine.show_progress = True
            self.discovery_results = self.discovery_engine.run()
            
            # Update backward-compatible state
            self.visited_urls = set(u.url for u in self.discovery_results.urls)
            self.all_urls = [u.url for u in self.discovery_results.urls]
            self.total_urls = len(self.all_urls)
            
            # Save valid URLs (parameterized) - already deduplicated by pattern
            for url_obj in self.discovery_results.get_parameterized_urls():
                if not self._is_language_related(url_obj.url):
                    self.valid_urls.append(url_obj.url)
                    self.valid_url_count += 1
                    self.save_valid_url(url_obj.url)
            
            print_status(f"Layer 1 complete. Found {self.total_urls} URLs, {self.valid_url_count} parameterized", "success")
            
            # Layer 2: AI analysis and prioritization
            if use_ai:
                self.discovery_agent = DiscoveryAgent(self.discovery_results)
                analysis = self.discovery_agent.analyze_endpoints()
                
                # Get prioritized scan queue
                prioritized = self.discovery_agent.get_scan_queue(limit=50)
                
                # Only save and print if we have results
                if prioritized:
                    self._save_prioritized_results(prioritized)
                    print_status(f"AI prioritized {len(prioritized)} endpoints for scanning", "success")
            
            # Print discovery summary (compact)
            summary = self.discovery_results.get_summary()
            print_status(f"Discovery: {summary['total_urls']} URLs, {summary['parameterized_urls']} parameterized, {summary['forms']} forms", "success")
            
        except KeyboardInterrupt:
            from lib.core.interrupt import exit_clean
            exit_clean()
        finally:
            crawl_duration = time.time() - crawl_start_time
            print_status(f"Crawling finished. Total: {self.total_urls}, Valid: {len(self.valid_urls)}", "success")
            
            # Emit scan end event
            end_event = ScanEndEvent(
                target=self.start_url,
                success=True,
                duration_seconds=crawl_duration,
                findings_count=self.valid_url_count
            )
            self.event_bus.publish(end_event)
            
        return self.valid_urls
    
    def _save_prioritized_results(self, prioritized: List[str]) -> None:
        """Save prioritized scan queue to file."""
        prioritized_file = os.path.join(
            config.get_domain_session_dir(self.base_domain),
            'prioritized.txt'
        )
        try:
            with open(prioritized_file, 'w') as f:
                for url in prioritized:
                    f.write(f"{url}\n")
            print_status(f"Saved prioritized queue to {prioritized_file}", "info")
        except Exception as e:
            logger.error(f"Error saving prioritized results: {e}")
    
    def get_discovery_results(self) -> Optional[DiscoveryResults]:
        """Get the discovery results object."""
        return self.discovery_results
    
    def get_ai_analysis(self) -> Optional[dict]:
        """Get the AI analysis results."""
        if self.discovery_agent:
            return {
                "prioritized_urls": self.discovery_agent.prioritized_urls,
                "duplicate_groups": self.discovery_agent.duplicate_groups,
                "vulnerability_hints": self.discovery_agent.get_vulnerability_hints()
            }
        return None

# Legacy wrapper for backward compatibility
def run_crawler(start_url: str, max_depth: int, thread_count: int, no_prompt: bool, use_ai: bool = True) -> List[str]:
    crawler = WaymapCrawler(start_url, max_depth, thread_count, use_ai)
    return crawler.start(no_prompt)
