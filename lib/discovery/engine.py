# Copyright (c) 2026 waymap developers
# See the file 'LICENSE' for copying permission.

"""Layer 1: High-speed Discovery Engine - Deterministic extraction."""

import re
import threading
from typing import List, Set, Optional, Dict
from urllib.parse import urljoin, urlparse, urlunparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed

from lib.core import http
from lib.core.config import get_config
from lib.core.logger import get_logger
from lib.ui import print_status, colored
from lib.discovery.models import (
    DiscoveryResults,
    DiscoveredURL,
    DiscoveredForm,
    DiscoveredAPIEndpoint,
    DiscoveredJSEndpoint,
    EndpointType,
    FormMethod
)
from lib.utils import is_valid_url, is_within_domain

config = get_config()
logger = get_logger(__name__)

try:
    from selectolax.parser import HTMLParser
    SELECTOLAX_AVAILABLE = True
    logger.info("Using selectolax for HTML parsing")
except ImportError:
    SELECTOLAX_AVAILABLE = False
    try:
        from bs4 import BeautifulSoup
        logger.info("Using BeautifulSoup for HTML parsing (selectolax not available)")
    except ImportError:
        logger.error("Neither selectolax nor BeautifulSoup is available!")
        SELECTOLAX_AVAILABLE = False


class DiscoveryEngine:
    """High-speed deterministic discovery engine."""
    
    def __init__(self, base_url: str, max_depth: int = 2, thread_count: int = 1):
        self.base_url = base_url
        self.max_depth = max_depth
        self.thread_count = thread_count
        self.base_domain = urlparse(base_url).netloc
        
        self.results = DiscoveryResults(base_url=base_url, domain=self.base_domain)
        self.visited_urls: Set[str] = set()
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.show_progress = True
    
    def normalize_url(self, url: str) -> str:
        """Normalize and canonicalize URL."""
        parsed = urlparse(url)
        
        # Remove fragment
        parsed = parsed._replace(fragment='')
        
        # Sort query parameters
        if parsed.query:
            query_dict = parse_qs(parsed.query, keep_blank_values=True)
            sorted_query = '&'.join(
                f'{k}={v[0]}' if v else k 
                for k, v in sorted(query_dict.items())
            )
            parsed = parsed._replace(query=sorted_query)
        
        # Remove trailing slash from path unless it's root
        if parsed.path and parsed.path != '/' and parsed.path.endswith('/'):
            parsed = parsed._replace(path=parsed.path.rstrip('/'))
        
        return urlunparse(parsed)
    
    def get_url_pattern(self, url: str) -> str:
        """Extract URL pattern by replacing parameter values with placeholders."""
        parsed = urlparse(url)
        
        if not parsed.query:
            return url
        
        # Replace parameter values with *
        query_dict = parse_qs(parsed.query, keep_blank_values=True)
        pattern_params = []
        for k in sorted(query_dict.keys()):
            pattern_params.append(f'{k}=*')
        
        pattern_query = '&'.join(pattern_params)
        parsed = parsed._replace(query=pattern_query)
        
        return urlunparse(parsed)
    
    def extract_links_from_html(self, html: str, base_url: str) -> List[str]:
        """Extract all links from HTML using fast parser."""
        links = []
        
        if SELECTOLAX_AVAILABLE:
            tree = HTMLParser(html)
            for a_tag in tree.css('a[href]'):
                href = a_tag.attributes.get('href')
                if href:
                    links.append(href)
        else:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html, 'html.parser')
            for a_tag in soup.find_all('a', href=True):
                links.append(a_tag['href'])
        
        return links
    
    def extract_forms_from_html(self, html: str, base_url: str, parent_url: str, depth: int) -> List[DiscoveredForm]:
        """Extract forms from HTML."""
        forms = []
        
        if SELECTOLAX_AVAILABLE:
            tree = HTMLParser(html)
            form_tags = tree.css('form')
            
            for form_tag in form_tags:
                action = form_tag.attributes.get('action', '')
                method = form_tag.attributes.get('method', 'GET').upper()
                
                if not action:
                    action = parent_url
                
                full_action = urljoin(base_url, action)
                
                inputs = {}
                hidden_inputs = {}
                
                for input_tag in form_tag.css('input'):
                    name = input_tag.attributes.get('name')
                    input_type = input_tag.attributes.get('type', 'text')
                    value = input_tag.attributes.get('value', '')
                    
                    if name:
                        if input_type.lower() == 'hidden':
                            hidden_inputs[name] = value
                        else:
                            inputs[name] = value
                
                form = DiscoveredForm(
                    action=full_action,
                    method=FormMethod.GET if method == 'GET' else FormMethod.POST,
                    inputs=inputs,
                    hidden_inputs=hidden_inputs,
                    parent_url=parent_url,
                    depth=depth
                )
                forms.append(form)
        else:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html, 'html.parser')
            
            for form_tag in soup.find_all('form'):
                action = form_tag.get('action', '')
                method = form_tag.get('method', 'GET').upper()
                
                if not action:
                    action = parent_url
                
                full_action = urljoin(base_url, action)
                
                inputs = {}
                hidden_inputs = {}
                
                for input_tag in form_tag.find_all('input'):
                    name = input_tag.get('name')
                    input_type = input_tag.get('type', 'text')
                    value = input_tag.get('value', '')
                    
                    if name:
                        if input_type.lower() == 'hidden':
                            hidden_inputs[name] = value
                        else:
                            inputs[name] = value
                
                form = DiscoveredForm(
                    action=full_action,
                    method=FormMethod.GET if method == 'GET' else FormMethod.POST,
                    inputs=inputs,
                    hidden_inputs=hidden_inputs,
                    parent_url=parent_url,
                    depth=depth
                )
                forms.append(form)
        
        return forms
    
    def extract_js_endpoints_from_html(self, html: str, base_url: str) -> List[DiscoveredJSEndpoint]:
        """Extract JavaScript file references and endpoints from HTML."""
        js_endpoints = []
        
        if SELECTOLAX_AVAILABLE:
            tree = HTMLParser(html)
            
            # Script tags with src
            for script in tree.css('script[src]'):
                src = script.attributes.get('src')
                if src:
                    full_src = urljoin(base_url, src)
                    js_endpoints.append(DiscoveredJSEndpoint(
                        endpoint=full_src,
                        source='script_tag',
                        parent_file=base_url
                    ))
        else:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html, 'html.parser')
            
            for script in soup.find_all('script', src=True):
                src = script['src']
                full_src = urljoin(base_url, src)
                js_endpoints.append(DiscoveredJSEndpoint(
                    endpoint=full_src,
                    source='script_tag',
                    parent_file=base_url
                ))
        
        return js_endpoints
    
    def extract_api_endpoints_from_text(self, text: str, base_url: str) -> List[DiscoveredAPIEndpoint]:
        """Extract API endpoints using regex patterns."""
        endpoints = []
        
        patterns = [
            # REST API patterns
            (r'/api/[a-zA-Z0-9_/-]+', 'rest_api'),
            (r'/v[0-9]+/[a-zA-Z0-9_/-]+', 'versioned_api'),
            # GraphQL
            (r'/graphql', 'graphql'),
            (r'/graphiql', 'graphiql'),
            # Common API patterns
            (r'/[a-zA-Z0-9_]+/api/[a-zA-Z0-9_/-]+', 'nested_api'),
            (r'/rest/[a-zA-Z0-9_/-]+', 'rest_endpoint'),
            (r'/ws/[a-zA-Z0-9_/-]+', 'websocket'),
            (r'/socket/[a-zA-Z0-9_/-]+', 'socket'),
        ]
        
        for pattern, source in patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                full_endpoint = urljoin(base_url, match)
                endpoints.append(DiscoveredAPIEndpoint(
                    endpoint=full_endpoint,
                    source=source
                ))
        
        # Extract fetch/axios calls from JavaScript-like content
        js_patterns = [
            (r'fetch\(["\']([^"\']+)["\']', 'fetch'),
            (r'axios\.[a-z]+\(["\']([^"\']+)["\']', 'axios'),
            (r'\.get\(["\']([^"\']+)["\']', 'http_get'),
            (r'\.post\(["\']([^"\']+)["\']', 'http_post'),
            (r'XMLHttpRequest\(["\']([^"\']+)["\']', 'xhr'),
        ]
        
        for pattern, source in js_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                if match.startswith('/'):
                    full_endpoint = urljoin(base_url, match)
                    endpoints.append(DiscoveredAPIEndpoint(
                        endpoint=full_endpoint,
                        source=source
                    ))
        
        return endpoints
    
    def extract_meta_redirects(self, html: str, base_url: str) -> List[str]:
        """Extract meta refresh redirects."""
        redirects = []
        
        if SELECTOLAX_AVAILABLE:
            tree = HTMLParser(html)
            for meta in tree.css('meta[http-equiv="refresh"]'):
                content = meta.attributes.get('content', '')
                if 'url=' in content.lower():
                    url = content.split('url=')[-1].strip()
                    redirects.append(urljoin(base_url, url))
        else:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html, 'html.parser')
            for meta in soup.find_all('meta', attrs={'http-equiv': 'refresh'}):
                content = meta.get('content', '')
                if 'url=' in content.lower():
                    url = content.split('url=')[-1].strip()
                    redirects.append(urljoin(base_url, url))
        
        return redirects
    
    def extract_canonical_urls(self, html: str, base_url: str) -> List[str]:
        """Extract canonical URLs."""
        canonical_urls = []
        
        if SELECTOLAX_AVAILABLE:
            tree = HTMLParser(html)
            for link in tree.css('link[rel="canonical"]'):
                href = link.attributes.get('href')
                if href:
                    canonical_urls.append(urljoin(base_url, href))
        else:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html, 'html.parser')
            for link in soup.find_all('link', rel='canonical'):
                href = link.get('href')
                if href:
                    canonical_urls.append(urljoin(base_url, href))
        
        return canonical_urls
    
    def extract_html_comment_urls(self, html: str, base_url: str) -> Set[str]:
        """Extract URLs from HTML comments."""
        urls = set()
        
        # Match HTML comments
        comment_pattern = r'<!--.*?-->'
        comments = re.findall(comment_pattern, html, re.DOTALL)
        
        # Extract URLs from comments
        url_pattern = r'https?://[^\s<>"\']+\.[^\s<>"\']|/[^\s<>"\'\)]+'
        for comment in comments:
            matches = re.findall(url_pattern, comment)
            for match in matches:
                if match.startswith('/'):
                    urls.add(urljoin(base_url, match))
                elif match.startswith('http'):
                    urls.add(match)
        
        return urls
    
    def parse_robots_txt(self, robots_url: str) -> Set[str]:
        """Parse robots.txt for disallowed paths."""
        urls = set()
        
        try:
            response = http.get(robots_url, timeout=config.REQUEST_TIMEOUT, verify=False)
            if response.status_code == 200:
                lines = response.text.split('\n')
                for line in lines:
                    line = line.strip()
                    if line.lower().startswith('disallow:'):
                        path = line.split(':', 1)[1].strip()
                        if path and path != '/':
                            full_url = urljoin(self.base_url, path)
                            urls.add(full_url)
        except Exception as e:
            logger.debug(f"Error parsing robots.txt: {e}")
        
        return urls
    
    def parse_sitemap_xml(self, sitemap_url: str) -> Set[str]:
        """Parse sitemap.xml for URLs."""
        urls = set()
        
        try:
            response = http.get(sitemap_url, timeout=config.REQUEST_TIMEOUT, verify=False)
            if response.status_code == 200:
                # Simple regex extraction for URLs
                url_pattern = r'<loc>(https?://[^<]+)</loc>'
                matches = re.findall(url_pattern, response.text)
                urls.update(matches)
        except Exception as e:
            logger.debug(f"Error parsing sitemap.xml: {e}")
        
        return urls
    
    def discover_page(self, url: str, depth: int) -> None:
        """Discover all endpoints from a single page."""
        if self.stop_event.is_set():
            return
        
        if url in self.visited_urls or depth > self.max_depth:
            return
        
        logger.debug(f"Starting to discover page: {url} at depth {depth}")
        
        try:
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            response = http.get(
                url,
                timeout=config.REQUEST_TIMEOUT,
                allow_redirects=True,
                verify=False,
                headers=headers
            )
            
            final_url = response.url
            content_type = response.headers.get('Content-Type', '')
            
            logger.debug(f"Visited {url} -> {final_url} (Status: {response.status_code}, Content-Type: {content_type})")
            
            # Skip non-HTML content (but be more lenient - if no content-type, assume HTML)
            if content_type and 'html' not in content_type.lower() and 'text/' not in content_type.lower():
                logger.debug(f"Skipping non-HTML content: {content_type}")
                return
            
            # Mark as visited
            with self.lock:
                self.visited_urls.add(final_url)
                self.results.total_pages_crawled += 1
                
                # Show progress
                if self.show_progress:
                    param_count = len([u for u in self.results.urls if u.has_params])
                    import sys
                    sys.stdout.write(f"\r{colored('[•]', 'yellow')} Pages: {self.results.total_pages_crawled} | URLs: {len(self.results.urls)} | Forms: {len(self.results.forms)} | APIs: {len(self.results.api_endpoints)} | Param URLs: {param_count}")
                    sys.stdout.flush()
            
            # Add the current page itself as a discovered URL
            parsed = urlparse(final_url)
            has_params = bool(parsed.query)
            params = list(parse_qs(parsed.query).keys()) if has_params else []
            
            page_url_obj = DiscoveredURL(
                url=final_url,
                source=EndpointType.URL,
                depth=depth,
                has_params=has_params,
                params=params,
                content_type=content_type,
                status_code=response.status_code,
                parent_url=url
            )
            
            with self.lock:
                # Check if already exists
                if not any(u.url == final_url for u in self.results.urls):
                    self.results.urls.append(page_url_obj)
                    logger.debug(f"Added current page to results: {final_url}")
            
            # Extract links
            links = self.extract_links_from_html(response.text, final_url)
            logger.debug(f"Extracted {len(links)} links from {final_url}")
            
            for link in links:
                full_url = urljoin(final_url, link)
                normalized = self.normalize_url(full_url)
                
                if is_within_domain(normalized, self.base_domain):
                    parsed = urlparse(normalized)
                    has_params = bool(parsed.query)
                    params = list(parse_qs(parsed.query).keys()) if has_params else []
                    
                    url_obj = DiscoveredURL(
                        url=normalized,
                        source=EndpointType.URL,
                        depth=depth,
                        has_params=has_params,
                        params=params,
                        content_type=content_type,
                        status_code=response.status_code,
                        parent_url=url
                    )
                    
                    with self.lock:
                        self.results.urls.append(url_obj)
                        
                        # Show progress update
                        if self.show_progress:
                            param_count = len([u for u in self.results.urls if u.has_params])
                            import sys
                            sys.stdout.write(f"\r{colored('[•]', 'yellow')} Pages: {self.results.total_pages_crawled} | URLs: {len(self.results.urls)} | Forms: {len(self.results.forms)} | APIs: {len(self.results.api_endpoints)} | Param URLs: {param_count}")
                            sys.stdout.flush()
                else:
                    logger.debug(f"Skipping out-of-domain URL: {normalized}")
            
            # Extract forms
            forms = self.extract_forms_from_html(response.text, final_url, url, depth)
            with self.lock:
                self.results.forms.extend(forms)
                if self.show_progress:
                    param_count = len([u for u in self.results.urls if u.has_params])
                    import sys
                    sys.stdout.write(f"\r{colored('[•]', 'yellow')} Pages: {self.results.total_pages_crawled} | URLs: {len(self.results.urls)} | Forms: {len(self.results.forms)} | APIs: {len(self.results.api_endpoints)} | Param URLs: {param_count}")
                    sys.stdout.flush()
            
            # Extract JS endpoints
            js_endpoints = self.extract_js_endpoints_from_html(response.text, final_url)
            with self.lock:
                self.results.js_endpoints.extend(js_endpoints)
                self.results.total_js_files += len(js_endpoints)
                if self.show_progress:
                    param_count = len([u for u in self.results.urls if u.has_params])
                    import sys
                    sys.stdout.write(f"\r{colored('[•]', 'yellow')} Pages: {self.results.total_pages_crawled} | URLs: {len(self.results.urls)} | Forms: {len(self.results.forms)} | APIs: {len(self.results.api_endpoints)} | Param URLs: {param_count}")
                    sys.stdout.flush()
            
            # Extract API endpoints from HTML
            api_endpoints = self.extract_api_endpoints_from_text(response.text, final_url)
            with self.lock:
                self.results.api_endpoints.extend(api_endpoints)
                if self.show_progress:
                    param_count = len([u for u in self.results.urls if u.has_params])
                    import sys
                    sys.stdout.write(f"\r{colored('[•]', 'yellow')} Pages: {self.results.total_pages_crawled} | URLs: {len(self.results.urls)} | Forms: {len(self.results.forms)} | APIs: {len(self.results.api_endpoints)} | Param URLs: {param_count}")
                    sys.stdout.flush()
            
            # Extract meta redirects
            redirects = self.extract_meta_redirects(response.text, final_url)
            for redirect in redirects:
                normalized = self.normalize_url(redirect)
                if is_within_domain(normalized, self.base_domain):
                    with self.lock:
                        self.results.urls.append(DiscoveredURL(
                            url=normalized,
                            source=EndpointType.META_REDIRECT,
                            depth=depth,
                            parent_url=url
                        ))
            
            # Extract canonical URLs
            canonical = self.extract_canonical_urls(response.text, final_url)
            for canon in canonical:
                normalized = self.normalize_url(canon)
                with self.lock:
                    self.results.canonical_urls.add(normalized)
            
            # Extract HTML comment URLs
            comment_urls = self.extract_html_comment_urls(response.text, final_url)
            for comment_url in comment_urls:
                if is_within_domain(comment_url, self.base_domain):
                    with self.lock:
                        self.results.html_comment_urls.add(comment_url)
            
        except Exception as e:
            logger.debug(f"Error discovering page {url}: {e}")
    
    def discover_special_sources(self) -> None:
        """Discover URLs from robots.txt and sitemap.xml."""
        # robots.txt
        robots_url = urljoin(self.base_url, '/robots.txt')
        robots_urls = self.parse_robots_txt(robots_url)
        with self.lock:
            self.results.robots_txt_urls.update(robots_urls)
        
        # sitemap.xml
        sitemap_url = urljoin(self.base_url, '/sitemap.xml')
        sitemap_urls = self.parse_sitemap_xml(sitemap_url)
        with self.lock:
            self.results.sitemap_urls.update(sitemap_urls)
    
    def discover_js_file_endpoints(self, js_url: str) -> None:
        """Download and analyze JavaScript file for endpoints."""
        try:
            response = http.get(js_url, timeout=config.REQUEST_TIMEOUT, verify=False)
            if response.status_code == 200:
                api_endpoints = self.extract_api_endpoints_from_text(response.text, self.base_url)
                with self.lock:
                    for endpoint in api_endpoints:
                        if endpoint.endpoint not in [e.endpoint for e in self.results.api_endpoints]:
                            self.results.api_endpoints.append(endpoint)
        except Exception as e:
            logger.debug(f"Error analyzing JS file {js_url}: {e}")
    
    def deduplicate_by_pattern(self, urls: List[str]) -> List[str]:
        """Deduplicate URLs by pattern, keeping one representative per pattern."""
        pattern_map = {}
        
        for url in urls:
            pattern = self.get_url_pattern(url)
            if pattern not in pattern_map:
                pattern_map[pattern] = url
        
        return list(pattern_map.values())
    
    def run(self) -> DiscoveryResults:
        """Run the discovery engine."""
        logger.info(f"Starting discovery engine for {self.base_url}")
        
        # Discover from special sources first
        self.discover_special_sources()
        
        # Crawl pages at each depth
        urls_to_crawl = [self.base_url]
        
        for depth in range(1, self.max_depth + 1):
            if self.stop_event.is_set():
                break
            
            logger.info(f"Discovering at depth {depth}")
            print_status(f"Crawling depth: {depth}", "info")
            next_urls = []
            
            if self.thread_count > 1 and len(urls_to_crawl) > 1:
                with ThreadPoolExecutor(max_workers=self.thread_count) as executor:
                    futures = [
                        executor.submit(self.discover_page, url, depth)
                        for url in urls_to_crawl
                    ]
                    for future in as_completed(futures):
                        if self.stop_event.is_set():
                            break
                        try:
                            future.result()
                        except Exception as e:
                            logger.debug(f"Error in discovery worker: {e}")
            else:
                for url in urls_to_crawl:
                    if self.stop_event.is_set():
                        break
                    self.discover_page(url, depth)
            
            # Collect unique URLs for next depth
            with self.lock:
                for url_obj in self.results.urls:
                    if url_obj.depth == depth and url_obj.source == EndpointType.URL:
                        next_urls.append(url_obj.url)
            
            urls_to_crawl = list(set(next_urls))
            logger.debug(f"Depth {depth}: Collected {len(urls_to_crawl)} unique URLs for next depth")
            
            # Print newline after progress
            if self.show_progress:
                print()
            
            print_status(f"Found {len(urls_to_crawl)} URLs at depth {depth}", "success")
        
        # Analyze JavaScript files for endpoints
        logger.info("Analyzing JavaScript files for endpoints")
        if self.results.total_js_files > 0:
            print_status(f"Analyzing {self.results.total_js_files} JavaScript files for endpoints", "info")
        js_files = [js.endpoint for js in self.results.js_endpoints]
        
        if self.thread_count > 1 and len(js_files) > 1:
            with ThreadPoolExecutor(max_workers=self.thread_count) as executor:
                futures = [
                    executor.submit(self.discover_js_file_endpoints, js_url)
                    for js_url in js_files[:20]  # Limit to 20 JS files
                ]
                for future in as_completed(futures):
                    if self.stop_event.is_set():
                        break
                    try:
                        future.result()
                    except Exception as e:
                        logger.debug(f"Error in JS analysis worker: {e}")
        else:
            for js_url in js_files[:20]:
                if self.stop_event.is_set():
                    break
                self.discover_js_file_endpoints(js_url)
        
        # Deduplicate parameterized URLs by pattern
        param_urls = [u.url for u in self.results.get_parameterized_urls()]
        deduplicated = self.deduplicate_by_pattern(param_urls)
        
        logger.info(f"Pattern deduplication: {len(param_urls)} -> {len(deduplicated)} unique patterns")
        print_status(f"Deduplicated {len(param_urls)} URLs to {len(deduplicated)} unique patterns", "info")
        
        # Update results with deduplicated URLs
        self.results.urls = [u for u in self.results.urls if not u.has_params or u.url in deduplicated]
        
        logger.info(f"Discovery complete. Summary: {self.results.get_summary()}")
        return self.results
