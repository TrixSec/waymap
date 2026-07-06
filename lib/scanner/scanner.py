# Copyright (c) 2026 waymap developers
# See the file 'LICENSE' for copying permission.

"""Main scanner module for waymap."""

import os
from typing import List, Optional
from lib.core.logger import get_logger
from lib.core.config import get_config
from lib.ui import print_status, print_header, print_separator
from lib.utils import is_valid_url, has_query_parameters, filter_urls_with_params, extract_domain, normalize_url

logger = get_logger(__name__)
config = get_config()

# Scans that require query parameters for injection testing
PARAM_SCANS = frozenset({
    'sqli', 'cmdi', 'rce', 'ssti', 'xss', 'lfi',
    'open-redirect', 'crlf', 'injection-advanced',
})


class WaymapScanner:
    """Main scanner class for waymap."""
    
    def __init__(self, thread_count: int = 1, no_prompt: bool = False, ai_payloads: bool = False, ai_discovery: bool = False):
        # Set up interrupt handler (in case it wasn't done yet)
        from lib.core.interrupt import setup_interrupt_handler
        setup_interrupt_handler()
        """
        Initialize scanner.
        
        Args:
            thread_count: Number of threads to use
            no_prompt: Skip interactive prompts
            ai_payloads: Use AI-generated payloads
            ai_discovery: Use AI for attack surface discovery
        """
        self.thread_count = thread_count
        self.no_prompt = no_prompt
        self.ai_payloads = ai_payloads
        self.ai_discovery = ai_discovery
        self.logger = get_logger(f"{__name__}.WaymapScanner")
    
    def scan(
        self,
        target: str,
        scan_type: str,
        crawl_depth: int = 0,
        profile_type: Optional[str] = None,
        technique_string: Optional[str] = None,
        deepscan_modules: Optional[List[str]] = None
    ) -> None:
        """
        Execute a scan on the target.
        
        Args:
            target: Target URL
            scan_type: Type of scan to perform
            crawl_depth: Depth for crawling
            profile_type: Optional scan profile
            technique_string: Optional SQLi techniques
            deepscan_modules: Optional deepscan modules
        """
        self.logger.info(f"Starting scan on {target}")
        
        # Extract domain for logging
        domain = extract_domain(target)
        if domain:
            self.logger = get_logger(f"{__name__}.WaymapScanner", domain)
        
        # Determine URLs to scan
        urls_to_scan = self._resolve_urls_to_scan(target, crawl_depth)
        
        if not urls_to_scan:
            print_status("No URLs found to scan", "warning")
            return
        
        # Run profile scan if specified
        if profile_type:
            self._run_profile_scan(target, profile_type)
            return
        
        # Run regular scan
        if scan_type:
            self._run_vulnerability_scan(
                urls_to_scan,
                scan_type,
                technique_string
            )

    def scan_urls(
        self,
        urls: List[str],
        scan_type: str,
        technique_string: Optional[str] = None,
    ) -> None:
        if not urls:
            print_status("No URLs provided to scan", "warning")
            return

        scan_urls = self._dedupe_urls([u for u in urls if isinstance(u, str) and u.strip()])
        if not scan_urls:
            print_status("No valid URLs provided to scan", "warning")
            return

        self._run_vulnerability_scan(scan_urls, scan_type, technique_string)
    
    def _resolve_urls_to_scan(self, target: str, crawl_depth: int) -> List[str]:
        """Resolve which URLs to scan, optionally crawling first."""
        if has_query_parameters(target):
            print_status("Target has query parameters, skipping crawl", "info")
            return [target]

        if crawl_depth > 0:
            print_status(f"Starting crawl with depth {crawl_depth}", "info")
            crawled = self._crawl_target(target, crawl_depth)
            if crawled:
                return crawled
            print_status(
                "Crawl found no parameterized URLs; falling back to base target",
                "warning",
            )

        print_status(f"Scanning base URL: {target}", "info")
        return [target]

    def _dedupe_urls(self, urls: List[str]) -> List[str]:
        """Normalize and dedupe URLs while preserving order."""
        seen = set()
        unique = []
        for url in urls:
            normalized = normalize_url(url.strip())
            if normalized in seen:
                continue
            seen.add(normalized)
            unique.append(normalized)
        return unique
    
    def _crawl_target(self, target: str, depth: int) -> List[str]:
        """
        Crawl target to find URLs.
        
        Args:
            target: Target URL
            depth: Crawl depth
            
        Returns:
            List of crawled URLs
        """
        try:
            from lib.waymapcrawlers.crawler import run_crawler
            
            urls = run_crawler(
                target,
                depth,
                thread_count=self.thread_count,
                no_prompt=self.no_prompt
            )
            
            # Filter valid URLs with parameters
            valid_urls = filter_urls_with_params([
                url for url in urls if is_valid_url(url)
            ])
            
            print_status(f"Found {len(valid_urls)} valid URLs with parameters", "success")
            return self._dedupe_urls(valid_urls)
            
        except Exception as e:
            self.logger.error(f"Crawling failed: {e}", exc_info=True)
            print_status(f"Crawling failed: {e}", "error")
            return []
    
    def _urls_for_scan_type(self, urls: List[str], scan_type: str) -> Optional[List[str]]:
        """Return the URL list appropriate for a scan type, or None to skip."""
        if scan_type not in PARAM_SCANS:
            return urls

        param_urls = filter_urls_with_params(urls)
        if not param_urls:
            print_status(
                f"{scan_type} requires URLs with query parameters; none found — skipping",
                "warning",
            )
            return None
        return param_urls
    
    def _run_vulnerability_scan(
        self,
        urls: List[str],
        scan_type: str,
        technique_string: Optional[str] = None
    ) -> None:
        """
        Run vulnerability scans on URLs.
        
        Args:
            urls: URLs to scan
            scan_type: Type of scan
            technique_string: Optional SQLi techniques
        """
        scan_configs = {
            'sqli': ('SQL Injection', 'yellow'),
            'cmdi': ('Command Injection', 'red'),
            'rce': ('RCE (Command Injection)', 'red'),
            'ssti': ('Server Side Template Injection', 'magenta'),
            'xss': ('Cross Site Scripting', 'cyan'),
            'lfi': ('Local File Inclusion', 'blue'),
            'open-redirect': ('Open Redirect', 'green'),
            'crlf': ('CRLF Injection', 'yellow'),
            'cors': ('CORS Misconfiguration', 'red'),
            'recon': ('Recon Scan', 'cyan'),
            'misconfig': ('Misconfiguration Scan', 'cyan'),
            'redirect': ('Redirect/Header Injection', 'cyan'),
            'injection-advanced': ('Advanced Injection', 'magenta'),
            'graphql-suite': ('GraphQL Suite', 'magenta'),
            'auth-logic': ('Auth Logic Checks', 'yellow'),
            'cache-smuggling': ('Cache/Smuggling Checks', 'yellow'),
            'wordpress-extras': ('WordPress Extras', 'green'),
            'optional': ('Optional Checks', 'blue')
        }
        
        if scan_type == 'all':
            print_header("Comprehensive Security Scan", "cyan")
            for stype in scan_configs.keys():
                self._execute_single_scan(urls, stype, technique_string)
                print_separator()
        elif scan_type in scan_configs:
            name, color = scan_configs[scan_type]
            print_header(f"{name} Scan", color)
            self._execute_single_scan(urls, scan_type, technique_string)
        else:
            print_status(f"Unknown scan type: {scan_type}", "error")
    
    def _execute_single_scan(
        self,
        urls: List[str],
        scan_type: str,
        technique_string: Optional[str] = None
    ) -> None:
        """
        Execute a single type of scan.
        
        Args:
            urls: URLs to scan
            scan_type: Type of scan
            technique_string: Optional SQLi techniques
        """
        try:
            scan_urls = self._urls_for_scan_type(self._dedupe_urls(urls), scan_type)
            if scan_urls is None:
                return

            print_status(f"Scanning {len(scan_urls)} URLs for {scan_type}", "info")
            
            if scan_type == 'sqli':
                from lib.injection.sqlin.sql import (
                    run_sql_tests,
                    run_boolean_sqli,
                    run_error_sqli,
                    run_time_blind_sqli,
                    run_union_sqli,
                    run_inline_sqli,
                    run_stacked_sqli,
                    vulnerable_pairs,
                )
                from lib.injection.sqlin.db_fetcher import fetch_databases_once
                from lib.ui import print_separator, print_header
                from lib.core.state import stop_scan
                from lib.core.interrupt import reset_interrupt
                
                # Reset vulnerable_pairs at the start of the scan
                vulnerable_pairs.clear()
                
                if technique_string:
                    technique_map = {
                        'B': run_boolean_sqli,
                        'E': run_error_sqli,
                        'T': run_time_blind_sqli,
                        'U': run_union_sqli,
                        'I': run_inline_sqli,
                        'S': run_stacked_sqli,
                    }
                    for char in technique_string.upper():
                        if stop_scan.is_set():
                            reset_interrupt()
                        runner = technique_map.get(char)
                        if runner:
                            runner(scan_urls, self.thread_count)
                        else:
                            print_status(f"Unknown SQLi technique '{char}' ignored", "warning")
                        # Reset interrupt after each technique to allow next technique to run
                        reset_interrupt()
                    # After all techniques, fetch DBs if any vulnerable pairs
                    if vulnerable_pairs:
                        for url, param in vulnerable_pairs:
                            if stop_scan.is_set(): break
                            try:
                                fetch_databases_once(url, param)
                            except Exception as e:
                                import logging
                                logging.error(f"Error fetching databases for {url}: {e}")
                else:
                    run_sql_tests(scan_urls, self.thread_count)
                    
            elif scan_type == 'cmdi':
                from lib.injection.cmdi import perform_cmdi_scan
                payloads = self._load_payloads('cmdipayload.txt')
                
                # Add AI-generated payloads if enabled
                if self.ai_payloads:
                    from lib.ai.payload_generator import generate_payloads
                    from lib.ai.llm_provider import is_llm_available
                    
                    if is_llm_available() and scan_urls:
                        # Use first URL to generate payloads
                        first_url = scan_urls[0]
                        # Extract first parameter
                        from urllib.parse import urlparse, parse_qs
                        parsed = urlparse(first_url)
                        params = parse_qs(parsed.query)
                        if params:
                            first_param = list(params.keys())[0]
                            ai_payloads = generate_payloads(
                                vuln_type='cmdi',
                                url=first_url,
                                parameter=first_param,
                                num_payloads=5
                            )
                            if ai_payloads:
                                payloads.extend(ai_payloads)
                
                perform_cmdi_scan(scan_urls, payloads, self.thread_count, self.no_prompt)

            elif scan_type == 'rce':
                from lib.injection.rce import perform_rce_scan
                perform_rce_scan(scan_urls, self.thread_count, self.no_prompt, verbose=True)
                
            elif scan_type == 'ssti':
                from lib.injection.ssti import perform_ssti_scan
                perform_ssti_scan(scan_urls, self.thread_count, self.no_prompt, verbose=True)
                
            elif scan_type == 'xss':
                from lib.injection.xss import perform_xss_scan
                perform_xss_scan(scan_urls, self.thread_count, self.no_prompt, verbose=True)
                
            elif scan_type == 'lfi':
                from lib.injection.lfi import perform_lfi_scan
                perform_lfi_scan(scan_urls, self.thread_count, self.no_prompt, verbose=True)
                
            elif scan_type == 'open-redirect':
                from lib.injection.openredirect import perform_redirect_scan
                perform_redirect_scan(scan_urls, self.thread_count, self.no_prompt, verbose=True)
                
            elif scan_type == 'crlf':
                from lib.injection.crlf import perform_crlf_scan
                perform_crlf_scan(scan_urls, self.thread_count, self.no_prompt, verbose=True)
                
            elif scan_type == 'cors':
                from lib.injection.cors import perform_cors_scan
                perform_cors_scan(scan_urls, self.thread_count, self.no_prompt, verbose=True)

            elif scan_type == 'recon':
                from lib.recon.foundation import perform_recon_scan
                perform_recon_scan(scan_urls, self.thread_count, self.no_prompt, verbose=True)

            elif scan_type == 'misconfig':
                from lib.recon.misconfig import perform_misconfig_scan
                perform_misconfig_scan(scan_urls, self.thread_count, self.no_prompt, verbose=True)

            elif scan_type == 'redirect':
                from lib.recon.redirects import perform_redirect_injection_scan
                perform_redirect_injection_scan(scan_urls, self.thread_count, self.no_prompt, verbose=True)

            elif scan_type == 'injection-advanced':
                from lib.injection.advanced import perform_injection_advanced_scan
                perform_injection_advanced_scan(scan_urls, self.thread_count, self.no_prompt, verbose=True)

            elif scan_type == 'graphql-suite':
                from lib.api.graphql_suite import perform_graphql_suite_scan
                perform_graphql_suite_scan(scan_urls, verbose=True)

            elif scan_type == 'auth-logic':
                from lib.api.auth_logic import perform_auth_logic_scan
                perform_auth_logic_scan(scan_urls, verbose=True)

            elif scan_type == 'cache-smuggling':
                from lib.cache.smuggling import perform_cache_smuggling_scan
                perform_cache_smuggling_scan(scan_urls, verbose=True)

            elif scan_type == 'wordpress-extras':
                from lib.ProfileWordpress.wordpress_extras import perform_wordpress_extras_scan
                perform_wordpress_extras_scan(scan_urls, verbose=True)

            elif scan_type == 'optional':
                from lib.optional.optional_checks import perform_optional_scan
                perform_optional_scan(scan_urls, verbose=True)
            
            self.logger.info(f"Completed {scan_type} scan")
            
        except Exception as e:
            self.logger.error(f"Scan failed for {scan_type}: {e}", exc_info=True)
            print_status(f"Scan failed: {e}", "error")
    
    def _run_profile_scan(
        self,
        target: str,
        profile_type: str,
        deepscan_modules: Optional[List[str]] = None
    ) -> None:
        """
        Run profile-based scan.
        
        Args:
            target: Target URL
            profile_type: Type of profile
            deepscan_modules: Optional deepscan modules
        """
        try:
            print_header(f"{profile_type.upper()} Profile Scan", "green")
            print_status(f"Target: {target}", "info")
            
            if profile_type == 'wordpress':
                from lib.ProfileWordpress.profile_wordpress import wordpress_vuln_scan
                wordpress_vuln_scan(target)
            
            self.logger.info(f"Completed {profile_type} profile scan")
            
        except Exception as e:
            self.logger.error(f"Profile scan failed: {e}", exc_info=True)
            print_status(f"Profile scan failed: {e}", "error")
    
    def _load_payloads(self, filename: str) -> List[str]:
        """
        Load payloads from file.
        
        Args:
            filename: Payload filename
            
        Returns:
            List of payloads
        """
        from lib.utils.file_utils import load_payloads
        filepath = os.path.join(config.DATA_DIR, filename)
        return load_payloads(filepath)
