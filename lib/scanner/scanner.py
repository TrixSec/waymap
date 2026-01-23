# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.

"""Main scanner module for waymap."""

import os
from typing import List, Optional
from lib.core.logger import get_logger
from lib.core.config import get_config
from lib.ui import print_status, print_header, print_separator
from lib.utils import is_valid_url, has_query_parameters, extract_domain

logger = get_logger(__name__)
config = get_config()


class WaymapScanner:
    """Main scanner class for waymap."""
    
    def __init__(self, thread_count: int = 1, no_prompt: bool = False):
        """
        Initialize scanner.
        
        Args:
            thread_count: Number of threads to use
            no_prompt: Skip interactive prompts
        """
        self.thread_count = thread_count
        self.no_prompt = no_prompt
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
        
        # Determine if we need to crawl
        urls_to_scan = []
        
        if has_query_parameters(target):
            print_status(f"Target has parameters, skipping crawl", "info")
            urls_to_scan = [target]
        elif crawl_depth > 0:
            print_status(f"Starting crawl with depth {crawl_depth}", "info")
            urls_to_scan = self._crawl_target(target, crawl_depth)
        else:
            print_status("No crawl depth specified and target has no parameters", "warning")
            urls_to_scan = [target]
        
        if not urls_to_scan:
            print_status("No URLs found to scan", "warning")
            return
        
        # Run profile scan if specified
        if profile_type:
            self._run_profile_scan(target, profile_type, deepscan_modules)
            return
        
        # Run regular scan
        if scan_type:
            self._run_vulnerability_scan(
                urls_to_scan,
                scan_type,
                technique_string
            )
    
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
            domain = extract_domain(target)
            valid_urls = [
                url for url in urls
                if is_valid_url(url) and has_query_parameters(url)
            ]
            
            print_status(f"Found {len(valid_urls)} valid URLs with parameters", "success")
            return valid_urls
            
        except Exception as e:
            self.logger.error(f"Crawling failed: {e}", exc_info=True)
            print_status(f"Crawling failed: {e}", "error")
            return []
    
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
            'ssti': ('Server Side Template Injection', 'magenta'),
            'xss': ('Cross Site Scripting', 'cyan'),
            'lfi': ('Local File Inclusion', 'blue'),
            'open-redirect': ('Open Redirect', 'green'),
            'crlf': ('CRLF Injection', 'yellow'),
            'cors': ('CORS Misconfiguration', 'red')
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
            print_status(f"Scanning {len(urls)} URLs for {scan_type}", "info")
            
            if scan_type == 'sqli':
                from lib.injection.sqlin.sql import run_sql_tests, run_boolean_sqli, run_error_sqli, run_time_blind_sqli
                
                if technique_string:
                    for char in technique_string.upper():
                        if char == 'B':
                            run_boolean_sqli(urls, self.thread_count)
                        elif char == 'E':
                            run_error_sqli(urls, self.thread_count)
                        elif char == 'T':
                            run_time_blind_sqli(urls, self.thread_count)
                else:
                    run_sql_tests(urls, self.thread_count)
                    
            elif scan_type == 'cmdi':
                from lib.injection.cmdi import perform_cmdi_scan
                payloads = self._load_payloads('cmdipayload.txt')
                perform_cmdi_scan(urls, payloads, self.thread_count, self.no_prompt)
                
            elif scan_type == 'ssti':
                from lib.injection.ssti import perform_ssti_scan
                perform_ssti_scan(urls, self.thread_count, self.no_prompt, verbose=True)
                
            elif scan_type == 'xss':
                from lib.injection.xss import perform_xss_scan
                perform_xss_scan(urls, self.thread_count, self.no_prompt, verbose=True)
                
            elif scan_type == 'lfi':
                from lib.injection.lfi import perform_lfi_scan
                perform_lfi_scan(urls, self.thread_count, self.no_prompt, verbose=True)
                
            elif scan_type == 'open-redirect':
                from lib.injection.openredirect import perform_redirect_scan
                perform_redirect_scan(urls, self.thread_count, self.no_prompt, verbose=True)
                
            elif scan_type == 'crlf':
                from lib.injection.crlf import perform_crlf_scan
                perform_crlf_scan(urls, self.thread_count, self.no_prompt, verbose=True)
                
            elif scan_type == 'cors':
                from lib.injection.cors import perform_cors_scan
                perform_cors_scan(urls, self.thread_count, self.no_prompt, verbose=True)
            
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
            
            if profile_type == 'high-risk':
                from lib.ProfileHigh.profile_high import high_risk_scan
                high_risk_scan(target)
                
            elif profile_type == 'critical-risk':
                from lib.ProfileCritical.profile_critical import critical_risk_scan
                critical_risk_scan(target)
                
            elif profile_type == 'deepscan':
                from lib.ProfileDeepScan.deepscan import deepscan
                if deepscan_modules:
                    self._run_deepscan_modules([target], deepscan_modules)
                else:
                    deepscan(target)
            
            self.logger.info(f"Completed {profile_type} profile scan")
            
        except Exception as e:
            self.logger.error(f"Profile scan failed: {e}", exc_info=True)
            print_status(f"Profile scan failed: {e}", "error")
    
    def _run_deepscan_modules(self, urls: List[str], modules: List[str]) -> None:
        """
        Run specific deepscan modules.
        
        Args:
            urls: URLs to scan
            modules: Modules to run
        """
        from lib.ProfileDeepScan.deepscan import (
            run_headers_scan,
            run_backupfile_scan,
            run_dirfuzz_scan,
            run_js_scan
        )
        
        module_map = {
            'hs': ('Header Deep Scan', run_headers_scan),
            'bf': ('Backup File Scan', run_backupfile_scan),
            'df': ('DirFuzz Scan', run_dirfuzz_scan),
            'js': ('JavaScript Deep Scan', run_js_scan)
        }
        
        for module in modules:
            if module in module_map:
                name, func = module_map[module]
                print_status(f"Running {name}", "info")
                func(urls)
            else:
                print_status(f"Unknown module: {module}", "warning")
    
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
