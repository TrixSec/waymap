# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.

"""Deep Scan Orchestrator Module."""

from typing import List, Union

from lib.core.logger import get_logger
from lib.ui import print_status, print_header, print_separator
from lib.ProfileDeepScan.headerdeepscan import headersdeepscan
from lib.ProfileDeepScan.waymap_dirfuzz import dirfuzz
from lib.ProfileDeepScan.waymap_backupfilefinder import backupfiles
from lib.ProfileDeepScan.waymap_jsdeepscan import jsscan

logger = get_logger(__name__)

def deepscan(profile_url: Union[str, List[str]]) -> None:
    """
    Perform comprehensive deep scan on target URL(s).
    
    Args:
        profile_url: Single URL or list of URLs to scan
    """
    print_header("Deep Scan Profile", color="cyan")
    
    if isinstance(profile_url, str):
        profile_url = [profile_url]
    
    print_status(f"Scanning {len(profile_url)} target(s)", "info")
    
    for url in profile_url:
        print_status(f"Starting deep scan for: {url}", "info")
        
        # Headers analysis
        try:
            print_status("Running Headers Analysis...", "info")
            headersdeepscan(url)
        except Exception as e:
            logger.error(f"Headers Analysis failed for {url}: {e}")
            print_status(f"Headers Analysis failed: {e}", "error")
        
        # Backup file finder
        try:
            print_status("Running Backup File Finder...", "info")
            backupfiles(url)
        except Exception as e:
            logger.error(f"Backup Finder failed for {url}: {e}")
            print_status(f"Backup Finder failed: {e}", "error")
        
        # JavaScript analysis
        try:
            print_status("Running JavaScript Analysis...", "info")
            jsscan(url)
        except Exception as e:
            logger.error(f"JavaScript scan failed for {url}: {e}")
            print_status(f"JavaScript scan failed: {e}", "error")
        
        # Directory fuzzing
        try:
            print_status("Running Directory Fuzzing...", "info")
            dirfuzz(url)
        except Exception as e:
            logger.error(f"Directory Fuzzing failed for {url}: {e}")
            print_status(f"Directory Fuzzing failed: {e}", "error")
        
        print_status(f"Deep scan completed for: {url}", "success")
    
    print_status("Deep Scan Profile completed", "info")

def run_headers_scan(urls: Union[str, List[str]]) -> None:
    """Run only headers analysis."""
    if isinstance(urls, str):
        urls = [urls]
    
    for url in urls:
        try:
            headersdeepscan(url)
        except Exception as e:
            logger.error(f"Headers Analysis failed for {url}: {e}")
            print_status(f"Headers Analysis failed: {e}", "error")

def run_backupfile_scan(urls: Union[str, List[str]]) -> None:
    """Run only backup file finder."""
    if isinstance(urls, str):
        urls = [urls]
    
    for url in urls:
        try:
            backupfiles(url)
        except Exception as e:
            logger.error(f"Backup Finder failed for {url}: {e}")
            print_status(f"Backup Finder failed: {e}", "error")

def run_dirfuzz_scan(urls: Union[str, List[str]]) -> None:
    """Run only directory fuzzing."""
    if isinstance(urls, str):
        urls = [urls]
    
    for url in urls:
        try:
            dirfuzz(url)
        except Exception as e:
            logger.error(f"Directory Fuzzing failed for {url}: {e}")
            print_status(f"Directory Fuzzing failed: {e}", "error")

def run_js_scan(urls: Union[str, List[str]]) -> None:
    """Run only JavaScript analysis."""
    if isinstance(urls, str):
        urls = [urls]
    
    for url in urls:
        try:
            jsscan(url)
        except Exception as e:
            logger.error(f"JavaScript scan failed for {url}: {e}")
            print_status(f"JavaScript scan failed: {e}", "error")