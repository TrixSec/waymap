# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.

"""High Risk Scan Orchestrator Module."""

from typing import Union, List

from lib.core.logger import get_logger
from lib.ui import print_status, print_header, print_separator
from lib.ProfileHigh.cms_detector import detect_cms
from lib.ProfileHigh.wordpress.wp import check_vulnerabilities
from lib.ProfileHigh.drupal.dp import scan_all_cves_for_target

logger = get_logger(__name__)

def high_risk_scan(profile_url: Union[str, List[str]]) -> None:
    """
    Perform high risk scan on target URL(s).
    
    Args:
        profile_url: Single URL or list of URLs to scan
    """
    print_header("High-Risk Profile Scan", color="cyan")
    
    if isinstance(profile_url, str):
        profile_url = [profile_url]
    
    print_status(f"Scanning {len(profile_url)} target(s)", "info")
    
    for url in profile_url:
        try:
            cms = detect_cms(url)
            print_status(f"Detected CMS: {cms}", "info")

            if cms == "WordPress":
                print_status("Initiating WordPress high-risk scan...", "info")
                perform_wordpress_high_scan(url)
            
            elif cms == "Drupal":
                print_status("Initiating Drupal high-risk scan...", "info")
                perform_drupal_scan(url)

            else:
                print_status("Unknown CMS. Skipping high-risk scan.", "warning")
                
        except KeyboardInterrupt:
            print_status("Scan interrupted by user", "warning")
            break
        except Exception as e:
            logger.error(f"Error in high risk scan for {url}: {e}")
            print_status(f"Error in high risk scan: {e}", "error")
    
    print_status("High-Risk Profile Scan completed", "info")

def perform_wordpress_high_scan(profile_urls: Union[str, List[str]]) -> None:
    """
    Perform High-risk scan on WordPress URL(s).
    
    Args:
        profile_urls: Single URL or list of URLs
    """
    if isinstance(profile_urls, str):
        profile_urls = [profile_urls]

    for target_url in profile_urls:
        try:
            print_status(f"Running WordPress High-risk scan on {target_url}", "info")
            check_vulnerabilities(target_url)
        except Exception as e:
            logger.error(f"Error while scanning {target_url}: {e}")
            print_status(f"Error while scanning {target_url}", "error")

def perform_drupal_scan(profile_urls: Union[str, List[str]]) -> None:
    """
    Perform High-risk scan on Drupal URL(s).
    
    Args:
        profile_urls: Single URL or list of URLs
    """
    if isinstance(profile_urls, str):
        profile_urls = [profile_urls]

    for target_url in profile_urls:
        try:
            print_status(f"Running Drupal High-risk scan on {target_url}", "info")
            scan_all_cves_for_target(target_url)
        except Exception as e:
            logger.error(f"Error while scanning {target_url}: {e}")
            print_status(f"Error while scanning {target_url}", "error")