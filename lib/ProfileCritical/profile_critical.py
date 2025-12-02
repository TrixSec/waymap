# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.

"""Critical Risk Scan Orchestrator Module."""

from typing import Union, List

from lib.core.logger import get_logger
from lib.ui import print_status, print_header, print_separator
from lib.ProfileCritical.cms_detector import detect_cms
from lib.ProfileCritical.wordpress.wp import check_vulnerabilities
from lib.ProfileCritical.drupal.dp import scan_all_cves_for_target
from lib.ProfileCritical.Generic.gen import handle_cve_2023_24774, handle_cve_2023_24775

logger = get_logger(__name__)

def critical_risk_scan(profile_url: Union[str, List[str]]) -> None:
    """
    Perform critical risk scan on target URL(s).
    
    Args:
        profile_url: Single URL or list of URLs to scan
    """
    print_header("Critical-Risk Profile Scan", color="cyan")
    
    if isinstance(profile_url, str):
        profile_url = [profile_url]
    
    print_status(f"Scanning {len(profile_url)} target(s)", "info")
    
    for url in profile_url:
        try:
            cms = detect_cms(url)
            print_status(f"Detected CMS: {cms}", "info")

            if cms == "WordPress":
                print_status("Initiating WordPress critical-risk scan...", "info")
                perform_wordpress_critical_scan(url)
            
            elif cms == "Drupal":
                print_status("Initiating Drupal critical-risk scan...", "info")
                perform_drupal_scan(url)

            else:
                print_status("Unknown CMS. Proceeding with generic critical-risk scan...", "info")
                perform_generic_critical_scan(url)
                
        except KeyboardInterrupt:
            print_status("Scan interrupted by user", "warning")
            break
        except Exception as e:
            logger.error(f"Error in critical risk scan for {url}: {e}")
            print_status(f"Error in critical risk scan: {e}", "error")
    
    print_status("Critical-Risk Profile Scan completed", "info")

def perform_wordpress_critical_scan(profile_urls: Union[str, List[str]]) -> None:
    """
    Perform Critical-risk scan on WordPress URL(s).
    
    Args:
        profile_urls: Single URL or list of URLs
    """
    if isinstance(profile_urls, str):
        profile_urls = [profile_urls]

    for target_url in profile_urls:
        try:
            print_status(f"Running WordPress Critical-risk scan on {target_url}", "info")
            check_vulnerabilities(target_url)
        except Exception as e:
            logger.error(f"Error while scanning {target_url}: {e}")
            print_status(f"Error while scanning {target_url}", "error")

def perform_drupal_scan(profile_urls: Union[str, List[str]]) -> None:
    """
    Perform Critical-risk scan on Drupal URL(s).
    
    Args:
        profile_urls: Single URL or list of URLs
    """
    if isinstance(profile_urls, str):
        profile_urls = [profile_urls]

    for target_url in profile_urls:
        try:
            print_status(f"Running Drupal Critical-risk scan on {target_url}", "info")
            scan_all_cves_for_target(target_url)
        except Exception as e:
            logger.error(f"Error while scanning {target_url}: {e}")
            print_status(f"Error while scanning {target_url}", "error")
            
def perform_generic_critical_scan(profile_url: str) -> None:
    """
    Perform generic critical-risk scan.
    
    Args:
        profile_url: URL to scan
    """
    print_status(f"Running Generic critical-risk scan on {profile_url}", "info")
    try:
        handle_cve_2023_24774(profile_url)
        handle_cve_2023_24775(profile_url)
    except KeyboardInterrupt:
        print_status("Scan interrupted by the user. Moving to the next CVE...", "warning")
    except Exception as e:
        logger.error(f"Error during Generic critical scan: {e}")
        print_status(f"Error during Generic critical scan", "error")