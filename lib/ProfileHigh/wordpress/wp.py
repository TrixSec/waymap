# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.

"""
WordPress High-Risk Vulnerability Scanner.

Note: This module contains CMS-specific vulnerability scanning logic.
This is a refactored wrapper maintaining the same interface.
"""

from lib.core.logger import get_logger
from lib.ui import print_status
from lib.ProfileCritical.wordpress.wpscan_scan import wpscan_wordpress_vulnerabilities

logger = get_logger(__name__)

def check_vulnerabilities(target_url: str) -> None:
    """
    Check WordPress installation for high-risk vulnerabilities.
    
    Args:
        target_url: WordPress site URL to scan
    """
    print_status(f"WordPress high-risk scan for: {target_url}", "info")
    logger.info(f"Starting WordPress high-risk scan for {target_url}")

    try:
        wpscan_wordpress_vulnerabilities(target_url)
    except Exception as e:
        logger.error(f"WPScan lookup failed: {e}")
        print_status(f"WPScan lookup failed: {e}", "error")