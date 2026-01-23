# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.

"""
WordPress Critical Vulnerability Scanner.

Note: This module contains CMS-specific vulnerability scanning logic.
For actual implementation, refer to the original wp.py file.
This is a refactored wrapper maintaining the same interface.
"""

from typing import Optional
from lib.core.logger import get_logger
from lib.ui import print_status
from lib.ProfileCritical.wordpress.wpscan_scan import wpscan_wordpress_vulnerabilities

logger = get_logger(__name__)

def check_vulnerabilities(target_url: str) -> None:
    """
    Check WordPress installation for critical vulnerabilities.
    
    Args:
        target_url: WordPress site URL to scan
        
    Note:
        This is a placeholder for the full WordPress vulnerability scanner.
        The original implementation should be integrated here with proper
        refactoring to use the new infrastructure (config, logger, ui).
    """
    print_status(f"WordPress vulnerability scan for: {target_url}", "info")
    logger.info(f"Starting WordPress vulnerability scan for {target_url}")

    try:
        wpscan_wordpress_vulnerabilities(target_url)
    except Exception as e:
        logger.error(f"WPScan lookup failed: {e}")
        print_status(f"WPScan lookup failed: {e}", "error")
