# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.

"""WordPress Plugin Version Detection Module."""

import requests
from urllib.parse import urljoin
from typing import Optional, List

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from lib.core.config import get_config
from lib.core.logger import get_logger
from lib.ui import print_status
from lib.parse.random_headers import generate_random_headers

config = get_config()
logger = get_logger(__name__)

def get_plugin_version_urls(plugin_name: str) -> List[str]:
    """Returns URLs where plugin version information might be found."""
    return [
        f"/wp-content/plugins/{plugin_name}/readme.txt",
        f"/wp-content/plugins/{plugin_name}/changelog.txt",
        f"/wp-content/plugins/{plugin_name}/changelog.md"
    ]

def detect_plugin_version(target_url: str, plugin_name: str) -> Optional[str]:
    """
    Fetch version details from plugin's files (readme.txt, changelog.txt, changelog.md).
    
    Args:
        target_url: Base URL of the WordPress site
        plugin_name: Name of the plugin to check
        
    Returns:
        Detected version string or None if not found
    """
    try:
        headers = generate_random_headers()
        urls_to_check = get_plugin_version_urls(plugin_name)
        all_404 = True

        for url_path in urls_to_check:
            full_url = urljoin(target_url, url_path)
            try:
                response = requests.get(full_url, headers=headers, timeout=config.REQUEST_TIMEOUT, verify=False)
                
                if response.status_code == 200:
                    all_404 = False
                    
                    # Check for "Version:" tag
                    if "Version:" in response.text:
                        for line in response.text.splitlines():
                            if "Version:" in line:
                                version = line.split(":")[1].strip()
                                return version

                    # Check for "Stable tag:" tag
                    elif "Stable tag:" in response.text:
                        for line in response.text.splitlines():
                            if "Stable tag:" in line:
                                version = line.split(":")[1].strip()
                                return version

                    # Check for markdown headers (####)
                    elif "#" in response.text:
                        for line in response.text.splitlines():
                            if line.startswith("####"):
                                parts = line.split()
                                if len(parts) > 1:
                                    version = parts[1]
                                    return version

            except requests.exceptions.RequestException:
                continue

        if all_404:
            logger.debug(f"Plugin '{plugin_name}' not found at {target_url}")
            return None
        
        return None

    except KeyboardInterrupt:
        print_status("Process interrupted by user", "warning")
        raise
    except requests.exceptions.RequestException as e:
        logger.error(f"Error detecting plugin version: {e}")
        return None