# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.

"""Drupal Version Detection Module."""

import requests
from typing import Optional

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from lib.core.config import get_config
from lib.core.logger import get_logger
from lib.ui import print_status
from lib.parse.random_headers import generate_random_headers

config = get_config()
logger = get_logger(__name__)

def fetch_drupal_version(target_url: str) -> Optional[str]:
    """
    Determine the Drupal version by checking HTML meta tags and HTTP headers.
    
    Args:
        target_url: The base URL of the target Drupal site
        
    Returns:
        Drupal version number as a string (e.g., '10') or None if not found
    """
    try:
        headers = generate_random_headers()
        
        # Check HTML meta tags
        response = requests.get(target_url, headers=headers, timeout=config.REQUEST_TIMEOUT, verify=False)
        if response.status_code == 200:
            for line in response.text.splitlines():
                if '<meta name="Generator"' in line and 'Drupal' in line:
                    try:
                        version = line.split('content="Drupal ')[1].split()[0]
                        return version
                    except (IndexError, AttributeError):
                        pass

        # Check HTTP headers
        response = requests.head(target_url, headers=headers, timeout=config.REQUEST_TIMEOUT, verify=False)
        if response.status_code == 200:
            x_generator = response.headers.get("x-generator")
            if x_generator and "Drupal" in x_generator:
                try:
                    version = x_generator.split("Drupal ")[1].split()[0]
                    return version
                except (IndexError, AttributeError):
                    pass

        return None

    except requests.exceptions.RequestException as e:
        logger.error(f"Error while checking Drupal version: {e}")
        return None
    except KeyboardInterrupt:
        print_status("Process interrupted by user", "warning")
        raise
