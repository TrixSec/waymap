# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.

"""CMS Detection Module."""

import requests
from urllib.parse import urljoin
from typing import Optional

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from lib.core.config import get_config
from lib.core.logger import get_logger
from lib.parse.random_headers import generate_random_headers

config = get_config()
logger = get_logger(__name__)

def detect_wordpress(response: requests.Response, profile_url: str) -> Optional[str]:
    """Detect WordPress CMS."""
    headers = generate_random_headers()
    
    # Check common WordPress paths
    wp_paths = ['/wp-admin', '/wp-login.php']
    for path in wp_paths:
        try:
            full_url = urljoin(profile_url, path)
            if requests.get(full_url, headers=headers, verify=False, timeout=config.REQUEST_TIMEOUT).status_code == 200:
                return "WordPress"
        except requests.RequestException:
            pass

    # Check meta generator tag
    if 'meta name="generator" content="WordPress' in response.text:
        return "WordPress"

    # Check common WordPress files
    wp_common_files = ['/wp-content/themes/', '/wp-includes/']
    for file in wp_common_files:
        try:
            full_url = urljoin(profile_url, file)
            if requests.get(full_url, headers=headers, verify=False, timeout=config.REQUEST_TIMEOUT).status_code == 200:
                return "WordPress"
        except requests.RequestException:
            pass

    # Check robots.txt
    try:
        robots_url = urljoin(profile_url, "/robots.txt")
        robots_response = requests.get(robots_url, verify=False, timeout=config.REQUEST_TIMEOUT)
        if robots_response.status_code == 200:
            robots_content = robots_response.text
            if "Disallow: /wp-admin/" in robots_content and "Allow: /wp-admin/admin-ajax.php" in robots_content:
                return "WordPress"
    except requests.RequestException:
        pass

    return None

def detect_drupal(response: requests.Response, profile_url: str) -> Optional[str]:
    """Detect Drupal CMS."""
    headers = generate_random_headers()
    
    # Check common Drupal paths
    drupal_paths = ['/sites/all/', '/sites/default/']
    for path in drupal_paths:
        try:
            full_url = urljoin(profile_url, path)
            if requests.get(full_url, headers=headers, verify=False, timeout=config.REQUEST_TIMEOUT).status_code == 200:
                return "Drupal"
        except requests.RequestException:
            pass
    
    # Check X-Generator header
    if 'X-Generator' in response.headers and 'Drupal' in response.headers['X-Generator']:
        return "Drupal"
    
    # Check meta generator tag
    if 'meta name="generator" content="Drupal' in response.text:
        return "Drupal"

    # Check common Drupal files
    drupal_common_files = ['/misc/drupal.js', '/modules/system/system.module']
    for file in drupal_common_files:
        try:
            full_url = urljoin(profile_url, file)
            if requests.get(full_url, headers=headers, verify=False, timeout=config.REQUEST_TIMEOUT).status_code == 200:
                return "Drupal"
        except requests.RequestException:
            pass
    
    return None

def detect_cms(profile_url: str) -> str:
    """Detect CMS type of target URL."""
    try:
        headers = generate_random_headers()
        response = requests.get(profile_url, headers=headers, verify=False, timeout=config.REQUEST_TIMEOUT)

        cms = detect_wordpress(response, profile_url)
        if cms:
            return cms

        cms = detect_drupal(response, profile_url)
        if cms:
            return cms

        return "Unknown/Other"
    
    except requests.RequestException as e:
        logger.error(f"Error connecting to {profile_url}: {e}")
        return "Unknown/Other"
