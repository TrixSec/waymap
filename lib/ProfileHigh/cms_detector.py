# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.
# waymap cms detector

import requests
from urllib.parse import urljoin
from lib.parse.random_headers import generate_random_headers
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
headers = generate_random_headers()

def detect_wordpress(response, profile_url):
    wp_paths = ['/wp-admin', '/wp-login.php']
    for path in wp_paths:
        full_url = urljoin(profile_url, path)
        if requests.get(full_url, headers=headers, verify=False).status_code == 200:
            return "WordPress"

    if 'meta name="generator" content="WordPress' in response.text:
        return "WordPress"

    wp_common_files = ['/wp-content/themes/', '/wp-includes/']
    for file in wp_common_files:
        full_url = urljoin(profile_url, file)
        if requests.get(full_url, headers=headers, verify=False).status_code == 200:
            return "WordPress"

    try:
        robots_url = urljoin(profile_url, "/robots.txt")
        robots_response = requests.get(robots_url, verify=False)
        if robots_response.status_code == 200:
            robots_content = robots_response.text
            if "Disallow: /wp-admin/" in robots_content and "Allow: /wp-admin/admin-ajax.php" in robots_content:
                return "WordPress"
    except requests.RequestException:
        pass 

    return None

def detect_drupal(response, profile_url):
    drupal_paths = ['/sites/all/', '/sites/default/']
    for path in drupal_paths:
        full_url = urljoin(profile_url, path)
        if requests.get(full_url, headers=headers, verify=False).status_code == 200:
            return "Drupal"
    
    if 'X-Generator' in response.headers and 'Drupal' in response.headers['X-Generator']:
        return "Drupal"
    if 'meta name="generator" content="Drupal' in response.text:
        return "Drupal"

    drupal_common_files = ['/misc/drupal.js', '/modules/system/system.module']
    for file in drupal_common_files:
        full_url = urljoin(profile_url, file)
        if requests.get(full_url, headers=headers, verify=False).status_code == 200:
            return "Drupal"
    
    return None

def detect_cms(profile_url):
    try:
        response = requests.get(profile_url)

        cms = detect_wordpress(response, profile_url)
        if cms:
            return cms

        cms = detect_drupal(response, profile_url)
        if cms:
            return cms

        return "Unknown/Other"
    
    except requests.RequestException as e:
        print(f"[!] Error connecting to {profile_url}: {str(e)}")
        return "Unknown/Other"