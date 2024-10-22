# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.
# cms_detector.py

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def detect_wordpress(response, target):
    wp_paths = ['/wp-admin', '/wp-login.php']
    for path in wp_paths:
        if requests.get(target + path, verify=False).status_code == 200:
            return "WordPress"

    if 'meta name="generator" content="WordPress' in response.text:
        return "WordPress"

    wp_common_files = ['/wp-content/themes/', '/wp-includes/']
    for file in wp_common_files:
        if requests.get(target + file, verify=False).status_code == 200:
            return "WordPress"

    try:
        robots_response = requests.get(target + "/robots.txt", verify=False)
        if robots_response.status_code == 200:
            robots_content = robots_response.text
            if "Disallow: /wp-admin/" in robots_content and "Allow: /wp-admin/admin-ajax.php" in robots_content:
                return "WordPress"
    except requests.RequestException:
        pass 

    return None

def detect_drupal(response, target):
    drupal_paths = ['/sites/all/', '/sites/default/']
    for path in drupal_paths:
        if requests.get(target + path, verify=False).status_code == 200:
            return "Drupal"
    
    if 'X-Generator' in response.headers and 'Drupal' in response.headers['X-Generator']:
        return "Drupal"
    if 'meta name="generator" content="Drupal' in response.text:
        return "Drupal"

    drupal_common_files = ['/misc/drupal.js', '/modules/system/system.module']
    for file in drupal_common_files:
        if requests.get(target + file, verify=False).status_code == 200:
            return "Drupal"
    
    return None

def detect_joomla(response, target):
    joomla_paths = ['/administrator/', '/index.php']
    for path in joomla_paths:
        if requests.get(target + path, verify=False).status_code == 200:
            return "Joomla"
    
    if 'meta name="generator" content="Joomla' in response.text:
        return "Joomla"

    joomla_common_files = ['/templates/', '/media/system/js/']
    for file in joomla_common_files:
        if requests.get(target + file, verify=False).status_code == 200:
            return "Joomla"
    
    return None

def detect_cms(target):
    try:
        response = requests.get(target, verify=False)

        cms = detect_wordpress(response, target)
        if cms:
            return cms

        cms = detect_drupal(response, target)
        if cms:
            return cms

        cms = detect_joomla(response, target)
        if cms:
            return cms

        return "Unknown/Other"
    
    except requests.RequestException as e:
        print(f"[!] Error connecting to {target}: {str(e)}")
        return "Unknown/Other"