# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.
# profile_critical.py

from lib.ProfileCritical.cms_detector import detect_cms
from lib.ProfileCritical.wordpress.wp import check_vulnerabilities
from lib.ProfileCritical.drupal.dp import scan_all_cves_for_target
from lib.ProfileCritical.Generic.gen import handle_cve_2023_24774
from lib.ProfileCritical.Generic.gen import handle_cve_2023_24775


def critical_risk_scan(profile_url):
    try:
        cms = detect_cms(profile_url)
        print(f"[•] Detected CMS: {cms}")

        if cms == "WordPress":
            print("[•] Initiating WordPress critical-risk scan...")
            perform_wordpress_critical_scan(profile_url)
        
        elif cms == "Drupal":
            print("[•] Initiating Drupal critical-risk scan...")
            perform_drupal_scan(profile_url)

        else:
            print("[•] Unknown CMS. Proceeding with generic critical-risk scan...")
            perform_generic_critical_scan(profile_url)
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by the user. Exiting gracefully.")
    except Exception as e:
        print(f"[!] Error in critical risk scan")

def perform_wordpress_critical_scan(profile_urls):
    """
    Perform a Critical-risk scan on one or more WordPress URLs.
    Handles both single URLs and lists of URLs.
    """
    if isinstance(profile_urls, str):
        profile_urls = [profile_urls]

    for target_url in profile_urls:
        try:
            print(f"[•] Running WordPress Critical-risk scan on {target_url}")
            check_vulnerabilities(target_url)
        except Exception as e:
            print(f"[!] Error while scanning {target_url}")

def perform_drupal_scan(profile_urls):
    """
    Perform a High-risk scan on one or more Drulap URLs.
    Handles both single URLs and lists of URLs.
    """
    if isinstance(profile_urls, str):
        profile_urls = [profile_urls]

    for target_url in profile_urls:
        try:
            print(f"[•] Running Drupal High-risk scan on {target_url}")
            scan_all_cves_for_target(target_url)
        except Exception as e:
            print(f"[!] Error while scanning {target_url}")
            
def perform_generic_critical_scan(profile_url):
    print(f"[•] Running Generic critical-risk scan on {profile_url}")
    try:
        handle_cve_2023_24774(profile_url)
        handle_cve_2023_24775(profile_url)
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by the user. Moving to the next CVE...")
    except Exception as e:
        print(f"[!] Error during Generic critical scan")