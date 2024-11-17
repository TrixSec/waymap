# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.

from lib.ProfileHigh.cms_detector import detect_cms
from lib.ProfileHigh.wordpress.wp import check_vulnerabilities
from lib.ProfileHigh.drupal.dp import handle_cve_2019_6340
from lib.ProfileHigh.joomla.jm import handle_cve_2020_10239
from lib.ProfileHigh.joomla.jm import handle_cve_2020_10238
from lib.ProfileHigh.joomla.jm import handle_cve_2018_8045

def high_risk_scan(profile_url):
    cms = detect_cms(profile_url)
    print(f"[•] Detected CMS: {cms}")

    if cms == "WordPress":
        print("[•] Initiating WordPress high-risk scan...")
        perform_wordpress_scan(profile_url)
    
    elif cms == "Drupal":
        print("[•] Initiating Drupal high-risk scan...")
        perform_drupal_scan(profile_url)

    elif cms == "Joomla":
        print("[•] Initiating Joomla high-risk scan...")
        perform_joomla_scan(profile_url)

    else:
        print("[•] Unknown CMS. Proceeding with generic high-risk scan...")
        perform_generic_scan(profile_url)


def perform_wordpress_scan(profile_urls):
    """
    Perform a High-risk scan on one or more WordPress URLs.
    Handles both single URLs and lists of URLs.
    """
    if isinstance(profile_urls, str):
        profile_urls = [profile_urls]

    for target_url in profile_urls:
        try:
            print(f"[•] Running WordPress High-risk scan on {target_url}")
            check_vulnerabilities(target_url)
        except Exception as e:
            print(f"[!] Error while scanning {target_url}: {e}")


def perform_drupal_scan(profile_url):
    print(f"[•] Running High-risk scan on {profile_url}")
    print("\n")
    
    try:
        handle_cve_2019_6340(profile_url)
    except KeyboardInterrupt:
        print("[!] Scan interrupted. Skipping to the next CVE scan...")
        return  # Move to the next CVE or exit safely
    except Exception as e:
        print(f"[!] Error during Drupal High scan: {e}")


def perform_joomla_scan(profile_url):
    print(f"[•] Running High-risk scan on {profile_url}")
    print("\n")
    
    try:
        handle_cve_2020_10239(profile_url)
        handle_cve_2020_10238(profile_url)
        handle_cve_2018_8045(profile_url)
    except KeyboardInterrupt:
        print("[!] Scan interrupted. Skipping to the next CVE scan...")
        return  # Move to the next CVE or exit safely
    except Exception as e:
        print(f"[!] Error during Joomla High scan: {e}")


def perform_generic_scan(profile_url):
    print(f"[•] No CVE Available For Scan. Wait for a new update of Waymap.")
    pass

