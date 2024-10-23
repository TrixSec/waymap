# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.
# profile_critical.py

from lib.ProfileCritical.cms_detector import detect_cms
from lib.ProfileCritical.wordpress.wp import handle_wordpress_exploit
from lib.ProfileCritical.wordpress.wp import handle_cve_2023_2732
from lib.ProfileCritical.wordpress.wp import handle_cve_2022_1386
from lib.ProfileCritical.wordpress.wp import handle_cve_2022_0739
from lib.ProfileCritical.wordpress.wp import handle_cve_2022_0441
from lib.ProfileCritical.wordpress.wp import handle_cve_2022_0316
from lib.ProfileCritical.wordpress.wp import handle_cve_2021_34656
from lib.ProfileCritical.wordpress.wp import handle_cve_2021_25003
from lib.ProfileCritical.wordpress.wp import handle_cve_2021_24884
from lib.ProfileCritical.wordpress.wp import handle_cve_2021_24741
from lib.ProfileCritical.wordpress.wp import handle_cve_2021_24507
from lib.ProfileCritical.wordpress.wp import handle_cve_2021_24499
from lib.ProfileCritical.drupal.dp import handle_cve_2019_6339
from lib.ProfileCritical.drupal.dp import handle_cve_2018_7602
from lib.ProfileCritical.drupal.dp import handle_cve_2018_7600
from lib.ProfileCritical.joomla.jm import handle_cve_2018_6396
from lib.ProfileCritical.joomla.jm import handle_cve_2018_17254
from lib.ProfileCritical.joomla.jm import handle_cve_2017_18345
from lib.ProfileCritical.joomla.jm import handle_cve_2017_8917
from lib.ProfileCritical.Generic.gen import handle_cve_2023_24774
from lib.ProfileCritical.Generic.gen import handle_cve_2023_24775


def critical_risk_scan(profile_url):
    cms = detect_cms(profile_url)
    print(f"[•] Detected CMS: {cms}")
    print("\n")

    if cms == "WordPress":
        print("[•] Initiating WordPress critical-risk scan...")
        print("\n")
        perform_wordpress_critical_scan(profile_url)
    
    elif cms == "Drupal":
        print("[•] Initiating Drupal critical-risk scan...")
        print("\n")
        perform_drupal_critical_scan(profile_url)

    elif cms == "Joomla":
        print("[•] Initiating Joomla critical-risk scan...")
        print("\n")
        perform_joomla_critical_scan(profile_url)

    else:
        print("[•] Unknown CMS. Proceeding with generic critical-risk scan...")
        print("\n")
        perform_generic_critical_scan(profile_url)


def perform_wordpress_critical_scan(profile_url):
    print(f"[•] Running Wordpress critical-risk scan on {profile_url}")
    print("\n")
    try:
        handle_wordpress_exploit(profile_url)
        handle_cve_2023_2732(profile_url)
        handle_cve_2022_1386(profile_url)
        handle_cve_2022_0739(profile_url)
        handle_cve_2022_0441(profile_url)
        handle_cve_2022_0316(profile_url)
        handle_cve_2021_34656(profile_url)
        handle_cve_2021_25003(profile_url)
        handle_cve_2021_24884(profile_url)
        handle_cve_2021_24741(profile_url)
        handle_cve_2021_24507(profile_url)
        handle_cve_2021_24499(profile_url)
    except Exception as e:
        print(f"[!] Error during WordPress critical scan: {e}")

def perform_drupal_critical_scan(profile_url):
    print(f"[•] Running Drupal critical-risk scan on {profile_url}")
    print("\n")
    
    try:
        handle_cve_2019_6339(profile_url)
        handle_cve_2018_7602(profile_url)
        handle_cve_2018_7600(profile_url)

    except Exception as e:
        print(f"[!] Error during Drupal critical scan: {e}")

def perform_joomla_critical_scan(profile_url):
    print(f"[•] Running Joomla critical-risk scan on {profile_url}")
    print("\n")
    
    try:
        handle_cve_2018_6396(profile_url)
        handle_cve_2018_17254(profile_url)
        handle_cve_2017_18345(profile_url)
        handle_cve_2017_8917(profile_url)

    except Exception as e:
        print(f"[!] Error during Joomla critical scan: {e}")


def perform_generic_critical_scan(profile_url):
    print(f"[•] Running Generic critical-risk scan on {profile_url}")
    print("\n")
    try:
        handle_cve_2023_24774(profile_url)
        handle_cve_2023_24775(profile_url)
    except Exception as e:
        print(f"[!] Error during Generic critical scan: {e}")
