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
from lib.ProfileCritical.generic.gen import handle_cve_2023_24774
from lib.ProfileCritical.generic.gen import handle_cve_2023_24775


def critical_risk_scan(target):
    cms = detect_cms(target)
    print(f"[•] Detected CMS: {cms}")

    if cms == "WordPress":
        print("[•] Initiating WordPress critical-risk scan...")
        perform_wordpress_critical_scan(target)
    
    elif cms == "Drupal":
        print("[•] Initiating Drupal critical-risk scan...")
        perform_drupal_critical_scan(target)

    elif cms == "Joomla":
        print("[•] Initiating Joomla critical-risk scan...")
        perform_joomla_critical_scan(target)

    else:
        print("[•] Unknown CMS. Proceeding with generic critical-risk scan...")
        perform_generic_critical_scan(target)


def perform_wordpress_critical_scan(target):
    print(f"[•] Running Wordpress critical-risk scan on {target}")
    
    try:
        handle_wordpress_exploit(target)
        handle_cve_2023_2732(target)
        handle_cve_2022_1386(target)
        handle_cve_2022_0739(target)
        handle_cve_2022_0441(target)
        handle_cve_2022_0316(target)
        handle_cve_2021_34656(target)
        handle_cve_2021_25003(target)
        handle_cve_2021_24884(target)
        handle_cve_2021_24741(target)
        handle_cve_2021_24507(target)
        handle_cve_2021_24499(target)
    except Exception as e:
        print(f"[!] Error during WordPress critical scan: {e}")

def perform_drupal_critical_scan(target):
    print(f"[•] Running Drupal critical-risk scan on {target}")
    
    try:
        handle_cve_2019_6339(target)
        handle_cve_2018_7602(target)
        handle_cve_2018_7600(target)

    except Exception as e:
        print(f"[!] Error during Drupal critical scan: {e}")

def perform_joomla_critical_scan(target):
    print(f"[•] Running Joomla critical-risk scan on {target}")
    
    try:
        handle_cve_2018_6396(target)
        handle_cve_2018_17254(target)
        handle_cve_2017_18345(target)
        handle_cve_2017_8917(target)

    except Exception as e:
        print(f"[!] Error during Joomla critical scan: {e}")


def perform_generic_critical_scan(target):
    print(f"[•] Running Generic critical-risk scan on {target}")
    
    try:
        handle_cve_2023_24774(target)
        handle_cve_2023_24775(target)
    except Exception as e:
        print(f"[!] Error during Generic critical scan: {e}")
