from lib.ProfileHigh.cms_detector import detect_cms
from lib.ProfileHigh.wordpress.wp import handle_cve_2022_21661
from lib.ProfileHigh.wordpress.wp import handle_cve_2022_1903
from lib.ProfileHigh.wordpress.wp import handle_cve_2022_1119
from lib.ProfileHigh.wordpress.wp import handle_cve_2022_0236
from lib.ProfileHigh.wordpress.wp import handle_cve_2022_43408
from lib.ProfileHigh.wordpress.wp import handle_cve_2021_25049
from lib.ProfileHigh.wordpress.wp import handle_cve_2020_35749
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


def perform_wordpress_scan(profile_url):
    print(f"[•] Running High-risk scan on {profile_url}")
    
    try:
        handle_cve_2022_21661(profile_url)
        handle_cve_2022_1903(profile_url) 
        handle_cve_2022_1119(profile_url) 
        handle_cve_2022_0236(profile_url)
        handle_cve_2022_43408(profile_url)
        handle_cve_2021_25049(profile_url)
        handle_cve_2020_35749(profile_url)
    except Exception as e:
        print(f"[!] Error during WordPress High scan: {e}")

def perform_drupal_scan(profile_url):
    print(f"[•] Running High-risk scan on {profile_url}")
    
    try:
        handle_cve_2019_6340(profile_url)

    except Exception as e:
        print(f"[!] Error during Drupal High scan: {e}")

def perform_joomla_scan(profile_url):
    print(f"[•] Running High-risk scan on {profile_url}")
    
    try:
        handle_cve_2020_10239(profile_url)
        handle_cve_2020_10238(profile_url)
        handle_cve_2018_8045(profile_url)

    except Exception as e:
        print(f"[!] Error during Joomla High scan: {e}")

def perform_generic_scan(profile_url):

    print(f"[•] No CVE Available For Scan Wait For A New Update Of Waymap")
    pass
