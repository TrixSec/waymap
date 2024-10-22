from cms_detector import detect_cms
from wordpress.wp import handle_cve_2022_21661
from wordpress.wp import handle_cve_2022_1903
from wordpress.wp import handle_cve_2022_1119
from wordpress.wp import handle_cve_2022_0236
from wordpress.wp import handle_cve_2021_43408
from wordpress.wp import handle_cve_2021_25094
from wordpress.wp import handle_cve_2020_35749
from drupal.dp import handle_cve_2019_6340
from joomla.jm import handle_cve_2020_10239
from joomla.jm import handle_cve_2020_10238
from joomla.jm import handle_cve_2018_8045

def high_risk_scan(target):
    cms = detect_cms(target)
    print(f"[•] Detected CMS: {cms}")

    if cms == "WordPress":
        print("[•] Initiating WordPress high-risk scan...")
        perform_wordpress_scan(target)
    
    elif cms == "Drupal":
        print("[•] Initiating Drupal high-risk scan...")
        perform_drupal_scan(target)

    elif cms == "Joomla":
        print("[•] Initiating Joomla high-risk scan...")
        perform_joomla_scan(target)

    else:
        print("[•] Unknown CMS. Proceeding with generic high-risk scan...")
        perform_generic_scan(target)


def perform_wordpress_scan(target):
    print(f"[•] Running High-risk scan on {target}")
    
    try:
        handle_cve_2022_21661(target)
        handle_cve_2022_1903(target) 
        handle_cve_2022_1119(target) 
        handle_cve_2022_0236(target)
        handle_cve_2021_43408(target)
        handle_cve_2021_25094(target)
        handle_cve_2020_35749(target)
    except Exception as e:
        print(f"[!] Error during WordPress High scan: {e}")

def perform_drupal_scan(target):
    print(f"[•] Running High-risk scan on {target}")
    
    try:
        handle_cve_2019_6340(target)

    except Exception as e:
        print(f"[!] Error during Drupal High scan: {e}")

def perform_joomla_scan(target):
    print(f"[•] Running High-risk scan on {target}")
    
    try:
        handle_cve_2020_10239(target)
        handle_cve_2020_10238(target)
        handle_cve_2018_8045(target)

    except Exception as e:
        print(f"[!] Error during Joomla High scan: {e}")

def perform_generic_scan(target):

    print(f"[•] No CVE Available For Scan Wait For A New Update Of Waymap")
    pass
