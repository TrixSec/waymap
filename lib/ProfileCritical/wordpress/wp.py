# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.
# wordpress.py profile critical

from colorama import Fore, Style
from Improper_Authentication.CVE_2023_28121 import verify_woocommerce_version, create_waymap_admin
from others.CVE_2023_2732 import version_check, fetch_usernames_rest_api, select_user, send_exploit
from other.CVE_2022_1386 import run_exploit
from sqlinjection.CVE_2022_0739 import scan_cve_2022_0739
from Improper_Authentication.CVE_2022_0441 import scan_cve_2022_0441
from others.CVE_2022_0316 import scan_cve_2022_0316
from others.CVE_2021_34646 import scan_cve_2021_34646
from injections.CVE_2021_25001 import scan_cve_2021_25003
from injections.CVE_2021_24884 import scan_cve_2021_24884
from sqlinjection.CVE_2021_24741 import scan_cve_2021_24741
from sqlinjection.CVE_2021_24507 import scan_cve_2021_24507
from injections.CVE_2021_24499 import scan_cve_2021_24499

def handle_wordpress_exploit(target_url):
    try:
        print(Fore.YELLOW + f"[•] Initiating test for CVE-2023-28121 on {target_url}..." + Style.RESET_ALL)
        
        print(Fore.CYAN + "[•] Checking WooCommerce version..." + Style.RESET_ALL)
        verify_woocommerce_version(target_url)
        
        print(Fore.CYAN + "[•] Attempting to create Waymap admin account..." + Style.RESET_ALL)
        create_waymap_admin(target_url)
        
        print(Fore.GREEN + "[•] CVE-2023-28121 exploit completed successfully." + Style.RESET_ALL)

    except Exception as e:
        print(Fore.RED + f"[•] An error occurred while handling CVE-2023-28121: {e}" + Style.RESET_ALL)


def handle_cve_2023_2732(target_url):
    try:
        print(Fore.YELLOW + f"[•] Initiating test for CVE-2023-2732 on {target_url}..." + Style.RESET_ALL)
        
        print(Fore.CYAN + "[•] Verifying plugin version..." + Style.RESET_ALL)
        if version_check(target_url):
            print(Fore.CYAN + "[•] Fetching usernames from REST API..." + Style.RESET_ALL)
            users = fetch_usernames_rest_api(target_url)
            if users:
                selected_user = select_user(users)
                if selected_user:
                    user_id = selected_user['id']
                    username = selected_user['name']
                    print(Fore.CYAN + "[•] Sending exploit..." + Style.RESET_ALL)
                    send_exploit(user_id, username, target_url)
                    print(Fore.GREEN + "[•] CVE-2023-2732 exploit completed successfully." + Style.RESET_ALL)
                else:
                    print(Fore.RED + "[•] No valid user selected for exploitation." + Style.RESET_ALL)
            else:
                print(Fore.RED + "[•] No users found for exploitation." + Style.RESET_ALL)
        else:
            print(Fore.RED + "[•] Target is not vulnerable to CVE-2023-2732." + Style.RESET_ALL)

    except Exception as e:
        print(Fore.RED + f"[•] An error occurred while handling CVE-2023-2732: {e}" + Style.RESET_ALL)

def handle_cve_2022_1386(target):

    print(f"{Fore.CYAN}[•] Starting scan for {Fore.YELLOW}CVE-2022-1386 {Fore.CYAN}on {Fore.GREEN}{target}{Style.RESET_ALL}...")

    run_exploit(target)

    print(f"{Fore.CYAN}[•] Completed scan for {Fore.YELLOW}CVE-2022-1386 {Fore.CYAN}on {Fore.GREEN}{target}{Style.RESET_ALL}.")

def handle_cve_2022_0739(target):
    
    print(f"{Fore.CYAN}[•] Starting scan for {Fore.YELLOW}CVE-2022-0739 {Fore.CYAN}on {Fore.GREEN}{target}{Style.RESET_ALL}...")

    scan_cve_2022_0739(target)

    print(f"{Fore.CYAN}[•] Completed scan for {Fore.YELLOW}CVE-2022-0739 {Fore.CYAN}on {Fore.GREEN}{target}{Style.RESET_ALL}.")

def handle_cve_2022_0441(target):

    print(f"{Fore.CYAN}[•] Starting scan for {Fore.YELLOW}CVE-2022-0441 {Fore.CYAN}on {Fore.GREEN}{target}{Style.RESET_ALL}...")

    scan_cve_2022_0441(target)

    print(f"{Fore.CYAN}[•] Completed scan for {Fore.YELLOW}CVE-2022-0441 {Fore.CYAN}on {Fore.GREEN}{target}{Style.RESET_ALL}.")

def handle_cve_2022_0316(target):

    print(f"{Fore.CYAN}[•] Starting scan for {Fore.YELLOW}CVE-2022-0316 {Fore.CYAN}on {Fore.GREEN}{target}{Style.RESET_ALL}...")

    scan_cve_2022_0316(target)

    print(f"{Fore.CYAN}[•] Completed scan for {Fore.YELLOW}CVE-2022-0316 {Fore.CYAN}on {Fore.GREEN}{target}{Style.RESET_ALL}.")

def handle_cve_2021_34646(target):

    print(f"{Fore.CYAN}[•] Starting scan for {Fore.YELLOW}CVE-2021_34646 {Fore.CYAN}on {Fore.GREEN}{target}{Style.RESET_ALL}...")

    scan_cve_2021_34646(target)

    print(f"{Fore.CYAN}[•] Completed scan for {Fore.YELLOW}CVE-2021_34646 {Fore.CYAN}on {Fore.GREEN}{target}{Style.RESET_ALL}.")

def handle_cve_2021_25003(target):

    print(f"{Fore.CYAN}[•] Starting scan for {Fore.YELLOW}CVE-2021_25003 {Fore.CYAN}on {Fore.GREEN}{target}{Style.RESET_ALL}...")

    scan_cve_2021_25003(target)

    print(f"{Fore.CYAN}[•] Completed scan for {Fore.YELLOW}CVE-2021_25003 {Fore.CYAN}on {Fore.GREEN}{target}{Style.RESET_ALL}.")

def handle_cve_2021_24884(target):

    print(f"{Fore.CYAN}[•] Starting scan for {Fore.YELLOW}CVE-2021_24884 {Fore.CYAN}on {Fore.GREEN}{target}{Style.RESET_ALL}...")

    scan_cve_2021_24884(target)

    print(f"{Fore.CYAN}[•] Completed scan for {Fore.YELLOW}CVE-2021_24884 {Fore.CYAN}on {Fore.GREEN}{target}{Style.RESET_ALL}.")

def handle_cve_2021_24741(target):

    print(f"{Fore.CYAN}[•] Starting scan for {Fore.YELLOW}CVE-2021_24741 {Fore.CYAN}on {Fore.GREEN}{target}{Style.RESET_ALL}...")

    scan_cve_2021_24741(target)

    print(f"{Fore.CYAN}[•] Completed scan for {Fore.YELLOW}CVE-2021_24741 {Fore.CYAN}on {Fore.GREEN}{target}{Style.RESET_ALL}.")

def handle_cve_2021_24507(target):

    print(f"{Fore.CYAN}[•] Starting scan for {Fore.YELLOW}CVE-2021_24507 {Fore.CYAN}on {Fore.GREEN}{target}{Style.RESET_ALL}...")

    scan_cve_2021_24507(target)

    print(f"{Fore.CYAN}[•] Completed scan for {Fore.YELLOW}CVE-2021_24507 {Fore.CYAN}on {Fore.GREEN}{target}{Style.RESET_ALL}.")

def handle_cve_2021_24499(target):

    print(f"{Fore.CYAN}[•] Starting scan for {Fore.YELLOW}CVE-2021_24499 {Fore.CYAN}on {Fore.GREEN}{target}{Style.RESET_ALL}...")

    scan_cve_2021_24499(target)

    print(f"{Fore.CYAN}[•] Completed scan for {Fore.YELLOW}CVE-2021_24499 {Fore.CYAN}on {Fore.GREEN}{target}{Style.RESET_ALL}.")
