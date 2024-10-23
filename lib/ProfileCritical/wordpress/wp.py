# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.
# wordpress.py profile critical

from colorama import Fore, Style
from lib.ProfileCritical.wordpress.Improper_Authentication.CVE_2023_28121 import verify_woocommerce_version, create_waymap_admin
from lib.ProfileCritical.wordpress.others.CVE_2023_2732 import scan_cve_2023_2732
from lib.ProfileCritical.wordpress.others.CVE_2022_1386 import run_exploit
from lib.ProfileCritical.wordpress.sqlinjection.CVE_2022_0739 import scan_cve_2022_0739
from lib.ProfileCritical.wordpress.Improper_Authentication.CVE_2022_0441 import scan_cve_2022_0441
from lib.ProfileCritical.wordpress.others.CVE_2022_0316 import scan_cve_2022_0316
from lib.ProfileCritical.wordpress.others.CVE_2021_34656 import scan_cve_2021_34656
from lib.ProfileCritical.wordpress.injections.CVE_2021_25003 import scan_cve_2021_25003
from lib.ProfileCritical.wordpress.injections.CVE_2021_24884 import scan_cve_2021_24884
from lib.ProfileCritical.wordpress.sqlinjection.CVE_2021_24507 import scan_cve_2021_24507
from lib.ProfileCritical.wordpress.injections.CVE_2021_24499 import scan_cve_2021_24499


def handle_wordpress_exploit(profile_url):
    try:
        print("\n")
        print(Fore.YELLOW + f"[•] Initiating test for CVE-2023-28121 on {profile_url}..." + Style.RESET_ALL)
        
        print(Fore.CYAN + "[•] Checking WooCommerce version..." + Style.RESET_ALL)
        verify_woocommerce_version(profile_url)
        
        print(Fore.CYAN + "[•] Attempting to create Waymap admin account..." + Style.RESET_ALL)
        create_waymap_admin(profile_url)
        
        print(Fore.GREEN + "[•] CVE-2023-28121 exploit completed successfully." + Style.RESET_ALL)

    except KeyboardInterrupt:
        print(Fore.RED + "[!] Scan interrupted by user. Moving to the next CVE..." + Style.RESET_ALL)
        return
    except Exception as e:
        print(Fore.RED + f"[•] An error occurred while handling CVE-2023-28121: {e}" + Style.RESET_ALL)


def handle_cve_2023_2732(profile_url):
    try:
        print("\n")
        print(f"{Fore.CYAN}[•] Starting scan for {Fore.YELLOW}CVE-2023-2732 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}...")

        scan_cve_2023_2732(profile_url)

        print(f"{Fore.CYAN}[•] Completed scan for {Fore.YELLOW}CVE-2023-2732 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}.")
    except KeyboardInterrupt:
        print(Fore.RED + "[!] Scan interrupted by user. Moving to the next CVE..." + Style.RESET_ALL)
        return


def handle_cve_2022_1386(profile_url):
    try:
        print("\n")
        print(f"{Fore.CYAN}[•] Starting scan for {Fore.YELLOW}CVE-2022-1386 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}...")

        run_exploit(profile_url)

        print(f"{Fore.CYAN}[•] Completed scan for {Fore.YELLOW}CVE-2022-1386 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}.")
    except KeyboardInterrupt:
        print(Fore.RED + "[!] Scan interrupted by user. Moving to the next CVE..." + Style.RESET_ALL)
        return


def handle_cve_2022_0739(profile_url):
    try:
        print("\n")
        print(f"{Fore.CYAN}[•] Starting scan for {Fore.YELLOW}CVE-2022-0739 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}...")

        scan_cve_2022_0739(profile_url)

        print(f"{Fore.CYAN}[•] Completed scan for {Fore.YELLOW}CVE-2022-0739 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}.")
    except KeyboardInterrupt:
        print(Fore.RED + "[!] Scan interrupted by user. Moving to the next CVE..." + Style.RESET_ALL)
        return


def handle_cve_2022_0441(profile_url):
    try:
        print("\n")
        print(f"{Fore.CYAN}[•] Starting scan for {Fore.YELLOW}CVE-2022-0441 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}...")

        scan_cve_2022_0441(profile_url)

        print(f"{Fore.CYAN}[•] Completed scan for {Fore.YELLOW}CVE-2022-0441 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}.")
    except KeyboardInterrupt:
        print(Fore.RED + "[!] Scan interrupted by user. Moving to the next CVE..." + Style.RESET_ALL)
        return


def handle_cve_2022_0316(profile_url):
    try:
        print("\n")
        print(f"{Fore.CYAN}[•] Starting scan for {Fore.YELLOW}CVE-2022-0316 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}...")

        scan_cve_2022_0316(profile_url)

        print(f"{Fore.CYAN}[•] Completed scan for {Fore.YELLOW}CVE-2022-0316 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}.")
    except KeyboardInterrupt:
        print(Fore.RED + "[!] Scan interrupted by user. Moving to the next CVE..." + Style.RESET_ALL)
        return


def handle_cve_2021_34656(profile_url):
    try:
        print("\n")
        print(f"{Fore.CYAN}[•] Starting scan for {Fore.YELLOW}CVE-2021_34656 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}...")

        scan_cve_2021_34656(profile_url)

        print(f"{Fore.CYAN}[•] Completed scan for {Fore.YELLOW}CVE-2021_34656 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}.")
    except KeyboardInterrupt:
        print(Fore.RED + "[!] Scan interrupted by user. Moving to the next CVE..." + Style.RESET_ALL)
        return


def handle_cve_2021_25003(profile_url):
    try:
        print("\n")
        print(f"{Fore.CYAN}[•] Starting scan for {Fore.YELLOW}CVE-2021_25003 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}...")

        scan_cve_2021_25003(profile_url)

        print(f"{Fore.CYAN}[•] Completed scan for {Fore.YELLOW}CVE-2021_25003 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}.")
    except KeyboardInterrupt:
        print(Fore.RED + "[!] Scan interrupted by user. Moving to the next CVE..." + Style.RESET_ALL)
        return


def handle_cve_2021_24884(profile_url):
    try:
        print("\n")
        print(f"{Fore.CYAN}[•] Starting scan for {Fore.YELLOW}CVE-2021_24884 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}...")

        scan_cve_2021_24884(profile_url)

        print(f"{Fore.CYAN}[•] Completed scan for {Fore.YELLOW}CVE-2021_24884 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}.")
    except KeyboardInterrupt:
        print(Fore.RED + "[!] Scan interrupted by user. Moving to the next CVE..." + Style.RESET_ALL)
        return


def handle_cve_2021_24507(profile_url):
    try:
        print("\n")
        print(f"{Fore.CYAN}[•] Starting scan for {Fore.YELLOW}CVE-2021_24507 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}...")

        scan_cve_2021_24507(profile_url)

        print(f"{Fore.CYAN}[•] Completed scan for {Fore.YELLOW}CVE-2021_24507 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}.")
    except KeyboardInterrupt:
        print(Fore.RED + "[!] Scan interrupted by user. Moving to the next CVE..." + Style.RESET_ALL)
        return


def handle_cve_2021_24499(profile_url):
    try:
        print("\n")
        print(f"{Fore.CYAN}[•] Starting scan for {Fore.YELLOW}CVE-2021_24499 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}...")

        scan_cve_2021_24499(profile_url)

        print(f"{Fore.CYAN}[•] Completed scan for {Fore.YELLOW}CVE-2021_24499 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}.")
    except KeyboardInterrupt:
        print(Fore.RED + "[!] Scan interrupted by user. Moving to the next CVE..." + Style.RESET_ALL)
        return
