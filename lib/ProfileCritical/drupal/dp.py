# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.
# dp.py profile critical

from colorama import Fore, Style, init
from lib.ProfileCritical.drupal.others.CVE_2019_6339 import scan_cve_2019_6339
from lib.ProfileCritical.drupal.rce.CVE_2018_7602 import scan_cve_2018_7602
from lib.ProfileCritical.drupal.others.CVE_2018_7600 import scan_cve_2018_7600

init(autoreset=True)


def handle_cve_2019_6339(profile_url):
    try:
        print("\n")
        print(f"{Fore.CYAN}[+] Starting scan for {Fore.YELLOW}CVE-2019_6339 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}...")
        scan_cve_2019_6339(profile_url)
        print(f"{Fore.CYAN}[-] Completed scan for {Fore.YELLOW}CVE-2019_6339 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}.")
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Scan for {Fore.YELLOW}CVE-2019_6339 {Fore.RED}interrupted. Moving to next CVE...{Style.RESET_ALL}")
        return
def handle_cve_2018_7602(profile_url):
    try:
        print("\n")
        print(f"{Fore.CYAN}[+] Starting scan for {Fore.YELLOW}CVE-2018_7602 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}...")
        scan_cve_2018_7602(profile_url)
        print(f"{Fore.CYAN}[-] Completed scan for {Fore.YELLOW}CVE-2018_7602 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}.")
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Scan for {Fore.YELLOW}CVE-2018_7602 {Fore.RED}interrupted. Moving to next CVE...{Style.RESET_ALL}")
        return
def handle_cve_2018_7600(profile_url):
    try:
        print("\n")
        print(f"{Fore.CYAN}[+] Starting scan for {Fore.YELLOW}CVE-2018_7600 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}...")
        scan_cve_2018_7600(profile_url)
        print(f"{Fore.CYAN}[-] Completed scan for {Fore.YELLOW}CVE-2018_7600 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}.")
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Scan for {Fore.YELLOW}CVE-2018_7600 {Fore.RED}interrupted. Moving to next CVE...{Style.RESET_ALL}")
        return