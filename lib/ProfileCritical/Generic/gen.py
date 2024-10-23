# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.
# gen.py profile critical

from colorama import Fore, Style, init
from lib.ProfileCritical.Generic.sqlinjection.CVE_2023_24774 import scan_cve_2023_24774
from lib.ProfileCritical.Generic.sqlinjection.CVE_2023_24775 import scan_cve_2023_24775


init(autoreset=True)


def handle_cve_2023_24774(profile_url):
    try:
        print("\n")
        print(f"{Fore.CYAN}[+] Starting scan for {Fore.YELLOW}CVE-2023_24774 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}...")
        scan_cve_2023_24774(profile_url)
        print(f"{Fore.CYAN}[-] Completed scan for {Fore.YELLOW}CVE-2023_24774 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}.")
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Scan for {Fore.YELLOW}CVE-2023_24774 {Fore.RED}interrupted. Moving to next CVE...{Style.RESET_ALL}")
        return
def handle_cve_2023_24775(profile_url):
    try:
        print("\n")
        print(f"{Fore.CYAN}[+] Starting scan for {Fore.YELLOW}CVE-2023_24775 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}...")
        scan_cve_2023_24775(profile_url)
        print(f"{Fore.CYAN}[-] Completed scan for {Fore.YELLOW}CVE-2023_24775 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}.")
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Scan for {Fore.YELLOW}CVE-2023_24775 {Fore.RED}interrupted. Moving to next CVE...{Style.RESET_ALL}")
        return