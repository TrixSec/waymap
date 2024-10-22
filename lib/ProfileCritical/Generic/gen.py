# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.
# gen.py profile critical

from colorama import Fore, Style, init
from lib.ProfileCritical.Generic.sqlinjection.CVE_2024_24774 import scan_cve_2023_24774
from lib.ProfileCritical.Generic.sqlinjection.CVE_2024_24775 import scan_cve_2023_24775
init(autoreset=True)

def handle_cve_2023_24774(target):

    print(f"{Fore.CYAN}[+] Starting scan for {Fore.YELLOW}CVE-2023_24774 {Fore.CYAN}on {Fore.GREEN}{target}{Style.RESET_ALL}...")

    scan_cve_2023_24774(target)

    print(f"{Fore.CYAN}[-] Completed scan for {Fore.YELLOW}CVE-2023_24774 {Fore.CYAN}on {Fore.GREEN}{target}{Style.RESET_ALL}.")

def handle_cve_2023_24775(target):

    print(f"{Fore.CYAN}[+] Starting scan for {Fore.YELLOW}CVE-2023_24775 {Fore.CYAN}on {Fore.GREEN}{target}{Style.RESET_ALL}...")

    scan_cve_2023_24775(target)

    print(f"{Fore.CYAN}[-] Completed scan for {Fore.YELLOW}CVE-2023_24775 {Fore.CYAN}on {Fore.GREEN}{target}{Style.RESET_ALL}.")
