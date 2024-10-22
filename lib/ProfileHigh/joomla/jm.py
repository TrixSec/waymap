# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.
# wordpress.py profile high

from colorama import Fore, Style, init
from auth.CVE_2020_10239 import scan_cve_2020_10239
from others.CVE_2020_10238 import scan_cve_2020_10238
from sqlinjection.CVE_2018_8045 import scan_cve_2018_8045

init(autoreset=True)

def handle_cve_2020_10239(target):

    print(f"{Fore.CYAN}[+] Starting scan for {Fore.YELLOW}CVE-2020-10239 {Fore.CYAN}on {Fore.GREEN}{target}{Style.RESET_ALL}...")

    scan_cve_2020_10239(target)

    print(f"{Fore.CYAN}[-] Completed scan for {Fore.YELLOW}CVE-2020-10239 {Fore.CYAN}on {Fore.GREEN}{target}{Style.RESET_ALL}.")

def handle_cve_2020_10238(target):

    print(f"{Fore.CYAN}[+] Starting scan for {Fore.YELLOW}CVE-2020-10238 {Fore.CYAN}on {Fore.GREEN}{target}{Style.RESET_ALL}...")

    scan_cve_2020_10238(target)

    print(f"{Fore.CYAN}[-] Completed scan for {Fore.YELLOW}CVE-2020-10238 {Fore.CYAN}on {Fore.GREEN}{target}{Style.RESET_ALL}.")

def handle_cve_2018_8045(target):

    print(f"{Fore.CYAN}[+] Starting scan for {Fore.YELLOW}CVE-2018_8045 {Fore.CYAN}on {Fore.GREEN}{target}{Style.RESET_ALL}...")

    scan_cve_2018_8045(target)

    print(f"{Fore.CYAN}[-] Completed scan for {Fore.YELLOW}CVE-2018_8045 {Fore.CYAN}on {Fore.GREEN}{target}{Style.RESET_ALL}.")
