# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.
# jm.py profile critical

from colorama import Fore, Style, init
from lib.ProfileCritical.joomla.sqlinjection.CVE_2018_6396 import scan_cve_2018_6396
from lib.ProfileCritical.joomla.sqlinjection.CVE_2018_17254 import scan_cve_2018_17254
from lib.ProfileCritical.joomla.auth.CVE_2017_18345 import scan_cve_2017_18345
from lib.ProfileCritical.joomla.sqlinjection.CVE_2017_8917 import scan_cve_2017_8917


init(autoreset=True)


def handle_cve_2018_6396(profile_url):
    try:
        print("\n")
        print(f"{Fore.CYAN}[+] Starting scan for {Fore.YELLOW}CVE-2018_6396 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}...")
        scan_cve_2018_6396(profile_url)
        print(f"{Fore.CYAN}[-] Completed scan for {Fore.YELLOW}CVE-2018_6396 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}.")
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Scan for {Fore.YELLOW}CVE-2018_6396 {Fore.RED}interrupted. Moving to next CVE...{Style.RESET_ALL}")
        return
def handle_cve_2018_17254(profile_url):
    try:
        print("\n")
        print(f"{Fore.CYAN}[+] Starting scan for {Fore.YELLOW}CVE-2018_17254 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}...")
        scan_cve_2018_17254(profile_url)
        print(f"{Fore.CYAN}[-] Completed scan for {Fore.YELLOW}CVE-2018_17254 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}.")
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Scan for {Fore.YELLOW}CVE-2018_17254 {Fore.RED}interrupted. Moving to next CVE...{Style.RESET_ALL}")
        return
def handle_cve_2017_18345(profile_url):
    try:
        print("\n")
        print(f"{Fore.CYAN}[+] Starting scan for {Fore.YELLOW}CVE-2017_18345 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}...")
        scan_cve_2017_18345(profile_url)
        print(f"{Fore.CYAN}[-] Completed scan for {Fore.YELLOW}CVE-2017_18345 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}.")
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Scan for {Fore.YELLOW}CVE-2017_18345 {Fore.RED}interrupted. Moving to next CVE...{Style.RESET_ALL}")
        return
def handle_cve_2017_8917(profile_url):
    try:
        print("\n")
        print(f"{Fore.CYAN}[+] Starting scan for {Fore.YELLOW}CVE-2017_8917 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}...")
        scan_cve_2017_8917(profile_url)
        print(f"{Fore.CYAN}[-] Completed scan for {Fore.YELLOW}CVE-2017_8917 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}.")
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Scan for {Fore.YELLOW}CVE-2017_8917 {Fore.RED}interrupted. Moving to next CVE...{Style.RESET_ALL}")
        return