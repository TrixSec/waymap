# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.
# wordpress.py profile high

from colorama import Fore, Style, init
from lib.ProfileHigh.joomla.auth.CVE_2020_10239 import scan_cve_2020_10239
from lib.ProfileHigh.joomla.others.CVE_2020_10238 import scan_cve_2020_10238
from lib.ProfileHigh.joomla.sqlinjection.CVE_2018_8045 import scan_cve_2018_8045


init(autoreset=True)

def handle_cve_2020_10239(profile_url):

    print("\n")
    print(f"{Fore.CYAN}[+] Starting scan for {Fore.YELLOW}CVE-2020-10239 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}...")

    scan_cve_2020_10239(profile_url)

    print(f"{Fore.CYAN}[-] Completed scan for {Fore.YELLOW}CVE-2020-10239 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}.")

def handle_cve_2020_10238(profile_url):

    print("\n")
    print(f"{Fore.CYAN}[+] Starting scan for {Fore.YELLOW}CVE-2020-10238 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}...")

    scan_cve_2020_10238(profile_url)

    print(f"{Fore.CYAN}[-] Completed scan for {Fore.YELLOW}CVE-2020-10238 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}.")

def handle_cve_2018_8045(profile_url):

    print("\n")
    print(f"{Fore.CYAN}[+] Starting scan for {Fore.YELLOW}CVE-2018_8045 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}...")

    scan_cve_2018_8045(profile_url)

    print(f"{Fore.CYAN}[-] Completed scan for {Fore.YELLOW}CVE-2018_8045 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}.")
