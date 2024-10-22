# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.
# drupal.py profile high

from colorama import Fore, Style, init
from lib.ProfileHigh.drupal.others.CVE_2019_6340 import scan_cve_2019_6340

init(autoreset=True)


def handle_cve_2019_6340(target):

    print(f"{Fore.CYAN}[+] Starting scan for {Fore.YELLOW}CVE-2019_6340 {Fore.CYAN}on {Fore.GREEN}{target}{Style.RESET_ALL}...")

    scan_cve_2019_6340(target)

    print(f"{Fore.CYAN}[-] Completed scan for {Fore.YELLOW}CVE-2019_6340 {Fore.CYAN}on {Fore.GREEN}{target}{Style.RESET_ALL}.")
