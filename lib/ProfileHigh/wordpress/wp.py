# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.
# wordpress.py profile high

from colorama import Fore, Style, init
from lib.ProfileHigh.wordpress.sqlinjection.CVE_2022_21661 import scan_url
from lib.ProfileHigh.wordpress.Missing_Authorization.CVE_2022_1903 import exploit_armember
from lib.ProfileHigh.wordpress.Missing_Authorization.CVE_2022_0236 import scan_cve_2022_0236
from lib.ProfileHigh.wordpress.others.CVE_2022_1119 import scan_cve_2022_1119
from lib.ProfileHigh.wordpress.sqlinjection.CVE_2021_43408 import scan_cve_2021_43408
from lib.ProfileHigh.wordpress.auth.CVE_2021_25094 import scan_cve_2021_25094
from lib.ProfileHigh.wordpress.others.CVE_2020_35749 import scan_cve_2020_35749

init(autoreset=True)

def handle_cve_2022_21661(target):

    print(f"{Fore.CYAN}[+] Starting scan for {Fore.YELLOW}CVE-2022-21661 {Fore.CYAN}on {Fore.GREEN}{target}{Style.RESET_ALL}...")

    scan_url(target) 

    print(f"{Fore.CYAN}[-] Completed scan for {Fore.YELLOW}CVE-2022-21661 {Fore.CYAN}on {Fore.GREEN}{target}{Style.RESET_ALL}.")

def handle_cve_2022_1903(target):
    
    print(f"{Fore.CYAN}[+] Starting scan for {Fore.YELLOW}CVE-2022-1903 {Fore.CYAN}on {Fore.GREEN}{target}{Style.RESET_ALL}...")

    exploit_armember(target)

    print(f"{Fore.CYAN}[-] Completed scan for {Fore.YELLOW}CVE-2022-1903 {Fore.CYAN}on {Fore.GREEN}{target}{Style.RESET_ALL}.")

def handle_cve_2022_1119(target):

    print(f"{Fore.CYAN}[+] Starting scan for {Fore.YELLOW}CVE-2022-1119 {Fore.CYAN}on {Fore.GREEN}{target}{Style.RESET_ALL}...")

    scan_cve_2022_1119(target)

    print(f"{Fore.CYAN}[-] Completed scan for {Fore.YELLOW}CVE-2022-1119 {Fore.CYAN}on {Fore.GREEN}{target}{Style.RESET_ALL}.")

def handle_cve_2022_0236(target):

    print(f"{Fore.CYAN}[+] Starting scan for {Fore.YELLOW}CVE-2022-0236 {Fore.CYAN}on {Fore.GREEN}{target}{Style.RESET_ALL}...")

    scan_cve_2022_0236(target)

    print(f"{Fore.CYAN}[-] Completed scan for {Fore.YELLOW}CVE-2022-0236 {Fore.CYAN}on {Fore.GREEN}{target}{Style.RESET_ALL}.")

def handle_cve_2021_43408(target):

    print(f"{Fore.CYAN}[+] Starting scan for {Fore.YELLOW}CVE-2021-43408 {Fore.CYAN}on {Fore.GREEN}{target}{Style.RESET_ALL}...")

    scan_cve_2021_43408(target)

    print(f"{Fore.CYAN}[-] Completed scan for {Fore.YELLOW}CVE-2021-43408 {Fore.CYAN}on {Fore.GREEN}{target}{Style.RESET_ALL}.")

def handle_cve_2021_25049(target):

    print(f"{Fore.CYAN}[+] Starting scan for {Fore.YELLOW}CVE-2021-25094 {Fore.CYAN}on {Fore.GREEN}{target}{Style.RESET_ALL}...")

    scan_cve_2021_25094(target)

    print(f"{Fore.CYAN}[+] Completed scan for {Fore.YELLOW}CVE-2021-25094 {Fore.CYAN}on {Fore.GREEN}{target}{Style.RESET_ALL}.")

def handle_cve_2020_35749(target):

    print(f"{Fore.CYAN}[+] Starting scan for {Fore.YELLOW}CVE-2020_35749 {Fore.CYAN}on {Fore.GREEN}{target}{Style.RESET_ALL}...")

    scan_cve_2020_35749(target)

    print(f"{Fore.CYAN}[-] Completed scan for {Fore.YELLOW}CVE-2020_35749 {Fore.CYAN}on {Fore.GREEN}{target}{Style.RESET_ALL}.")
