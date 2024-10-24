# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.
# wp.py profile high

from colorama import Fore, Style, init
from lib.ProfileHigh.wordpress.sqlinjection.CVE_2022_21661 import scan_cve_2022_21661
from lib.ProfileHigh.wordpress.Missing_Authorization.CVE_2022_1903 import exploit_armember
from lib.ProfileHigh.wordpress.Missing_Authorization.CVE_2022_0236 import scan_cve_2022_0236
from lib.ProfileHigh.wordpress.others.CVE_2022_1119 import scan_cve_2022_1119
from lib.ProfileHigh.wordpress.sqlinjection.CVE_2022_43408 import scan_cve_2022_43408
from lib.ProfileHigh.wordpress.auth.CVE_2021_25094 import scan_cve_2021_25094
from lib.ProfileHigh.wordpress.others.CVE_2020_35749 import scan_cve_2020_35749

init(autoreset=True)

def handle_cve_2022_21661(profile_url):
    try:
        print("\n")
        print(f"{Fore.CYAN}[+] Starting scan for {Fore.YELLOW}CVE-2022-21661 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}...")
        scan_cve_2022_21661(profile_url)
        print(f"{Fore.CYAN}[-] Completed scan for {Fore.YELLOW}CVE-2022-21661 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}.")
    except KeyboardInterrupt:
        print(f"{Fore.RED}[!] Scan interrupted for {Fore.YELLOW}CVE-2022-21661{Style.RESET_ALL}. Skipping to the next CVE...")
        return  # Move to the next CVE scan safely

def handle_cve_2022_1903(profile_url):
    try:
        print("\n")
        print(f"{Fore.CYAN}[+] Starting scan for {Fore.YELLOW}CVE-2022-1903 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}...")
        exploit_armember(profile_url)
        print(f"{Fore.CYAN}[-] Completed scan for {Fore.YELLOW}CVE-2022-1903 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}.")
    except KeyboardInterrupt:
        print(f"{Fore.RED}[!] Scan interrupted for {Fore.YELLOW}CVE-2022-1903{Style.RESET_ALL}. Skipping to the next CVE...")
        return

def handle_cve_2022_1119(profile_url):
    try:
        print("\n")
        print(f"{Fore.CYAN}[+] Starting scan for {Fore.YELLOW}CVE-2022-1119 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}...")
        scan_cve_2022_1119(profile_url)
        print(f"{Fore.CYAN}[-] Completed scan for {Fore.YELLOW}CVE-2022-1119 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}.")
    except KeyboardInterrupt:
        print(f"{Fore.RED}[!] Scan interrupted for {Fore.YELLOW}CVE-2022-1119{Style.RESET_ALL}. Skipping to the next CVE...")
        return

def handle_cve_2022_0236(profile_url):
    try:
        print("\n")
        print(f"{Fore.CYAN}[+] Starting scan for {Fore.YELLOW}CVE-2022-0236 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}...")
        scan_cve_2022_0236(profile_url)
        print(f"{Fore.CYAN}[-] Completed scan for {Fore.YELLOW}CVE-2022-0236 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}.")
    except KeyboardInterrupt:
        print(f"{Fore.RED}[!] Scan interrupted for {Fore.YELLOW}CVE-2022-0236{Style.RESET_ALL}. Skipping to the next CVE...")
        return

def handle_cve_2022_43408(profile_url):
    try:
        print("\n")
        print(f"{Fore.CYAN}[+] Starting scan for {Fore.YELLOW}CVE-2022-43408 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}...")
        scan_cve_2022_43408(profile_url)
        print(f"{Fore.CYAN}[-] Completed scan for {Fore.YELLOW}CVE-2022-43408 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}.")
    except KeyboardInterrupt:
        print(f"{Fore.RED}[!] Scan interrupted for {Fore.YELLOW}CVE-2022-43408{Style.RESET_ALL}. Skipping to the next CVE...")
        return

def handle_cve_2021_25049(profile_url):
    try:
        print("\n")
        print(f"{Fore.CYAN}[+] Starting scan for {Fore.YELLOW}CVE-2021-25094 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}...")
        scan_cve_2021_25094(profile_url)
        print(f"{Fore.CYAN}[+] Completed scan for {Fore.YELLOW}CVE-2021-25094 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}.")
    except KeyboardInterrupt:
        print(f"{Fore.RED}[!] Scan interrupted for {Fore.YELLOW}CVE-2021-25094{Style.RESET_ALL}. Skipping to the next CVE...")
        return

def handle_cve_2020_35749(profile_url):
    try:
        print("\n")
        print(f"{Fore.CYAN}[+] Starting scan for {Fore.YELLOW}CVE-2020-35749 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}...")
        scan_cve_2020_35749(profile_url)
        print(f"{Fore.CYAN}[-] Completed scan for {Fore.YELLOW}CVE-2020-35749 {Fore.CYAN}on {Fore.GREEN}{profile_url}{Style.RESET_ALL}.")
    except KeyboardInterrupt:
        print(f"{Fore.RED}[!] Scan interrupted for {Fore.YELLOW}CVE-2020-35749{Style.RESET_ALL}. Skipping to the next CVE...")
        return
