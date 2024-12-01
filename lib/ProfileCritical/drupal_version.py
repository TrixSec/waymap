# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.

import requests
import urllib3
from colorama import Fore, Style 
from lib.parse.random_headers import generate_random_headers
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

headers = generate_random_headers()


def fetch_drupal_version(target_url):
    """
    Attempts to determine the Drupal version of the target site by checking HTML meta tags and HTTP headers.
    Parameters:
        - target_url: The base URL of the target Drupal site.
    Returns:
        - Drupal version number as a string (e.g., '10') or None if not found.
    """
    try:
        response = requests.get(target_url, headers=headers, timeout=10, verify=False)
        if response.status_code == 200:
            for line in response.text.splitlines():
                if '<meta name="Generator"' in line and 'Drupal' in line:
                    version = line.split('content="Drupal ')[1].split()[0]
                    return version

        response = requests.head(target_url, headers=headers, timeout=10, verify=False)
        if response.status_code == 200:
            x_generator = response.headers.get("x-generator")
            if x_generator and "Drupal" in x_generator:
                version = x_generator.split("Drupal ")[1].split()[0]
                return version

        return None  

    except requests.exceptions.RequestException as e:
        print(f"[!] Error while checking version: {e}")
        return None

    except KeyboardInterrupt:
        handle_user_interrupt()


def handle_user_interrupt():
    """
    Handles user interruption (Ctrl+C) with a prompt for action.
    """
    print("\n[!] Process interrupted by user. What would you like to do?")
    while True:
            user_input = input(f"{Style.BRIGHT}{Fore.CYAN}Enter 'n' for next CVE, 'e' to exit, or press Enter to resume: {Style.RESET_ALL}")
            if user_input.lower() == 'n':
                print(f"{Style.BRIGHT}{Fore.GREEN}Continuing with next CVE...{Style.RESET_ALL}")
                break 
            elif user_input.lower() == 'e':
                print(f"{Style.BRIGHT}{Fore.RED}Exiting...{Style.RESET_ALL}")
                exit(0) 
            elif user_input == '':
                print(f"{Style.BRIGHT}{Fore.GREEN}Resuming scan...{Style.RESET_ALL}")
                break 
            else:
                print(f"{Style.BRIGHT}{Fore.YELLOW}Invalid input, please try again.{Style.RESET_ALL}")
                continue
