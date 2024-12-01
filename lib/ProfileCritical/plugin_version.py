# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.

import requests
from urllib.parse import urljoin
import urllib3
from colorama import Fore, Style  
from lib.parse.random_headers import generate_random_headers
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


headers = generate_random_headers()

def get_plugin_version_urls(plugin_name):
    """
    Returns a list of URLs where the plugin version information might be found.
    """
    urls = [
        f"/wp-content/plugins/{plugin_name}/readme.txt",
        f"/wp-content/plugins/{plugin_name}/changelog.txt",
        f"/wp-content/plugins/{plugin_name}/changelog.md"
    ]
    return urls

def detect_plugin_version(target_url, plugin_name):
    """
    Fetches version details from the plugin's relevant files like readme.txt, changelog.txt, and changelog.md.
    Returns the detected version or a message if not found.
    """
    try:
        urls_to_check = get_plugin_version_urls(plugin_name)
        all_404 = True  

        for url_path in urls_to_check:
            full_url = urljoin(target_url, url_path)
            try:
                
                response = requests.get(full_url, headers=headers, timeout=10, verify=False)
                
                if response.status_code == 200:
                    if "Version:" in response.text:
                        version_line = next(line for line in response.text.splitlines() if "Version:" in line)
                        version = version_line.split(":")[1].strip()
                        return version

                    elif "Stable tag:" in response.text:
                        version_line = next(line for line in response.text.splitlines() if "Stable tag:" in line)
                        version = version_line.split(":")[1].strip()
                        return version

                    elif "#" in response.text:
                        lines = response.text.splitlines()
                        for line in lines:
                            if line.startswith("####"):
                                version = line.split()[1]
                                return version
                    
                    all_404 = False 

            except requests.exceptions.RequestException as e:
                continue  

        if all_404:
            return f"Plugin '{plugin_name}' not found at {target_url}"

    except KeyboardInterrupt:
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

    except requests.exceptions.RequestException:
        return None