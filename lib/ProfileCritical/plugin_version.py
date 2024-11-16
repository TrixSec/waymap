# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.

import requests
from urllib.parse import urljoin
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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
    Returns the detected version or None if not found.
    """
    try:
        urls_to_check = get_plugin_version_urls(plugin_name)
        failed_urls = [] 
        
        for url_path in urls_to_check:
            full_url = urljoin(target_url, url_path)
            response = requests.get(full_url, timeout=10, verify=False)
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
            else:
                failed_urls.append(full_url)
        
        if len(failed_urls) == len(urls_to_check):
            print(f"Plugin '{plugin_name}' not found at {target_url}. All URLs failed.")
        
        return None  
    except requests.exceptions.RequestException as e:
        return None

