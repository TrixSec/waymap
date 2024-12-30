# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.

import os
import requests
import re
import json
from urllib.parse import urlparse
from datetime import datetime
from packaging.version import Version, InvalidVersion
from colorama import Fore, Style, init
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor
from lib.waymapcrawlers.jscrawler import start_crawl
from lib.core.settings import JS_VERSION_PATTERN
from lib.core.settings import MAX_THREADS
from lib.core.settings import TIMEOUT
from lib.parse.random_headers import generate_random_headers

init(autoreset=True)

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

def load_vulnerability_database(vuln_file):
    try:
        with open(vuln_file, "r") as file:
            return json.load(file)
    except Exception as e:
        print(f"{Fore.RED}Error loading vulnerability database: {e}{Style.RESET_ALL}")
        return {}

def is_version_vulnerable(version, vuln_ranges):
    try:
        parsed_version = Version(version)
    except InvalidVersion:
        return False

    for range_item in vuln_ranges:
        try:
            at_or_above = range_item.get("atOrAbove")
            below = range_item.get("below")

            if at_or_above and below:
                if parsed_version >= Version(at_or_above) and parsed_version < Version(below):
                    return True
            elif at_or_above:
                if parsed_version >= Version(at_or_above):
                    return True
            elif below:
                if parsed_version < Version(below):
                    return True
        except InvalidVersion:
            continue
    return False

def check_js_version(js_url, vuln_db):
    """Check the JS file for vulnerable versions."""
    try:
        headers = generate_random_headers()
        response = requests.get(js_url, timeout=TIMEOUT, verify=False, headers=headers)
        if response.status_code != 200:
            return None

        content = response.text
        matches = re.findall(JS_VERSION_PATTERN, content)

        vulnerabilities = []
        for name, version in matches:
            lib_name = name.strip().rstrip('-:').strip()
            if lib_name in vuln_db:
                for vuln in vuln_db[lib_name]["vulnerabilities"]:
                    if is_version_vulnerable(version, vuln.get("ranges", [])):
                        vulnerabilities.append({
                            "library": lib_name,
                            "version": version,
                            "summary": vuln.get("summary"),
                            "cve": vuln.get("cve"),
                            "cwe": vuln.get("cwe")
                        })

        if vulnerabilities:
            print(f"\n{Fore.RED}[!] Vulnerabilities found in: {js_url}{Style.RESET_ALL}")
            for vuln in vulnerabilities:
                print(f"{Fore.YELLOW}  Library: {vuln['library']}")
                print(f"  Version: {vuln['version']}")
                print(f"  CVE: {vuln.get('cve', 'N/A')}")
                print(f"  CWE: {vuln.get('cwe', 'N/A')}")
                print(f"  Summary: {vuln.get('summary', 'No summary available.')}{Style.RESET_ALL}")
            return {"url": js_url, "vulnerabilities": vulnerabilities}
        return None
    except Exception as e:
        print(f"{Fore.RED}Error checking JS URL: {js_url} - {e}{Style.RESET_ALL}")
        return None

def process_js_url(js_url, vuln_db, results):
    result = check_js_version(js_url, vuln_db)
    if result:
        results.append(result)

def get_session_dir(base_url):
    parsed_url = urlparse(base_url)
    domain = parsed_url.netloc.replace(":", "_")
    return os.path.join("sessions", domain)

def save_results(results, output_file):
    with open(output_file, "w") as file:
        json.dump({"scan_date": datetime.now().isoformat(), "results": results}, file, indent=4)
    print(f"\n{Fore.GREEN}Scan results saved to {output_file}.{Style.RESET_ALL}")

def jsscan(input_url):
    print(f"{Fore.YELLOW}This Is The Beta Version Of JS Scanner If You Find Any Bug or Error Please Report It.{Style.RESET_ALL}")
    vuln_file = os.path.join("data", "jsvulnpattern.json")
    vuln_db = load_vulnerability_database(vuln_file)

    if not vuln_db:
        print(f"{Fore.RED}Vulnerability database not loaded. Exiting.{Style.RESET_ALL}")
        return 

    if not input_url:
        print(f"{Fore.RED}No URL provided. Exiting.{Style.RESET_ALL}")
        return 

    session_dir = get_session_dir(input_url)
    os.makedirs(session_dir, exist_ok=True)
    crawl_output_file = os.path.join(session_dir, "crawl3.txt")

    print(f"{Fore.YELLOW}Starting Crawler...{Style.RESET_ALL}")
    start_crawl(input_url)

    if not os.path.isfile(crawl_output_file):
        print(f"{Fore.RED}Crawling output file not found: {crawl_output_file}{Style.RESET_ALL}")
        return 

    with open(crawl_output_file, "r") as file:
        crawled_urls = file.read().splitlines()

    print(f"{Fore.GREEN}Processing {len(crawled_urls)} crawled URLs...{Style.RESET_ALL}")
    results = []
    results_file = os.path.join(session_dir, "js_deepscan_results.json")

    while True:  
        try:
            with tqdm(total=len(crawled_urls), desc="Scanning", unit="URL") as pbar:
                with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
                    futures = [executor.submit(process_js_url, js_url, vuln_db, results) for js_url in crawled_urls]
                    for future in futures:
                        future.result()
                        pbar.update(1)

            if results:
                print(f"\n{Fore.GREEN}Vulnerabilities detected! Summary of findings:{Style.RESET_ALL}")
                for result in results:
                    print(f"\n{Fore.MAGENTA}URL: {result['url']}{Style.RESET_ALL}")
                    for vuln in result["vulnerabilities"]:
                        print(f"{Fore.YELLOW}  Library: {vuln['library']}")
                        print(f"  Version: {vuln['version']}")
                        print(f"  CVE: {vuln.get('cve', 'N/A')}")
                        print(f"  CWE: {vuln.get('cwe', 'N/A')}")
                        print(f"  Summary: {vuln.get('summary', 'No summary available.')}{Style.RESET_ALL}")
                save_results(results, results_file)
            else:
                print(f"{Fore.CYAN}No vulnerable JS files found.{Style.RESET_ALL}")
            break 

        except KeyboardInterrupt:
            print(f"\n{Fore.RED}Scan interrupted by user. Saving partial results...{Style.RESET_ALL}")
            save_results(results, results_file)
            break  