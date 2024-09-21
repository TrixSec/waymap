import os
import argparse
import requests
from termcolor import colored
from lib.crawler import run_crawler
from lib.sqli import perform_sqli_scan  
from lib.cmdi import perform_cmdi_scan  
from extras.error_handler import check_internet_connection, check_required_files, check_required_directories, handle_error
from urllib.parse import urlparse

data_dir = os.path.join(os.getcwd(), 'data')
session_dir = os.path.join(os.getcwd(), 'session')

WAYMAP_VERSION = "1.0.4"  
AUTHOR = "Trix Cyrus"
COPYRIGHT = "Copyright © 2024 Trixsec Org"

def check_for_updates():
    current_version = WAYMAP_VERSION  
    print(colored(f"[•] Current version: {current_version}", 'yellow'))

    latest_version_url = 'https://raw.githubusercontent.com/TrixSec/waymap/refs/heads/main/VERSION'

    try:
        response = requests.get(latest_version_url)
        response.raise_for_status()
        latest_version = response.text.strip()
        print(colored(f"[•] Latest version fetched from repository: {latest_version}", 'yellow'))

        if current_version != latest_version:
            print(colored(f"[•] New version available: {latest_version}. Updating...", 'yellow'))
            os.system('git pull')  
            with open('VERSION', 'w') as version_file:
                version_file.write(latest_version)  
        else:
            print(colored(f"[•] You are using the latest version: {current_version}.", 'green'))

    except requests.RequestException as e:
        print(colored(f"[×] Error checking for updates: {e}", 'red'))

def print_banner():
    banner = r"""
     __    __
    / / /\ \ \  __ _  _   _  _ __ ___    __ _  _ __
    \ \/  \/ / / _ || | | || '_  _ \  / _ || '_ \
     \  /\  / | (_| || |_| || | | | | || (_| || |_) |
      \/  \/   \__,_| \__, ||_| |_| |_| \__,_|| .__/
                      |___/                   |_|    Fastest And Optimised Web Vulnerability Scanner  v1.0.4
    """
    print(colored(banner, 'cyan'))
    print(colored(f"Waymap Version: {WAYMAP_VERSION}", 'yellow'))
    print(colored(f"Made by {AUTHOR}", 'yellow'))
    print(colored(COPYRIGHT, 'yellow'))
    print("")

def load_payloads(file_path):
    with open(file_path, 'r') as f:
        return [line.strip() for line in f.readlines()]

def save_to_file(domain, urls):
    domain_path = os.path.join(session_dir, domain)
    os.makedirs(domain_path, exist_ok=True)
    crawl_file = os.path.join(domain_path, 'crawl.txt')

    with open(crawl_file, 'w') as f:
        for url in urls:
            f.write(url + '\n')

def load_crawled_urls(domain):
    domain_path = os.path.join(session_dir, domain)
    crawl_file = os.path.join(domain_path, 'crawl.txt')

    if os.path.exists(crawl_file):
        with open(crawl_file, 'r') as f:
            return [url.strip() for url in f.readlines()]
    return []

def load_user_agents(file_path):
    with open(file_path, 'r') as f:
        return [line.strip() for line in f.readlines()]

def handle_redirection(target_url):
    try:
        response = requests.get(target_url, allow_redirects=True, timeout=10)
        final_url = response.url
        parsed_final_url = urlparse(final_url)
        parsed_target_url = urlparse(target_url)

        if parsed_final_url.netloc != parsed_target_url.netloc:
            print(colored(f"[•] Target URL redirected to a different domain: {final_url}", 'yellow'))
            return final_url
        return target_url
    except requests.RequestException as e:
        print(colored(f"[×] Error handling redirection for {target_url}: {e}", 'red'))
        return target_url

def main():
    print_banner()
    check_for_updates()  

    if not check_internet_connection():
        handle_error("No internet connection. Please check your network and try again.")

    required_files = ['sqlipayload.txt', 'cmdipayload.txt', 'ua.txt', 'errors.xml', 'cmdi.xml']

    missing_files = check_required_files(data_dir, session_dir, required_files)
    if missing_files:
        handle_error(f"Missing required files: {', '.join(missing_files)}")

    required_directories = [data_dir, session_dir]
    missing_dirs = check_required_directories(required_directories)
    if missing_dirs:
        handle_error(f"Missing required directories: {', '.join(missing_dirs)}")

    parser = argparse.ArgumentParser(description="Waymap - Crawler and Scanner")
    parser.add_argument('--crawl', type=int, required=True, help="Crawl depth")
    parser.add_argument('--scan', type=str, required=True, choices=['sql', 'cmdi'], help="Scan type: 'sql' or 'cmdi'")
    parser.add_argument('--target', type=str, required=True, help="Target URL")
    args = parser.parse_args()

    target = args.target
    crawl_depth = args.crawl
    scan_type = args.scan

    target = handle_redirection(target)
    domain = target.split("//")[-1].split("/")[0]

    crawled_urls = load_crawled_urls(domain)

    if crawled_urls and len(crawled_urls) > 0 and args.crawl != len(crawled_urls):
        crawled_urls = []

    if not crawled_urls:
        print(colored(f"[•] Starting crawling on: {target} with depth {crawl_depth}", 'yellow'))
        crawled_urls = run_crawler(target, crawl_depth)
        save_to_file(domain, crawled_urls)

    sql_payloads = load_payloads(os.path.join(data_dir, 'sqlipayload.txt'))
    cmdi_payloads = load_payloads(os.path.join(data_dir, 'cmdipayload.txt'))
    user_agents = load_user_agents(os.path.join(data_dir, 'ua.txt'))

    try:
        if scan_type == 'sql':
            print(colored(f"[•] Performing SQL Injection scan on {target}", 'yellow'))
            perform_sqli_scan(crawled_urls, sql_payloads, user_agents)

        elif scan_type == 'cmdi':
            print(colored(f"[•] Performing Command Injection scan on {target}", 'yellow'))
            perform_cmdi_scan(crawled_urls, cmdi_payloads, user_agents)

    except KeyboardInterrupt:
        print(colored("\n[×] Scan interrupted by the user. Exiting...", 'red'))
        print(colored("[•] Exiting Waymap.", 'yellow'))
        exit()

if __name__ == "__main__":
    main()

