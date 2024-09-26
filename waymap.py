import os
import argparse
import requests
import logging
from termcolor import colored
from lib.crawler import run_crawler
from lib.sqli import perform_sqli_scan
from lib.cmdi import perform_cmdi_scan
from extras.error_handler import check_internet_connection, check_required_files, check_required_directories, handle_error
from urllib.parse import urlparse
session_dir = 'session'

# Configure the logger
log_file_path = os.path.join(session_dir, 'logs.txt') 
logging.basicConfig(
    filename=log_file_path,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def log_scan_start(target, scan_type):
    logging.info(f'Starting {scan_type} scan on {target}')

def log_scan_end(target, scan_type):
    logging.info(f'Finished {scan_type} scan on {target}')

def log_error(message):
    logging.error(message)

# Update your crawl_and_scan function
def crawl_and_scan(target, crawl_depth, scan_type):
    log_scan_start(target, scan_type)  # Log the start of the scan
    try:
        response = requests.head(target, timeout=10)
        response.raise_for_status()
    except requests.RequestException as e:
        log_error(f"Cannot connect to the URL: {target} - {e}")
        print(colored(f"[×] Cannot connect to the URL: {target}", 'red'))
        return

    target = handle_redirection(target)

    if not target or not is_valid_url(target):
        print(colored(f"[×] Skipping {target} due to connection issues.", 'yellow'))
        return

    domain = target.split("//")[-1].split("/")[0]

    crawled_urls = load_crawled_urls(domain)

    if not crawled_urls:
        print(colored(f"[•] Starting crawling on: {target} with depth {crawl_depth}", 'yellow'))
        crawled_urls = run_crawler(target, crawl_depth)

        crawled_urls = [url for url in crawled_urls if is_valid_url(url) and has_query_parameters(url) and is_within_domain(url, domain)]
        save_to_file(domain, crawled_urls)

    sql_payloads = load_payloads(os.path.join(data_dir, 'sqlipayload.txt'))
    cmdi_payloads = load_payloads(os.path.join(data_dir, 'cmdipayload.txt'))
    user_agents = load_user_agents(os.path.join(data_dir, 'ua.txt'))

    try:
        if scan_type == 'sql':
            print(colored(f"[•] Performing SQL Injection scan on {target}", 'yellow'))
            perform_sqli_scan(crawled_urls, sql_payloads, user_agents)
            log_scan_end(target, 'SQL Injection')  # Log the end of the scan

        elif scan_type == 'cmdi':
            print(colored(f"[•] Performing Command Injection scan on {target}", 'yellow'))
            perform_cmdi_scan(crawled_urls, cmdi_payloads, user_agents)
            log_scan_end(target, 'Command Injection')  # Log the end of the scan

    except KeyboardInterrupt:
        print(colored("\n[×] Scan interrupted by the user. Exiting...", 'red'))
        log_error("Scan interrupted by the user.")
        exit()


data_dir = os.path.join(os.getcwd(), 'data')
session_dir = os.path.join(os.getcwd(), 'session')

WAYMAP_VERSION = "1.0.8"
AUTHOR = "Trix Cyrus & Yash"
COPYRIGHT = "Copyright © 2024 Trixsec Org"

def check_for_updates():
    try:
        response = requests.get("https://raw.githubusercontent.com/TrixSec/waymap/main/VERSION")
        response.raise_for_status()
        latest_version = response.text.strip()

        if WAYMAP_VERSION != latest_version:
            print(colored(f"[•] New version available: {latest_version}. Updating...", 'yellow'))
            os.system('git reset --hard HEAD')
            os.system('git pull')
            with open('VERSION', 'w') as version_file:
                version_file.write(latest_version)
            print(colored("[•] Update completed. Please rerun Waymap.", 'green'))
            exit()

        print(colored(f"[•] You are using the latest version: {latest_version}.", 'green'))
    except requests.RequestException as e:
        print(colored(f"[×] Error fetching the latest version: {e}. Please check your internet connection.", 'red'))

def print_banner():
    banner = r"""
░██╗░░░░░░░██╗░█████╗░██╗░░░██╗███╗░░░███╗░█████╗░██████╗░
░██║░░██╗░░██║██╔══██╗╚██╗░██╔╝████╗░████║██╔══██╗██╔══██╗
░╚██╗████╗██╔╝███████║░╚████╔╝░██╔████╔██║███████║██████╔╝
░░████╔═████║░██╔══██║░░╚██╔╝░░██║╚██╔╝██║██╔══██║██╔═══╝░
░░╚██╔╝░╚██╔╝░██║░░██║░░░██║░░░██║░╚═╝░██║██║░░██║██║░░░░░
░░░╚═╝░░░╚═╝░░╚═╝░░╚═╝░░░╚═╝░░░╚═╝░░░░░╚═╝╚═╝░░╚═╝╚═╝░░░░░  Fastest And Optimised Web Vulnerability Scanner  v1.0.8
    """
    print(colored(banner, 'cyan'))
    print(colored(f"Waymap Version: {WAYMAP_VERSION}", 'yellow'))
    print(colored(f"Made by {AUTHOR}", 'yellow'))
    print(colored(COPYRIGHT, 'yellow'))
    print("")

def load_payloads(file_path):
    try:
        with open(file_path, 'r') as f:
            return [line.strip() for line in f.readlines()]
    except FileNotFoundError:
        handle_error(f"Payload file {file_path} not found.")
        return []

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
    try:
        with open(file_path, 'r') as f:
            return [line.strip() for line in f.readlines()]
    except FileNotFoundError:
        handle_error(f"User-agent file {file_path} not found.")
        return []

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
    except requests.RequestException:
        print(colored(f"[×] Cannot connect to the URL: {target_url}", 'red'))
        return target_url

def is_valid_url(url):
    parsed = urlparse(url)
    return bool(parsed.netloc) and bool(parsed.scheme)

def has_query_parameters(url):
    return any(symbol in url for symbol in ['?', '&', '='])

def is_within_domain(url, base_domain):
    return urlparse(url).netloc == base_domain

def crawl_and_scan(target, crawl_depth, scan_type):
    try:
        response = requests.head(target, timeout=10)
        response.raise_for_status()
    except requests.RequestException:
        print(colored(f"[×] Cannot connect to the URL: {target}", 'red'))
        return

    target = handle_redirection(target)

    if not target or not is_valid_url(target):
        print(colored(f"[×] Skipping {target} due to connection issues.", 'yellow'))
        return

    domain = target.split("//")[-1].split("/")[0]

    crawled_urls = load_crawled_urls(domain)

    if not crawled_urls:
        print(colored(f"[•] Starting crawling on: {target} with depth {crawl_depth}", 'yellow'))
        crawled_urls = run_crawler(target, crawl_depth)

        crawled_urls = [url for url in crawled_urls if is_valid_url(url) and has_query_parameters(url) and is_within_domain(url, domain)]
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

def load_targets_from_file(file_path):
    if os.path.exists(file_path):
        with open(file_path, 'r') as f:
            return [line.strip() for line in f.readlines() if line.strip()]
    else:
        print(colored(f"[×] Target file {file_path} does not exist.", 'red'))
        return []

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
    parser.add_argument('--target', type=str, help="Target URL (for single target)")
    parser.add_argument('--multi-target', type=str, help="File containing multiple target URLs (one per line)")
    args = parser.parse_args()

    target = args.target
    multi_target_file = args.multi_target

    if multi_target_file:
        targets = load_targets_from_file(multi_target_file)
        if not targets:
            return
    else:
        if target is None:
            print(colored("[×] Error: Please specify a target URL or provide a file with URLs.", 'red'))
            return
        targets = [target]

    for target in targets:
        if not target:
            continue

        crawl_and_scan(target, args.crawl, args.scan)

    for target in targets:
        domain = target.split("//")[-1].split("/")[0]
        crawl_file = os.path.join(session_dir, domain, 'crawl.txt')
        if os.path.exists(crawl_file):
            os.remove(crawl_file)
            print(colored(f"[•] Removed crawl file for {domain}.", 'green'))

if __name__ == "__main__":
    main()
