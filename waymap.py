# Copyright (c) 2024 waymap developers 
# See the file 'LICENSE' for copying permission.

import os
import argparse
import requests
import logging
from termcolor import colored
from lib.waymapcrawlers.crawler import run_crawler
from lib.injection.sqli import perform_sqli_scan
from lib.injection.cmdi import perform_cmdi_scan
from lib.injection.ssti import perform_ssti_scan
from lib.injection.xss import perform_xss_scan
from lib.injection.lfi import perform_lfi_scan
from lib.injection.openredirect import perform_redirect_scan
from lib.injection.crlf import perform_crlf_scan
from lib.injection.cors import perform_cors_scan
from extras.error_handler import check_internet_connection, check_required_files, check_required_directories, handle_error
from urllib.parse import urlparse
session_dir = 'session'

def setup_logger(domain):
    
    domain_dir = os.path.join(session_dir, domain)
    os.makedirs(domain_dir, exist_ok=True)  
    log_file_path = os.path.join(domain_dir, 'logs.txt')
    
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

data_dir = os.path.join(os.getcwd(), 'data')
session_dir = os.path.join(os.getcwd(), 'session')

WAYMAP_VERSION = "2.5.2"
AUTHOR = "Trix Cyrus"
Devs = "@TrixSec & @0day-Yash & @JeninSutradhar"
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
░░░╚═╝░░░╚═╝░░╚═╝░░╚═╝░░░╚═╝░░░╚═╝░░░░░╚═╝╚═╝░░╚═╝╚═╝░░░░░  Fastest And Optimised Web Vulnerability Scanner  v2.5.2
    """
    print(colored(banner, 'cyan'))
    print(colored(f"Waymap Version: {WAYMAP_VERSION}", 'yellow'))
    print(colored(f"Made by {AUTHOR}", 'yellow'))
    print(colored(f"#Devs {Devs}", 'yellow'))
    print(colored(COPYRIGHT, 'yellow'))
    print("")

def load_payloads(file_path):
    try:
        with open(file_path, 'r') as f:
            return [line.strip() for line in f.readlines()]
    except FileNotFoundError:
        log_error(f"Payload file {file_path} not found.")  
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
        log_error(f"User-agent file {file_path} not found.")  
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
    except requests.RequestException as e:
        log_error(f"Error connecting to {target_url}: {e}") 
        print(colored(f"[×]Waymap Cannot connect to the URL: {target_url}", 'red'))
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
        response = requests.get(target, timeout=10)
        response.raise_for_status()
    except requests.RequestException as e:
        log_error(f"Cannot connect to {target}: {e}")
        print(colored(f"[×]Crawler Cannot connect to the URL: {target}", 'red'))
        return

    target = handle_redirection(target)

    if not target or not is_valid_url(target):
        log_error(f"Skipping {target} due to connection issues.")
        print(colored(f"[×] Skipping {target} due to connection issues.", 'yellow'))
        return

    domain = target.split("//")[-1].split("/")[0]
    setup_logger(domain)

    log_scan_start(target, scan_type)

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
            print("\n")  
            print(colored(f"[•] Performing SQL Injection scan on {target}", 'yellow'))
            perform_sqli_scan(crawled_urls, sql_payloads, user_agents)

        elif scan_type == 'cmdi':
            print("\n")  
            print(colored(f"[•] Performing Command Injection scan on {target}", 'yellow'))
            perform_cmdi_scan(crawled_urls, cmdi_payloads, user_agents)

        elif scan_type == 'ssti':
            print("\n")  
            print(colored(f"[•] Performing Server Side Template Injection scan on {target}", 'yellow'))
            perform_ssti_scan(crawled_urls, user_agents, verbose=True)

        elif scan_type == 'xss':
            print("\n")  
            print(colored(f"[•] Performing Cross Site Scripting scan on {target}", 'yellow'))
            perform_xss_scan(crawled_urls, user_agents, verbose=True)

        elif scan_type == 'lfi':
            print("\n")  
            print(colored(f"[•] Performing Local File Inclusion scan on {target}", 'yellow'))
            perform_lfi_scan(crawled_urls, user_agents, verbose=True)

        elif scan_type == 'open-redirect':
            print("\n")  
            print(colored(f"[•] Performing Open Redirect scan on {target}", 'yellow'))
            perform_redirect_scan(crawled_urls, user_agents, verbose=True)

        elif scan_type == 'crlf':
            print("\n")  
            print(colored(f"[•] Performing Carriage Return and Line Feed scan on {target}", 'yellow'))
            perform_crlf_scan(crawled_urls, user_agents, verbose=True)

        elif scan_type == 'cors':
            print("\n")  
            print(colored(f"[•] Performing Cross-origin resource sharing scan on {target}", 'yellow'))
            perform_cors_scan(crawled_urls, user_agents, verbose=True)

        elif scan_type == 'all':
            print("\n[•] Performing all scans on target...\n")  
            print(colored("[•] Performing SQL Injection scan...", 'cyan'))
            perform_sqli_scan(crawled_urls, sql_payloads, user_agents)

            print("\n")  
            print(colored("[•] Performing Command Injection (CMDi) scan...", 'cyan'))
            perform_cmdi_scan(crawled_urls, cmdi_payloads, user_agents)

            print("\n")  
            print(colored("[•] Performing Server-Side Template Injection (SSTI) scan...", 'cyan'))
            perform_ssti_scan(crawled_urls, user_agents, verbose=True)

            print("\n")  
            print(colored("[•] Performing Cross Site Scripting scan...", 'cyan'))
            perform_xss_scan(crawled_urls, user_agents, verbose=True)

            print("\n")  
            print(colored("[•] Performing Local File Inclusion scan...", 'cyan'))
            perform_lfi_scan(crawled_urls, user_agents, verbose=True)

            print("\n")  
            print(colored("[•] Performing Open Redirect scan...", 'cyan'))
            perform_redirect_scan(crawled_urls, user_agents, verbose=True)

            print("\n")  
            print(colored(f"[•] Performing Carriage Return and Line Feed scan on {target}", 'yellow'))
            perform_crlf_scan(crawled_urls, user_agents, verbose=True)

            print("\n")  
            print(colored(f"[•] Performing Cross-origin resource sharing scan on {target}", 'yellow'))
            perform_cors_scan(crawled_urls, user_agents, verbose=True)

        log_scan_end(target, scan_type)

    except KeyboardInterrupt:
        print(colored("\n[×] Scan interrupted by the user. Exiting...", 'red'))
        log_error("Scan interrupted by the user.")
        exit()

        log_scan_end(target, scan_type)  

    except KeyboardInterrupt:
        print(colored("\n[×] Scan interrupted by the user. Exiting...", 'red'))
        log_error("Scan interrupted by the user.")
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

    required_files = ['sqlipayload.txt', 'cmdipayload.txt', 'basicxsspayload.txt', 'filtersbypassxss.txt', 'lfipayload.txt', 'openredirectpayloads.txt', 'crlfpayload.txt', 'corspayload.txt', 'sstipayload.txt', 'ua.txt', 'errors.xml', 'cmdi.xml']
    missing_files = check_required_files(data_dir, session_dir, required_files)
    if missing_files:
        handle_error(f"Missing required files: {', '.join(missing_files)}")

    required_directories = [data_dir, session_dir]
    missing_dirs = check_required_directories(required_directories)
    if missing_dirs:
        handle_error(f"Missing required directories: {', '.join(missing_dirs)}")

    parser = argparse.ArgumentParser(description="Waymap - Web Vulnerability Scanner")
    parser.add_argument('--crawl', type=int, required=True, help="Crawl depth")
    parser.add_argument('--scan', type=str, required=True, choices=['sql', 'cmdi', 'all', 'ssti', 'xss', 'lfi', 'open-redirect', 'crlf', 'cors'], help="Scan type: 'sql' 'ssti' 'xss' 'lfi' 'open-redirect' 'crlf' 'cors' or 'cmdi'")
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
