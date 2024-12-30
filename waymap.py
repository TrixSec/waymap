# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.

import os
import argparse
import requests
import logging
from termcolor import colored
from lib.parse.random_headers import generate_random_headers
from lib.waymapcrawlers.crawler import run_crawler
from lib.injection.cmdi import perform_cmdi_scan
from lib.injection.ssti import perform_ssti_scan
from lib.injection.xss import perform_xss_scan
from lib.injection.lfi import perform_lfi_scan
from lib.injection.openredirect import perform_redirect_scan
from lib.ProfileCritical.profile_critical import critical_risk_scan
from lib.ProfileDeepScan.deepscan import deepscan
from lib.ProfileHigh.profile_high import high_risk_scan
from lib.injection.crlf import perform_crlf_scan
from lib.injection.cors import perform_cors_scan
from lib.injection.sqlin.sql import run_sql_tests
from lib.core.wafdetector import check_wafs
from lib.core.settings import DEFAULT_THREADS
from lib.core.settings import AUTHOR
from lib.core.settings import WAYMAP_VERSION
from lib.core.settings import COPYRIGHT
from extras.error_handler import check_internet_connection, check_required_files, check_required_directories, handle_error
from urllib.parse import urlparse
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

session_dir = 'sessions'

headers = generate_random_headers()

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
session_dir = os.path.join(os.getcwd(), 'sessions')

def check_for_updates():
    try:
        response = requests.get("https://raw.githubusercontent.com/TrixSec/waymap/main/VERSION")
        response.raise_for_status()
        latest_version = response.text.strip()

        if WAYMAP_VERSION != latest_version:
            print(colored(f"[•] New version available: {latest_version}. Updating...", 'yellow'))
            
            os.system('git stash push -u')
            os.system('git reset --hard HEAD')
            os.system('git pull')

            with open('VERSION', 'w') as version_file:
                version_file.write(latest_version)

            os.system('git stash pop')

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
░░░╚═╝░░░╚═╝░░╚═╝░░╚═╝░░░╚═╝░░░╚═╝░░░░░╚═╝╚═╝░░╚═╝╚═╝░░░░░  Fastest And Optimised Web Vulnerability Scanner  v6.1.6
    """
    print(colored(banner, 'cyan'))
    print(colored(f"Waymap Version: {WAYMAP_VERSION}", 'yellow'))
    print(colored(f"Made by {AUTHOR}", 'yellow'))
    print(colored(COPYRIGHT, 'yellow'))

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

def handle_redirection(target_url):
    try:
        response = requests.get(target_url, allow_redirects=True, headers=headers, timeout=10, verify=False)
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

def crawl(target, crawl_depth, thread_count=1, no_prompt=False):
    domain = target.split("//")[-1].split("/")[0]

    try:
        response = requests.get(target, headers=headers, timeout=10, verify=False)
        response.raise_for_status()
    except requests.RequestException as e:
        log_error(f"Cannot connect to {target}: {e}")
        print(colored(f"[×]Crawler Cannot connect to the URL: {target}", 'red'))
        return None

    target = handle_redirection(target)

    if not target or not is_valid_url(target):
        log_error(f"Skipping {target} due to connection issues.")
        print(colored(f"[×] Skipping {target} due to connection issues.", 'yellow'))
        return None

    setup_logger(domain)

    crawled_urls = load_crawled_urls(domain)

    if not crawled_urls:
        print(colored(f"[•] Starting crawling on: {target} with depth {crawl_depth}", 'yellow'))
        crawled_urls = run_crawler(target, crawl_depth, thread_count=thread_count, no_prompt=no_prompt)
        crawled_urls = [url for url in crawled_urls if is_valid_url(url) and has_query_parameters(url) and is_within_domain(url, domain)]
        save_to_file(domain, crawled_urls)

    return crawled_urls

def scan(target, scan_type, crawled_urls=None, provided_urls=None, thread_count=1, no_prompt=False):
    log_scan_start(target, scan_type)

    cmdi_payloads = load_payloads(os.path.join(data_dir, 'cmdipayload.txt'))

    urls_to_scan = provided_urls if provided_urls else crawled_urls

    if not urls_to_scan:
        print(colored(f"[×] No URLs to scan.", 'red'))
        return

    try:
        if scan_type == 'sqli':
            print("\n")
            print(colored(f"[•] Performing SQL Injection scan on {target}", 'yellow'))
            urls = crawled_urls if crawled_urls else provided_urls
            if urls:
                run_sql_tests(urls)
        elif scan_type == 'cmdi':
            print("\n")
            print(colored(f"[•] Performing Command Injection scan on {target}", 'yellow'))
            perform_cmdi_scan(urls_to_scan, cmdi_payloads, thread_count=thread_count, no_prompt=no_prompt)

        elif scan_type == 'ssti':
            print("\n")
            print(colored(f"[•] Performing Server Side Template Injection scan on {target}", 'yellow'))
            perform_ssti_scan(urls_to_scan, thread_count=thread_count, no_prompt=no_prompt, verbose=True)

        elif scan_type == 'xss':
            print("\n")
            print(colored(f"[•] Performing Cross Site Scripting scan on {target}", 'yellow'))
            perform_xss_scan(urls_to_scan, thread_count=thread_count, no_prompt=no_prompt, verbose=True)

        elif scan_type == 'lfi':
            print("\n")
            print(colored(f"[•] Performing Local File Inclusion scan on {target}", 'yellow'))
            perform_lfi_scan(urls_to_scan, thread_count=thread_count, no_prompt=no_prompt, verbose=True)

        elif scan_type == 'open-redirect':
            print("\n")
            print(colored(f"[•] Performing Open Redirect scan on {target}", 'yellow'))
            perform_redirect_scan(urls_to_scan, thread_count=thread_count, no_prompt=no_prompt, verbose=True)

        elif scan_type == 'crlf':
            print("\n")
            print(colored(f"[•] Performing Carriage Return and Line Feed scan on {target}", 'yellow'))
            perform_crlf_scan(urls_to_scan, thread_count=thread_count, no_prompt=no_prompt, verbose=True)

        elif scan_type == 'cors':
            print("\n")
            print(colored(f"[•] Performing Cross-origin resource sharing scan on {target}", 'yellow'))
            perform_cors_scan(urls_to_scan, thread_count=thread_count, no_prompt=no_prompt, verbose=True)

        elif scan_type == 'all':
            print("\n")
            print(colored(f"[•] Performing SQL Injection scan on {target}", 'yellow'))
            urls = crawled_urls if crawled_urls else provided_urls
            if urls:
                run_sql_tests(urls)
            print("\n")
            print(colored("[•] Performing Command Injection (CMDi) scan...", 'cyan'))
            perform_cmdi_scan(urls_to_scan, cmdi_payloads, thread_count=thread_count, no_prompt=no_prompt)

            print("\n")
            print(colored("[•] Performing Server-Side Template Injection (SSTI) scan...", 'cyan'))
            perform_ssti_scan(urls_to_scan, thread_count=thread_count, no_prompt=no_prompt, verbose=True)

            print("\n")
            print(colored("[•] Performing Cross Site Scripting scan...", 'cyan'))
            perform_xss_scan(urls_to_scan, thread_count=thread_count, no_prompt=no_prompt, verbose=True)

            print("\n")
            print(colored("[•] Performing Local File Inclusion scan...", 'cyan'))
            perform_lfi_scan(urls_to_scan, thread_count=thread_count, no_prompt=no_prompt, verbose=True)

            print("\n")
            print(colored("[•] Performing Open Redirect scan...", 'cyan'))
            perform_redirect_scan(urls_to_scan, thread_count=thread_count, no_prompt=no_prompt, verbose=True)

            print("\n")
            print(colored(f"[•] Performing Carriage Return and Line Feed scan on {target}", 'yellow'))
            perform_crlf_scan(urls_to_scan, thread_count=thread_count, no_prompt=no_prompt, verbose=True)

            print("\n")
            print(colored(f"[•] Performing Cross-origin resource sharing scan on {target}", 'yellow'))
            perform_cors_scan(urls_to_scan, thread_count=thread_count, no_prompt=no_prompt, verbose=True)

    finally:
        log_scan_end(target, scan_type)

def crawl_and_scan(target, crawl_depth, scan_type, url=None, multi_url=None, thread_count=1, no_prompt=False):
    provided_urls = []

    if url:
        provided_urls = [url] if is_valid_url(url) and has_query_parameters(url) else []

    elif multi_url:
        with open(multi_url, 'r') as file:
            for line in file:
                line_url = line.strip()
                if is_valid_url(line_url) and has_query_parameters(line_url):
                    provided_urls.append(line_url)

    if provided_urls:
        print(colored(f"[•] Using provided URLs for scanning.", 'green'))
        scan(target, scan_type, provided_urls=provided_urls, thread_count=thread_count, no_prompt=no_prompt)
    else:
        crawled_urls = crawl(target, crawl_depth, thread_count=thread_count, no_prompt=no_prompt)
        if crawled_urls:
            scan(target, scan_type, crawled_urls=crawled_urls, thread_count=thread_count, no_prompt=no_prompt)

def load_targets_from_file(file_path):
    if os.path.exists(file_path):
        with open(file_path, 'r') as f:
            return [line.strip() for line in f.readlines() if line.strip()]
    else:
        print(colored(f"[×] Target file {file_path} does not exist.", 'red'))
        return []

def perform_profile_scan(profile_url, profile_type):
    print(f"Starting {profile_type} scan on {profile_url}.")
    
    if profile_type == 'high-risk':
        high_risk_scan(profile_url)
    elif profile_type == 'critical-risk':
        critical_risk_scan(profile_url)
    elif profile_type == 'deepscan':
        deepscan(profile_url)
    else:
        print(f"Error: Unknown scan type '{profile_type}'.")


def main():
    print_banner()

    if not check_internet_connection():
        handle_error("No internet connection. Please check your network and try again.")

    required_files = [
        'cmdipayload.txt', 'basicxsspayload.txt', 'filtersbypassxss.txt',
        'lfipayload.txt', 'openredirectpayloads.txt', 'waymap_dirfuzzlist.txt', 'waymap_dirfuzzlist2.txt', 'openredirectparameters.txt', 'crlfpayload.txt', 'corspayload.txt',
        'sstipayload.txt', 'jsvulnpattern.json', 'wafsig.json', 'ua.txt', 'cmdi.xml', 'error_based.xml', 'cveinfo.py', 'headers.json'
    ]
    missing_files = check_required_files(data_dir, session_dir, required_files)
    if missing_files:
        handle_error(f"Missing required files: {', '.join(missing_files)}")

    required_directories = [data_dir, session_dir]
    missing_dirs = check_required_directories(required_directories)
    if missing_dirs:
        handle_error(f"Missing required directories: {', '.join(missing_dirs)}")

    parser = argparse.ArgumentParser(description="Waymap - Fast and Optimized Web Vulnerability Scanner")
    parser.add_argument('--target', '-t', type=str, help='Target URL for crawling and scanning, example: https://example.com/')
    parser.add_argument('--multi-target', '-mt', type=str, help='File with multiple target URLs for crawling and scanning')
    parser.add_argument('--crawl', '-c', type=int, help='Crawl depth')
    parser.add_argument('--scan', '-s', type=str, choices=['sqli', 'cmdi', 'ssti', 'xss', 'lfi', 'open-redirect', 'crlf', 'cors', 'all', 'high-risk', 'critical-risk'], help='Type of scan to perform')
    parser.add_argument('--threads', '-T', type=int, default=DEFAULT_THREADS, help='Number of threads to use for scanning (default: 1)')
    parser.add_argument('--no-prompt', '-np', action='store_true', help='Automatically use default input for prompts')
    parser.add_argument('--profile', '-p', choices=['high-risk', 'deepscan', 'critical-risk'], help="Specify the profile: 'high-risk', 'deepscan' or 'critical-risk'. This skips crawling.")
    parser.add_argument('--check-updates', action='store_true', help='Check for Latest Waymap updates.')
    parser.add_argument('--check-waf', '--waf', type=str, help='To Detect WAF/IPS Of Any Website')

    args = parser.parse_args()

    target = args.target
    multi_target_file = args.multi_target
    thread_count = args.threads
    no_prompt = args.no_prompt
    profile_type = args.profile


    if args.check_updates:
        check_for_updates()

    if args.check_waf:
        waf_url = args.check_waf.strip()
        check_wafs(waf_url)

    if multi_target_file:
        targets = load_targets_from_file(multi_target_file)
        if not targets:
            return
        for target in targets:
            process_target(target, args.crawl, args.scan, thread_count, no_prompt, profile_type)
        return

    if target:
        process_target(target, args.crawl, args.scan, thread_count, no_prompt, profile_type)

def process_target(target, crawl_depth, scan_type, thread_count, no_prompt, profile_type):
    """Process a single target, determining whether to crawl or scan directly."""
    if "?" in target and "=" in target:
        print(colored(f"[•] GET parameter found in URL {target}. Skipping crawling and starting scan directly.", 'yellow'))
        scan(target, scan_type, [target], thread_count=thread_count, no_prompt=no_prompt)
        return

    if profile_type:
        print(colored(f"[•] Running profile scan on {target} with profile {profile_type}", 'cyan'))
        perform_profile_scan(target, profile_type)
    elif crawl_depth:
        print(colored(f"[•] Crawling and scanning on {target}", 'cyan'))
        crawl_and_scan(target, crawl_depth, scan_type, thread_count=thread_count, no_prompt=no_prompt)
        cleanup_crawl_file(target)
    else:
        print(colored(f"[•] Direct scanning on {target}", 'cyan'))
        scan(target, scan_type, [target], thread_count=thread_count, no_prompt=no_prompt)

def cleanup_crawl_file(target):
    """Remove crawl.txt file associated with the target domain."""
    domain = target.split("//")[-1].split("/")[0]
    crawl_file = os.path.join(session_dir, domain, 'crawl.txt')
    if os.path.exists(crawl_file):
        os.remove(crawl_file)
        print(colored(f"[•] Removed crawl file for {domain}.", 'green'))

if __name__ == "__main__":
    main()