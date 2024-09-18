import argparse
import os
from lib.crawler import run_crawler
from lib.injector import inject_payloads
from termcolor import colored
import random
# Directory paths for session and data
session_dir = '/waymap/session/'
data_dir = '/waymap/data/'

def print_banner():
    banner = r"""
     __    __                                        
    / / /\ \ \  __ _  _   _  _ __ ___    __ _  _ __  
    \ \/  \/ / / _` || | | || '_ ` _ \  / _` || '_ \ 
     \  /\  / | (_| || |_| || | | | | || (_| || |_) |
      \/  \/   \__,_| \__, ||_| |_| |_| \__,_|| .__/ 
                      |___/                   |_|    
    """
    print(banner)

def main():
    parser = argparse.ArgumentParser(description="Waymap - Web Vulnerability Scanner")
    
    # Argument for crawl depth
    parser.add_argument('--crawl', type=int, default=2, help="Set crawl depth (max 10)")
    
    # Option to choose scanning type
    parser.add_argument('--scan', choices=['sql', 'cmdi'], required=True, help="Choose the type of injection scan (sql for SQLi, cmdi for Command Injection)")
    
    # Option to set a target URL
    parser.add_argument('--target', type=str, required=True, help="Target URL for scanning")
    
    # Optional argument for custom User-Agent
    parser.add_argument('--user-agent', type=str, help="Custom User-Agent string")

    args = parser.parse_args()

    # Ensure that crawl depth does not exceed the maximum allowed value
    if args.crawl > 10:
        print(colored("[×] Maximum crawl depth is 10. Setting crawl depth to 10.", 'red'))
        crawl_depth = 10
    else:
        crawl_depth = args.crawl

    # Start the crawling process
    print(colored(f"[•] Starting crawling on: {args.target} with depth {crawl_depth}", 'green'))
    crawled_urls = run_crawler(args.target, crawl_depth)  # Calls the crawler

    # Load necessary data (payloads, user-agents, errors)
    sql_payloads = load_payloads(os.path.join(data_dir, 'sqlipayload.txt'))
    cmdi_payloads = load_payloads(os.path.join(data_dir, 'cmdipayload.txt'))
    user_agents = load_user_agents()

    # Set headers for requests
    headers = {}
    if args.user_agent:
        headers['User-Agent'] = args.user_agent
    else:
        headers['User-Agent'] = random.choice(user_agents)

    # Call the appropriate scan type based on user input
    if args.scan == 'sql':
        print(colored(f"[•] Starting SQL Injection scan on {len(crawled_urls)} URLs", 'yellow'))
        inject_payloads(crawled_urls, sql_payloads, [], user_agents)  # SQLi scan
    elif args.scan == 'cmdi':
        print(colored(f"[•] Starting Command Injection scan on {len(crawled_urls)} URLs", 'yellow'))
        inject_payloads(crawled_urls, [], cmdi_payloads, user_agents)  # CMDi scan

    print(colored("[★] Scan complete!", 'green'))

# Utility function to load payloads
def load_payloads(file_path):
    with open(file_path, 'r') as f:
        return [line.strip() for line in f.readlines()]

# Utility function to load user-agents
def load_user_agents():
    ua_file = os.path.join(data_dir, 'ua.txt')
    return load_payloads(ua_file)

if __name__ == "__main__":
    main()
