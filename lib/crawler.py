import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import time
import sys
import os

visited_urls = set()
valid_urls = []
total_urls = 0

REQUEST_TIMEOUT = 10

def get_domain_dir(base_domain):
    domain_dir = os.path.join(os.getcwd(), 'sessions', base_domain)
    if not os.path.exists(domain_dir):
        os.makedirs(domain_dir)  
    return domain_dir

def get_crawl_file_path(base_domain):
    domain_dir = get_domain_dir(base_domain)
    return os.path.join(domain_dir, 'crawl.txt')

def load_crawled_urls(base_domain):
    crawl_file = get_crawl_file_path(base_domain)
    if os.path.exists(crawl_file):
        with open(crawl_file, 'r') as file:
            return set(line.strip() for line in file.readlines())
    return set()

def save_crawled_urls(base_domain, urls):
    crawl_file = get_crawl_file_path(base_domain)
    with open(crawl_file, 'a') as file:
        for url in urls:
            file.write(f"{url}\n")

def remove_crawl_file(base_domain):
    crawl_file = get_crawl_file_path(base_domain)
    if os.path.exists(crawl_file):
        os.remove(crawl_file)
        print(f"\n[•] Removed {crawl_file} as user is re-crawling a previously crawled URL.")

def crawl(url, depth, max_depth, start_time, base_domain):
    global total_urls
    if depth > max_depth:  
        return

    try:
        response = requests.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
        final_url = response.url

        parsed_final_url = urlparse(final_url)
        if parsed_final_url.netloc != base_domain:  
            return

        soup = BeautifulSoup(response.text, 'html.parser')
        links = soup.find_all('a')

        for link in links:
            href = link.get('href')
            if href:
                full_url = urljoin(final_url, href)  

                if is_valid_url(full_url) and full_url not in visited_urls and is_within_domain(full_url, base_domain) and has_query_parameters(full_url):
                    visited_urls.add(full_url)  
                    valid_urls.append(full_url)
                    total_urls += 1

                    elapsed_time = time.time() - start_time
                    estimated_total_time = (elapsed_time / total_urls) * (total_urls + len(links) - total_urls)
                    remaining_time = max(estimated_total_time - elapsed_time, 0)
                    sys.stdout.write(f"\r[•] URLs crawled: {total_urls}, Estimated time remaining: {remaining_time:.2f} seconds")
                    sys.stdout.flush()

                    crawl(full_url, depth + 1, max_depth, start_time, base_domain)

    except requests.RequestException as e:
        print(f"\n[×] Error crawling {url}: {e}")

def is_valid_url(url):
    parsed = urlparse(url)
    return bool(parsed.netloc) and bool(parsed.scheme)

def has_query_parameters(url):
    return any(symbol in url for symbol in ['?', '&', '='])

def is_within_domain(url, base_domain):
    return urlparse(url).netloc == base_domain

def run_crawler(start_url, max_depth):
    global total_urls
    total_urls = 0
    visited_urls.clear()
    valid_urls.clear()

    parsed_start_url = urlparse(start_url)
    base_domain = parsed_start_url.netloc

    previously_crawled = load_crawled_urls(base_domain)

    if start_url in previously_crawled:
        remove_crawl_file(base_domain)

    start_time = time.time()

    crawl(start_url, 0, max_depth, start_time, base_domain)

    save_crawled_urls(base_domain, valid_urls)

    return valid_urls