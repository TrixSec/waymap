import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import os

# Directory to save crawled URLs
session_dir = '/waymap/session/'

# Function to extract URLs with ?= and & symbols
def extract_urls(url, domain, depth, max_depth, crawled=set()):
    if depth > max_depth or url in crawled:
        return []

    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (compatible; Waymap/1.0; +http://kali.org)'
        }
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
    except (requests.RequestException, requests.Timeout):
        print(f"Failed to access {url}")
        return []

    crawled.add(url)

    soup = BeautifulSoup(response.text, 'html.parser')
    urls = []
    
    # Find all anchor tags with href attributes
    for a_tag in soup.find_all('a', href=True):
        link = urljoin(url, a_tag['href'])
        parsed_url = urlparse(link)

        # Check if URL contains ?, =, or &
        if '?' in parsed_url.query or '=' in parsed_url.query or '&' in parsed_url.query:
            if parsed_url.netloc == domain:  # Ensure URL is within the same domain
                urls.append(link)

    return urls

# Function to recursively crawl the domain
def crawl_domain(url, domain, crawl_depth, max_depth, crawled=set()):
    urls = extract_urls(url, domain, crawl_depth, max_depth, crawled)

    if crawl_depth < max_depth:
        for link in urls:
            if link not in crawled:
                new_urls = crawl_domain(link, domain, crawl_depth + 1, max_depth, crawled)
                urls.extend(new_urls)

    return urls

# Function to save URLs to file
def save_urls(domain, urls):
    domain_dir = os.path.join(session_dir, domain)
    os.makedirs(domain_dir, exist_ok=True)
    crawl_file = os.path.join(domain_dir, 'crawl.txt')

    with open(crawl_file, 'w') as f:
        for url in urls:
            f.write(f"{url}\n")

# Main crawler function called from waymap.py
def run_crawler(starting_url, max_depth):
    parsed_url = urlparse(starting_url)
    domain = parsed_url.netloc

    print(f"Starting crawl on {starting_url} with max depth {max_depth}...")

    crawled_urls = crawl_domain(starting_url, domain, 0, max_depth)
    
    print(f"Crawled {len(crawled_urls)} URLs.")
    save_urls(domain, crawled_urls)
    print(f"Saved crawled URLs to /waymap/session/{domain}/crawl.txt")

