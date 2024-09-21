import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import time
import sys

visited_urls = set()
valid_urls = []
total_urls = 0

REQUEST_TIMEOUT = 10  

def crawl(url, depth, max_depth, start_time):
    global total_urls
    if depth > max_depth:
        return

    try:
        response = requests.get(url, timeout=REQUEST_TIMEOUT)
        soup = BeautifulSoup(response.text, 'html.parser')
        links = soup.find_all('a')

        for link in links:
            href = link.get('href')
            if href:
                full_url = urljoin(url, href)
                if is_valid_url(full_url) and full_url not in visited_urls:
                    if has_query_parameters(full_url): 
                        visited_urls.add(full_url)
                        valid_urls.append(full_url)
                        total_urls += 1

                        elapsed_time = time.time() - start_time
                        estimated_total_time = (elapsed_time / total_urls) * (total_urls + len(links) - total_urls)
                        remaining_time = max(estimated_total_time - elapsed_time, 0)
                        sys.stdout.write(f"\r[•] URLs crawled: {total_urls}, Estimated time remaining: {remaining_time:.2f} seconds")
                        sys.stdout.flush()

                        crawl(full_url, depth + 1, max_depth, start_time)

    except requests.RequestException as e:
        print(f"\n[×] Error crawling {url}: {e}")

def is_valid_url(url):
    parsed = urlparse(url)
    return bool(parsed.netloc) and bool(parsed.scheme)

def has_query_parameters(url):
    return '?' in url or '&' in url or '=' in url

def run_crawler(start_url, max_depth):
    global total_urls
    total_urls = 0
    visited_urls.clear()
    valid_urls.clear()

    start_time = time.time()

    crawl(start_url, 0, max_depth, start_time)

    return valid_urls

