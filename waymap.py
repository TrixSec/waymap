import tempfile
import os
from cmdline import parse_args
from thirdparty.scraper import run_scrapy_spider
from thirdparty.archive_scraper import fetch_archive_urls
from filters.remove_duplicates import remove_duplicates
from filters.remove_no_params import remove_no_params

# Output tempfile for URLs
OUTPUT_FILE = tempfile.NamedTemporaryFile(delete=False, mode='w', suffix='.txt')

# Function to handle all scraping processes
def scrape_urls(args):
    # Step 1: Scrapy Spider
    if args.verbosity >= 1:
        print("[INFO] Starting Scrapy crawl.")
    run_scrapy_spider(args.url, args.crawl_depth, OUTPUT_FILE.name)
    
    # Step 2: Archive.org Scraper (Optional)
    if args.use_archive:
        if args.verbosity >= 1:
            print("[INFO] Fetching URLs from archive.org.")
        fetch_archive_urls(args.url, OUTPUT_FILE.name)
    
    # Step 3: Apply filters
    if args.verbosity >= 1:
        print("[INFO] Applying URL filters.")
    remove_duplicates(OUTPUT_FILE.name)
    remove_no_params(OUTPUT_FILE.name)
    
    if args.verbosity >= 2:
        with open(OUTPUT_FILE.name, 'r') as f:
            print(f"[INFO] Filtered URLs: \n{f.read()}")
    
    return OUTPUT_FILE.name

# Main Waymap logic
def main():
    # Parse the command-line arguments
    args = parse_args()

    # Scraping phase
    scraped_file = scrape_urls(args)
    
    # Vulnerability testing phase (starting with SQL injection)
    print(f"[INFO] Running SQL injection tests on URLs from {scraped_file}.")
    # Here, you will call the SQLi module and then command injection

    # Additional tests can be integrated here, such as command injection
    print(f"[INFO] Running command injection tests on URLs from {scraped_file}.")

if __name__ == "__main__":
    main()
