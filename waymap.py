import tempfile
import logging
import requests
from cmdline import parse_args
from thirdparty.scraper import run_scrapy_spider
from thirdparty.archive_scraper import fetch_archive_urls
from thirdparty.waf_detection import run_waf_detection

# Output tempfile for URLs
OUTPUT_FILE = tempfile.NamedTemporaryFile(delete=False, mode='w', suffix='.txt')

# Banner
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

# Configure logging
def setup_logging(verbosity):
    log_level = logging.INFO
    if verbosity == 2:
        log_level = logging.DEBUG
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s]: %(message)s",
        handlers=[logging.StreamHandler()]
    )

# Test connection to the domain
def test_connection(domain):
    """Test connection to the target domain."""
    try:
        response = requests.get(domain, timeout=10)
        if response.status_code == 200:
            logging.info(f"Successfully connected to {domain}")
            return True
        else:
            logging.warning(f"Unexpected status code {response.status_code} when connecting to {domain}")
            return False
    except requests.ConnectionError as e:
        logging.error(f"Failed to connect to {domain}: {str(e)}")
        return False
    except requests.Timeout:
        logging.error(f"Connection to {domain} timed out.")
        return False

# WAF detection logic
def run_waf_check(domain):
    """Check for WAF and ask the user if they want to continue if WAF is detected."""
    logging.info(f"Checking for WAF protection on {domain}...")
    waf_detected = run_waf_detection(domain)

    if waf_detected:
        logging.critical("WAF detected! Proceeding might trigger security alerts.")
        user_input = input("[*] Do you want to continue? (y/N): ").strip().lower()
        if user_input != 'y':
            logging.info("Aborting operation due to WAF detection.")
            return False
    return True

# Retry connection if needed
def retry_request(domain, max_retries=3):
    """Retry the connection up to max_retries times if the connection is lost."""
    retries = 0
    while retries < max_retries:
        if test_connection(domain):
            return True
        retries += 1
        logging.info(f"Retry {retries}/{max_retries}...")
    logging.error("Maximum retries reached. Aborting.")
    return False

# Scraping logic
def scrape_urls(args):
    # Step 1: Scrapy Spider
    logging.info("Starting Scrapy crawl.")
    run_scrapy_spider(args.url, args.crawl_depth, OUTPUT_FILE.name)
    
    # Step 2: Archive.org Scraper (Optional)
    if args.use_archive:
        logging.info("Fetching URLs from archive.org.")
        fetch_archive_urls(args.url, OUTPUT_FILE.name)
    
    # Scrapy has already filtered URLs (no need for post-filtering)

    if args.verbosity >= 2:
        with open(OUTPUT_FILE.name, 'r') as f:
            logging.debug(f"Filtered URLs: \n{f.read()}")
    
    return OUTPUT_FILE.name

# SQL injection test placeholder
def run_sqli_tests(file):
    """Placeholder for SQL injection testing logic."""
    logging.info(f"Running SQL injection tests on URLs from {file}.")
    # This is where you'd integrate your SQLi logic.
    # Output should be similar to SQLMap-style with detailed info.
    # For example:
    logging.info("SQL injection test: No vulnerabilities detected.")
    
# Command injection test placeholder
def run_cmdi_tests(file):
    """Placeholder for Command injection testing logic."""
    logging.info(f"Running command injection tests on URLs from {file}.")
    # Similar to SQLi, this is where you'd implement command injection detection.
    # Example:
    logging.info("Command injection test: No vulnerabilities detected.")

# Main Waymap logic
def main():
    # Print the banner
    print_banner()

    # Parse the command-line arguments
    args = parse_args()

    # Set up logging based on verbosity level
    setup_logging(args.verbosity)

    # Scraping phase
    if not retry_request(args.url):
        return

    # Run WAF check
    if not run_waf_check(args.url):
        return

    # Start scraping
    scraped_file = scrape_urls(args)
    
    # Vulnerability testing phase
    run_sqli_tests(scraped_file)
    run_cmdi_tests(scraped_file)

if __name__ == "__main__":
    main()


