import argparse

def parse_args():
    parser = argparse.ArgumentParser(description="Waymap v1 - A multi-tool for vulnerability assessment")
    
    # URL input
    parser.add_argument("-u", "--url", required=True, help="Target URL for crawling and vulnerability testing.")
    
    # Crawl depth: default is 2
    parser.add_argument("--crawl-depth", type=int, default=2, choices=range(1, 11), help="Depth of crawl for the Scrapy spider (1 to 10).")
    
    # Exclude archive URLs
    parser.add_argument("--use-archive", action="store_true", help="Fetch URLs from archive.org for the given domain.")
    
    # Verbosity levels
    parser.add_argument("-v", "--verbosity", type=int, choices=[1, 2, 3], default=1, help="Set verbosity level (1, 2, or 3).")

    args = parser.parse_args()
    
    return args
