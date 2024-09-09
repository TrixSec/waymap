import argparse
from waymap import run_waymap

def parse_arguments():
    """Parse command-line arguments similar to SQLMap."""
    parser = argparse.ArgumentParser(
        description="Waymap v1: Automated Website URL Scraper and Vulnerability Detection Tool"
    )

    # Target URL input (required)
    parser.add_argument('-u', '--url', type=str, help='Target URL to scan', required=True)

    # Crawl level: Choose how many scrapers to run (default: all 5 scrapers)
    parser.add_argument('--crawl', type=int, choices=[1, 2, 3, 4, 5], default=5,
                        help='Crawl level (1 = one scraper, 2 = two scrapers, etc.)')

    # Verbosity level: 1, 2, or 3
    parser.add_argument('-v', type=int, choices=[1, 2, 3], default=1, 
                        help='Verbosity level (1 = basic, 2 = detailed, 3 = debug)')

    # Parse arguments
    return parser.parse_args()

def main():
    # Parse the command-line arguments
    args = parse_arguments()

    # Display basic information based on verbosity level
    if args.v >= 1:
        print(f"[*] Target URL: {args.url}")
        print(f"[*] Running {args.crawl} scraper(s)")
        print(f"[*] Verbosity Level: {args.v}")
    
    # Run Waymap process based on provided arguments
    run_waymap(url=args.url, crawl_level=args.crawl, verbosity=args.v)

if __name__ == "__main__":
    main()
