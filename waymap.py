#!/usr/bin/env python3
# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.

"""
Waymap - Fast and Optimized Web Vulnerability Scanner

A powerful web security scanner for automated vulnerability detection.
"""

import argparse
import sys
import importlib.util
from typing import List, Optional

def check_dependencies():
    """Check if required dependencies are installed."""
    required = {
        'requests': 'requests',
        'bs4': 'beautifulsoup4',
        'colorama': 'colorama',
        'urllib3': 'urllib3',
        'tqdm': 'tqdm',
        'packaging': 'packaging'
    }
    missing = []
    for module, package in required.items():
        if importlib.util.find_spec(module) is None:
            missing.append(package)
    
    if missing:
        print("❌ Missing required dependencies:")
        for pkg in missing:
            print(f"   - {pkg}")
        print("\n💡 Please run: pip install -r requirements.txt")
        sys.exit(1)

# Check dependencies before importing local modules
check_dependencies()

# Core imports
from lib.core.config import get_config
from lib.core.logger import get_logger
from lib.core.error_handler import validate_environment, handle_error
from lib.ui import print_banner, print_header, print_status, print_separator, confirm_action
from lib.utils import validate_url, validate_crawl_depth, validate_thread_count, validate_scan_type


logger = get_logger(__name__)
config = get_config()


def check_for_updates() -> None:
    """Check for waymap updates."""
    try:
        from lib.ui import animate_loading
        import requests
        
        animate_loading("Checking for updates", 1)
        response = requests.get(config.VERSION_CHECK_URL, timeout=5)
        response.raise_for_status()
        latest_version = response.text.strip()

        if config.VERSION != latest_version:
            print_status(f"New version available: {latest_version}", "warning")
            print_status(f"Current version: {config.VERSION}", "info")
        else:
            print_status("Waymap is up to date", "success")
    except Exception as e:
        logger.error(f"Error checking for updates: {e}")
        print_status(f"Could not check for updates: {e}", "warning")


def parse_arguments() -> argparse.Namespace:
    """
    Parse command line arguments.
    
    Returns:
        Parsed arguments
    """
    parser = argparse.ArgumentParser(
        description="Waymap - Fast and Optimized Web Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  waymap --target https://example.com --scan xss --crawl 2
  waymap --target https://test.com --scan all --threads 4
  waymap --multi-target targets.txt --scan sqli
  waymap --target https://example.com --check-waf
        """
    )
    
    parser.add_argument('--target', '-t', type=str, help='Target URL for scanning')
    parser.add_argument('--multi-target', '-mt', type=str, help='File with multiple target URLs')
    parser.add_argument('--crawl', '-c', type=int, help='Crawl depth (0-10)')
    parser.add_argument('--scan', '-s', type=str, 
                        choices=['sqli', 'cmdi', 'ssti', 'xss', 'lfi', 'open-redirect', 'crlf', 'cors', 'all'],
                        help='Type of scan to perform')
    parser.add_argument('--technique', '-k', type=str, 
                        help='SQL injection technique [B (boolean), E (error), T (time)]. Combine like BET')
    parser.add_argument('--threads', '-T', type=int, default=config.DEFAULT_THREADS, 
                        help='Number of threads')
    parser.add_argument('--no-prompt', '-np', action='store_true', 
                        help='Automatically use default input')
    parser.add_argument('--profile', '-p', choices=['high-risk', 'deepscan', 'critical-risk'], 
                        help="Scan profile")
    parser.add_argument('--deepscan', '-ds', type=str, 
                        help="Run specific deepscan module(s): hs,bf,df,js")
    parser.add_argument('--check-waf', '--waf', action='store_true', 
                        help='Detect WAF/IPS for target URL')
    parser.add_argument('--resetup', action='store_true', 
                        help='Reset input mode configuration')
    parser.add_argument('--version', '-v', action='version', 
                        version=f'Waymap {config.VERSION}')
    
    return parser.parse_args()


def validate_arguments(args: argparse.Namespace) -> bool:
    """
    Validate command line arguments.
    
    Args:
        args: Parsed arguments
        
    Returns:
        True if valid, False otherwise
    """
    # Validate target URL if provided
    if args.target:
        is_valid, error_msg = validate_url(args.target)
        if not is_valid:
            print_status(f"Invalid target URL: {error_msg}", "error")
            return False
    
    # Validate crawl depth if provided
    if args.crawl is not None:
        is_valid, error_msg = validate_crawl_depth(args.crawl)
        if not is_valid:
            print_status(f"Invalid crawl depth: {error_msg}", "error")
            return False
    
    # Validate thread count
    is_valid, error_msg = validate_thread_count(args.threads, config.MAX_THREADS)
    if not is_valid:
        print_status(f"Invalid thread count: {error_msg}", "error")
        return False
    
    # Validate scan type if provided
    if args.scan:
        is_valid, error_msg = validate_scan_type(args.scan)
        if not is_valid:
            print_status(f"Invalid scan type: {error_msg}", "error")
            return False
    
    # Validate technique flag usage
    if args.technique and args.scan != 'sqli':
        print_status("The '--technique' argument can only be used with '--scan sqli'", "error")
        return False
    
    # Validate profile and deepscan combination
    if args.profile == "deepscan" and args.deepscan:
        print_status("Cannot use '--profile deepscan' and '--deepscan' together", "error")
        return False
    
    return True


def run_waf_detection(target: str) -> None:
    """
    Run WAF detection on target.
    
    Args:
        target: Target URL
    """
    try:
        from lib.core.wafdetector import check_wafs
        print_header("WAF Detection", "red")
        print_status(f"Checking WAF for: {target}", "info")
        check_wafs(target)
    except Exception as e:
        logger.error(f"WAF detection failed: {e}")
        print_status(f"WAF detection failed: {e}", "error")


def run_scan(args: argparse.Namespace) -> None:
    """
    Execute the scanning process.
    
    Args:
        args: Parsed command line arguments
    """
    # Import scanning modules (lazy import for performance)
    from lib.scanner.scanner import WaymapScanner
    
    scanner = WaymapScanner(
        thread_count=args.threads,
        no_prompt=args.no_prompt
    )
    
    # Determine targets
    targets = []
    if args.target:
        targets = [args.target]
    elif args.multi_target:
        try:
            with open(args.multi_target, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            handle_error(f"Target file not found: {args.multi_target}")
            return
    
    if not targets:
        print_status("No targets specified", "error")
        return
    
    # Run WAF detection if requested
    if args.check_waf and args.target:
        run_waf_detection(args.target)
        if not args.scan:
            return
    
    # Execute scans
    for i, target in enumerate(targets, 1):
        if len(targets) > 1:
            print_status(f"Processing target {i}/{len(targets)}: {target}", "info")
        
        scanner.scan(
            target=target,
            scan_type=args.scan,
            crawl_depth=args.crawl or 0,
            profile_type=args.profile,
            technique_string=args.technique,
            deepscan_modules=args.deepscan.split(',') if args.deepscan else None
        )
        
        if i < len(targets):
            print_separator("─", "blue", 50)


def main() -> None:
    """Main entry point for waymap."""
    try:
        # Print banner
        print_banner()
        
        # Check for updates
        check_for_updates()
        
        # Validate environment
        if not validate_environment():
            sys.exit(1)
        
        # Parse and validate arguments
        args = parse_arguments()
        
        if not validate_arguments(args):
            sys.exit(1)
        
        # Run scan
        run_scan(args)
        
        print_separator()
        print_status("Scan completed successfully", "success")
        
    except KeyboardInterrupt:
        print_status("\nScan interrupted by user", "warning")
        logger.info("Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        print_status(f"Unexpected error: {e}", "error")
        sys.exit(1)


if __name__ == "__main__":
    main()
