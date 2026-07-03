#!/usr/bin/env python3
# Copyright (c) 2026 waymap developers
# See the file 'LICENSE' for copying permission.

"""
Waymap - Fast and Optimized Web Vulnerability Scanner

A powerful web security scanner for automated vulnerability detection.
"""

import argparse
import sys
import os
import json

# Ensure the waymap package directory is in sys.path so internal absolute imports starting with 'lib' work.
pkg_dir = os.path.dirname(os.path.abspath(__file__))
if pkg_dir not in sys.path:
    sys.path.insert(0, pkg_dir)
import importlib.util
import warnings
from typing import List, Optional, Dict, Any
from urllib.parse import urlparse

warnings.filterwarnings('ignore', category=UserWarning, message=r'.*Unverified HTTPS request.*')

def check_dependencies():
    """Check if required dependencies are installed."""
    required = {
        'requests': 'requests',
        'bs4': 'beautifulsoup4',
        'colorama': 'colorama',
        'urllib3': 'urllib3',
        'tqdm': 'tqdm',
        'packaging': 'packaging',
        'defusedxml': 'defusedxml',
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
from lib.core.result_manager import format_results_for_report
from lib.core.interrupt import exit_clean
from lib.core.error_handler import validate_environment, handle_error
from lib.ui import print_banner, print_header, print_status, print_separator, confirm_action
from lib.ui.interactive import run_interactive_wizard
from lib.utils import validate_url, validate_crawl_depth, validate_thread_count, validate_scan_type

# New Feature Imports (v7.1.0)
from lib.core.reporting import generate_all_reports
from lib.core.auth import setup_authentication
from lib.api.api_scanner import perform_api_scan
from lib.discovery.searchapi_dork import discover_google_dork, save_discovered_urls
from lib.core.secrets import get_secret

try:
    from urllib3.exceptions import InsecureRequestWarning

    warnings.simplefilter('ignore', InsecureRequestWarning)
except ImportError:
    pass

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
  
  # New Features v7.1.0
  waymap --target https://api.example.com --scan api --api-type rest
  waymap --target https://example.com --scan all --report-format html,pdf
  waymap --target https://example.com --auth-type form --username admin --password pass
        """
    )
    
    # Target Arguments
    target_group = parser.add_argument_group('Target')
    target_group.add_argument('--target', '-t', type=str, help='Target URL for scanning')
    target_group.add_argument('--multi-target', '-mt', type=str, help='File with multiple target URLs')
    
    # Scan Configuration
    scan_group = parser.add_argument_group('Scan Configuration')
    scan_group.add_argument('--crawl', '-c', type=int, help='Crawl depth (0-10)')
    scan_group.add_argument('--scan', '-s', type=str, 
                        choices=[
                            'sqli', 'cmdi', 'rce', 'ssti', 'xss', 'lfi', 'open-redirect', 'crlf', 'cors', 'api', 'all',
                            'recon', 'misconfig', 'redirect', 'injection-advanced', 'graphql-suite', 'auth-logic',
                            'cache-smuggling', 'wordpress-extras', 'optional'
                        ],
                        help='Type of scan to perform')
    scan_group.add_argument('--technique', '-k', type=str, 
                        help='SQL injection technique [B (boolean), E (error), T (time)]. Combine like BET')
    scan_group.add_argument('--profile', '-p', type=str,
                        choices=['wordpress'],
                        help='Scan profile to use')
    scan_group.add_argument('--threads', type=int, default=1, help='Number of threads (default: 1)')
    scan_group.add_argument('--no-prompt', action='store_true', help='Disable user prompts')
    scan_group.add_argument('--verbose', '-v', action='store_true', help='Enable verbose output')
    
    # Utility Arguments
    util_group = parser.add_argument_group('Utilities')
    util_group.add_argument('--check-waf', action='store_true', help='Check for WAF/IPS')
    util_group.add_argument('--waf', type=str, help='Check WAF for specific URL')
    util_group.add_argument('--check-updates', action='store_true', help='Check for updates')
    util_group.add_argument('--version', action='version', version=f'Waymap v{config.VERSION}')
    
    # Reporting Arguments (New v7.1.0)
    report_group = parser.add_argument_group('Reporting')
    report_group.add_argument('--report-format', type=str, help='Report formats (html,csv,markdown,pdf). Comma separated.')
    report_group.add_argument('--output-dir', type=str, default='reports', help='Directory to save reports')
    
    # Authentication Arguments (New v7.1.0)
    auth_group = parser.add_argument_group('Authentication')
    auth_group.add_argument('--auth-type', type=str, choices=['form', 'basic', 'digest', 'bearer', 'api_key'], help='Authentication type')
    auth_group.add_argument('--auth-url', type=str, help='Login URL for form authentication')
    auth_group.add_argument('--username', '-u', type=str, help='Username for authentication')
    auth_group.add_argument('--password', '-pw', type=str, help='Password for authentication')
    auth_group.add_argument('--token', type=str, help='Bearer token or API key')
    auth_group.add_argument('--auth-header', type=str, default='X-API-Key', help='Header name for API key auth')
    
    # API Scanning Arguments (New v7.1.0)
    api_group = parser.add_argument_group('API Scanning')
    api_group.add_argument('--api-type', type=str, choices=['rest', 'graphql'], default='rest', help='Type of API to scan')
    api_group.add_argument('--api-endpoints', type=str, help='Comma separated list of API endpoints to scan')

    # Discovery Arguments (New v7.2.0)
    discovery_group = parser.add_argument_group('Discovery')
    discovery_group.add_argument('--dork', type=str, help='Google dork query for target discovery (SearchAPI)')
    discovery_group.add_argument('--dork-api-key', type=str, help='SearchAPI api_key (or set env SEARCHAPI_API_KEY)')
    discovery_group.add_argument('--dork-output', type=str, help='Output file to save discovered URLs')

    # WPScan API (v7.2.0)
    wpscan_group = parser.add_argument_group('WPScan')
    wpscan_group.add_argument('--wpscan-token', type=str, help='WPScan API token (or set env WPSCAN_API_TOKEN)')

    return parser.parse_args()


def load_standard_scan_results(target: str) -> List[Dict[str, Any]]:
    """
    Load results from standard scans (SQLi, XSS, etc.)
    
    Args:
        target: Target URL
        
    Returns:
        List of formatted scan results
    """
    try:
        domain = urlparse(target).netloc
        return format_results_for_report(domain)
    except Exception as e:
        logger.error(f"Error loading standard scan results: {e}")
        return []


def interactive_wizard() -> argparse.Namespace:
    """Run interactive wizard (delegates to lib.ui.interactive)."""
    return run_interactive_wizard()


def main():
    """Main execution function."""
    try:
        _run()
    except KeyboardInterrupt:
        exit_clean()


def _run():
    """Main scan logic."""
    print_banner()
    
    # Check if running in interactive mode (no args)
    if len(sys.argv) == 1:
        args = interactive_wizard()
    else:
        args = parse_arguments()
    
    # Handle update check
    if args.check_updates:
        check_for_updates()
        return

    if getattr(args, 'no_prompt', False) and not os.environ.get('WAYMAP_NO_PROMPT'):
        os.environ['WAYMAP_NO_PROMPT'] = '1'

    # Export WPScan token for modules that read from environment
    if getattr(args, 'wpscan_token', None) and not os.environ.get('WPSCAN_API_TOKEN'):
        os.environ['WPSCAN_API_TOKEN'] = args.wpscan_token

    # Handle Google dork discovery (SearchAPI)
    if getattr(args, 'dork', None):
        api_key = args.dork_api_key or os.environ.get('SEARCHAPI_API_KEY')
        if not api_key:
            api_key = get_secret('searchapi_api_key', env_var='SEARCHAPI_API_KEY')
        if not api_key and not getattr(args, 'no_prompt', False):
            from lib.ui import prompt_line
            api_key = prompt_line("[?] Enter SearchAPI API Key")
        if api_key:
            os.environ['SEARCHAPI_API_KEY'] = api_key

        output_file = args.dork_output
        if not output_file:
            if args.target:
                domain = urlparse(args.target).netloc
                session_dir = config.get_domain_session_dir(domain)
                output_file = os.path.join(session_dir, 'dork_targets.txt')
            else:
                output_file = os.path.join(os.getcwd(), 'dork_targets.txt')

        try:
            urls = discover_google_dork(
                query=args.dork,
                api_key=api_key,
                limit=None
            )
            saved_path = save_discovered_urls(urls, output_file)
            print_status(f"Saved {len(urls)} discovered URL(s) to: {saved_path}", "success")

            try:
                with open(saved_path, "r", encoding="utf-8") as f:
                    scan_urls = [line.strip() for line in f if line.strip()]
            except Exception as e:
                print_status(f"Failed to read discovered URLs for scanning: {e}", "error")
                return

            if not scan_urls:
                print_status("No parameterized URLs found after filtering; skipping auto SQLi scan", "warning")
                return

            print_separator()
            print_status(f"Auto-starting SQLi scan on {len(scan_urls)} discovered URL(s)", "info")

            from lib.scanner.scanner import WaymapScanner
            scanner = WaymapScanner(thread_count=args.threads, no_prompt=getattr(args, 'no_prompt', False))
            scanner.scan_urls(scan_urls, 'sqli', technique_string=getattr(args, 'technique', None))
        except KeyboardInterrupt:
            exit_clean()
        except Exception as e:
            handle_error(str(e))
        return

    # Handle WAF check
    if args.check_waf or args.waf:
        target = args.waf if args.waf else args.target
        if not target:
            print_status("Target URL required for WAF check", "error")
            return
        
        from lib.core.wafdetector import detect_waf
        detect_waf(target)
        return

    # Validate arguments
    if not args.target and not args.multi_target:
        print_status("No target specified. Use --target or --multi-target", "error")
        print_status("Use --help for usage information", "info")
        return

    # Setup Authentication
    auth_session = None
    if args.auth_type:
        auth_config = {
            'type': args.auth_type,
            'username': args.username,
            'password': args.password,
            'token': args.token,
            'api_key': args.token, # Reuse token arg for api key
            'header_name': args.auth_header,
            'login_url': args.auth_url if args.auth_url else args.target
        }
        
        # Basic validation for auth
        if args.auth_type in ['form', 'basic', 'digest'] and (not args.username or not args.password):
            print_status(f"Username and password required for {args.auth_type} auth", "error")
            return
        if args.auth_type in ['bearer', 'api_key'] and not args.token:
            print_status(f"Token required for {args.auth_type} auth", "error")
            return
            
        auth_manager = setup_authentication(auth_config)
        if auth_manager and auth_manager.authenticated:
            auth_session = auth_manager.get_session()
        else:
            print_status("Authentication setup failed. Continuing without auth...", "warning")

    # Initialize results container for reporting
    scan_results = {
        'target': args.target,
        'scans': []
    }

    try:
        # Handle API Scan
        if args.scan == 'api':
            if not args.target:
                 print_status("Target URL required for API scan", "error")
                 return
                 
            endpoints = args.api_endpoints.split(',') if args.api_endpoints else None
            vulns = perform_api_scan(
                base_url=args.target,
                api_type=args.api_type,
                endpoints=endpoints,
                auth_session=auth_session,
                verbose=args.verbose
            )
            
            scan_results['scans'].append({
                'scan_type': 'api',
                'vulnerabilities': vulns,
                'timestamp': 'now' # simplified
            })

        # Handle Standard Scans
        elif args.scan or args.profile:
            if args.scan:
                print_status(f"Starting {args.scan} scan on {args.target or 'multi-target list'}", "info")

                from lib.scanner.scanner import WaymapScanner
                scanner = WaymapScanner(thread_count=args.threads, no_prompt=args.no_prompt)

                if args.target:
                    scanner.scan(
                        args.target,
                        args.scan,
                        crawl_depth=args.crawl or 0,
                        technique_string=args.technique,
                    )
                elif args.multi_target:
                    from lib.utils.file_utils import load_file_lines
                    targets = load_file_lines(args.multi_target)
                    for target in targets:
                        if not target:
                            continue
                        scanner.scan(
                            target,
                            args.scan,
                            crawl_depth=args.crawl or 0,
                            technique_string=args.technique,
                        )

            if args.profile:
                print_status(f"Starting {args.profile} profile scan", "info")
                if args.profile == 'wordpress':
                    from lib.ProfileWordpress.profile_wordpress import wordpress_vuln_scan
                    if args.target:
                        wordpress_vuln_scan(args.target)

            # Load results from standard scans if target is provided
            if args.target:
                standard_results = load_standard_scan_results(args.target)
                scan_results['scans'].extend(standard_results)

        # Generate Reports
        if args.report_format:
            print_separator()
            print_status("Generating Reports...", "info")
            generate_all_reports(scan_results, args.output_dir)

    except KeyboardInterrupt:
        exit_clean()
    except Exception as e:
        handle_error(str(e))
        if args.verbose:
            import traceback
            traceback.print_exc()


if __name__ == "__main__":
    main()
