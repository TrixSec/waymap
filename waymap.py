#!/usr/bin/env python3
# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.

"""
Waymap - Fast and Optimized Web Vulnerability Scanner

A powerful web security scanner for automated vulnerability detection.
"""

import argparse
import sys
import os
import json
import importlib.util
from typing import List, Optional, Dict, Any
from urllib.parse import urlparse

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

# New Feature Imports (v7.1.0)
from lib.core.reporting import generate_all_reports
from lib.core.auth import setup_authentication
from lib.api.api_scanner import perform_api_scan

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
                        choices=['sqli', 'cmdi', 'ssti', 'xss', 'lfi', 'open-redirect', 'crlf', 'cors', 'api', 'all'],
                        help='Type of scan to perform')
    scan_group.add_argument('--technique', '-k', type=str, 
                        help='SQL injection technique [B (boolean), E (error), T (time)]. Combine like BET')
    scan_group.add_argument('--profile', '-p', type=str,
                        choices=['high-risk', 'critical-risk', 'deepscan'],
                        help='Scan profile to use')
    scan_group.add_argument('--deepscan', '-ds', type=str, 
                        help="Run specific deepscan module(s): hs,bf,df,js")
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

    return parser.parse_args()


def load_standard_scan_results(target: str) -> List[Dict[str, Any]]:
    """
    Load results from standard scans (SQLi, XSS, etc.)
    
    Args:
        target: Target URL
        
    Returns:
        List of formatted scan results
    """
    formatted_results = []
    try:
        domain = urlparse(target).netloc
        session_dir = config.get_domain_session_dir(domain)
        session_file = os.path.join(session_dir, 'waymap_full_results.json')
        
        if os.path.exists(session_file):
            with open(session_file, 'r') as f:
                data = json.load(f)
                
            # Convert Dict[url, List[vulns]] to List[ScanResult]
            for url, vulns in data.items():
                # Group vulnerabilities by type
                type_groups = {}
                for vuln in vulns:
                    v_type = vuln.get('type', 'Unknown')
                    if v_type not in type_groups:
                        type_groups[v_type] = []
                    
                    # Ensure vuln has 'url' field
                    if 'url' not in vuln:
                        vuln['url'] = url
                    type_groups[v_type].append(vuln)
                
                for v_type, v_list in type_groups.items():
                    formatted_results.append({
                        'scan_type': v_type,
                        'vulnerabilities': v_list,
                        'timestamp': 'now'
                    })
                    
    except Exception as e:
        logger.error(f"Error loading standard scan results: {e}")
        
    return formatted_results


def interactive_wizard() -> argparse.Namespace:
    """
    Run interactive wizard to configure scan.
    
    Returns:
        Namespace with configured arguments
    """
    from lib.ui import colored
    
    print_separator("Interactive Mode", "cyan")
    print_status("Configure your scan options below:", "info")
    print()
    
    args = argparse.Namespace()
    
    # Initialize defaults
    args.target = None
    args.multi_target = None
    args.scan = None
    args.profile = None
    args.crawl = 0
    args.threads = 1
    args.no_prompt = False
    args.verbose = False
    args.check_waf = False
    args.waf = None
    args.check_updates = False
    args.technique = None
    args.deepscan = None
    
    # New feature defaults
    args.api_type = 'rest'
    args.api_endpoints = None
    args.auth_type = None
    args.username = None
    args.password = None
    args.token = None
    args.auth_header = 'X-API-Key'
    args.auth_url = None
    args.report_format = None
    args.output_dir = 'reports'
    
    # 1. Target Configuration
    while not args.target:
        target = input(colored("[?] Enter Target URL: ", "yellow")).strip()
        if target:
            args.target = target
            
    # 2. Scan Mode
    print(colored("\n[?] Select Scan Mode:", "yellow"))
    print("    1. Standard Scan (SQLi, XSS, etc.)")
    print("    2. API Scan (REST/GraphQL)")
    print("    3. Profile Scan (High-Risk, DeepScan)")
    
    mode = input(colored("    Choice [1]: ", "yellow")).strip() or "1"
    
    if mode == "2":
        args.scan = 'api'
        print(colored("\n[?] API Type:", "yellow"))
        print("    1. REST (default)")
        print("    2. GraphQL")
        api_choice = input(colored("    Choice [1]: ", "yellow")).strip()
        if api_choice == "2":
            args.api_type = 'graphql'
            
        endpoints = input(colored("[?] Enter Endpoints (comma separated, optional): ", "yellow")).strip()
        if endpoints:
            args.api_endpoints = endpoints
            
    elif mode == "3":
        print(colored("\n[?] Select Profile:", "yellow"))
        print("    1. High-Risk (CMS)")
        print("    2. Critical-Risk (CVEs)")
        print("    3. DeepScan")
        prof_choice = input(colored("    Choice [1]: ", "yellow")).strip()
        
        if prof_choice == "2":
            args.profile = 'critical-risk'
        elif prof_choice == "3":
            args.profile = 'deepscan'
        else:
            args.profile = 'high-risk'
            
    else:
        print(colored("\n[?] Select Scan Type:", "yellow"))
        print("    1. All (default)")
        print("    2. XSS")
        print("    3. SQLi")
        print("    4. CMDi")
        print("    5. LFI")
        scan_choice = input(colored("    Choice [1]: ", "yellow")).strip()
        
        scan_map = {'1': 'all', '2': 'xss', '3': 'sqli', '4': 'cmdi', '5': 'lfi'}
        args.scan = scan_map.get(scan_choice, 'all')
        
    # 3. Authentication
    auth_choice = input(colored("\n[?] Configure Authentication? [y/N]: ", "yellow")).strip().lower()
    if auth_choice == 'y':
        print(colored("\n[?] Auth Type:", "yellow"))
        print("    1. Form-Based")
        print("    2. Bearer Token")
        print("    3. Basic Auth")
        print("    4. API Key")
        
        ac = input(colored("    Choice [1]: ", "yellow")).strip()
        
        if ac == "2":
            args.auth_type = 'bearer'
            args.token = input(colored("    Enter Token: ", "yellow")).strip()
        elif ac == "3":
            args.auth_type = 'basic'
            args.username = input(colored("    Enter Username: ", "yellow")).strip()
            args.password = input(colored("    Enter Password: ", "yellow")).strip()
        elif ac == "4":
            args.auth_type = 'api_key'
            args.token = input(colored("    Enter API Key: ", "yellow")).strip()
        else:
            args.auth_type = 'form'
            args.username = input(colored("    Enter Username: ", "yellow")).strip()
            args.password = input(colored("    Enter Password: ", "yellow")).strip()
            args.auth_url = input(colored("    Login URL (optional): ", "yellow")).strip()
            
    # 4. Reporting
    rep_choice = input(colored("\n[?] Generate Reports? [Y/n]: ", "yellow")).strip().lower()
    if rep_choice != 'n':
        args.report_format = "html,csv,markdown"
        print_status("Reports will be generated in HTML, CSV, and Markdown formats", "info")
        
    print_separator()
    return args


def main():
    """Main execution function."""
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

    # Handle WAF check
    if args.check_waf or args.waf:
        target = args.waf if args.waf else args.target
        if not target:
            print_status("Target URL required for WAF check", "error")
            return
        
        from lib.scanner.waf_detector import detect_waf
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
                 
                 # Map scan types to functions
                 if args.scan == 'xss':
                     from lib.injection.xss import perform_xss_scan
                     perform_xss_scan([args.target] if args.target else [], args.threads, args.no_prompt, args.verbose)
                     
                 elif args.scan == 'sqli':
                     # Placeholder for SQLi integration
                     pass
                     
                 # ... other scan types would be called here
            
            if args.profile:
                 print_status(f"Starting {args.profile} profile scan", "info")
                 
                 if args.profile == 'high-risk':
                     from lib.ProfileHigh.profile_high import high_risk_scan
                     if args.target:
                         high_risk_scan(args.target)
                         
                 elif args.profile == 'critical-risk':
                     from lib.ProfileCritical.profile_critical import critical_risk_scan
                     if args.target:
                         critical_risk_scan(args.target)
                         
                 elif args.profile == 'deepscan':
                     from lib.ProfileDeepScan.deepscan import deep_scan
                     if args.target:
                         deep_scan(args.target)
            
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
        print_status("\nScan interrupted by user", "warning")
    except Exception as e:
        handle_error(e)
        if args.verbose:
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    main()
