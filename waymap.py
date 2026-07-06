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
        'urllib3': 'urllib3',
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
from lib.core.interrupt import exit_clean, setup_interrupt_handler, reset_interrupt
from lib.core.error_handler import validate_environment, handle_error
from lib.ui import print_banner, print_header, print_status, print_separator, confirm_action
from lib.ui.interactive import run_interactive_wizard
from lib.utils import validate_url, validate_crawl_depth, validate_thread_count, validate_scan_type
from lib.utils.url_utils import has_query_parameters, filter_urls_with_params

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
        from lib.core import http
        
        animate_loading("Checking for updates", 1)
        response = http.get(config.VERSION_CHECK_URL, timeout=5)
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
                        help='SQL injection techniques [B boolean, E error, T time, U union, I inline, S stacked]. Combine like BETUIS')
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
    util_group.add_argument('--flush', action='store_true', help='Flush/delete previous scan results and findings')
    
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

    # AI/LLM Arguments
    ai_group = parser.add_argument_group('AI/LLM')
    ai_group.add_argument('--use-ai', action='store_true', help='Enable all AI features (result analysis + AI reports + payloads + discovery)')
    ai_group.add_argument('--analyze', action='store_true', help='Analyze results with AI after scan')
    ai_group.add_argument('--ai-report', action='store_true', help='Generate AI-enhanced reports')
    ai_group.add_argument('--ai-payloads', action='store_true', help='Use AI-generated adaptive payloads')
    ai_group.add_argument('--ai-discovery', action='store_true', help='Use AI for attack surface discovery')
    ai_group.add_argument('--llm-provider', type=str, choices=['none', 'openai', 'anthropic', 'ollama', 'cerebras'], help='LLM provider to use')
    ai_group.add_argument('--llm-model', type=str, help='LLM model to use')

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


def _validate_and_configure_ai(args):
    """Validate AI configuration."""
    from lib.ai.llm_provider import (
        get_llm_config,
        test_llm_connection,
        save_llm_config_to_secrets,
        is_llm_available,
        LLMConfig
    )
    from lib.ui import print_status, prompt_line, confirm_action

    # Handle --use-ai
    if getattr(args, 'use_ai', False):
        args.analyze = True
        args.ai_report = True
        args.ai_payloads = True
        args.ai_discovery = True
    
    # Check if AI features are requested
    ai_requested = getattr(args, 'analyze', False) or getattr(args, 'ai_report', False) or getattr(args, 'ai_payloads', False) or getattr(args, 'ai_discovery', False)
    if not ai_requested:
        return
    
    # Handle --llm-provider and --llm-model
    llm_config = get_llm_config()
    if getattr(args, 'llm_provider', None):
        llm_config.provider = args.llm_provider
    if getattr(args, 'llm_model', None):
        llm_config.model = args.llm_model
    
    # Check existing config
    if is_llm_available():
        print_status("Testing LLM connection...", "info")
        if test_llm_connection():
            print_status("LLM connection successful!", "success")
            return
        else:
            print_status("LLM connection failed!", "error")
    else:
        print_status("No valid LLM config found.", "warning")
    
    # Ask for API key if no_prompt is False
    if not getattr(args, 'no_prompt', False):
        if not confirm_action("Would you like to configure AI features now?", default=True):
            args.analyze = False
            args.ai_report = False
            args.ai_payloads = False
            args.ai_discovery = False
            print_status("AI features disabled.", "info")
            return
        
        print("\nAvailable providers:")
        print("    1. Cerebras (default)")
        print("    2. OpenAI")
        print("    3. Anthropic")
        print("    4. Ollama (local)")
        
        provider_choice = prompt_line("Choice", "1")
        provider_map = {"1": "cerebras", "2": "openai", "3": "anthropic", "4": "ollama"}
        selected_provider = provider_map.get(provider_choice, "cerebras")
        api_key = prompt_line(f"Enter {selected_provider.capitalize()} API key")
        if not api_key:
            print_status("No API key provided, AI features disabled.", "warning")
            args.analyze = False
            args.ai_report = False
            args.ai_payloads = False
            args.ai_discovery = False
            return
        
        default_model = (
            "gpt-oss-120b" if selected_provider == "cerebras"
            else "gpt-4o-mini" if selected_provider == "openai"
            else "claude-3-haiku-20240307" if selected_provider == "anthropic"
            else "llama3.1"
        )
        model = prompt_line(f"Model (default: {default_model})", default_model)
        
        llm_config.provider = selected_provider
        llm_config.api_key = api_key
        llm_config.model = model
        save_llm_config_to_secrets(llm_config)
        
        print_status("Testing LLM connection...", "info")
        if test_llm_connection():
            print_status("LLM connection successful!", "success")
        else:
            print_status("LLM connection failed! AI features disabled.", "error")
            args.analyze = False
            args.ai_report = False
            args.ai_payloads = False
            args.ai_discovery = False
            return


def _auto_set_crawl_depth(args):
    """Auto-set crawl depth to 0 if all targets already have query parameters."""
    # Get target URLs
    urls = []
    if args.multi_target:
        from lib.utils.file_utils import load_file_lines
        try:
            urls = load_file_lines(args.multi_target)
        except Exception:
            urls = []
    elif args.target:
        urls = [args.target]
    
    if len(urls) == 0:
        return
    
    parameterized_urls = filter_urls_with_params(urls)
    non_parameterized_urls = [url for url in urls if url not in parameterized_urls]
    
    if len(non_parameterized_urls) == 0 and len(urls) > 0:
        # All URLs have parameters, auto-set crawl to 0
        args.crawl = 0
        print_status("All targets already have parameters, auto-setting crawl depth to 0.", "info")


def _run():
    """Main scan logic."""
    print_banner()
    
    # Check if running in interactive mode (no args)
    if len(sys.argv) == 1:
        args = run_interactive_wizard()
    else:
        args = parse_arguments()
    # Validate and configure AI
    _validate_and_configure_ai(args)
    # Auto-set crawl depth
    _auto_set_crawl_depth(args)
    
    # Handle update check
    if args.check_updates:
        check_for_updates()
        return

    if getattr(args, 'no_prompt', False) and not os.environ.get('WAYMAP_NO_PROMPT'):
        os.environ['WAYMAP_NO_PROMPT'] = '1'
        
    # Flush previous findings if requested
    if getattr(args, 'flush', False):
        from lib.core.result_manager import ResultManager
        from lib.utils.file_utils import load_file_lines
        
        # Collect all target domains
        domains = set()
        
        if args.target:
            domain = urlparse(args.target).netloc
            domains.add(domain)
        elif args.multi_target:
            try:
                targets = load_file_lines(args.multi_target)
                for target in targets:
                    if target:
                        domain = urlparse(target).netloc
                        domains.add(domain)
            except Exception as e:
                logger.error(f"Could not load multi-target list: {e}")
        
        # Flush each domain's results
        for domain in domains:
            print_status(f"Flushing previous findings for domain: {domain}", "info")
            result_manager = ResultManager(domain)
            result_manager.flush()
        if domains:
            print_status("Flushed previous scan results successfully!", "success")

    # Export WPScan token for modules that read from environment
    if getattr(args, 'wpscan_token', None) and not os.environ.get('WPSCAN_API_TOKEN'):
        os.environ['WPSCAN_API_TOKEN'] = args.wpscan_token

    # Handle Google dork discovery (SearchAPI)
    if getattr(args, 'dork', None):
        from lib.core.secrets import get_secret
        from lib.discovery.searchapi_dork import discover_google_dork, save_discovered_urls

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
            scanner = WaymapScanner(
                thread_count=args.threads, 
                no_prompt=getattr(args, 'no_prompt', False),
                ai_payloads=getattr(args, 'ai_payloads', False),
                ai_discovery=getattr(args, 'ai_discovery', False)
            )
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
            
        from lib.core.auth import setup_authentication
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
            from lib.api.api_scanner import perform_api_scan
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
                scanner = WaymapScanner(
                    thread_count=args.threads, 
                    no_prompt=args.no_prompt,
                    ai_payloads=getattr(args, 'ai_payloads', False),
                    ai_discovery=getattr(args, 'ai_discovery', False)
                )

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
                
                # Analyze vulnerabilities with AI if enabled
                if getattr(args, 'analyze', False) or getattr(args, 'use_ai', False):
                    print_separator()
                    print_header("AI Vulnerability Analysis", color="cyan")
                    
                    from lib.ai.result_analyzer import analyze_vulnerability
                    from lib.core.result_manager import ResultManager
                    
                    domain = urlparse(args.target).netloc
                    result_manager = ResultManager(domain)
                    results = result_manager.get_results()
                    
                    # Collect all findings for chain analysis
                    all_findings = []
                    analyzed_ai = {}
                    
                    # Analyze each finding
                    for scan_entry in results.get('scans', []):
                        for scan_type, findings in scan_entry.items():
                            if isinstance(findings, dict):
                                for sub_type, sub_findings in findings.items():
                                    for finding in sub_findings:
                                        if isinstance(finding, dict):
                                            all_findings.append(finding)
                                            # Skip if already has ai analysis
                                            if 'ai_analysis' in finding and finding['ai_analysis']:
                                                continue
                                                
                                            vuln_url = finding.get('url') or finding.get('Vulnerable URL') or ''
                                            vuln_param = finding.get('parameter') or finding.get('Parameter') or ''
                                            vuln_payload = finding.get('payload') or finding.get('Payload') or ''
                                            vuln_details = finding.get('details') or ''
                                            ai_key = (scan_type, vuln_url, vuln_param)
                                            if ai_key in analyzed_ai:
                                                finding['ai_analysis'] = analyzed_ai[ai_key]
                                                continue
                                            
                                            analysis = analyze_vulnerability(
                                                vuln_type=scan_type,
                                                url=vuln_url,
                                                parameter=vuln_param,
                                                payload=vuln_payload,
                                                details=vuln_details
                                            )
                                            
                                            if analysis:
                                                analyzed_ai[ai_key] = analysis
                                                # Save AI analysis to finding
                                                finding['ai_analysis'] = analysis
                                                result_manager.replace_all(results)  # Save updated findings
                                                # Pretty output
                                                from lib.ui import colored
                                                print()
                                                print_separator()
                                                print(colored(f"AI Analysis: {vuln_url}", "cyan"))
                                                print_separator()
                                                print(colored("Severity Justification:", "yellow") + " " + analysis.get('severity_justification', 'N/A'))
                                                print(colored("Impact:", "yellow") + " " + analysis.get('impact', 'N/A'))
                                                print(colored("Remediation Steps:", "yellow"))
                                                for step in analysis.get('remediation_steps', []):
                                                    print(f"  - {step}")
                                                print(colored("False Positive Likelihood:", "yellow") + f" {analysis.get('false_positive_likelihood', 'N/A')}")
                                                print(colored("Confidence Score:", "yellow") + f" {analysis.get('confidence_score', 'N/A')}")
                            elif isinstance(findings, list):
                                for finding in findings:
                                    if isinstance(finding, dict):
                                        all_findings.append(finding)
                                        # Skip if already has ai analysis
                                        if 'ai_analysis' in finding and finding['ai_analysis']:
                                            continue
                                            
                                        vuln_url = finding.get('url') or finding.get('Vulnerable URL') or ''
                                        vuln_param = finding.get('parameter') or finding.get('Parameter') or ''
                                        vuln_payload = finding.get('payload') or finding.get('Payload') or ''
                                        vuln_details = finding.get('details') or ''
                                        ai_key = (scan_type, vuln_url, vuln_param)
                                        if ai_key in analyzed_ai:
                                            finding['ai_analysis'] = analyzed_ai[ai_key]
                                            continue
                                        
                                        analysis = analyze_vulnerability(
                                            vuln_type=scan_type,
                                            url=vuln_url,
                                            parameter=vuln_param,
                                            payload=vuln_payload,
                                            details=vuln_details
                                        )
                                        
                                        if analysis:
                                            analyzed_ai[ai_key] = analysis
                                            # Save AI analysis to finding
                                            finding['ai_analysis'] = analysis
                                            result_manager.replace_all(results)  # Save updated findings
                                            # Pretty output
                                            from lib.ui import colored
                                            print()
                                            print_separator()
                                            print(colored(f"AI Analysis: {vuln_url}", "cyan"))
                                            print_separator()
                                            print(colored("Severity Justification:", "yellow") + " " + analysis.get('severity_justification', 'N/A'))
                                            print(colored("Impact:", "yellow") + " " + analysis.get('impact', 'N/A'))
                                            print(colored("Remediation Steps:", "yellow"))
                                            for step in analysis.get('remediation_steps', []):
                                                print(f"  - {step}")
                                            print(colored("False Positive Likelihood:", "yellow") + f" {analysis.get('false_positive_likelihood', 'N/A')}")
                                            print(colored("Confidence Score:", "yellow") + f" {analysis.get('confidence_score', 'N/A')}")
                
                # Analyze finding chains if AI is enabled and we have multiple findings
                if (getattr(args, 'analyze', False) or getattr(args, 'use_ai', False)) and len(all_findings) > 1:
                    print_separator()
                    print_header("AI Finding Chain Analysis", color="magenta")
                    
                    from lib.ai.chain_analyzer import analyze_finding_chains
                    chains = analyze_finding_chains(all_findings, args.target)
                    
                    if chains:
                        from lib.ui import colored
                        for chain in chains:
                            print()
                            print_separator()
                            print(colored(f"Chain: {chain.get('chain_name', 'Unknown')}", "magenta"))
                            print(colored("Description:", "yellow") + " " + chain.get('chain_description', 'N/A'))
                            print(colored("Severity:", "yellow") + " " + chain.get('severity', 'N/A'))
                            print(colored("Attack Flow:", "yellow"))
                            for step in chain.get('attack_flow', []):
                                print(f"  - {step}")
                            print(colored("Confidence:", "yellow") + f" {chain.get('confidence', 'N/A')}")
        
        # Enhance scan results with AI if --ai-report is enabled
        if getattr(args, 'ai_report', False) or getattr(args, 'use_ai', False):
            from lib.ai.report_enhancer import enhance_report_data
            scan_results = enhance_report_data(scan_results, args.target)

        # Generate Reports
        if args.report_format:
            from lib.core.reporting import generate_all_reports

            print_separator()
            print_status("Generating Reports...", "info")
            formats = [f.strip() for f in args.report_format.split(',') if f.strip()]
            generate_all_reports(scan_results, args.output_dir, formats=formats)

    except KeyboardInterrupt:
        exit_clean()
    except Exception as e:
        handle_error(str(e))
        if args.verbose:
            import traceback
            traceback.print_exc()


if __name__ == "__main__":
    main()
