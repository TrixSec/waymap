# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.

"""Interactive CLI wizard for waymap."""

import argparse
import os
from typing import Dict, List, Optional, Tuple

from lib.core.config import get_config
from lib.ui.display import (
    colored,
    confirm_action,
    print_header,
    print_separator,
    print_status,
    prompt_line,
)
from lib.utils.validators import (
    validate_crawl_depth,
    validate_thread_count,
    validate_url,
)
from lib.utils.url_utils import (
    has_query_parameters,
    filter_urls_with_params,
)

config = get_config()

# Grouped scan catalog — keys must match CLI --scan choices and validators.py
SCAN_CATALOG: List[Tuple[str, List[Tuple[str, str, str]]]] = [
    (
        "Injection Scans",
        [
            ("all", "Full comprehensive scan", "Runs every standard vulnerability module"),
            ("sqli", "SQL Injection", "Boolean, error, and time-based techniques"),
            ("xss", "Cross-Site Scripting", "Basic + optional filter-bypass payloads"),
            ("cmdi", "Command Injection", "Error-based OS command injection"),
            ("rce", "Remote Code Execution", "Safe marker-based RCE detection"),
            ("ssti", "Server-Side Template Injection", "Template engine payload testing"),
            ("lfi", "Local File Inclusion", "Path traversal / file read"),
            ("open-redirect", "Open Redirect", "Unvalidated redirect parameters"),
            ("crlf", "CRLF Injection", "HTTP response splitting / header injection"),
            ("cors", "CORS Misconfiguration", "Permissive cross-origin policies"),
            ("injection-advanced", "Advanced Injection", "SSRF, XXE, NoSQL, HPP, prototype pollution"),
        ],
    ),
    (
        "Recon & Hardening",
        [
            ("recon", "Foundation Recon", "Tech fingerprint, sitemap, DNS, buckets"),
            ("misconfig", "Misconfiguration Scan", "Headers, admin panels, sensitive files"),
            ("redirect", "Redirect & Header Injection", "Host header, open redirect, CRLF bundle"),
        ],
    ),
    (
        "Specialized",
        [
            ("graphql-suite", "GraphQL Security Suite", "Introspection, batching, depth checks"),
            ("auth-logic", "Auth & Access Control", "IDOR, JWT, OAuth signals"),
            ("cache-smuggling", "Cache & Smuggling", "Cache poisoning, HTTP desync indicators"),
            ("wordpress-extras", "WordPress Extras", "User enum, xmlrpc, readme exposure"),
            ("optional", "Optional Checks", "WebSocket, extended WAF, redirect chains"),
        ],
    ),
]

SCAN_BY_KEY: Dict[str, Tuple[str, str, str]] = {}
SCAN_BY_NUMBER: Dict[str, str] = {}


def _build_scan_lookup() -> None:
    """Build lookup maps from the catalog."""
    if SCAN_BY_KEY:
        return
    idx = 1
    for _group, items in SCAN_CATALOG:
        for key, label, _desc in items:
            SCAN_BY_KEY[key] = (label, _desc, str(idx))
            SCAN_BY_NUMBER[str(idx)] = key
            idx += 1


def _prompt(text: str, default: Optional[str] = None) -> str:
    return prompt_line(text, default)


def _prompt_yes_no(text: str, default: bool = False) -> bool:
    return confirm_action(text, default=default)


def _prompt_int(
    text: str,
    default: int,
    minimum: int,
    maximum: int,
    validator=None,
) -> int:
    while True:
        raw = _prompt(text, str(default))
        try:
            value = int(raw)
        except ValueError:
            print_status("Please enter a valid number.", "error")
            continue
        if validator:
            ok, err = validator(value)
            if not ok:
                print_status(err or "Invalid value.", "error")
                continue
        elif value < minimum or value > maximum:
            print_status(f"Value must be between {minimum} and {maximum}.", "error")
            continue
        return value


def _print_scan_menu() -> None:
    _build_scan_lookup()
    print(colored("\n[?] Select Scan Type (number or name, e.g. sqli / all):", "yellow"))
    print(colored("    Tip: press Enter for 'all' (comprehensive scan)\n", "cyan"))
    for group_name, items in SCAN_CATALOG:
        print(colored(f"  ── {group_name} ──", "magenta"))
        for key, label, desc in items:
            num = SCAN_BY_KEY[key][2]
            print(colored(f"  {num:>2}. {label:<28}", "white") + colored(f" ({key})", "grey"))
            print(colored(f"      {desc}", "grey"))
        print()


def _resolve_scan_choice(raw: str) -> Optional[str]:
    _build_scan_lookup()
    choice = (raw or "1").strip().lower()
    if choice in SCAN_BY_NUMBER:
        return SCAN_BY_NUMBER[choice]
    if choice in SCAN_BY_KEY:
        return choice
    aliases = {
        "sql": "sqli",
        "sql injection": "sqli",
        "open redirect": "open-redirect",
        "advanced": "injection-advanced",
        "wp": "wordpress-extras",
        "wordpress": "wordpress-extras",
    }
    if choice in aliases:
        return aliases[choice]
    return None


def _select_scan_type() -> str:
    _print_scan_menu()
    while True:
        raw = _prompt("    Choice", "1")
        scan = _resolve_scan_choice(raw)
        if scan:
            label = SCAN_BY_KEY[scan][0]
            print_status(f"Selected: {label} ({scan})", "success")
            return scan
        print_status(
            "Invalid choice. Enter a menu number (e.g. 3) or scan name (e.g. sqli, xss, all).",
            "error",
        )


def _get_target_urls(args: argparse.Namespace) -> List[str]:
    """Load target URLs from args.multi_target or args.target."""
    urls = []
    if args.multi_target:
        try:
            with open(args.multi_target, "r", encoding="utf-8") as f:
                urls = [line.strip() for line in f if line.strip()]
        except Exception:
            urls = []
    elif args.target:
        urls = [args.target]
    return urls


def _configure_target(args: argparse.Namespace, *, required: bool = True, allow_multi: bool = True) -> None:
    print(colored("\n[?] Target Configuration", "yellow"))

    if allow_multi and _prompt_yes_no("Scan multiple targets from a file?", default=False):
        while True:
            path = _prompt("Path to targets file (one URL per line)")
            if path and os.path.isfile(path):
                args.multi_target = path
                print_status(f"Multi-target file: {path}", "success")
                return
            print_status("File not found. Please enter a valid path.", "error")
        return

    while not args.target:
        label = "Enter Target URL (https://example.com)"
        if not required:
            label += " — optional, press Enter to skip"
        target = _prompt(label)
        if not target:
            if not required:
                return
            continue
        if not target.startswith(("http://", "https://")):
            target = f"https://{target.lstrip('/')}"
        ok, err = validate_url(target)
        if ok:
            args.target = target
            print_status(f"Target: {args.target}", "success")
        else:
            print_status(err or "Invalid URL.", "error")


def _configure_scan_options(args: argparse.Namespace, *, include_crawl: bool = True) -> None:
    print(colored("\n[?] Scan Options", "yellow"))

    if include_crawl:
        # Check if we need to ask about crawling
        urls = _get_target_urls(args)
        parameterized_urls = filter_urls_with_params(urls)
        non_parameterized_urls = [url for url in urls if url not in parameterized_urls]
        
        if len(non_parameterized_urls) == 0 and len(urls) > 0:
            # All URLs already have parameters, skip crawl prompt
            args.crawl = 0
            print_status("All targets already have parameters, skipping crawl.", "info")
        else:
            args.crawl = _prompt_int(
                "Crawl depth (0 = no crawl, 1-10 to discover parameterized URLs)",
                default=0,
                minimum=0,
                maximum=10,
                validator=validate_crawl_depth,
            )

    args.threads = _prompt_int(
        "Thread count",
        default=1,
        minimum=1,
        maximum=config.MAX_THREADS,
        validator=lambda n: validate_thread_count(n, config.MAX_THREADS),
    )

    if args.scan == "sqli":
        print(colored("\n  SQLi techniques: B=Boolean  E=Error  T=Time-based", "cyan"))
        technique = _prompt("SQLi techniques (e.g. BET, BE, B)", "BET").upper()
        valid_chars = set("BET")
        filtered = "".join(c for c in technique if c in valid_chars)
        args.technique = filtered or "BET"
        print_status(f"SQLi techniques: {args.technique}", "info")

    args.verbose = _prompt_yes_no("Enable verbose output?", default=False)
    args.no_prompt = _prompt_yes_no(
        "Disable interactive prompts during scan? (recommended for automation)",
        default=False,
    )
    args.flush = _prompt_yes_no(
        "Flush/delete previous scan results and start fresh?",
        default=False,
    )


def _configure_api_scan(args: argparse.Namespace) -> None:
    args.scan = "api"
    print(colored("\n[?] API Scan Configuration", "yellow"))
    print("    1. REST (default)")
    print("    2. GraphQL")
    api_choice = _prompt("API type", "1")
    args.api_type = "graphql" if api_choice == "2" else "rest"

    if args.api_type == "rest":
        endpoints = _prompt("REST endpoints (comma-separated, optional)", "")
        if endpoints:
            args.api_endpoints = endpoints


def _configure_wordpress_profile(args: argparse.Namespace) -> None:
    args.profile = "wordpress"
    token = _prompt("WPScan API token (optional — uses env/secrets file if blank)", "")
    if token:
        args.wpscan_token = token
    print_status("Profile: WordPress (WPScan API)", "success")


def _configure_dork_discovery(args: argparse.Namespace) -> None:
    print(colored("\n[?] Google Dork Discovery (SearchAPI)", "yellow"))
    args.dork = _prompt("Enter dork query (e.g. inurl:.php?id=)")
    if not args.dork:
        print_status("Dork query is required.", "error")
        from lib.core.interrupt import exit_clean
        exit_clean("Scan cancelled.", code=1)
    key = _prompt("SearchAPI key (optional — uses env/secrets file if blank)", "")
    if key:
        args.dork_api_key = key
    output = _prompt("Output file (optional)", "")
    if output:
        args.dork_output = output
    if _prompt_yes_no("Auto-run SQLi scan on discovered URLs?", default=True):
        args.scan = "sqli"
        args.technique = "BET"
    args.threads = _prompt_int(
        "Thread count for auto-scan",
        default=1,
        minimum=1,
        maximum=config.MAX_THREADS,
        validator=lambda n: validate_thread_count(n, config.MAX_THREADS),
    )


def _configure_waf_only(args: argparse.Namespace) -> None:
    args.check_waf = True
    print_status("Mode: WAF detection only", "info")


def _configure_auth(args: argparse.Namespace) -> None:
    if not _prompt_yes_no("\nConfigure authentication?", default=False):
        return

    print(colored("\n[?] Auth Type:", "yellow"))
    print("    1. Form-Based (default)")
    print("    2. Bearer Token")
    print("    3. Basic Auth")
    print("    4. API Key")

    ac = _prompt("Choice", "1")
    if ac == "2":
        args.auth_type = "bearer"
        args.token = _prompt("Bearer token")
    elif ac == "3":
        args.auth_type = "basic"
        args.username = _prompt("Username")
        args.password = _prompt("Password")
    elif ac == "4":
        args.auth_type = "api_key"
        args.token = _prompt("API key")
        header = _prompt("Header name", "X-API-Key")
        args.auth_header = header or "X-API-Key"
    else:
        args.auth_type = "form"
        args.username = _prompt("Username")
        args.password = _prompt("Password")
        args.auth_url = _prompt("Login URL (optional)", "")


def _configure_ai(args: argparse.Namespace) -> None:
    from lib.ai.llm_provider import (
        get_llm_config,
        test_llm_connection,
        save_llm_config_to_secrets,
        is_llm_available
    )

    print(colored("\n[?] AI Configuration", "yellow"))
    
    # First, simple "use AI?" prompt
    if not _prompt_yes_no("Would you like to use AI features?", default=False):
        args.analyze = False
        args.ai_report = False
        args.ai_payloads = False
        args.ai_discovery = False
        print_status("AI features disabled.", "info")
        return
    
    # Check existing config first
    existing_config = get_llm_config()
    if is_llm_available():
        print_status("Existing LLM config found. Testing connection...", "info")
        if test_llm_connection():
            print_status("Connection successful!", "success")
            args.analyze = True
            args.ai_report = True
            return
        else:
            print_status("Existing config failed to connect!", "error")

    # Ask if user wants to configure AI
    if not _prompt_yes_no("Would you like to configure AI now?", default=True):
        args.analyze = False
        args.ai_report = False
        args.ai_payloads = False
        args.ai_discovery = False
        print_status("AI features disabled.", "info")
        return

    # Provider selection
    print("\n    1. Cerebras (default)")
    print("    2. OpenAI")
    print("    3. Anthropic")
    print("    4. Ollama (local)")
    provider_choice = _prompt("Choice", "1")
    provider_map = {
        "1": "cerebras",
        "2": "openai",
        "3": "anthropic",
        "4": "ollama"
    }
    selected_provider = provider_map.get(provider_choice, "cerebras")
    
    # API key
    api_key = _prompt(f"Enter {selected_provider.capitalize()} API key")
    if not api_key:
        print_status("No API key provided, AI features disabled.", "warning")
        args.analyze = False
        args.ai_report = False
        args.ai_payloads = False
        args.ai_discovery = False
        return

    # Model
    default_model = "gpt-oss-120b" if selected_provider == "cerebras" else "gpt-4o-mini" if selected_provider == "openai" else "claude-3-haiku-20240307" if selected_provider == "anthropic" else "llama3.1"
    model = _prompt(f"Model (default: {default_model})", default_model)

    # Build config
    new_config = existing_config
    new_config.provider = selected_provider
    new_config.api_key = api_key
    new_config.model = model

    # Test connection
    print_status("Testing connection...", "info")
    # Temporarily set env vars for test? Wait, no: let's save first? Or just test with new config
    # Wait, current get_llm_config() uses secrets/env, so let's save it first, then test
    save_llm_config_to_secrets(new_config)
    
    if test_llm_connection():
        print_status("Connection successful! Config saved.", "success")
        args.analyze = _prompt_yes_no("Enable AI result analysis?", default=True)
        args.ai_report = _prompt_yes_no("Generate AI-enhanced reports?", default=True)
        args.ai_payloads = _prompt_yes_no("Use AI-generated adaptive payloads?", default=True)
        args.ai_discovery = _prompt_yes_no("Use AI for attack surface discovery?", default=True)
    else:
        print_status("Connection test failed! AI features will be disabled.", "error")
        args.analyze = False
        args.ai_report = False
        args.ai_payloads = False
        args.ai_discovery = False


def _configure_reporting(args: argparse.Namespace) -> None:
    if not _prompt_yes_no("\nGenerate reports after scan?", default=True):
        return

    print(colored("\n[?] Report formats (comma-separated):", "yellow"))
    print("    html, csv, markdown, pdf")
    fmt = _prompt("Formats", "html,csv,markdown")
    args.report_format = fmt or "html,csv,markdown"
    args.output_dir = _prompt("Output directory", "reports")
    print_status(f"Reports → {args.output_dir}/ ({args.report_format})", "info")


def _print_summary(args: argparse.Namespace) -> None:
    _build_scan_lookup()
    print_separator("─", "cyan", 60)
    print_header("Scan Summary", color="cyan", top_padding=0, bottom_padding=0)
    if args.multi_target:
        print_status(f"Targets file: {args.multi_target}", "info")
    elif args.target:
        print_status(f"Target:       {args.target}", "info")
    if args.check_waf:
        print_status("Action:       WAF detection", "info")
    elif args.dork:
        print_status(f"Dork:         {args.dork}", "info")
        if args.scan:
            print_status(f"After dork:   auto {args.scan} scan", "info")
    elif args.profile:
        print_status(f"Profile:      {args.profile}", "info")
    elif args.scan:
        label = SCAN_BY_KEY.get(args.scan, (args.scan, "", ""))[0]
        print_status(f"Scan:         {label} ({args.scan})", "info")
    if args.crawl:
        print_status(f"Crawl depth:  {args.crawl}", "info")
    if args.threads and args.threads > 1:
        print_status(f"Threads:      {args.threads}", "info")
    if args.technique:
        print_status(f"SQLi tech:    {args.technique}", "info")
    if args.auth_type:
        print_status(f"Auth:         {args.auth_type}", "info")
    if args.report_format:
        print_status(f"Reports:      {args.report_format}", "info")
    if args.analyze or args.ai_report or args.ai_payloads or args.ai_discovery:
        ai_features = []
        if args.analyze:
            ai_features.append("result analysis")
        if args.ai_report:
            ai_features.append("AI reports")
        if args.ai_payloads:
            ai_features.append("adaptive payloads")
        if args.ai_discovery:
            ai_features.append("attack surface discovery")
        print_status(f"AI features:  {', '.join(ai_features)}", "info")
    print_separator("─", "cyan", 60)
    print()


def run_interactive_wizard() -> argparse.Namespace:
    """Run the full interactive configuration wizard."""
    _build_scan_lookup()

    print_header("Interactive Mode", color="cyan")
    print_status("Configure your scan — all CLI scan types are available here.", "info")
    print()

    args = argparse.Namespace(
        target=None,
        multi_target=None,
        scan=None,
        profile=None,
        crawl=0,
        threads=1,
        no_prompt=False,
        verbose=False,
        check_waf=False,
        waf=None,
        check_updates=False,
        technique=None,
        deepscan=None,
        api_type="rest",
        api_endpoints=None,
        auth_type=None,
        username=None,
        password=None,
        token=None,
        auth_header="X-API-Key",
        auth_url=None,
        report_format=None,
        output_dir="reports",
        dork=None,
        dork_api_key=None,
        dork_output=None,
        wpscan_token=None,
        use_ai=False,
        analyze=False,
        ai_report=False,
        ai_payloads=False,
        ai_discovery=False,
        llm_provider=None,
        llm_model=None,
        flush=False
    )

    print(colored("[?] Select Scan Mode:", "yellow"))
    print("    1. Vulnerability Scan (all 19 scan types)")
    print("    2. API Security Scan (REST / GraphQL)")
    print("    3. WordPress Profile (WPScan API)")
    print("    4. Google Dork Discovery (SearchAPI)")
    print("    5. WAF Detection Only")
    mode = _prompt("Choice", "1")

    if mode == "2":
        _configure_target(args, required=True)
        _configure_api_scan(args)
        _configure_scan_options(args, include_crawl=False)
    elif mode == "3":
        _configure_target(args, required=True)
        _configure_wordpress_profile(args)
    elif mode == "4":
        _configure_dork_discovery(args)
        _configure_target(args, required=False)
    elif mode == "5":
        _configure_target(args, required=True)
        _configure_waf_only(args)
    else:
        _configure_target(args, required=True)
        args.scan = _select_scan_type()
        _configure_scan_options(args, include_crawl=True)

    if not args.check_waf and not args.dork:
        _configure_auth(args)
        _configure_reporting(args)
        _configure_ai(args)
    elif args.dork and args.scan:
        _configure_reporting(args)
        _configure_ai(args)

    _print_summary(args)

    if not _prompt_yes_no("Start scan now?", default=True):
        from lib.core.interrupt import exit_clean
        exit_clean("Scan cancelled.")

    return args
