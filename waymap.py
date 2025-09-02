
# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.

import os
import sys
import time
import logging

def colored(text, color):
    # ANSI escape codes for colors
    ansi_colors = {
        "grey": "\033[90m",
        "red": "\033[91m",
        "green": "\033[92m",
        "yellow": "\033[93m",
        "blue": "\033[94m",
        "magenta": "\033[95m",
        "cyan": "\033[96m",
        "white": "\033[97m"
    }
    reset = "\033[0m"
    color_code = ansi_colors.get(color, "")
    return f"{color_code}{text}{reset}" if color_code else text

def generate_random_headers():
    from lib.parse.random_headers import generate_random_headers as _generate_random_headers
    return _generate_random_headers()

session_dir = 'sessions'
headers = generate_random_headers()

# ===== ENHANCED UI COMPONENTS =====
def print_separator(char="─", color="cyan", length=60):
    """Print a decorative separator line"""
    print(colored(char * length, color))

def print_header(text, color="yellow", top_padding=1, bottom_padding=1):
    """Print a formatted header"""
    if top_padding:
        print()
    print(colored(f"╔{'═' * (len(text) + 2)}╗", color))
    print(colored(f"║ {text.upper()} ║", color))
    print(colored(f"╚{'═' * (len(text) + 2)}╝", color))
    if bottom_padding:
        print()

def print_status(message, status_type="info", icon="•"):
    """Print status messages with colored icons"""
    colors = {
        "info": "cyan",
        "success": "green",
        "warning": "yellow",
        "error": "red",
        "debug": "blue"
    }
    icons = {
        "info": "•",
        "success": "✓",
        "warning": "⚠",
        "error": "✗",
        "debug": "⚙"
    }
    color = colors.get(status_type, "white")
    icon_char = icons.get(status_type, icon)
    print(colored(f"[{icon_char}] {message}", color))

def print_progress_bar(iteration, total, prefix='Progress:', suffix='Complete', length=40, fill='█'):
    """Display a progress bar"""
    percent = ("{0:.1f}").format(100 * (iteration / float(total)))
    filled_length = int(length * iteration // total)
    bar = fill * filled_length + '░' * (length - filled_length)
    print(f'\r{prefix} |{bar}| {percent}% {suffix}', end='\r')
    if iteration == total:
        print()

def animate_loading(text, duration=2, frames=["⣾", "⣽", "⣻", "⢿", "⡿", "⣟", "⣯", "⣷"]):
    """Animated loading indicator"""
    end_time = time.time() + duration
    frame_index = 0
    while time.time() < end_time:
        print(f"\r{colored(frames[frame_index], 'cyan')} {text}", end="")
        frame_index = (frame_index + 1) % len(frames)
        time.sleep(0.1)
    print("\r" + " " * (len(text) + 2) + "\r", end="")

def print_table(headers, data, col_colors=None):
    """Print data in a formatted table"""
    if not data:
        return
    
    col_widths = [len(str(header)) for header in headers]
    for row in data:
        for i, item in enumerate(row):
            col_widths[i] = max(col_widths[i], len(str(item)))
    
    # Print header
    header_line = "║"
    for i, header in enumerate(headers):
        header_line += f" {colored(str(header).ljust(col_widths[i]), 'yellow')} ║"
    print(colored("╔" + "═" * (sum(col_widths) + len(headers) * 3 - 1) + "╗", "cyan"))
    print(header_line)
    print(colored("╠" + "═" * (sum(col_widths) + len(headers) * 3 - 1) + "╣", "cyan"))
    
    # Print data
    for row in data:
        row_line = "║"
        for i, item in enumerate(row):
            color = col_colors[i] if col_colors and i < len(col_colors) else "white"
            row_line += f" {colored(str(item).ljust(col_widths[i]), color)} ║"
        print(row_line)
    
    print(colored("╚" + "═" * (sum(col_widths) + len(headers) * 3 - 1) + "╝", "cyan"))

def setup_logger(domain):
    domain_dir = os.path.join(session_dir, domain)
    os.makedirs(domain_dir, exist_ok=True)
    log_file_path = os.path.join(domain_dir, 'logs.txt')

    logging.basicConfig(
        filename=log_file_path,
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

def log_scan_start(target, scan_type):
    logging.info(f'Starting {scan_type} scan on {target}')

def log_scan_end(target, scan_type):
    logging.info(f'Finished {scan_type} scan on {target}')

def log_error(message):
    logging.error(message)

data_dir = os.path.join(os.getcwd(), 'data')
session_dir = os.path.join(os.getcwd(), 'sessions')

def check_for_updates():
    try:
        animate_loading("Checking for updates", 1)
        import requests
        from lib.core.settings import WAYMAP_VERSION
        response = requests.get("https://raw.githubusercontent.com/TrixSec/waymap/main/VERSION", timeout=5)
        response.raise_for_status()
        latest_version = response.text.strip()

        if WAYMAP_VERSION != latest_version:
            print_status(f"New version available: {latest_version}", "warning")
        else:
            print_status("Waymap is up to date", "success")
    except Exception as e:
        print_status(f"Error fetching updates: {e}", "error")

def print_banner():
    banner = r"""
╔══════════════════════════════════════════════════════════════════╗
║ ██╗    ██╗ █████╗ ██╗   ██╗███╗   ███╗ █████╗ ██████╗            ║
║ ██║    ██║██╔══██╗╚██╗ ██╔╝████╗ ████║██╔══██╗██╔══██╗           ║
║ ██║ █╗ ██║███████║ ╚████╔╝ ██╔████╔██║███████║██████╔╝           ║
║ ██║███╗██║██╔══██║  ╚██╔╝  ██║╚██╔╝██║██╔══██║██╔═══╝            ║
║ ╚███╔███╔╝██║  ██║   ██║   ██║ ╚═╝ ██║██║  ██║██║                ║
║  ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝                ║
║                  Fastest Optimized Web Scanner                   ║
╚══════════════════════════════════════════════════════════════════╝
    """
    print(colored(banner, 'cyan'))
    print_separator("═", "cyan", 70)
    from lib.core.settings import WAYMAP_VERSION, AUTHOR, COPYRIGHT
    print(colored(f"Version: {WAYMAP_VERSION:>50}", 'yellow'))
    print(colored(f"Author:  {AUTHOR:>50}", 'yellow'))
    print(colored(f"{COPYRIGHT:>70}", 'yellow'))
    print_separator("═", "cyan", 70)
    print()

def load_payloads(file_path):
    try:
        with open(file_path, 'r') as f:
            return [line.strip() for line in f.readlines()]
    except FileNotFoundError:
        log_error(f"Payload file {file_path} not found.")
        print_status(f"Payload file {file_path} not found.", "error")
        return []

def save_to_file(domain, urls):
    domain_path = os.path.join(session_dir, domain)
    os.makedirs(domain_path, exist_ok=True)
    crawl_file = os.path.join(domain_path, 'crawl.txt')

    with open(crawl_file, 'w') as f:
        for url in urls:
            f.write(url + '\n')

def load_crawled_urls(domain):
    domain_path = os.path.join(session_dir, domain)
    crawl_file = os.path.join(domain_path, 'crawl.txt')

    if os.path.exists(crawl_file):
        with open(crawl_file, 'r') as f:
            return [url.strip() for url in f.readlines()]
    return []

def handle_redirection(target_url):
    try:
        import requests
        from urllib.parse import urlparse
        response = requests.get(target_url, allow_redirects=True, headers=headers, timeout=10, verify=False)
        final_url = response.url
        parsed_final_url = urlparse(final_url)
        parsed_target_url = urlparse(target_url)

        if parsed_final_url.netloc != parsed_target_url.netloc:
            print_status(f"Target redirected to different domain: {final_url}", "warning")
            return final_url
        return target_url
    except Exception as e:
        log_error(f"Error connecting to {target_url}: {e}")
        print_status(f"Cannot connect to URL: {target_url}", "error")
        return target_url

def is_valid_url(url):
    from urllib.parse import urlparse
    parsed = urlparse(url)
    return bool(parsed.netloc) and bool(parsed.scheme)

def has_query_parameters(url):
    return any(symbol in url for symbol in ['?', '&', '='])

def is_within_domain(url, base_domain):
    from urllib.parse import urlparse
    return urlparse(url).netloc == base_domain

def crawl(target, crawl_depth, thread_count=1, no_prompt=False):
    domain = target.split("//")[-1].split("/")[0]
    import requests
    from lib.waymapcrawlers.crawler import run_crawler

    try:
        response = requests.get(target, headers=headers, timeout=10, verify=False)
        response.raise_for_status()
    except Exception as e:
        log_error(f"Cannot connect to {target}: {e}")
        print_status(f"Crawler cannot connect to URL: {target}", "error")
        return None

    target = handle_redirection(target)

    if not target or not is_valid_url(target):
        log_error(f"Skipping {target} due to connection issues.")
        print_status(f"Skipping {target} due to connection issues", "warning")
        return None

    setup_logger(domain)

    crawled_urls = load_crawled_urls(domain)

    if not crawled_urls:
        print_status(f"Starting crawling on: {target} with depth {crawl_depth}", "info")
        crawled_urls = run_crawler(target, crawl_depth, thread_count=thread_count, no_prompt=no_prompt)
        crawled_urls = [url for url in crawled_urls if is_valid_url(url) and has_query_parameters(url) and is_within_domain(url, domain)]
        save_to_file(domain, crawled_urls)
        print_status(f"Found {len(crawled_urls)} URLs with parameters", "success")

    return crawled_urls

def scan(target, scan_type, crawled_urls=None, provided_urls=None, thread_count=1, no_prompt=False, technique_string=None):
    log_scan_start(target, scan_type)
    from lib.injection.cmdi import perform_cmdi_scan
    from lib.injection.ssti import perform_ssti_scan
    from lib.injection.lfi import perform_lfi_scan
    from lib.injection.xss import perform_xss_scan
    from lib.injection.openredirect import perform_redirect_scan
    from lib.injection.crlf import perform_crlf_scan
    from lib.injection.cors import perform_cors_scan
    from lib.injection.sqlin.sql import run_sql_tests

    cmdi_payloads = load_payloads(os.path.join(data_dir, 'cmdipayload.txt'))

    urls_to_scan = provided_urls if provided_urls else crawled_urls

    if not urls_to_scan:
        print_status("No URLs to scan", "error")
        return

    try:
        scan_types = {
            'sqli': ("SQL Injection", 'yellow'),
            'cmdi': ("Command Injection", 'red'),
            'ssti': ("Server Side Template Injection", 'magenta'),
            'xss': ("Cross Site Scripting", 'cyan'),
            'lfi': ("Local File Inclusion", 'blue'),
            'open-redirect': ("Open Redirect", 'green'),
            'crlf': ("CRLF Injection", 'yellow'),
            'cors': ("CORS Misconfiguration", 'red')
        }

        if scan_type in scan_types:
            scan_name, color = scan_types[scan_type]
            print_header(f"Starting {scan_name} Scan", color)
            print_status(f"Target: {target}", "info")
            print_status(f"URLs to scan: {len(urls_to_scan)}", "info")
            print_separator()

        if scan_type == 'sqli':
            if technique_string:
                run_selected_sql_techniques(urls_to_scan, technique_string)
            else:
                run_sql_tests(urls_to_scan)
        elif scan_type == 'cmdi':
            perform_cmdi_scan(urls_to_scan, cmdi_payloads, thread_count=thread_count, no_prompt=no_prompt)
        elif scan_type == 'ssti':
            perform_ssti_scan(urls_to_scan, thread_count=thread_count, no_prompt=no_prompt, verbose=True)
        elif scan_type == 'xss':
            perform_xss_scan(urls_to_scan, thread_count=thread_count, no_prompt=no_prompt, verbose=True)
        elif scan_type == 'lfi':
            perform_lfi_scan(urls_to_scan, thread_count=thread_count, no_prompt=no_prompt, verbose=True)
        elif scan_type == 'open-redirect':
            perform_redirect_scan(urls_to_scan, thread_count=thread_count, no_prompt=no_prompt, verbose=True)
        elif scan_type == 'crlf':
            perform_crlf_scan(urls_to_scan, thread_count=thread_count, no_prompt=no_prompt, verbose=True)
        elif scan_type == 'cors':
            perform_cors_scan(urls_to_scan, thread_count=thread_count, no_prompt=no_prompt, verbose=True)
        elif scan_type == 'all':
            print_header("Starting Comprehensive Security Scan", "cyan")
            print_status(f"Target: {target}", "info")
            print_status(f"URLs to scan: {len(urls_to_scan)}", "info")
            print_separator()
            
            print_status("Performing SQL Injection scan...", "info")
            if technique_string:
                run_selected_sql_techniques(urls_to_scan, technique_string)
            else:
                run_sql_tests(urls_to_scan)
            
            print_status("Performing Command Injection (CMDi) scan...", "info")
            perform_cmdi_scan(urls_to_scan, cmdi_payloads, thread_count=thread_count, no_prompt=no_prompt)

            print_status("Performing Server-Side Template Injection (SSTI) scan...", "info")
            perform_ssti_scan(urls_to_scan, thread_count=thread_count, no_prompt=no_prompt, verbose=True)

            print_status("Performing Cross Site Scripting scan...", "info")
            perform_xss_scan(urls_to_scan, thread_count=thread_count, no_prompt=no_prompt, verbose=True)

            print_status("Performing Local File Inclusion scan...", "info")
            perform_lfi_scan(urls_to_scan, thread_count=thread_count, no_prompt=no_prompt, verbose=True)

            print_status("Performing Open Redirect scan...", "info")
            perform_redirect_scan(urls_to_scan, thread_count=thread_count, no_prompt=no_prompt, verbose=True)

            print_status("Performing CRLF Injection scan...", "info")
            perform_crlf_scan(urls_to_scan, thread_count=thread_count, no_prompt=no_prompt, verbose=True)

            print_status("Performing CORS Misconfiguration scan...", "info")
            perform_cors_scan(urls_to_scan, thread_count=thread_count, no_prompt=no_prompt, verbose=True)

    finally:
        log_scan_end(target, scan_type)
        print_separator()
        print_status(f"Completed {scan_type} scan on {target}", "success")

def crawl_and_scan(target, crawl_depth, scan_type, url=None, multi_url=None, thread_count=1, no_prompt=False, technique_string=None):
    provided_urls = []

    if url:
        provided_urls = [url] if is_valid_url(url) and has_query_parameters(url) else []

    elif multi_url:
        with open(multi_url, 'r') as file:
            for line in file:
                line_url = line.strip()
                if is_valid_url(line_url) and has_query_parameters(line_url):
                    provided_urls.append(line_url)

    if provided_urls:
        print_status("Using provided URLs for scanning", "success")
        scan(target, scan_type, provided_urls=provided_urls, thread_count=thread_count, no_prompt=no_prompt, technique_string=technique_string)
    else:
        crawled_urls = crawl(target, crawl_depth, thread_count=thread_count, no_prompt=no_prompt)
        if crawled_urls:
            scan(target, scan_type, crawled_urls=crawled_urls, thread_count=thread_count, no_prompt=no_prompt, technique_string=technique_string)

def load_targets_from_file(file_path):
    if os.path.exists(file_path):
        with open(file_path, 'r') as f:
            return [line.strip() for line in f.readlines() if line.strip()]
    else:
        print_status(f"Target file {file_path} does not exist", "error")
        return []

def perform_profile_scan(profile_url, profile_type, deepscan_modules=None):
    print_header(f"Starting {profile_type} Profile Scan", "green")
    print_status(f"Target: {profile_url}", "info")
    print_separator()
    
    if profile_type == 'high-risk':
        from lib.ProfileHigh.profile_high import high_risk_scan
        high_risk_scan(profile_url)
    elif profile_type == 'critical-risk':
        from lib.ProfileCritical.profile_critical import critical_risk_scan
        critical_risk_scan(profile_url)
    elif profile_type == 'deepscan':
        from lib.ProfileDeepScan.deepscan import deepscan
        if deepscan_modules:
            run_deepscan([profile_url], deepscan_modules)
        else:
            deepscan(profile_url)
    else:
        print_status(f"Unknown scan type '{profile_type}'", "error")

def run_selected_sql_techniques(urls, technique_string):
    from lib.injection.sqlin.sql import run_sql_tests, run_boolean_sqli, run_error_sqli, run_time_blind_sqli
    if not technique_string:
        run_sql_tests(urls)
        return
    
    print_status(f"Running SQLi techniques: {technique_string}", "info")
    for char in technique_string.upper():
        if char == "B":
            print_status("Running Boolean-based SQL injection scan...", "info")
            run_boolean_sqli(urls)
        elif char == "E":
            print_status("Running Error-based SQL injection scan...", "info")
            run_error_sqli(urls)
        elif char == "T":
            print_status("Running Time-based SQL injection scan...", "info")
            run_time_blind_sqli(urls)
        else:
            print_status(f"Unknown SQLi technique code: {char}. Valid codes are B, E, T.", "error")

def run_deepscan(urls, selected_modules):
    print_header("Starting Deep Scan Modules", "magenta")
    from lib.ProfileDeepScan.deepscan import run_headers_scan, run_backupfile_scan, run_dirfuzz_scan, run_js_scan
    for module in selected_modules:
        if module == "hs":
            print_status("Running Header Deep Scan", "info")
            run_headers_scan(urls)
        elif module == "bf":
            print_status("Running Backup File Scan", "info")
            run_backupfile_scan(urls)
        elif module == "df":
            print_status("Running DirFuzz", "info")
            run_dirfuzz_scan(urls)
        elif module == "js":
            print_status("Running JavaScript Deep Scan", "info")
            run_js_scan(urls)
        else:
            print_status(f"Unknown deepscan module: {module}. Valid options are: hs, bf, df, js", "error")

def get_config_path():
    config_dir = os.path.join('config', 'waymap')
    os.makedirs(config_dir, exist_ok=True)
    return os.path.join(config_dir, 'mode.cfg')

def get_input_mode():
    config_path = get_config_path()
    
    # Check if this is a first-time setup (no config exists yet)
    is_first_run = not os.path.exists(config_path)
    
    # If --resetup is used, force re-setup
    if '--resetup' in sys.argv:
        print_header("Reset Input Mode Setup")
        print("Select your preferred input mode:")
        print(colored("  [1]", "green") + " Argument-based " + colored("(CLI flags like --target, --scan)", "cyan"))
        print(colored("  [2]", "green") + " Prompt-based   " + colored("(Interactive questions)", "cyan"))
        print_separator("─", "cyan", 50)
        while True:
            try:
                choice = input(colored("Choice [1/2]: ", "yellow")).strip()
                if choice in ('1', '2'):
                    mode = 'args' if choice == '1' else 'prompt'
                    with open(config_path, 'w') as f:
                        f.write(f"input_mode={mode}\n")
                    print_status(f"Configuration saved: {mode} mode", "success")
                    return mode
                print_status("Invalid choice. Please enter 1 or 2.", "error")
            except KeyboardInterrupt:
                print_status("Configuration cancelled. Using default (CLI) mode.", "warning")
                return 'args'
    
    # If --no-prompt is used, force args mode
    if '--no-prompt' in sys.argv or '-np' in sys.argv:
        return 'args'
    
    # If config exists, read it
    if os.path.exists(config_path):
        with open(config_path, 'r') as f:
            line = f.readline().strip()
            if line.startswith('input_mode='):
                return line.split('=')[1]
    
    # First run - enhanced UI (only show if not called with CLI args)
    # Check if CLI arguments are present (excluding --resetup which we already handled)
    cli_args = [arg for arg in sys.argv[1:] if arg != '--resetup']
    has_cli_args = any(arg.startswith('--') for arg in cli_args)
    
    # If CLI args are present on first run, default to args mode
    if has_cli_args:
        mode = 'args'
        with open(config_path, 'w') as f:
            f.write(f"input_mode={mode}\n")
        return mode
    
    # Otherwise, show first run configuration
    print_header("First Run Configuration")
    print("Select your preferred input mode:")
    print(colored("  [1]", "green") + " Argument-based " + colored("(CLI flags like --target, --scan)", "cyan"))
    print(colored("  [2]", "green") + " Prompt-based   " + colored("(Interactive questions)", "cyan"))
    print_separator("─", "cyan", 50)
    while True:
        try:
            choice = input(colored("Choice [1/2]: ", "yellow")).strip()
            if choice in ('1', '2'):
                mode = 'args' if choice == '1' else 'prompt'
                with open(config_path, 'w') as f:
                    f.write(f"input_mode={mode}\n")
                print_status(f"Configuration saved: {mode} mode", "success")
                return mode
            print_status("Invalid choice. Please enter 1 or 2.", "error")
        except KeyboardInterrupt:
            print_status("Configuration cancelled. Using default (CLI) mode.", "warning")
            return 'args'

def prompt_for_input():
    print_header("Interactive Scan Setup")
    print("Enter the scan parameters:")
    print_separator("─", "cyan", 40)

    # Handle multi-target support
    target_choice = input(colored("🌐 Single target or multiple targets? [1] - Single, [2] - Multiple: ", "cyan")).strip()
    
    targets = []
    if target_choice == "2":
        target_file = input(colored("📁 Path to targets file: ", "cyan")).strip()
        if os.path.exists(target_file):
            targets = load_targets_from_file(target_file)
            if not targets:
                print_status("No valid targets found in file", "error")
                return None
        else:
            print_status("Target file does not exist", "error")
            return None
    else:
        target = input(colored("🌐 Target URL: ", "cyan")).strip()
        if not target:
            return None
        targets = [target]

    print("\nAvailable scan types:")
    scan_types = ["sqli", "cmdi", "ssti", "xss", "lfi", "open-redirect", "crlf", "cors", "all"]
    for i, st in enumerate(scan_types, 1):
        print(colored(f"  [{i}]", "green") + f" {st}")

    scan_type = input(colored("🔍 Scan type [1-9]: ", "cyan")).strip()
    try:
        scan_type = scan_types[int(scan_type) - 1] if scan_type.isdigit() else scan_type
    except (ValueError, IndexError):
        print_status("Invalid scan type selection", "error")
        return None

    technique_string = None
    if scan_type == "sqli":
        technique_string = input(colored("Optional: SQLi technique [B (boolean), E (error), T (time), combine like BET, or press Enter for all]: ", "magenta")).strip().upper()
        if technique_string == "":
            technique_string = None

    print("\nAvailable Scan Profiles:")
    profile_types = ["high-risk", "deepscan", "critical-risk", "none"]
    for i, pt in enumerate(profile_types, 1):
        print(colored(f"  [{i}]", "green") + f" {pt}")
    profile_type = input(colored("📋 Profile type [1-4, or press Enter to skip]: ", "cyan")).strip()
    try:
        if profile_type.isdigit():
            profile_type = profile_types[int(profile_type) - 1]
        if profile_type == "none":
            profile_type = None
    except (ValueError, IndexError):
        print_status("Invalid profile type selection", "error")
        return None

    deepscan_modules = None
    if profile_type == "deepscan":
        print(colored("Select deepscan modules (comma separated): hs (header scan), bf (backup file), df (dirfuzz), js (javascript)", "magenta"))
        modules_input = input(colored("Modules [e.g. hs,bf,df,js or press Enter for all]: ", "magenta")).strip()
        if modules_input:
            deepscan_modules = [m.strip() for m in modules_input.split(",") if m.strip() in ["hs", "bf", "df", "js"]]
        else:
            deepscan_modules = ["hs", "bf", "df", "js"]

    # Check if any target has parameters to determine crawl depth
    needs_crawling = any(not has_query_parameters(t) for t in targets)
    crawl_depth = 0
    
    if needs_crawling:
        crawl_depth = input(colored("📊 Crawl depth [0-10, 0 to skip]: ", "cyan")).strip()
        try:
            crawl_depth = max(0, min(10, int(crawl_depth)))  # Limit to max 10
        except ValueError:
            crawl_depth = 0
    else:
        print_status("All targets have parameters. Skipping crawl depth selection.", "info")

    from lib.core.settings import DEFAULT_THREADS
    # Ask for threads count
    threads = input(colored("🔧 Threads count [default: %d]: " % DEFAULT_THREADS, "cyan")).strip()
    try:
        threads = int(threads)
        if threads < 1:
            print_status("Threads count must be at least 1. Using default.", "warning")
            threads = DEFAULT_THREADS
    except ValueError:
        threads = DEFAULT_THREADS

    # Ask if user wants to check WAF for each target
    waf_check = input(colored("Do you want to check WAF for each target? [Press Enter for Yes, n for No]: ", "red")).strip().lower()
    check_waf = (waf_check == '' or waf_check == 'y' or waf_check == 'yes')
    return targets, scan_type, crawl_depth, profile_type, technique_string, deepscan_modules, threads, check_waf

def process_target(target, crawl_depth, scan_type, thread_count, no_prompt, profile_type, technique_string=None, deepscan_modules=None):
    """Process a single target, determining whether to crawl or scan directly."""
    
    if has_query_parameters(target):
        print_status(f"GET parameter found in URL {target}. Skipping crawling and starting scan directly.", "info")
        if profile_type:
            if profile_type == "deepscan" and deepscan_modules:
                run_deepscan([target], deepscan_modules)
            else:
                perform_profile_scan(target, profile_type, deepscan_modules)
        else:
            scan(target, scan_type, provided_urls=[target], thread_count=thread_count, no_prompt=no_prompt, technique_string=technique_string)
        return

    if profile_type:
        print_status(f"Running profile scan on {target} with profile {profile_type}", "info")
        if profile_type == "deepscan" and deepscan_modules:
            if crawl_depth > 0:
                crawled_urls = crawl(target, crawl_depth, thread_count=thread_count, no_prompt=no_prompt)
                if crawled_urls:
                    run_deepscan(crawled_urls, deepscan_modules)
                else:
                    run_deepscan([target], deepscan_modules)
            else:
                run_deepscan([target], deepscan_modules)
        else:
            perform_profile_scan(target, profile_type, deepscan_modules)
    elif crawl_depth > 0:
        print_status(f"Crawling and scanning on {target}", "info")
        crawled_urls = crawl(target, crawl_depth, thread_count=thread_count, no_prompt=no_prompt)
        if crawled_urls:
            scan(target, scan_type, crawled_urls=crawled_urls, thread_count=thread_count, no_prompt=no_prompt, technique_string=technique_string)
        cleanup_crawl_file(target)
    else:
        print_status(f"Target '{target}' doesn't have GET parameters and no crawl depth specified. Consider using '--crawl' argument.", "warning")

def cleanup_crawl_file(target):
    """Remove crawl.txt file associated with the target domain."""
    domain = target.split("//")[-1].split("/")[0]
    crawl_file = os.path.join(session_dir, domain, 'crawl.txt')
    if os.path.exists(crawl_file):
        os.remove(crawl_file)
        print_status(f"Removed crawl file for {domain}", "success")

def main():
    from extras.error_handler import check_internet_connection, check_required_files, check_required_directories, handle_error
    from lib.core.settings import DEFAULT_THREADS
    from lib.core.wafdetector import check_wafs
    import argparse

    print_banner()
    check_for_updates()

    if not check_internet_connection():
        handle_error("No internet connection. Please check your network and try again.")

    print_header("System Check")
    required_files = [
        'cmdipayload.txt', 'basicxsspayload.txt', 'filtersbypassxss.txt',
        'lfipayload.txt', 'openredirectpayloads.txt', 'waymap_dirfuzzlist.txt', 
        'waymap_dirfuzzlist2.txt', 'openredirectparameters.txt', 'crlfpayload.txt', 
        'corspayload.txt', 'sstipayload.txt', 'jsvulnpattern.json', 'wafsig.json', 
        'ua.txt', 'cmdi.xml', 'error_based.xml', 'cveinfo.py', 'headers.json'
    ]
    
    missing_files = check_required_files(data_dir, session_dir, required_files)
    if missing_files:
        print_table(["Missing Files"], [[file] for file in missing_files], ["red"])
        handle_error(f"Missing {len(missing_files)} required files")

    required_directories = [data_dir, session_dir]
    missing_dirs = check_required_directories(required_directories)
    if missing_dirs:
        print_table(["Missing Directories"], [[dir] for dir in missing_dirs], ["red"])
        handle_error(f"Missing {len(missing_dirs)} required directories")

    print_status("All system checks passed", "success")
    print_separator()

    # Get input mode and handle accordingly
    input_mode = get_input_mode()
    
    # Check if this is a first run (we just created the config)
    config_path = get_config_path()
    is_first_run_just_completed = not any(arg.startswith('--') for arg in sys.argv[1:] if arg != '--resetup')
    
    # Only show mode mismatch warning if it's not the first run setup
    if not is_first_run_just_completed:
        # Detect if user is running with CLI args or not
        cli_args = [a for a in sys.argv[1:] if not a.startswith('--resetup')]
        has_cli_args = any(a.startswith('--') for a in cli_args)
        
        # Warn if input mode and usage do not match
        if input_mode == 'prompt' and has_cli_args:
            print_header("Warning: Input Mode Mismatch", "red")
            print_status("You chose PROMPT mode in initial setup, but are running with CLI arguments.", "warning")
            print_status("To use CLI arguments, reconfigure with:", "yellow")
            print(colored("  python waymap.py --resetup", "cyan"))
            print_status("Or run without arguments for prompt mode:", "yellow")
            print(colored("  python waymap.py", "cyan"))
        elif input_mode == 'args' and not has_cli_args:
            print_header("Warning: Input Mode Mismatch", "red")
            print_status("You chose ARGUMENT mode in initial setup, but are running without CLI arguments.", "warning")
            print_status("To use prompt mode, reconfigure with:", "yellow")
            print(colored("  python waymap.py --resetup", "cyan"))
            print_status("Or run with CLI arguments for arg mode:", "yellow")
            print(colored("  python waymap.py --target <URL> --scan <TYPE>", "cyan"))
    
    # Initialize result variable
    result = None
    
    if input_mode == 'args':
        parser = argparse.ArgumentParser(
            description="Waymap - Fast and Optimized Web Vulnerability Scanner",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog=colored("""
Examples:
  python waymap.py --target https://example.com --scan xss --crawl 2
  python waymap.py --target https://test.com --scan all --threads 4
  python waymap.py --multi-target targets.txt --scan sqli
  python waymap.py --target https://example.com --check-waf
            """, 'cyan')
        )
        
        parser.add_argument('--target', '-t', type=str, help='Target URL for scanning')
        parser.add_argument('--multi-target', '-mt', type=str, help='File with multiple target URLs')
        parser.add_argument('--crawl', '-c', type=int, help='Crawl depth (0-10)')
        parser.add_argument('--scan', '-s', type=str, choices=['sqli', 'cmdi', 'ssti', 'xss', 'lfi', 'open-redirect', 'crlf', 'cors', 'all'], help='Type of scan to perform')
        parser.add_argument('--technique', '-k', type=str, help='Optional: Use SQL injection technique [B (boolean), E (error), T (time)]. Combine like BET')
        parser.add_argument('--threads', '-T', type=int, default=DEFAULT_THREADS, help='Number of threads')
        parser.add_argument('--no-prompt', '-np', action='store_true', help='Automatically use default input')
        parser.add_argument('--profile', '-p', choices=['high-risk', 'deepscan', 'critical-risk'], help="Scan profile")
        parser.add_argument('--deepscan', '-ds', type=str, help="Run specific deepscan module(s): hs (header scan), bf (backup file), df (dirfuzz), js (javascript) or Combine like: hs,bf")
        parser.add_argument('--check-waf', '--waf', action='store_true', help='Detect WAF/IPS for target URL')

        args = parser.parse_args()

        if not any(vars(args).values()):
            print_header("CLI Mode Activated")
            print_status("Waymap is configured for command-line arguments", "info")
            print(colored("""
Usage:
  waymap --target URL --scan TYPE [--crawl DEPTH] [--threads COUNT]

Quick Start:
  waymap --target https://example.com --scan xss --crawl 2
  waymap --target https://test.com?id=5 --scan all --threads 4

Use '--help' for complete options and examples.
            """, 'yellow'))
            return

        # WAF detection logic
        if args.check_waf:
            if args.target:
                print_header("WAF Detection", "red")
                print_status(f"Checking WAF for: {args.target}", "info")
                check_wafs(args.target)
            else:
                print_status("Target URL is required for WAF detection. Use --target <URL>", "error")
            if not args.scan:  # If only WAF check is requested
                return

        target = args.target
        multi_target_file = args.multi_target
        thread_count = args.threads
        no_prompt = args.no_prompt
        profile_type = args.profile
        technique_string = args.technique
        
        # Handle deepscan modules
        deepscan_modules = None
        if args.deepscan:
            deepscan_modules = [m.strip() for m in args.deepscan.split(",") if m.strip() in ["hs", "bf", "df", "js"]]
            if not deepscan_modules:
                print_status("Invalid deepscan modules. Valid options: hs, bf, df, js", "error")
                return

        # Validation checks
        if args.technique and args.scan != 'sqli':
            handle_error("The '--technique' argument can only be used with '--scan sqli'. Please remove it or change the scan type to 'sqli'.")
            return

        if args.profile == "deepscan" and args.deepscan:
            handle_error("You cannot use '--profile deepscan' and '--deepscan' together. Please choose one.")
            return
        
        # Limit crawl depth to max 10
        if args.crawl and args.crawl > 10:
            print_status("Crawl depth limited to maximum of 10", "warning")
            args.crawl = 10

        # Process multi-target
        if multi_target_file:
            targets = load_targets_from_file(multi_target_file)
            if not targets:
                return
            print_header(f"Multi-Target Scan ({len(targets)} targets)")
            for i, target in enumerate(targets, 1):
                print_status(f"Processing target {i}/{len(targets)}: {target}", "info")
                process_target(target, args.crawl, args.scan, thread_count, no_prompt, profile_type, technique_string, deepscan_modules)
                if i < len(targets):
                    print_separator("─", "blue", 50)
            return

        # Process single target
        if target:
            # Check if target has parameters and adjust crawl depth accordingly
            if has_query_parameters(target) and args.crawl:
                print_status("Target URL already has parameters. Crawl depth ignored.", "warning")
                args.crawl = 0
            
            process_target(target, args.crawl, args.scan, thread_count, no_prompt, profile_type, technique_string, deepscan_modules)
    
    else:  # Prompt mode
        print_header("Interactive Mode")
        result = prompt_for_input()
        if not result or len(result) < 4:
            print_status("Target and scan type are required", "error")
            return
        
        targets, scan_type, crawl_depth, profile_type, technique_string, deepscan_modules, threads, check_waf = result

        print_separator()
        print_header("Scan Summary")
        
        summary_data = [
            ["Targets", f"{len(targets)} target(s)"],
            ["Scan Type", scan_type],
            ["Profile Type", profile_type if profile_type else "N/A"],
            ["Crawl Depth", str(crawl_depth)],
            ["Threads", str(threads)],
            ["SQLi Techniques", technique_string if technique_string else "BET"],
            ["Deepscan Modules", ", ".join(deepscan_modules) if deepscan_modules else "N/A"]
        ]
        
        print_table(["Parameter", "Value"], summary_data)

        if len(targets) > 1:
            print_status(f"Multi-target scan with {len(targets)} targets", "info")

        confirm = input(colored("\nStart scan? [Y/n]: ", "yellow")).strip().lower()
        if confirm not in ('', 'y', 'yes'):
            print_status("Scan cancelled", "warning")
            return

        # Process all targets
        if len(targets) > 1:
            print_header(f"Multi-Target Scan ({len(targets)} targets)")
        
        for i, target in enumerate(targets, 1):
            if len(targets) > 1:
                print_status(f"Processing target {i}/{len(targets)}: {target}", "info")
            # Optionally check WAF
            if check_waf:
                print_header("WAF Detection", "red")
                print_status(f"Checking WAF for: {target}", "info")
                check_wafs(target)
            # Check if target has parameters and adjust crawl depth
            actual_crawl_depth = crawl_depth
            if has_query_parameters(target) and crawl_depth > 0:
                print_status("Target URL already has parameters. Crawl depth ignored for this target.", "warning")
                actual_crawl_depth = 0
            process_target(target, actual_crawl_depth, scan_type, threads, False, profile_type, technique_string, deepscan_modules)
            if i < len(targets):
                print_separator("─", "blue", 50)

if __name__ == "__main__":
    main()