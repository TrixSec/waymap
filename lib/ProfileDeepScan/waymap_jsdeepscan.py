# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.

"""JavaScript Deep Scan Module - Vulnerability Detection in JS Libraries."""

import os
import re
import json
import requests
from urllib.parse import urlparse
from packaging.version import Version, InvalidVersion
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional
from tqdm import tqdm

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from lib.core.config import get_config
from lib.core.logger import get_logger
from lib.ui import print_status
from lib.waymapcrawlers.jscrawler import start_crawl
from lib.parse.random_headers import generate_random_headers

config = get_config()
logger = get_logger(__name__)

def load_vulnerability_database(vuln_file: str) -> Dict:
    """Load JS vulnerability database."""
    try:
        with open(vuln_file, "r") as file:
            return json.load(file)
    except Exception as e:
        logger.error(f"Error loading vulnerability database: {e}")
        return {}

def is_version_vulnerable(version: str, vuln_ranges: List[Dict]) -> bool:
    """Check if a version is vulnerable based on ranges."""
    try:
        parsed_version = Version(version)
    except InvalidVersion:
        return False

    for range_item in vuln_ranges:
        try:
            at_or_above = range_item.get("atOrAbove")
            below = range_item.get("below")

            if at_or_above and below:
                if parsed_version >= Version(at_or_above) and parsed_version < Version(below):
                    return True
            elif at_or_above:
                if parsed_version >= Version(at_or_above):
                    return True
            elif below:
                if parsed_version < Version(below):
                    return True
        except InvalidVersion:
            continue
    return False

def check_js_version(js_url: str, vuln_db: Dict) -> Optional[Dict]:
    """Check a JS file for vulnerable library versions."""
    try:
        headers = generate_random_headers()
        response = requests.get(js_url, timeout=config.TIMEOUT, verify=False, headers=headers)
        if response.status_code != 200:
            return None

        content = response.text
        matches = re.findall(config.JS_VERSION_PATTERN, content)

        vulnerabilities = []
        for name, version in matches:
            lib_name = name.strip().rstrip('-:').strip()
            if lib_name in vuln_db:
                for vuln in vuln_db[lib_name]["vulnerabilities"]:
                    if is_version_vulnerable(version, vuln.get("ranges", [])):
                        vulnerabilities.append({
                            "library": lib_name,
                            "version": version,
                            "summary": vuln.get("summary"),
                            "cve": vuln.get("cve"),
                            "cwe": vuln.get("cwe")
                        })

        if vulnerabilities:
            print_status(f"Vulnerabilities found in: {js_url}", "error")
            for vuln in vulnerabilities:
                print_status(f"  Library: {vuln['library']} v{vuln['version']}", "warning")
                print_status(f"  CVE: {vuln.get('cve', 'N/A')}", "info")
                print_status(f"  Summary: {vuln.get('summary', 'N/A')}", "info")
            return {"url": js_url, "vulnerabilities": vulnerabilities}
        return None
    except Exception as e:
        logger.debug(f"Error checking JS URL {js_url}: {e}")
        return None

def process_js_url(js_url: str, vuln_db: Dict, results: List) -> None:
    """Process a single JS URL."""
    result = check_js_version(js_url, vuln_db)
    if result:
        results.append(result)

def save_js_scan_results(domain: str, new_results: List[Dict]) -> None:
    """Save JS scan results to JSON file."""
    session_dir = config.get_domain_session_dir(domain)
    path = os.path.join(session_dir, "waymap_full_results.json")
    
    data = {"scans": {}}
    if os.path.exists(path):
        try:
            with open(path, "r") as file:
                data = json.load(file)
        except json.JSONDecodeError:
            pass

    scans = data.setdefault("scans", {})
    profile = scans.setdefault("ProfileDeepscan", {})
    js_deep = profile.setdefault("JS Deepscan", [])

    # Deduplicate
    existing_urls = {entry["url"] for entry in js_deep}
    for entry in new_results:
        if entry["url"] not in existing_urls:
            js_deep.append(entry)

    profile["JS Deepscan"] = js_deep

    try:
        with open(path, "w") as file:
            json.dump(data, file, indent=4)
        print_status(f"JS Deepscan results saved to {path}", "success")
    except Exception as e:
        logger.error(f"Error saving results: {e}")

def jsscan(input_url: str) -> None:
    """Perform JavaScript vulnerability scanning."""
    print_status("JS Scanner (Beta) - Report bugs if found", "info")
    
    vuln_file = os.path.join(config.DATA_DIR, "jsvulnpattern.json")
    vuln_db = load_vulnerability_database(vuln_file)

    if not vuln_db:
        print_status("Vulnerability database not loaded. Exiting.", "error")
        return

    if not input_url:
        print_status("No URL provided. Exiting.", "error")
        return

    domain = urlparse(input_url).netloc
    session_dir = config.get_domain_session_dir(domain)
    crawl_output_file = os.path.join(session_dir, "crawl3.txt")

    print_status("Starting JS crawler...", "info")
    start_crawl(input_url)

    if not os.path.isfile(crawl_output_file):
        print_status(f"Crawling output file not found: {crawl_output_file}", "error")
        return

    with open(crawl_output_file, "r") as file:
        crawled_urls = file.read().splitlines()

    print_status(f"Processing {len(crawled_urls)} crawled URLs...", "info")
    results = []

    # Load existing results to avoid duplicates
    waymap_results_file = os.path.join(session_dir, "waymap_full_results.json")
    existing_urls = set()
    if os.path.exists(waymap_results_file):
        try:
            with open(waymap_results_file, "r") as f:
                existing_data = json.load(f)
                existing_js = (
                    existing_data.get("scans", {})
                    .get("ProfileDeepscan", {})
                    .get("JS Deepscan", [])
                )
                existing_urls = {entry["url"] for entry in existing_js}
        except Exception:
            pass

    try:
        with tqdm(total=len(crawled_urls), desc="Scanning JS", unit="URL") as pbar:
            with ThreadPoolExecutor(max_workers=config.MAX_THREADS) as executor:
                futures = []
                for js_url in crawled_urls:
                    if js_url not in existing_urls:
                        futures.append(executor.submit(process_js_url, js_url, vuln_db, results))
                    else:
                        pbar.update(1)
                
                for future in futures:
                    future.result()
                    pbar.update(1)

        if results:
            print_status(f"Vulnerabilities detected! Found {len(results)} vulnerable files", "warning")
            save_js_scan_results(domain, results)
        else:
            print_status("No vulnerable JS files found.", "success")

    except KeyboardInterrupt:
        print_status("Scan interrupted by user. Saving partial results...", "warning")
        if results:
            save_js_scan_results(domain, results)
