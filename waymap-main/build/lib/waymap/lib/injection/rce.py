import random
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Tuple
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import requests

from lib.core.config import get_config
from lib.core.logger import get_logger
from lib.core.result_manager import ResultManager
from lib.core.state import stop_scan
from lib.parse.random_headers import generate_random_headers
from lib.ui import print_header, print_status, ask_continue_scanning

config = get_config()
logger = get_logger(__name__)


def _get_domain(url: str) -> str:
    return urlparse(url).netloc


def _extract_parameters(url: str) -> List[str]:
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    return list(params.keys())


def _build_url_with_param(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    qs[param] = [value]
    new_query = urlencode(qs, doseq=True)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))


def _marker() -> str:
    return f"WAYMAP_RCE_{random.randint(100000, 999999)}"


def _payloads(marker: str) -> List[Tuple[str, str]]:
    return [
        ("unix", f";echo {marker};"),
        ("unix", f"|echo {marker}|"),
        ("unix", f"`echo {marker}`"),
        ("unix", f"$(echo {marker})"),
        ("windows", f"& echo {marker} &"),
        ("windows", f"| echo {marker} |"),
    ]


def _test_payload(url: str, parameter: str, payload: str, marker: str) -> Dict[str, Any]:
    if stop_scan.is_set():
        return {"vulnerable": False}

    headers = generate_random_headers()
    test_url = _build_url_with_param(url, parameter, payload)

    try:
        resp = requests.get(test_url, headers=headers, timeout=config.REQUEST_TIMEOUT, verify=False)
    except requests.RequestException as e:
        logger.debug(f"Request failed for {test_url}: {e}")
        return {"vulnerable": False}

    if marker in resp.text:
        return {
            "vulnerable": True,
            "url": test_url,
            "parameter": parameter,
            "payload": payload,
            "headers": dict(resp.headers),
        }

    return {"vulnerable": False}


def perform_rce_scan(crawled_urls: List[str], thread_count: int = 1, no_prompt: bool = False, verbose: bool = False) -> None:
    if not crawled_urls:
        print_status("No URLs to scan", "warning")
        return

    stop_scan.clear()
    thread_count = max(1, min(thread_count, config.MAX_THREADS))

    print_header("RCE (Command Injection) Scan", color="cyan")

    try:
        domain = _get_domain(crawled_urls[0]) or "unknown_domain"
    except Exception:
        domain = "unknown_domain"

    result_manager = ResultManager(domain)
    vuln_key = "rce"

    print_status(f"Scanning {len(crawled_urls)} URLs", "info")

    for url in crawled_urls:
        if stop_scan.is_set():
            break

        params = _extract_parameters(url)
        if not params:
            if verbose:
                print_status(f"No parameters in {url}, skipping", "debug")
            continue

        m = _marker()
        payloads = _payloads(m)
        if len(payloads) > 8:
            payloads = random.sample(payloads, 8)

        futures = {}
        with ThreadPoolExecutor(max_workers=thread_count) as executor:
            for param in params:
                for _, suffix in payloads:
                    if stop_scan.is_set():
                        break

                    injected = (parse_qs(urlparse(url).query).get(param, [""])[0] or "") + suffix
                    test_url = _build_url_with_param(url, param, injected)

                    if result_manager.has_duplicate(
                        vuln_key,
                        ["url", "parameter", "payload"],
                        {"url": test_url, "parameter": param, "payload": injected},
                    ):
                        continue

                    futures[executor.submit(_test_payload, url, param, injected, m)] = (test_url, param, injected)

            for fut in as_completed(futures):
                if stop_scan.is_set():
                    break

                test_url, param, injected = futures[fut]
                try:
                    res = fut.result()
                except Exception as e:
                    logger.error(f"Worker error: {e}")
                    continue

                if res.get("vulnerable"):
                    print_status("Vulnerability Found!", "success")
                    print_status(f"  URL: {test_url}", "info")
                    print_status(f"  Parameter: {param}", "info")
                    print_status(f"  Payload: {injected}", "info")

                    result_manager.add_finding(vuln_key, "", {
                        "url": test_url,
                        "parameter": param,
                        "payload": injected,
                    })

                    if not no_prompt:
                        if not ask_continue_scanning():
                            stop_scan.set()
                            return

    print_status("RCE Scan completed", "info")
