"""Redirect and header-injection related checks."""

from typing import Dict, List, Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from lib.recon.common import build_url, get_domain, normalize_target, now_iso, request_url, save_and_report
from lib.core.logger import get_logger
from lib.ui import print_header, print_status

logger = get_logger(__name__)


def _detect_host_header_injection(base_url: str) -> Optional[Dict[str, str]]:
    test_host = "evil.example"
    response = request_url(base_url, headers={"Host": test_host})
    if not response:
        return None

    location = response.headers.get("Location") or response.headers.get("location")
    body = response.text or ""
    if test_host in (location or "") or test_host in body:
        return {
            "url": base_url,
            "header": "Host",
            "value": test_host,
            "location": location or "",
        }

    return None


def _replace_param(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [value]
    new_query = urlencode(qs, doseq=True)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))


def _check_open_redirect(domain: str, url: str, params: List[str]) -> None:
    payload = "https://example.com"
    for param in params[:2]:
        test_url = _replace_param(url, param, payload)
        response = request_url(test_url, allow_redirects=False)
        if not response:
            continue
        location = response.headers.get("Location") or response.headers.get("location")
        if location and payload in location:
            save_and_report(
                domain,
                "open_redirect_advanced",
                {
                    "url": test_url,
                    "parameter": param,
                    "payload": payload,
                    "timestamp": now_iso(),
                },
                unique_keys=["url", "parameter", "payload"],
            )


def _check_crlf_injection(domain: str, url: str, params: List[str]) -> None:
    payload = "%0d%0aX-Waymap: injected"
    for param in params[:2]:
        test_url = _replace_param(url, param, payload)
        response = request_url(test_url, allow_redirects=False)
        if not response:
            continue
        if any(h.lower() == "x-waymap" for h in response.headers.keys()):
            record = {
                "url": test_url,
                "parameter": param,
                "payload": payload,
                "timestamp": now_iso(),
            }
            save_and_report(
                domain,
                "crlf_advanced",
                record,
                unique_keys=["url", "parameter", "payload"],
            )
            save_and_report(
                domain,
                "http_response_splitting",
                record,
                unique_keys=["url", "parameter", "payload"],
            )
            save_and_report(
                domain,
                "request_splitting",
                record,
                unique_keys=["url", "parameter", "payload"],
            )


def perform_redirect_injection_scan(
    crawled_urls: List[str],
    thread_count: int = 1,
    no_prompt: bool = False,
    verbose: bool = False,
) -> None:
    if not crawled_urls:
        print_status("No target URL provided for redirect scan", "warning")
        return

    base_url = normalize_target(crawled_urls[0])
    domain = get_domain(base_url)

    from lib.core.result_manager import ResultManager
    if ResultManager(domain).has_duplicate("host_header_injection", ["url"], {"url": base_url}):
        print_status("Skipping Redirect/Header Injection scan - results already found in previous scan.", "info")
        return

    print_header("Redirect/Header Injection Scan", color="cyan")
    print_status(f"Target: {base_url}", "info")

    host_hit = _detect_host_header_injection(base_url)
    if host_hit:
        save_and_report(
            domain,
            "host_header_injection",
            {
                "url": base_url,
                "timestamp": now_iso(),
                **host_hit,
            },
            unique_keys=["url", "value"],
        )

    for url in crawled_urls:
        parsed = urlparse(url)
        params = list(parse_qs(parsed.query, keep_blank_values=True).keys())
        if not params:
            continue
        _check_open_redirect(domain, url, params)
        _check_crlf_injection(domain, url, params)

    try:
        from lib.injection.openredirect import perform_redirect_scan
        perform_redirect_scan(crawled_urls, thread_count, no_prompt, verbose)
    except Exception as e:
        logger.error(f"Open redirect scan failed: {e}")

    try:
        from lib.injection.crlf import perform_crlf_scan
        perform_crlf_scan(crawled_urls, thread_count, no_prompt, verbose)
    except Exception as e:
        logger.error(f"CRLF scan failed: {e}")

    print_status("Redirect/Header Injection scan completed", "info")
