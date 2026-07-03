"""Cache and request smuggling related checks."""

from typing import Dict, List, Optional
from urllib.parse import urlparse

from lib.recon.common import build_url, get_domain, normalize_target, now_iso, request_url, save_and_report
from lib.ui import print_header, print_status

CACHE_HEADERS = [
    "Cache-Control",
    "Expires",
    "Pragma",
    "Age",
    "X-Cache",
    "CF-Cache-Status",
    "Vary",
]


def _collect_cache_headers(response) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    if not response:
        return headers
    for name in CACHE_HEADERS:
        value = response.headers.get(name) or response.headers.get(name.lower())
        if value:
            headers[name] = value
    return headers


def _detect_cache_poisoning(domain: str, base_url: str) -> None:
    poison_host = "evil-cache.example"
    response = request_url(base_url, headers={"X-Forwarded-Host": poison_host})
    if not response:
        return
    if poison_host in (response.text or "") or poison_host in (response.headers.get("Location", "") or ""):
        save_and_report(
            domain,
            "cache_poisoning",
            {
                "url": base_url,
                "timestamp": now_iso(),
                "header": "X-Forwarded-Host",
                "value": poison_host,
                "status": str(response.status_code),
            },
            unique_keys=["url", "value"],
        )


def _detect_cache_deception(domain: str, base_url: str) -> None:
    parsed = urlparse(base_url)
    fake_path = parsed.path.rstrip("/") + "/waymap.css"
    fake_url = f"{parsed.scheme}://{parsed.netloc}{fake_path}"
    response = request_url(fake_url)
    if not response:
        return
    content_type = response.headers.get("Content-Type", "")
    cache_control = response.headers.get("Cache-Control", "")
    if "text/html" in content_type.lower() and "max-age" in cache_control:
        save_and_report(
            domain,
            "cache_deception",
            {
                "url": fake_url,
                "timestamp": now_iso(),
                "content_type": content_type,
                "cache_control": cache_control,
            },
            unique_keys=["url", "cache_control"],
        )


def _detect_cache_routing(domain: str, base_url: str) -> None:
    response = request_url(base_url)
    headers = _collect_cache_headers(response)
    if headers:
        save_and_report(
            domain,
            "web_cache_routing",
            {
                "url": base_url,
                "timestamp": now_iso(),
                "headers": headers,
            },
            unique_keys=["url", "headers"],
        )


def _detect_misconfigured_headers(domain: str, base_url: str) -> None:
    response = request_url(base_url)
    if not response:
        return
    cache_control = response.headers.get("Cache-Control", "")
    set_cookie = response.headers.get("Set-Cookie") or response.headers.get("set-cookie")
    if cache_control and "public" in cache_control.lower() and set_cookie:
        save_and_report(
            domain,
            "misconfigured_caching_headers",
            {
                "url": base_url,
                "timestamp": now_iso(),
                "cache_control": cache_control,
                "set_cookie": set_cookie,
            },
            unique_keys=["url", "cache_control", "set_cookie"],
        )


def _detect_desync(domain: str, base_url: str) -> None:
    headers = {
        "Transfer-Encoding": "chunked",
        "Content-Length": "4",
    }
    response = request_url(base_url, method="POST", headers=headers, data="0\r\n\r\n")
    if response and response.status_code < 400:
        save_and_report(
            domain,
            "http_desync",
            {
                "url": base_url,
                "timestamp": now_iso(),
                "status": str(response.status_code),
            },
            unique_keys=["url", "status"],
        )
        save_and_report(
            domain,
            "http_smuggling",
            {
                "url": base_url,
                "timestamp": now_iso(),
                "status": str(response.status_code),
            },
            unique_keys=["url", "status"],
        )
        save_and_report(
            domain,
            "request_smuggling",
            {
                "url": base_url,
                "timestamp": now_iso(),
                "status": str(response.status_code),
            },
            unique_keys=["url", "status"],
        )


def perform_cache_smuggling_scan(urls: List[str], verbose: bool = False) -> None:
    if not urls:
        print_status("No URLs provided for cache/smuggling scan", "warning")
        return

    base_url = normalize_target(urls[0])
    domain = get_domain(base_url)

    print_header("Cache/Smuggling Checks", color="cyan")
    print_status(f"Target: {base_url}", "info")

    _detect_cache_routing(domain, base_url)
    _detect_misconfigured_headers(domain, base_url)
    _detect_cache_poisoning(domain, base_url)
    _detect_cache_deception(domain, base_url)
    _detect_desync(domain, base_url)

    print_status("Cache/Smuggling checks completed", "info")
