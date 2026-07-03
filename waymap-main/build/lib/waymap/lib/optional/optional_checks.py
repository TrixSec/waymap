"""Optional extra checks that are safe but lower priority."""

from typing import List
from urllib.parse import urlparse

from lib.core.wafdetector import check_wafs
from lib.recon.common import build_url, get_domain, normalize_target, now_iso, request_url, save_and_report
from lib.ui import print_header, print_status

WEBSOCKET_PATHS = [
    "/ws",
    "/websocket",
    "/socket",
    "/socket.io/",
]


def _check_websocket(domain: str, base_url: str) -> None:
    headers = {
        "Connection": "Upgrade",
        "Upgrade": "websocket",
        "Sec-WebSocket-Version": "13",
        "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
    }
    for path in WEBSOCKET_PATHS:
        url = build_url(base_url, path)
        resp = request_url(url, headers=headers, allow_redirects=False)
        if resp and resp.status_code in {101, 426, 400}:
            save_and_report(
                domain,
                "websocket_security_checks",
                {
                    "url": url,
                    "timestamp": now_iso(),
                    "status": str(resp.status_code),
                },
                unique_keys=["url", "status"],
            )


def _check_redirect_chains(domain: str, base_url: str) -> None:
    resp = request_url(base_url, allow_redirects=True)
    if not resp:
        return
    if resp.history and len(resp.history) >= 3:
        final_domain = urlparse(resp.url).netloc if resp.url else ""
        save_and_report(
            domain,
            "insecure_redirect_chains",
            {
                "url": base_url,
                "timestamp": now_iso(),
                "chain_length": len(resp.history),
                "final": final_domain,
            },
            unique_keys=["url", "chain_length", "final"],
        )


def _check_waf(domain: str, base_url: str) -> None:
    detected = check_wafs(base_url)
    if detected and detected.lower() != "unknown":
        save_and_report(
            domain,
            "waf_detection_extended",
            {
                "url": base_url,
                "timestamp": now_iso(),
                "waf": detected,
            },
            unique_keys=["url", "waf"],
        )


def perform_optional_scan(urls: List[str], verbose: bool = False) -> None:
    if not urls:
        print_status("No URLs provided for optional scan", "warning")
        return

    base_url = normalize_target(urls[0])
    domain = get_domain(base_url)

    print_header("Optional Checks", color="cyan")
    print_status(f"Target: {base_url}", "info")

    _check_websocket(domain, base_url)
    _check_redirect_chains(domain, base_url)
    _check_waf(domain, base_url)

    print_status("Optional checks completed", "info")
