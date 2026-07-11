"""Misconfiguration and exposure checks."""

import re
import socket
import ssl
from typing import Dict, List, Optional

from lib.recon.common import (
    build_url,
    get_domain,
    normalize_target,
    now_iso,
    request_url,
    save_and_report,
)
from lib.ui import print_header, print_status

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

CORS_TEST_ORIGIN = "https://evil.example"

ADMIN_PATHS = [
    "/admin",
    "/administrator",
    "/admin/login",
    "/admin.php",
    "/wp-admin/",
    "/wp-login.php",
    "/login",
    "/signin",
    "/dashboard",
]

DEBUG_PATHS = [
    "/debug",
    "/debug/vars",
    "/_debugbar/",
    "/phpinfo.php",
    "/_profiler",
    "/server-status",
]

SENSITIVE_FILES = [
    "/.git/config",
    "/.env",
    "/config.php",
    "/config.yml",
    "/settings.py",
    "/local.settings.php",
    "/wp-config.php",
    "/composer.json",
    "/composer.lock",
]

BACKUP_FILES = [
    "/index.php.bak",
    "/index.php~",
    "/config.php.bak",
    "/config.php~",
    "/wp-config.php.bak",
    "/backup.zip",
    "/backup.tar.gz",
]

DIRECTORY_LISTING_PATHS = [
    "/uploads/",
    "/files/",
    "/backup/",
    "/logs/",
    "/data/",
]

SWAGGER_PATHS = [
    "/swagger.json",
    "/openapi.json",
    "/v2/api-docs",
    "/v3/api-docs",
    "/swagger-ui/",
    "/swagger-ui/index.html",
    "/api-docs",
]

SOAP_PATHS = [
    "/?wsdl",
    "/wsdl",
    "/service?wsdl",
    "/services?wsdl",
]


def _get_set_cookies(headers: Dict[str, str], response: Optional[object]) -> List[str]:
    cookies: List[str] = []
    try:
        raw_headers = getattr(response, "raw", None)
        if raw_headers is not None and hasattr(raw_headers, "headers"):
            raw = raw_headers.headers
            if hasattr(raw, "get_all"):
                cookies = raw.get_all("Set-Cookie") or []
            elif hasattr(raw, "getlist"):
                cookies = raw.getlist("Set-Cookie") or []
    except Exception:
        cookies = []

    if not cookies:
        header = headers.get("Set-Cookie") or headers.get("set-cookie")
        if header:
            cookies = [c.strip() for c in header.split("\n") if c.strip()]

    return cookies


def _probe_paths(base_url: str, paths: List[str], match_terms: Optional[List[str]] = None) -> List[Dict[str, str]]:
    found: List[Dict[str, str]] = []
    for path in paths:
        url = build_url(base_url, path)
        response = request_url(url, allow_redirects=True)
        if not response:
            continue
        status = response.status_code
        if status not in {200, 204, 301, 302, 401, 403}:
            continue
        if match_terms:
            body = response.text.lower()
            if not any(term in body for term in match_terms):
                continue
        found.append({"url": url, "status": str(status)})
    return found


def _detect_directory_listing(base_url: str) -> List[Dict[str, str]]:
    return _probe_paths(
        base_url,
        DIRECTORY_LISTING_PATHS,
        match_terms=["index of /", "<title>index of", "directory listing"],
    )


def _detect_env_exposure(base_url: str) -> Optional[Dict[str, str]]:
    url = build_url(base_url, "/.env")
    response = request_url(url)
    if not response or response.status_code != 200:
        return None
    if "APP_KEY" in response.text or "DB_" in response.text or "DATABASE_URL" in response.text:
        return {"url": url, "status": str(response.status_code)}
    return None


def _detect_file_upload(html: str) -> Optional[List[str]]:
    if not html:
        return None
    inputs = re.findall(r"<input[^>]+>", html, re.I)
    upload_fields = []
    for inp in inputs:
        if re.search(r"type=[\"']?file[\"']?", inp, re.I):
            name_match = re.search(r"name=[\"']?([^\"'>\s]+)", inp, re.I)
            if name_match:
                upload_fields.append(name_match.group(1))
            else:
                upload_fields.append("file")
    return upload_fields or None


def _detect_clickjacking(headers: Dict[str, str]) -> bool:
    x_frame = headers.get("X-Frame-Options") or headers.get("x-frame-options")
    csp = headers.get("Content-Security-Policy") or headers.get("content-security-policy")
    if x_frame:
        return False
    if csp and "frame-ancestors" in csp.lower():
        return False
    return True


def _detect_cors_advanced(base_url: str) -> Optional[Dict[str, str]]:
    response = request_url(base_url, method="OPTIONS", headers={"Origin": CORS_TEST_ORIGIN})
    if not response:
        return None
    allow_origin = response.headers.get("Access-Control-Allow-Origin") or response.headers.get("access-control-allow-origin")
    allow_creds = response.headers.get("Access-Control-Allow-Credentials") or response.headers.get("access-control-allow-credentials")
    if not allow_origin:
        return None
    if allow_origin == "*" or allow_origin == CORS_TEST_ORIGIN:
        if allow_creds and allow_creds.lower() == "true":
            return {"origin": allow_origin, "credentials": allow_creds}
    return None


def _detect_csrf_tokens(html: str) -> Optional[int]:
    if not html:
        return None
    forms = re.findall(r"<form[^>]*>", html, re.I)
    if not forms:
        return None
    has_token = bool(re.search(r"name=\"?(csrf|token|_token)\"?", html, re.I))
    if not has_token:
        return len(forms)
    return None


def _detect_tls_audit(base_url: str) -> Optional[Dict[str, str]]:
    if not base_url.startswith("https://"):
        return None
    parsed = re.sub(r"^https?://", "", base_url).split("/")[0]
    host = parsed.split(":")[0]
    port = 443
    if ":" in parsed:
        try:
            port = int(parsed.split(":")[1])
        except ValueError:
            port = 443
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                version = tls.version()
                cipher = tls.cipher()[0] if tls.cipher() else ""
                return {"version": version, "cipher": cipher}
    except Exception:
        return None


def _detect_trace_method(base_url: str) -> Optional[str]:
    response = request_url(base_url, method="TRACE", allow_redirects=False)
    if response and response.status_code == 200:
        return str(response.status_code)
    return None


def perform_misconfig_scan(
    crawled_urls: List[str],
    thread_count: int = 1,
    no_prompt: bool = False,
    verbose: bool = False,
) -> None:
    if not crawled_urls:
        print_status("No target URL provided for misconfiguration scan", "warning")
        return

    base_url = normalize_target(crawled_urls[0])
    domain = get_domain(base_url)

    if ResultManager(domain).has_duplicate("security_headers_audit", ["url"], {"url": base_url}):
        print_status("Skipping Misconfiguration scan - results already found in previous scan.", "info")
        return

    print_header("Misconfiguration Scan", color="cyan")
    print_status(f"Target: {base_url}", "info")

    response = request_url(base_url)
    headers = dict(response.headers) if response else {}

    if response:
        missing_headers = [h for h in SECURITY_HEADERS if h.lower() not in [k.lower() for k in headers.keys()]]
        save_and_report(
            domain,
            "security_headers_audit",
            {
                "url": base_url,
                "timestamp": now_iso(),
                "missing": missing_headers,
                "present": [h for h in SECURITY_HEADERS if h not in missing_headers],
            },
            unique_keys=["url", "missing"],
        )

        if _detect_clickjacking(headers):
            save_and_report(
                domain,
                "clickjacking",
                {
                    "url": base_url,
                    "timestamp": now_iso(),
                },
                unique_keys=["url"],
            )

        csp_value = headers.get("Content-Security-Policy") or headers.get("content-security-policy")
        if csp_value:
            save_and_report(
                domain,
                "csp_analyzer",
                {
                    "url": base_url,
                    "timestamp": now_iso(),
                    "csp": csp_value,
                },
                unique_keys=["url", "csp"],
            )

        hsts_value = headers.get("Strict-Transport-Security") or headers.get("strict-transport-security")
        save_and_report(
            domain,
            "hsts_audit",
            {
                "url": base_url,
                "timestamp": now_iso(),
                "hsts": hsts_value or "missing",
            },
            unique_keys=["url", "hsts"],
        )

        cookies = _get_set_cookies(headers, response)
        cookie_findings = []
        for cookie in cookies:
            lowered = cookie.lower()
            cookie_findings.append({
                "cookie": cookie.split(";", 1)[0],
                "secure": "secure" in lowered,
                "httponly": "httponly" in lowered,
                "samesite": "samesite" in lowered,
            })
        if cookie_findings:
            save_and_report(
                domain,
                "insecure_cookie_flags",
                {
                    "url": base_url,
                    "timestamp": now_iso(),
                    "cookies": cookie_findings,
                },
                unique_keys=["url", "cookies"],
            )

        version_hits = []
        for header_name in ["Server", "X-Powered-By", "X-AspNet-Version"]:
            value = headers.get(header_name) or headers.get(header_name.lower())
            if value and re.search(r"\d+\.\d+", value):
                version_hits.append({"header": header_name, "value": value})
        if version_hits:
            save_and_report(
                domain,
                "version_disclosure",
                {
                    "url": base_url,
                    "timestamp": now_iso(),
                    "headers": version_hits,
                },
                unique_keys=["url", "headers"],
            )

        csrf_missing = _detect_csrf_tokens(response.text if response else "")
        if csrf_missing:
            save_and_report(
                domain,
                "csrf_token_checks",
                {
                    "url": base_url,
                    "timestamp": now_iso(),
                    "forms_missing": csrf_missing,
                },
                unique_keys=["url", "forms_missing"],
            )

        cors_issue = _detect_cors_advanced(base_url)
        if cors_issue:
            save_and_report(
                domain,
                "cors_advanced",
                {
                    "url": base_url,
                    "timestamp": now_iso(),
                    **cors_issue,
                },
                unique_keys=["url", "origin", "credentials"],
            )

        tls_info = _detect_tls_audit(base_url)
        if tls_info:
            save_and_report(
                domain,
                "tls_ssl_audit",
                {
                    "url": base_url,
                    "timestamp": now_iso(),
                    **tls_info,
                },
                unique_keys=["url", "version", "cipher"],
            )

        trace_status = _detect_trace_method(base_url)
        if trace_status:
            save_and_report(
                domain,
                "trace_track_methods",
                {
                    "url": base_url,
                    "timestamp": now_iso(),
                    "status": trace_status,
                },
                unique_keys=["url", "status"],
            )

        upload_fields = _detect_file_upload(response.text if response else "")
        if upload_fields:
            save_and_report(
                domain,
                "file_upload",
                {
                    "url": base_url,
                    "timestamp": now_iso(),
                    "fields": upload_fields,
                },
                unique_keys=["url", "fields"],
            )

    admin_hits = _probe_paths(base_url, ADMIN_PATHS)
    if admin_hits:
        save_and_report(
            domain,
            "admin_panels",
            {
                "url": base_url,
                "timestamp": now_iso(),
                "paths": admin_hits,
            },
            unique_keys=["url", "paths"],
        )

    debug_hits = _probe_paths(base_url, DEBUG_PATHS)
    if debug_hits:
        save_and_report(
            domain,
            "debug_endpoints",
            {
                "url": base_url,
                "timestamp": now_iso(),
                "paths": debug_hits,
            },
            unique_keys=["url", "paths"],
        )

    sensitive_hits = _probe_paths(base_url, SENSITIVE_FILES)
    if sensitive_hits:
        save_and_report(
            domain,
            "sensitive_files_exposure",
            {
                "url": base_url,
                "timestamp": now_iso(),
                "files": sensitive_hits,
            },
            unique_keys=["url", "files"],
        )

        save_and_report(
            domain,
            "secrets_exposure",
            {
                "url": base_url,
                "timestamp": now_iso(),
                "files": sensitive_hits,
            },
            unique_keys=["url", "files"],
        )

    backup_hits = _probe_paths(base_url, BACKUP_FILES)
    if backup_hits:
        save_and_report(
            domain,
            "backup_files",
            {
                "url": base_url,
                "timestamp": now_iso(),
                "files": backup_hits,
            },
            unique_keys=["url", "files"],
        )

    env_hit = _detect_env_exposure(base_url)
    if env_hit:
        save_and_report(
            domain,
            "env_exposure",
            {
                "url": base_url,
                "timestamp": now_iso(),
                "file": env_hit,
            },
            unique_keys=["url", "file"],
        )

        save_and_report(
            domain,
            "secrets_exposure",
            {
                "url": base_url,
                "timestamp": now_iso(),
                "file": env_hit,
            },
            unique_keys=["url", "file"],
        )

    listing_hits = _detect_directory_listing(base_url)
    if listing_hits:
        save_and_report(
            domain,
            "directory_listing",
            {
                "url": base_url,
                "timestamp": now_iso(),
                "directories": listing_hits,
            },
            unique_keys=["url", "directories"],
        )

    swagger_hits = _probe_paths(base_url, SWAGGER_PATHS)
    if swagger_hits:
        save_and_report(
            domain,
            "swagger_openapi_exposure",
            {
                "url": base_url,
                "timestamp": now_iso(),
                "paths": swagger_hits,
            },
            unique_keys=["url", "paths"],
        )

    soap_hits = _probe_paths(base_url, SOAP_PATHS)
    if soap_hits:
        save_and_report(
            domain,
            "soap_wsdl_exposure",
            {
                "url": base_url,
                "timestamp": now_iso(),
                "paths": soap_hits,
            },
            unique_keys=["url", "paths"],
        )

    print_status("Misconfiguration scan completed", "info")
