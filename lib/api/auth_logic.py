"""Authentication and access control logic checks."""

import re
from typing import Dict, List, Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from lib.recon.common import build_url, get_domain, normalize_target, now_iso, request_url, save_and_report
from lib.ui import print_header, print_status

SENSITIVE_PATHS = [
    "/admin",
    "/admin/",
    "/admin/login",
    "/admin/dashboard",
    "/admin/panel",
    "/admin/home",
    "/administrator",
    "/administrator/",
    "/administrator/login",
    "/administrator/dashboard",
    "/administrator/panel",
    "/wp-admin",
    "/wp-admin/",
    "/wp-login.php",
    "/backend",
    "/backend/",
    "/backend/admin",
    "/backend/login",
    "/backend/dashboard",
    "/cpanel",
    "/cpanel/",
    "/webmail",
    "/webmail/",
    "/roundcube",
    "/roundcube/",
    "/horde",
    "/horde/",
    "/phpmyadmin",
    "/phpmyadmin/",
    "/phpMyAdmin",
    "/phpMyAdmin/",
    "/mysql",
    "/mysql/",
    "/mysql/admin",
    "/pma",
    "/pma/",
    "/myadmin",
    "/myadmin/",
    "/settings",
    "/settings/",
    "/account",
    "/account/",
    "/account/settings",
    "/account/profile",
    "/user",
    "/user/",
    "/user/profile",
    "/user/settings",
    "/users",
    "/users/",
    "/users/admin",
    "/users/manage",
    "/profile",
    "/profile/",
    "/profile/edit",
    "/profile/settings",
    "/dashboard",
    "/dashboard/",
    "/dashboard/admin",
    "/dashboard/user",
    "/dashboard/settings",
    "/panel",
    "/panel/",
    "/panel/admin",
    "/panel/user",
    "/panel/settings",
    "/control",
    "/control/",
    "/control/panel",
    "/console",
    "/console/",
    "/console/admin",
    "/manage",
    "/manage/",
    "/manage/users",
    "/manage/admin",
    "/management",
    "/management/",
    "/management/users",
    "/management/admin",
    "/config",
    "/config/",
    "/config/admin",
    "/configuration",
    "/configuration/",
    "/configuration/admin",
    "/setup",
    "/setup/",
    "/install",
    "/install/",
    "/install.php",
    "/setup.php",
    "/auth",
    "/auth/",
    "/auth/login",
    "/auth/admin",
    "/auth/user",
    "/login",
    "/login/",
    "/login/admin",
    "/login/user",
    "/signin",
    "/signin/",
    "/signin/admin",
    "/signin/user",
    "/register",
    "/register/",
    "/signup",
    "/signup/",
    "/reset",
    "/reset/",
    "/reset/password",
    "/forgot",
    "/forgot/",
    "/forgot/password",
    "/change",
    "/change/",
    "/change/password",
    "/password",
    "/password/",
    "/password/reset",
    "/password/change",
    "/security",
    "/security/",
    "/security/settings",
    "/api/admin",
    "/api/admin/",
    "/api/user",
    "/api/user/",
    "/api/settings",
    "/api/settings/",
    "/api/config",
    "/api/config/",
    "/api/auth",
    "/api/auth/",
    "/api/users",
    "/api/users/",
    "/api/dashboard",
    "/api/dashboard/",
    "/rest/admin",
    "/rest/admin/",
    "/rest/user",
    "/rest/user/",
    "/rest/settings",
    "/rest/settings/",
    "/graphql/admin",
    "/graphql/admin/",
    "/graphql/user",
    "/graphql/user/",
    "/v1/admin",
    "/v1/admin/",
    "/v1/user",
    "/v1/user/",
    "/v1/settings",
    "/v1/settings/",
    "/v2/admin",
    "/v2/admin/",
    "/v2/user",
    "/v2/user/",
    "/v2/settings",
    "/v2/settings/",
    "/private",
    "/private/",
    "/private/admin",
    "/protected",
    "/protected/",
    "/protected/admin",
    "/internal",
    "/internal/",
    "/internal/admin",
    "/secret",
    "/secret/",
    "/secret/admin",
    "/dev",
    "/dev/",
    "/dev/admin",
    "/staging",
    "/staging/",
    "/staging/admin",
    "/test",
    "/test/",
    "/test/admin",
    "/debug",
    "/debug/",
    "/debug/admin",
    "/maintenance",
    "/maintenance/",
    "/maintenance/admin",
    "/status",
    "/status/",
    "/status/admin",
    "/health",
    "/health/",
    "/health/admin",
    "/monitor",
    "/monitor/",
    "/monitor/admin",
    "/logs",
    "/logs/",
    "/logs/admin",
    "/log",
    "/log/",
    "/log/admin",
    "/backup",
    "/backup/",
    "/backup/admin",
    "/backups",
    "/backups/",
    "/backups/admin",
    "/database",
    "/database/",
    "/database/admin",
    "/db",
    "/db/",
    "/db/admin",
    "/sql",
    "/sql/",
    "/sql/admin",
    "/shell",
    "/shell/",
    "/shell/admin",
    "/terminal",
    "/terminal/",
    "/terminal/admin",
    "/cmd",
    "/cmd/",
    "/cmd/admin",
    "/exec",
    "/exec/",
    "/exec/admin",
    "/upload",
    "/upload/",
    "/upload/admin",
    "/uploads",
    "/uploads/",
    "/uploads/admin",
    "/download",
    "/download/",
    "/download/admin",
    "/downloads",
    "/downloads/",
    "/downloads/admin",
    "/files",
    "/files/",
    "/files/admin",
    "/file",
    "/file/",
    "/file/admin",
    "/assets",
    "/assets/",
    "/assets/admin",
    "/static",
    "/static/",
    "/static/admin",
    "/media",
    "/media/",
    "/media/admin",
    "/images",
    "/images/",
    "/images/admin",
    "/css",
    "/css/",
    "/css/admin",
    "/js",
    "/js/",
    "/js/admin",
    "/scripts",
    "/scripts/",
    "/scripts/admin",
    "/includes",
    "/includes/",
    "/includes/admin",
    "/lib",
    "/lib/",
    "/lib/admin",
    "/vendor",
    "/vendor/",
    "/vendor/admin",
    "/node_modules",
    "/node_modules/",
    "/node_modules/admin",
    "/.git",
    "/.git/",
    "/.svn",
    "/.svn/",
    "/.env",
    "/.env/",
    "/.htaccess",
    "/.htaccess/",
    "/web.config",
    "/web.config/",
    "/robots.txt",
    "/sitemap.xml",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
    "/.well-known",
    "/.well-known/",
    "/.well-known/change-password",
    "/.well-known/openid-configuration",
    "/.well-known/jwks.json",
    "/.well-known/apple-app-site-association",
    "/.well-known/assetlinks.json",
]

ID_PARAMS = {"id", "user", "uid", "account", "profile", "member"}


def _update_param(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [value]
    new_query = urlencode(qs, doseq=True)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))


def _looks_like_login(body: str) -> bool:
    if not body:
        return False
    lowered = body.lower()
    return any(token in lowered for token in ["login", "signin", "password", "username"])


def _detect_broken_access_control(domain: str, base_url: str) -> None:
    hits = []
    for path in SENSITIVE_PATHS:
        url = build_url(base_url, path)
        response = request_url(url, allow_redirects=True)
        if not response:
            continue
        if response.status_code == 200 and not _looks_like_login(response.text):
            hits.append({"url": url, "status": str(response.status_code)})
    if hits:
        save_and_report(
            domain,
            "broken_access_control_checks",
            {
                "url": base_url,
                "timestamp": now_iso(),
                "paths": hits,
            },
            unique_keys=["url", "paths"],
        )


def _detect_basic_auth(domain: str, base_url: str) -> None:
    response = request_url(base_url, allow_redirects=False)
    if not response:
        return
    header = response.headers.get("WWW-Authenticate") or response.headers.get("www-authenticate")
    if header and "basic" in header.lower():
        save_and_report(
            domain,
            "basic_auth_bruteforce_safe",
            {
                "url": base_url,
                "timestamp": now_iso(),
                "www_authenticate": header,
            },
            unique_keys=["url", "www_authenticate"],
        )


def _detect_oauth_misconfig(domain: str, base_url: str) -> None:
    url = build_url(base_url, "/.well-known/openid-configuration")
    response = request_url(url)
    if response and response.status_code == 200 and "authorization_endpoint" in response.text:
        save_and_report(
            domain,
            "oauth_misconfig",
            {
                "url": url,
                "timestamp": now_iso(),
                "status": str(response.status_code),
            },
            unique_keys=["url", "status"],
        )


def _detect_idor(domain: str, url: str) -> None:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    for param, values in qs.items():
        if param not in ID_PARAMS:
            continue
        if not values:
            continue
        value = values[0]
        if not value.isdigit():
            continue
        candidate = str(int(value) + 1)
        test_url = _update_param(url, param, candidate)
        base_resp = request_url(url)
        test_resp = request_url(test_url)
        if not base_resp or not test_resp:
            continue
        if base_resp.status_code == 200 and test_resp.status_code == 200:
            base_len = len(base_resp.text or "")
            test_len = len(test_resp.text or "")
            if base_len > 0 and abs(base_len - test_len) / base_len < 0.15:
                save_and_report(
                    domain,
                    "idor",
                    {
                        "url": url,
                        "parameter": param,
                        "tested": test_url,
                        "timestamp": now_iso(),
                    },
                    unique_keys=["url", "parameter", "tested"],
                )


def perform_auth_logic_scan(urls: List[str], verbose: bool = False) -> None:
    if not urls:
        print_status("No URLs provided for auth logic scan", "warning")
        return

    base_url = normalize_target(urls[0])
    domain = get_domain(base_url)

    print_header("Auth Logic Checks", color="cyan")
    print_status(f"Target: {base_url}", "info")

    _detect_broken_access_control(domain, base_url)
    _detect_basic_auth(domain, base_url)
    _detect_oauth_misconfig(domain, base_url)

    for url in urls:
        if "?" in url:
            _detect_idor(domain, url)

    print_status("Auth logic checks completed", "info")
