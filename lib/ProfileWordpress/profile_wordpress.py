# Copyright (c) 2026 waymap developers
# See the file 'LICENSE' for copying permission.

"""WordPress Vulnerability Scanner - Consolidated Module.

Provides comprehensive WordPress security scanning:
  - WordPress detection (multi-signal)
  - Version, plugin, and theme enumeration (with version extraction)
  - Security checks: XML-RPC, WP-Cron, debug.log, install.php, config exposure,
    backup files, user enumeration, REST API namespaces, login hardening,
    readme exposure, and hardening audit
  - Optional WPScan API integration for known CVE lookups
"""

import os
import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from lib.core import http
from lib.core.config import get_config
from lib.core.logger import get_logger
from lib.core.result_manager import ResultManager
from lib.core.secrets import get_secret
from lib.core.state import stop_scan
from lib.parse.random_headers import generate_random_headers
from lib.recon.common import build_url, get_domain, normalize_target, now_iso, request_url
from lib.ui import print_header, print_status, print_separator, ask_continue_scanning

logger = get_logger(__name__)
config = get_config()

# ---------------------------------------------------------------------------
# WordPress detection
# ---------------------------------------------------------------------------

_WP_INDICATORS = [
    "wp-content",
    "wp-includes",
    "wp-json",
    "/wp-login.php",
    "/wp-admin",
]


def _detect_wordpress(html: str, headers: Dict[str, str]) -> bool:
    """Multi-signal WordPress detection."""
    if not html and not headers:
        return False

    html_lower = html.lower() if html else ""

    # Check HTML body for common WordPress artifacts
    for indicator in _WP_INDICATORS:
        if indicator in html_lower:
            return True

    # Check generator meta tag
    if re.search(
        r"<meta[^>]+name=['\"]generator['\"][^>]+content=['\"][^'\"]*wordpress",
        html_lower,
        flags=re.IGNORECASE,
    ):
        return True

    # Check X-Generator / X-Powered-By headers
    for header_name in ("X-Generator", "x-generator", "X-Powered-By", "x-powered-by"):
        value = headers.get(header_name, "")
        if "wordpress" in value.lower():
            return True

    # Check Link header for REST API
    link = headers.get("Link", headers.get("link", ""))
    if "wp-json" in link:
        return True

    return False


# ---------------------------------------------------------------------------
# Enumeration helpers
# ---------------------------------------------------------------------------

def _extract_version(html: str) -> Optional[str]:
    """Extract WordPress core version from HTML (meta generator, feeds, scripts)."""
    if not html:
        return None

    # Meta generator tag
    m = re.search(
        r'<meta[^>]+content=["\']WordPress\s+([\d.]+)',
        html,
        flags=re.IGNORECASE,
    )
    if m:
        return m.group(1)

    # RSS/Atom feed generator
    m = re.search(
        r'<generator>https?://wordpress\.org/\?v=([\d.]+)</generator>',
        html,
        flags=re.IGNORECASE,
    )
    if m:
        return m.group(1)

    # ?ver= query param on wp-includes scripts
    m = re.search(r'/wp-includes/[^"\']+\?ver=([\d.]+)', html)
    if m:
        return m.group(1)

    # Fallback: any WordPress version string in HTML
    m = re.search(r'WordPress\s+([\d]+(?:\.[\d]+){1,3})', html, flags=re.IGNORECASE)
    if m:
        return m.group(1)

    return None


def _extract_version_from_feeds(base_url: str) -> Optional[str]:
    """Try to extract WordPress version from RSS/Atom feeds."""
    feed_paths = ["/feed/", "/feed/atom/", "/?feed=rss2"]
    for path in feed_paths:
        if stop_scan.is_set():
            return None
        resp = request_url(build_url(base_url, path))
        if resp and resp.status_code == 200:
            m = re.search(
                r'<generator>https?://wordpress\.org/\?v=([\d.]+)</generator>',
                resp.text,
                flags=re.IGNORECASE,
            )
            if m:
                return m.group(1)
    return None


def _extract_slugs(html: str) -> Tuple[Dict[str, Optional[str]], Dict[str, Optional[str]]]:
    """Extract plugin and theme slugs with optional version numbers.

    Returns:
        (plugins, themes) where each is a dict of {slug: version_or_None}.
    """
    plugins: Dict[str, Optional[str]] = {}
    themes: Dict[str, Optional[str]] = {}

    if not html:
        return plugins, themes

    for m in re.finditer(r'/wp-content/plugins/([^/]+)/[^"\']*(?:\?ver=([\d.]+))?', html, flags=re.IGNORECASE):
        slug = m.group(1).strip()
        ver = m.group(2) if m.group(2) else None
        if slug and (slug not in plugins or ver):
            plugins[slug] = ver

    for m in re.finditer(r'/wp-content/themes/([^/]+)/[^"\']*(?:\?ver=([\d.]+))?', html, flags=re.IGNORECASE):
        slug = m.group(1).strip()
        ver = m.group(2) if m.group(2) else None
        if slug and (slug not in themes or ver):
            themes[slug] = ver

    return plugins, themes


# ---------------------------------------------------------------------------
# Individual security checks
# ---------------------------------------------------------------------------

def _check_xmlrpc(domain: str, base_url: str) -> None:
    """Check if XML-RPC is enabled (brute-force and DDoS amplification risk)."""
    if stop_scan.is_set():
        return
    url = build_url(base_url, "/xmlrpc.php")
    resp = request_url(url, method="POST", headers={
        "Content-Type": "text/xml",
    }, data='<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>')

    if resp and resp.status_code == 200 and "system.listMethods" in resp.text:
        methods_count = resp.text.count("<string>")
        print_status(f"XML-RPC enabled at {url} ({methods_count} methods exposed)", "success")
        ResultManager(domain).add_finding("wordpress_xmlrpc", "", {
            "url": url,
            "timestamp": now_iso(),
            "status": str(resp.status_code),
            "methods_exposed": methods_count,
            "risk": "XML-RPC brute-force and DDoS amplification",
        })
    elif resp and resp.status_code in {200, 405}:
        # Fallback: just check GET presence
        get_resp = request_url(url)
        if get_resp and get_resp.status_code in {200, 405} and "XML-RPC" in (get_resp.text or ""):
            print_status(f"XML-RPC detected at {url}", "success")
            ResultManager(domain).add_finding("wordpress_xmlrpc", "", {
                "url": url,
                "timestamp": now_iso(),
                "status": str(get_resp.status_code),
                "risk": "XML-RPC endpoint accessible",
            })


def _check_wp_cron(domain: str, base_url: str) -> None:
    """Check if WP-Cron is publicly accessible (DDoS abuse vector)."""
    if stop_scan.is_set():
        return
    url = build_url(base_url, "/wp-cron.php")
    resp = request_url(url)
    if resp and resp.status_code == 200:
        print_status(f"WP-Cron publicly accessible at {url}", "success")
        ResultManager(domain).add_finding("wordpress_wp_cron", "", {
            "url": url,
            "timestamp": now_iso(),
            "risk": "WP-Cron abuse - can be used for DDoS amplification",
        })


def _check_debug_log(domain: str, base_url: str) -> None:
    """Check for exposed debug.log file."""
    if stop_scan.is_set():
        return
    url = build_url(base_url, "/wp-content/debug.log")
    resp = request_url(url)
    if resp and resp.status_code == 200 and len(resp.text) > 50:
        # Confirm it looks like a PHP debug log
        if "PHP" in resp.text or "Warning" in resp.text or "Fatal" in resp.text or "Notice" in resp.text:
            print_status(f"Debug log exposed at {url} ({len(resp.text)} bytes)", "success")
            ResultManager(domain).add_finding("wordpress_debug_log", "", {
                "url": url,
                "timestamp": now_iso(),
                "size_bytes": len(resp.text),
                "risk": "Exposed debug log may leak sensitive paths, queries, and credentials",
            })


def _check_install_page(domain: str, base_url: str) -> None:
    """Check for accessible WordPress installation page."""
    if stop_scan.is_set():
        return
    url = build_url(base_url, "/wp-admin/install.php")
    resp = request_url(url)
    if resp and resp.status_code == 200:
        if "wp-install" in resp.text.lower() or "installation" in resp.text.lower():
            print_status(f"WordPress install page accessible at {url}", "success")
            ResultManager(domain).add_finding("wordpress_install_exposed", "", {
                "url": url,
                "timestamp": now_iso(),
                "risk": "Installation page accessible - potential site takeover",
            })


def _check_user_enum(domain: str, base_url: str) -> None:
    """Enumerate WordPress users via REST API and author archives."""
    if stop_scan.is_set():
        return

    # REST API user enumeration
    api_url = build_url(base_url, "/wp-json/wp/v2/users?per_page=100")
    resp = request_url(api_url)
    if resp and resp.status_code == 200:
        try:
            users = resp.json()
            if isinstance(users, list) and users:
                usernames = [u.get("slug", "unknown") for u in users if isinstance(u, dict)]
                print_status(f"User enumeration via REST API: {len(usernames)} user(s) found", "success")
                ResultManager(domain).add_finding("wordpress_user_enum", "", {
                    "url": api_url,
                    "timestamp": now_iso(),
                    "method": "wp-json",
                    "users": usernames[:20],  # Cap at 20
                    "user_count": len(usernames),
                })
        except Exception:
            pass

    if stop_scan.is_set():
        return

    # Author archive enumeration (first 5 IDs)
    found_authors = []
    for author_id in range(1, 6):
        if stop_scan.is_set():
            break
        author_url = f"{base_url.rstrip('/')}/?author={author_id}"
        author_resp = request_url(author_url, allow_redirects=True)
        if author_resp and author_resp.status_code in {200, 301, 302}:
            final_url = getattr(author_resp, "url", "") or ""
            if "/author/" in final_url:
                slug = final_url.rstrip("/").rsplit("/", 1)[-1]
                found_authors.append({"id": author_id, "slug": slug})

    if found_authors:
        print_status(f"User enumeration via author archives: {len(found_authors)} user(s)", "success")
        ResultManager(domain).add_finding("wordpress_user_enum", "", {
            "url": base_url,
            "timestamp": now_iso(),
            "method": "author-archive",
            "authors": found_authors,
        })


def _check_rest_api_namespaces(domain: str, base_url: str) -> None:
    """Enumerate REST API namespaces to discover installed plugins/features."""
    if stop_scan.is_set():
        return
    url = build_url(base_url, "/wp-json/")
    resp = request_url(url)
    if resp and resp.status_code == 200:
        try:
            data = resp.json()
            namespaces = data.get("namespaces", [])
            if isinstance(namespaces, list) and namespaces:
                # Filter out core namespaces to highlight plugin-specific ones
                plugin_namespaces = [ns for ns in namespaces if ns not in ("wp/v2", "oembed/1.0", "")]
                print_status(f"REST API: {len(namespaces)} namespace(s), {len(plugin_namespaces)} plugin namespace(s)", "info")
                ResultManager(domain).add_finding("wordpress_rest_api", "", {
                    "url": url,
                    "timestamp": now_iso(),
                    "namespaces": namespaces,
                    "plugin_namespaces": plugin_namespaces,
                })
        except Exception:
            pass


def _check_readme(domain: str, base_url: str) -> None:
    """Check for exposed WordPress readme.html (version disclosure)."""
    if stop_scan.is_set():
        return
    url = build_url(base_url, "/readme.html")
    resp = request_url(url)
    if resp and resp.status_code == 200 and "WordPress" in resp.text:
        version = None
        m = re.search(r'Version\s+([\d.]+)', resp.text)
        if m:
            version = m.group(1)
        print_status(f"WordPress readme.html exposed at {url}" + (f" (version {version})" if version else ""), "success")
        ResultManager(domain).add_finding("wordpress_readme", "", {
            "url": url,
            "timestamp": now_iso(),
            "version_disclosed": version,
        })


def _check_config_exposure(domain: str, base_url: str) -> None:
    """Check for exposed wp-config.php (critical)."""
    if stop_scan.is_set():
        return
    paths = ["/wp-config.php", "/wp-config.php.bak", "/wp-config.php~",
             "/wp-config.php.save", "/wp-config.php.old", "/wp-config.bak",
             "/wp-config.txt"]
    for path in paths:
        if stop_scan.is_set():
            break
        url = build_url(base_url, path)
        resp = request_url(url)
        if resp and resp.status_code == 200:
            if any(marker in resp.text for marker in ("DB_NAME", "DB_PASSWORD", "AUTH_KEY", "table_prefix")):
                print_status(f"CRITICAL: wp-config exposed at {url}", "success")
                ResultManager(domain).add_finding("wordpress_config_exposure", "", {
                    "url": url,
                    "timestamp": now_iso(),
                    "risk": "WordPress configuration file exposed - database credentials leaked",
                    "severity": "critical",
                })


def _check_login_hardening(domain: str, base_url: str) -> None:
    """Check login page for brute-force protection indicators."""
    if stop_scan.is_set():
        return
    url = build_url(base_url, "/wp-login.php")
    resp = request_url(url)
    if not resp or resp.status_code != 200:
        return

    issues = []
    html_lower = resp.text.lower()

    # Check for CAPTCHA
    has_captcha = any(term in html_lower for term in (
        "recaptcha", "captcha", "hcaptcha", "turnstile", "g-recaptcha",
    ))
    if not has_captcha:
        issues.append("No CAPTCHA detected on login page")

    # Check for rate limiting headers
    rate_headers = ("X-RateLimit-Limit", "Retry-After", "X-Rate-Limit")
    has_rate_limit = any(resp.headers.get(h) for h in rate_headers)
    if not has_rate_limit:
        issues.append("No rate-limiting headers detected")

    if issues:
        print_status(f"Login hardening issues: {', '.join(issues)}", "success")
        ResultManager(domain).add_finding("wordpress_login_hardening", "", {
            "url": url,
            "timestamp": now_iso(),
            "issues": issues,
            "has_captcha": has_captcha,
            "has_rate_limit": has_rate_limit,
        })


def _check_directory_listing(domain: str, base_url: str) -> None:
    """Check for directory listing on common WordPress directories."""
    if stop_scan.is_set():
        return
    dirs = ["/wp-content/uploads/", "/wp-content/plugins/", "/wp-content/themes/"]
    hits = []
    for path in dirs:
        if stop_scan.is_set():
            break
        url = build_url(base_url, path)
        resp = request_url(url)
        if resp and resp.status_code == 200:
            body_lower = resp.text.lower()
            if "index of" in body_lower or "<title>index of" in body_lower or "directory listing" in body_lower:
                hits.append(url)

    if hits:
        print_status(f"Directory listing enabled on {len(hits)} path(s)", "success")
        ResultManager(domain).add_finding("wordpress_directory_listing", "", {
            "url": base_url,
            "timestamp": now_iso(),
            "directories": hits,
        })


# ---------------------------------------------------------------------------
# WPScan API integration (optional)
# ---------------------------------------------------------------------------

def _run_wpscan_api(
    domain: str,
    target_url: str,
    wp_version: Optional[str],
    plugins: Dict[str, Optional[str]],
    themes: Dict[str, Optional[str]],
    verbose: bool = False,
) -> None:
    """Query WPScan API for known CVEs if a token is available."""
    token = os.environ.get("WPSCAN_API_TOKEN")
    if not token:
        token = get_secret("wpscan_api_token", env_var="WPSCAN_API_TOKEN")
    if not token:
        if verbose:
            print_status("WPScan API token not configured - skipping CVE lookup", "info")
            print_status("Set WPSCAN_API_TOKEN env var or add to secrets.json for CVE enrichment", "info")
        return

    from lib.ProfileWordpress.wpscan_scan import run_wpscan_batch_lookup

    print_separator()
    print_header("WPScan API - Known CVE Lookup", color="cyan")

    plugin_set = set(plugins.keys())
    theme_set = set(themes.keys())

    try:
        batch_result = run_wpscan_batch_lookup(
            target_url=target_url,
            wp_version=wp_version,
            plugins=plugin_set,
            themes=theme_set,
            token=token,
        )
        if batch_result:
            ResultManager(domain).add_finding("wordpress_wpscan_cves", "", {
                "target": target_url,
                "timestamp": now_iso(),
                "status": "ok",
                **batch_result,
            })
    except Exception as e:
        logger.error(f"WPScan API lookup failed: {e}")
        print_status(f"WPScan API lookup failed: {e}", "error")


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def perform_wordpress_scan(
    crawled_urls: List[str],
    thread_count: int = 1,
    no_prompt: bool = False,
    verbose: bool = False,
) -> None:
    """Comprehensive WordPress vulnerability scanner.

    Consistent with other scan modules (SSTI, LFI, XSS, etc.):
      - Accepts crawled_urls, thread_count, no_prompt, verbose
      - Uses stop_scan for graceful Ctrl+C
      - Saves findings via ResultManager
    """
    if not crawled_urls:
        print_status("No URLs to scan", "warning")
        return

    stop_scan.clear()
    print_header("WordPress Vulnerability Scanner", color="cyan")

    # Normalize target
    if isinstance(crawled_urls, str):
        crawled_urls = [crawled_urls]

    base_url = normalize_target(crawled_urls[0])
    domain = get_domain(base_url)

    if ResultManager(domain).has_duplicate("wordpress_enumeration", ["target"], {"target": base_url}):
        print_status("Skipping WordPress scan - results already found in previous scan.", "info")
        return

    print_status(f"Target: {base_url}", "info")

    # ---- Phase 1: Detection ----
    print_separator()
    print_status("Phase 1: WordPress Detection", "info")

    headers = generate_random_headers()
    try:
        resp = http.get(base_url, headers=headers, verify=False, timeout=config.REQUEST_TIMEOUT)
        html = resp.text if resp else ""
        resp_headers = dict(resp.headers) if resp else {}
    except Exception as e:
        logger.error(f"Failed to fetch target: {e}")
        print_status(f"Failed to fetch target: {e}", "error")
        return

    is_wp = _detect_wordpress(html, resp_headers)

    if not is_wp:
        if no_prompt or os.environ.get("WAYMAP_NO_PROMPT") == "1":
            print_status("WordPress not detected - skipping", "warning")
            return

        from lib.ui import prompt_line
        choice = prompt_line(f"[?] WordPress not detected for {base_url}. Continue anyway? [y/N]", "n").lower()
        if choice != "y":
            print_status("Skipping target", "warning")
            return

    print_status("WordPress detected", "success" if is_wp else "warning")

    # ---- Phase 2: Enumeration ----
    if stop_scan.is_set():
        return

    print_separator()
    print_status("Phase 2: Enumeration", "info")

    wp_version = _extract_version(html)
    if not wp_version:
        wp_version = _extract_version_from_feeds(base_url)

    plugins, themes = _extract_slugs(html)

    print_status(f"WordPress version: {wp_version or 'unknown'}", "info")
    print_status(f"Plugins detected: {len(plugins)}", "info")
    if plugins and verbose:
        for slug, ver in sorted(plugins.items()):
            print_status(f"  - {slug}" + (f" v{ver}" if ver else ""), "info")
    print_status(f"Themes detected: {len(themes)}", "info")
    if themes and verbose:
        for slug, ver in sorted(themes.items()):
            print_status(f"  - {slug}" + (f" v{ver}" if ver else ""), "info")

    # Save enumeration results
    ResultManager(domain).add_finding("wordpress_enumeration", "", {
        "target": base_url,
        "timestamp": now_iso(),
        "wordpress_version": wp_version,
        "plugins": {k: v for k, v in plugins.items()},
        "themes": {k: v for k, v in themes.items()},
        "plugin_count": len(plugins),
        "theme_count": len(themes),
    })

    # ---- Phase 3: Security Checks ----
    if stop_scan.is_set():
        return

    print_separator()
    print_status("Phase 3: Security Checks", "info")

    checks = [
        ("XML-RPC", _check_xmlrpc),
        ("WP-Cron", _check_wp_cron),
        ("Debug Log", _check_debug_log),
        ("Install Page", _check_install_page),
        ("User Enumeration", _check_user_enum),
        ("REST API Namespaces", _check_rest_api_namespaces),
        ("Readme Exposure", _check_readme),
        ("Config Exposure", _check_config_exposure),
        ("Login Hardening", _check_login_hardening),
        ("Directory Listing", _check_directory_listing),
    ]

    for check_name, check_fn in checks:
        if stop_scan.is_set():
            break
        if verbose:
            print_status(f"Running: {check_name}", "info")
        try:
            check_fn(domain, base_url)
        except Exception as e:
            logger.error(f"{check_name} check failed: {e}")
            if verbose:
                print_status(f"{check_name} check failed: {e}", "error")

    # ---- Phase 4: WPScan API (optional) ----
    if stop_scan.is_set():
        return

    _run_wpscan_api(domain, base_url, wp_version, plugins, themes, verbose=verbose)

    # ---- Summary ----
    print_separator()
    print_status("WordPress scan completed", "info")


# ---------------------------------------------------------------------------
# Legacy entry points (backward compatibility)
# ---------------------------------------------------------------------------

def wordpress_vuln_scan(profile_url) -> None:
    """Legacy entry point for --profile wordpress."""
    urls = [profile_url] if isinstance(profile_url, str) else profile_url
    no_prompt = os.environ.get("WAYMAP_NO_PROMPT") == "1"
    perform_wordpress_scan(urls, thread_count=1, no_prompt=no_prompt, verbose=True)
