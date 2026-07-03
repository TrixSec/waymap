"""Additional WordPress checks."""

import re
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse

from lib.recon.common import build_url, get_domain, normalize_target, now_iso, request_url, save_and_report
from lib.ui import print_header, print_status


def _is_wordpress(html: str) -> bool:
    if not html:
        return False
    return bool(re.search(r"/wp-content/|/wp-includes/|content=\"WordPress\"", html, re.I))


def _extract_wp_slugs(html: str) -> Dict[str, Set[str]]:
    plugins: Set[str] = set()
    themes: Set[str] = set()

    for match in re.finditer(r"/wp-content/plugins/([^/]+)/", html, re.I):
        plugins.add(match.group(1))
    for match in re.finditer(r"/wp-content/themes/([^/]+)/", html, re.I):
        themes.add(match.group(1))

    return {"plugins": plugins, "themes": themes}


def _check_user_enum(domain: str, base_url: str) -> None:
    api_url = build_url(base_url, "/wp-json/wp/v2/users?per_page=100")
    response = request_url(api_url)
    if response and response.status_code == 200 and "name" in response.text:
        save_and_report(
            domain,
            "wordpress_user_enum",
            {
                "url": api_url,
                "timestamp": now_iso(),
                "method": "wp-json",
            },
            unique_keys=["url", "method"],
        )

    author_url = f"{base_url.rstrip('/')}?author=1"
    author_resp = request_url(author_url, allow_redirects=True)
    if author_resp and author_resp.status_code in {200, 301, 302} and "/author/" in (author_resp.url or ""):
        save_and_report(
            domain,
            "wordpress_user_enum",
            {
                "url": author_url,
                "timestamp": now_iso(),
                "method": "author-redirect",
            },
            unique_keys=["url", "method"],
        )


def _check_xmlrpc(domain: str, base_url: str) -> None:
    xmlrpc_url = build_url(base_url, "/xmlrpc.php")
    response = request_url(xmlrpc_url, method="GET")
    if response and response.status_code in {200, 405} and "XML-RPC" in response.text:
        save_and_report(
            domain,
            "wordpress_xmlrpc_checks",
            {
                "url": xmlrpc_url,
                "timestamp": now_iso(),
                "status": str(response.status_code),
            },
            unique_keys=["url", "status"],
        )


def _check_readme(domain: str, base_url: str) -> None:
    readme_url = build_url(base_url, "/readme.html")
    response = request_url(readme_url)
    if response and response.status_code == 200 and "WordPress" in response.text:
        save_and_report(
            domain,
            "wordpress_readme_enum",
            {
                "url": readme_url,
                "timestamp": now_iso(),
            },
            unique_keys=["url"],
        )


def _check_config_exposure(domain: str, base_url: str) -> None:
    config_url = build_url(base_url, "/wp-config.php")
    response = request_url(config_url)
    if response and response.status_code == 200 and "DB_NAME" in response.text:
        save_and_report(
            domain,
            "wordpress_config_exposure",
            {
                "url": config_url,
                "timestamp": now_iso(),
            },
            unique_keys=["url"],
        )


def _check_backup_files(domain: str, base_url: str) -> None:
    backup_paths = [
        "/wp-config.php.bak",
        "/wp-config.php~",
        "/wp-config.php.save",
    ]
    hits = []
    for path in backup_paths:
        url = build_url(base_url, path)
        resp = request_url(url)
        if resp and resp.status_code == 200:
            hits.append({"url": url, "status": str(resp.status_code)})
    if hits:
        save_and_report(
            domain,
            "wordpress_backup_files",
            {
                "url": base_url,
                "timestamp": now_iso(),
                "files": hits,
            },
            unique_keys=["url", "files"],
        )


def _check_hardening(domain: str, base_url: str, html: str) -> None:
    findings = {
        "xmlrpc": bool(request_url(build_url(base_url, "/xmlrpc.php"))),
        "wp_json": bool(request_url(build_url(base_url, "/wp-json/"))),
        "readme": "readme.html" in (html or ""),
    }
    save_and_report(
        domain,
        "wordpress_hardening_audit",
        {
            "url": base_url,
            "timestamp": now_iso(),
            **findings,
        },
        unique_keys=["url", "xmlrpc", "wp_json", "readme"],
    )


def perform_wordpress_extras_scan(urls: List[str], verbose: bool = False) -> None:
    if not urls:
        print_status("No URLs provided for WordPress extras", "warning")
        return

    base_url = normalize_target(urls[0])
    domain = get_domain(base_url)

    print_header("WordPress Extras", color="cyan")
    print_status(f"Target: {base_url}", "info")

    response = request_url(base_url)
    html = response.text if response else ""
    if not _is_wordpress(html):
        print_status("WordPress not detected; skipping extras", "warning")
        return

    slugs = _extract_wp_slugs(html)
    if slugs.get("plugins"):
        save_and_report(
            domain,
            "wordpress_plugin_enum",
            {
                "url": base_url,
                "timestamp": now_iso(),
                "plugins": sorted(slugs["plugins"]),
            },
            unique_keys=["url", "plugins"],
        )

    if slugs.get("themes"):
        save_and_report(
            domain,
            "wordpress_theme_enum",
            {
                "url": base_url,
                "timestamp": now_iso(),
                "themes": sorted(slugs["themes"]),
            },
            unique_keys=["url", "themes"],
        )

    _check_user_enum(domain, base_url)
    _check_xmlrpc(domain, base_url)
    _check_readme(domain, base_url)
    _check_backup_files(domain, base_url)
    _check_config_exposure(domain, base_url)
    _check_hardening(domain, base_url, html)

    print_status("WordPress extras completed", "info")
