"""Foundation reconnaissance modules (fingerprinting and discovery helpers)."""

import re
import subprocess
from typing import Dict, List, Optional
from urllib.parse import urlparse

from lib.recon.common import (
    build_url,
    get_domain,
    normalize_target,
    now_iso,
    request_url,
    save_and_report,
)
from lib.ui import print_header, print_status

COMMON_CONTENT_PATHS = [
    "/admin",
    "/administrator",
    "/login",
    "/signin",
    "/dashboard",
    "/wp-admin/",
    "/wp-login.php",
    "/phpinfo.php",
    "/server-status",
]

SITEMAP_PATHS = [
    "/sitemap.xml",
    "/sitemap_index.xml",
    "/sitemap.txt",
]

CMS_PATTERNS = {
    "wordpress": [r"/wp-content/", r"/wp-includes/", r"content=\"WordPress"],
    "joomla": [r"content=\"Joomla", r"/media/system/"],
    "drupal": [r"content=\"Drupal", r"/sites/default/"],
    "magento": [r"/static/frontend/", r"Magento"],
}

DOM_XSS_SOURCES = [
    "location.hash",
    "location.search",
    "document.location",
    "document.url",
]

DOM_XSS_SINKS = [
    "innerHTML",
    "outerHTML",
    "document.write",
    "insertAdjacentHTML",
]

TAKEOVER_FINGERPRINTS = {
    "s3_bucket_takeover": [
        "NoSuchBucket",
        "The specified bucket does not exist",
    ],
    "subdomain_takeover": [
        "There isn't a GitHub Pages site here",
        "NoSuchBucket",
        "Sorry, this shop is currently unavailable",
        "Fastly error: unknown domain",
        "The site you were looking for couldn't be found",
    ],
}


def _extract_parameters(urls: List[str]) -> List[str]:
    params = set()
    for url in urls:
        parsed = urlparse(url)
        if parsed.query:
            for part in parsed.query.split("&"):
                name = part.split("=")[0]
                if name:
                    params.add(name)
    return sorted(params)


def _fingerprint_tech(headers: Dict[str, str], html: str) -> Dict[str, Optional[str]]:
    server = headers.get("Server") or headers.get("server")
    powered = headers.get("X-Powered-By") or headers.get("x-powered-by")
    aspnet = headers.get("X-AspNet-Version") or headers.get("x-aspnet-version")

    generator = None
    if html:
        match = re.search(r"<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']([^\"']+)[\"']", html, re.I)
        if match:
            generator = match.group(1).strip()

    return {
        "server": server,
        "x_powered_by": powered,
        "aspnet_version": aspnet,
        "generator": generator,
    }


def _fingerprint_cms(html: str) -> Optional[str]:
    if not html:
        return None
    for cms, patterns in CMS_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, html, re.I):
                return cms
    return None


def _detect_dom_xss(html: str) -> Optional[Dict[str, List[str]]]:
    if not html:
        return None
    sources = [s for s in DOM_XSS_SOURCES if s in html]
    sinks = [s for s in DOM_XSS_SINKS if s in html]
    if sources and sinks:
        return {"sources": sources, "sinks": sinks}
    return None


def _parse_robots(text: str) -> Dict[str, List[str]]:
    disallow: List[str] = []
    allow: List[str] = []
    sitemaps: List[str] = []

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.lower().startswith("disallow:"):
            disallow.append(line.split(":", 1)[1].strip())
        elif line.lower().startswith("allow:"):
            allow.append(line.split(":", 1)[1].strip())
        elif line.lower().startswith("sitemap:"):
            sitemaps.append(line.split(":", 1)[1].strip())

    return {"disallow": disallow, "allow": allow, "sitemaps": sitemaps}


def _check_paths(base_url: str, paths: List[str]) -> List[Dict[str, str]]:
    found = []
    for path in paths:
        url = build_url(base_url, path)
        response = request_url(url, method="GET", allow_redirects=True)
        if response and response.status_code in {200, 204, 301, 302, 401, 403}:
            found.append({"url": url, "status": str(response.status_code)})
    return found


def _detect_open_bucket(base_url: str) -> Optional[Dict[str, str]]:
    response = request_url(base_url)
    if not response:
        return None
    body = response.text or ""
    if "<ListBucketResult" in body or "<ListAllMyBucketsResult" in body:
        return {"url": base_url, "status": str(response.status_code)}
    if "Index of /" in body:
        return {"url": base_url, "status": str(response.status_code)}
    return None


def _detect_takeover_signals(domain: str, base_url: str, html: str) -> None:
    for key, patterns in TAKEOVER_FINGERPRINTS.items():
        if any(pattern.lower() in (html or "").lower() for pattern in patterns):
            save_and_report(
                domain,
                key,
                {
                    "url": base_url,
                    "timestamp": now_iso(),
                    "pattern": next(p for p in patterns if p.lower() in (html or "").lower()),
                },
                unique_keys=["url", "pattern"],
            )

    dom_xss = _detect_dom_xss(html)
    if dom_xss:
        save_and_report(
            domain,
            "dom_xss",
            {
                "url": base_url,
                "timestamp": now_iso(),
                **dom_xss,
            },
            unique_keys=["url", "sources", "sinks"],
        )
        save_and_report(
            domain,
            "xss_dom",
            {
                "url": base_url,
                "timestamp": now_iso(),
                **dom_xss,
            },
            unique_keys=["url", "sources", "sinks"],
        )


def _detect_vhost_fuzzing(domain: str, base_url: str) -> None:
    parsed = urlparse(base_url)
    if not parsed.netloc:
        return
    wildcard_host = f"waymap-test.{parsed.netloc}"
    baseline = request_url(base_url)
    test_resp = request_url(base_url, headers={"Host": wildcard_host})
    if baseline and test_resp and test_resp.status_code == baseline.status_code:
        base_len = len(baseline.text or "")
        test_len = len(test_resp.text or "")
        if base_len and abs(base_len - test_len) / base_len < 0.2:
            save_and_report(
                domain,
                "vhost_fuzzing",
                {
                    "url": base_url,
                    "timestamp": now_iso(),
                    "host": wildcard_host,
                },
                unique_keys=["url", "host"],
            )


def _detect_dns_zone_transfer(domain: str) -> None:
    try:
        ns_lookup = subprocess.run(
            ["nslookup", "-type=ns", domain],
            capture_output=True,
            text=True,
            timeout=8,
        )
        output = ns_lookup.stdout or ""
        servers = []
        for line in output.splitlines():
            if "nameserver" in line.lower():
                parts = line.split("=")
                if len(parts) > 1:
                    servers.append(parts[-1].strip().rstrip("."))
        if not servers:
            return
        for server in servers[:2]:
            transfer = subprocess.run(
                ["nslookup", "-type=any", domain, server],
                capture_output=True,
                text=True,
                timeout=8,
            )
            out = (transfer.stdout or "") + (transfer.stderr or "")
            if "AXFR" in out or "transfer" in out.lower():
                save_and_report(
                    domain,
                    "dns_zone_transfer",
                    {
                        "url": domain,
                        "timestamp": now_iso(),
                        "nameserver": server,
                    },
                    unique_keys=["url", "nameserver"],
                )
                return
    except Exception:
        return


def perform_recon_scan(
    crawled_urls: List[str],
    thread_count: int = 1,
    no_prompt: bool = False,
    verbose: bool = False,
) -> None:
    if not crawled_urls:
        print_status("No target URL provided for recon scan", "warning")
        return

    base_url = normalize_target(crawled_urls[0])
    domain = get_domain(base_url)

    print_header("Recon Scan", color="cyan")
    print_status(f"Target: {base_url}", "info")

    response = request_url(base_url)
    html = response.text if response else ""
    headers = dict(response.headers) if response else {}

    tech_info = _fingerprint_tech(headers, html)
    save_and_report(
        domain,
        "tech_fingerprint",
        {
            "url": base_url,
            "timestamp": now_iso(),
            **tech_info,
        },
        unique_keys=["url", "server", "x_powered_by", "generator"],
    )

    cms = _fingerprint_cms(html)
    if cms:
        save_and_report(
            domain,
            "cms_fingerprint",
            {
                "url": base_url,
                "timestamp": now_iso(),
                "cms": cms,
            },
            unique_keys=["url", "cms"],
        )

    _detect_takeover_signals(domain, base_url, html)

    open_bucket = _detect_open_bucket(base_url)
    if open_bucket:
        save_and_report(
            domain,
            "open_bucket_enum",
            {
                "url": open_bucket["url"],
                "timestamp": now_iso(),
                "status": open_bucket["status"],
            },
            unique_keys=["url", "status"],
        )

    robots_url = build_url(base_url, "/robots.txt")
    robots_resp = request_url(robots_url)
    if robots_resp and robots_resp.status_code == 200:
        robots_data = _parse_robots(robots_resp.text)
        save_and_report(
            domain,
            "robots_sitemap_enum",
            {
                "url": robots_url,
                "timestamp": now_iso(),
                **robots_data,
            },
            unique_keys=["url", "disallow", "allow", "sitemaps"],
        )

    sitemap_found = _check_paths(base_url, SITEMAP_PATHS)
    if sitemap_found:
        save_and_report(
            domain,
            "sitemap_endpoint_enum",
            {
                "url": base_url,
                "timestamp": now_iso(),
                "sitemaps": sitemap_found,
            },
            unique_keys=["url", "sitemaps"],
        )

    content_paths = _check_paths(base_url, COMMON_CONTENT_PATHS)
    if content_paths:
        save_and_report(
            domain,
            "content_discovery",
            {
                "url": base_url,
                "timestamp": now_iso(),
                "paths": content_paths,
            },
            unique_keys=["url", "paths"],
        )

    params = _extract_parameters(crawled_urls)
    if params:
        save_and_report(
            domain,
            "parameter_mining",
            {
                "url": base_url,
                "timestamp": now_iso(),
                "parameters": params,
            },
            unique_keys=["url", "parameters"],
        )

    _detect_vhost_fuzzing(domain, base_url)
    _detect_dns_zone_transfer(domain)

    print_status("Recon scan completed", "info")
