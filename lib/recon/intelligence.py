# Copyright (c) 2026 waymap developers
# See the file 'LICENSE' for copying permission.

"""Reconnaissance Intelligence Module - Three-tier gathering approach."""

import secrets
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Any
from urllib.parse import urljoin, urlparse
import re
import hashlib
from datetime import datetime

from lib.core import http
from lib.core.logger import get_logger
from lib.core.config import get_config
from lib.core.result_manager import ResultManager
from lib.recon.common import request_url, build_url, get_domain
from lib.ui import print_status

logger = get_logger(__name__)
config = get_config()

EVIDENCE_WINDOW = 90


def _proof_token() -> str:
    """Generate a unique proof token for recon findings."""
    return f"waymap_recon_{secrets.token_hex(4)}"


def _evidence_snippet(response_text: str) -> str:
    """Extract evidence snippet from response text."""
    if not response_text:
        return ""
    if len(response_text) <= EVIDENCE_WINDOW * 2:
        return response_text
    return response_text[:EVIDENCE_WINDOW] + "..." + response_text[-EVIDENCE_WINDOW:]


def _proof_evidence(response_text: str, expected_indicators: List[str]) -> Dict[str, Any]:
    """Generate proof evidence for recon finding."""
    found_indicators = [ind for ind in expected_indicators if ind in response_text]
    
    return {
        "confirmed": len(found_indicators) > 0,
        "found_indicators": found_indicators,
        "indicator_count": len(found_indicators),
        "snippet": _evidence_snippet(response_text),
    }


@dataclass
class PassiveReconData:
    """Data collected from passive reconnaissance."""
    domain: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    meta_tags: Dict[str, str] = field(default_factory=dict)
    html_comments: List[str] = field(default_factory=list)
    js_files: List[str] = field(default_factory=list)
    css_files: List[str] = field(default_factory=list)
    forms: List[Dict[str, Any]] = field(default_factory=list)
    server: Optional[str] = None
    powered_by: Optional[str] = None
    x_frame_options: Optional[str] = None
    csp: Optional[str] = None
    technologies: Set[str] = field(default_factory=set)


@dataclass
class CheapActiveReconData:
    """Data collected from cheap active reconnaissance."""
    domain: str = ""
    robots_txt: Optional[str] = None
    robots_urls: List[str] = field(default_factory=list)
    sitemap_xml: Optional[str] = None
    sitemap_urls: List[str] = field(default_factory=list)
    security_txt: Optional[str] = None
    favicon_hash: Optional[str] = None
    possible_framework: Optional[str] = None


@dataclass
class DeepActiveReconData:
    """Data collected from deep active reconnaissance."""
    domain: str = ""
    swagger_endpoints: List[str] = field(default_factory=list)
    graphql_endpoints: List[str] = field(default_factory=list)
    api_endpoints: List[str] = field(default_factory=list)
    admin_panels: List[str] = field(default_factory=list)
    backup_files: List[str] = field(default_factory=list)
    exposed_configs: List[str] = field(default_factory=list)
    framework_version: Optional[str] = None
    waf_detected: Optional[str] = None


@dataclass
class ReconIntelligence:
    """Combined reconnaissance intelligence."""
    domain: str = ""
    passive: PassiveReconData = field(default_factory=PassiveReconData)
    cheap: CheapActiveReconData = field(default_factory=CheapActiveReconData)
    deep: DeepActiveReconData = field(default_factory=DeepActiveReconData)
    
    def get_summary(self) -> Dict[str, Any]:
        """Get summary of reconnaissance data."""
        return {
            "domain": self.domain,
            "passive": {
                "headers_count": len(self.passive.headers),
                "cookies_count": len(self.passive.cookies),
                "meta_tags_count": len(self.passive.meta_tags),
                "js_files_count": len(self.passive.js_files),
                "technologies": list(self.passive.technologies),
                "server": self.passive.server,
                "powered_by": self.passive.powered_by
            },
            "cheap": {
                "robots_urls_count": len(self.cheap.robots_urls),
                "sitemap_urls_count": len(self.cheap.sitemap_urls),
                "security_txt": bool(self.cheap.security_txt),
                "favicon_hash": self.cheap.favicon_hash,
                "possible_framework": self.cheap.possible_framework
            },
            "deep": {
                "swagger_endpoints_count": len(self.deep.swagger_endpoints),
                "graphql_endpoints_count": len(self.deep.graphql_endpoints),
                "api_endpoints_count": len(self.deep.api_endpoints),
                "admin_panels_count": len(self.deep.admin_panels),
                "framework_version": self.deep.framework_version,
                "waf_detected": self.deep.waf_detected
            }
        }


class ReconIntelligenceEngine:
    """Three-tier reconnaissance intelligence engine."""
    
    def __init__(self, target: str):
        self.target = target
        self.domain = get_domain(target)
        self.base_url = f"https://{self.domain}"
        self.intelligence = ReconIntelligence(domain=self.domain)
        self.result_manager = ResultManager(self.domain)
        self.tested_paths = set()
    
    def run_passive_recon(self) -> PassiveReconData:
        """Run passive reconnaissance (headers, cookies, HTML, JS, meta tags)."""
        logger.info(f"Running passive reconnaissance on {self.domain}")
        print_status("Running passive reconnaissance...", "info")
        
        passive_data = PassiveReconData()
        passive_data.domain = self.domain
        
        # Get the main page
        response = request_url(self.base_url, method="GET", timeout=10)
        if not response:
            logger.warning(f"Could not get main page for {self.domain}")
            return passive_data
        
        # Extract headers
        passive_data.headers = dict(response.headers)
        passive_data.server = response.headers.get("Server")
        passive_data.x_frame_options = response.headers.get("X-Frame-Options")
        passive_data.csp = response.headers.get("Content-Security-Policy")
        
        # Security header analysis
        security_headers = {
            "X-Frame-Options": response.headers.get("X-Frame-Options"),
            "X-Content-Type-Options": response.headers.get("X-Content-Type-Options"),
            "X-XSS-Protection": response.headers.get("X-XSS-Protection"),
            "Strict-Transport-Security": response.headers.get("Strict-Transport-Security"),
            "Content-Security-Policy": response.headers.get("Content-Security-Policy"),
            "Referrer-Policy": response.headers.get("Referrer-Policy"),
            "Permissions-Policy": response.headers.get("Permissions-Policy"),
            "Cross-Origin-Opener-Policy": response.headers.get("Cross-Origin-Opener-Policy"),
            "Cross-Origin-Resource-Policy": response.headers.get("Cross-Origin-Resource-Policy"),
            "Cross-Origin-Embedder-Policy": response.headers.get("Cross-Origin-Embedder-Policy"),
        }
        
        # Check for missing security headers
        missing_security_headers = [header for header, value in security_headers.items() if not value]
        if missing_security_headers:
            proof_token = _proof_token()
            print_status(f"Missing security headers: {', '.join(missing_security_headers)}", "warning")
            print_status(f"  Proof Token: {proof_token}", "info")
            
            self.result_manager.add_finding("Recon Missing Security Headers", "", {
                "url": self.base_url,
                "missing_headers": missing_security_headers,
                "proof_token": proof_token,
                "poc_url": self.base_url,
                "evidence": {"confirmed": True, "found_indicators": missing_security_headers, "indicator_count": len(missing_security_headers)},
                "confirmations": [f'{len(missing_security_headers)} security headers missing'],
                "injected": True,
                "timestamp": datetime.now().isoformat(),
            })
        
        # Extract cookies
        if response.cookies:
            passive_data.cookies = {cookie.name: cookie.value for cookie in response.cookies}
            
            # Cookie security analysis
            insecure_cookies = []
            for cookie in response.cookies:
                issues = []
                if not cookie.secure:
                    issues.append("missing Secure flag")
                if not cookie.has_nonstandard_attr('HttpOnly'):
                    issues.append("missing HttpOnly flag")
                if not cookie.has_nonstandard_attr('SameSite'):
                    issues.append("missing SameSite flag")
                
                if issues:
                    insecure_cookies.append({
                        "name": cookie.name,
                        "issues": issues,
                    })
            
            if insecure_cookies:
                proof_token = _proof_token()
                print_status(f"Found {len(insecure_cookies)} insecure cookies", "warning")
                print_status(f"  Proof Token: {proof_token}", "info")
                
                self.result_manager.add_finding("Recon Insecure Cookies", "", {
                    "url": self.base_url,
                    "insecure_cookies": insecure_cookies,
                    "proof_token": proof_token,
                    "poc_url": self.base_url,
                    "evidence": {"confirmed": True, "found_indicators": [c["name"] for c in insecure_cookies], "indicator_count": len(insecure_cookies)},
                    "confirmations": [f'{len(insecure_cookies)} cookies with security issues'],
                    "injected": True,
                    "timestamp": datetime.now().isoformat(),
                })
        
        # Extract HTML content
        html_content = response.text
        
        # Extract meta tags
        passive_data.meta_tags = self._extract_meta_tags(html_content)
        passive_data.powered_by = passive_data.meta_tags.get("generator")
        
        # Extract HTML comments
        passive_data.html_comments = self._extract_html_comments(html_content)
        
        # Extract JS files
        passive_data.js_files = self._extract_js_files(html_content, self.base_url)
        
        # Extract CSS files
        passive_data.css_files = self._extract_css_files(html_content, self.base_url)
        
        # Extract forms
        passive_data.forms = self._extract_forms(html_content)
        
        # Detect technologies
        passive_data.technologies = self._detect_technologies(
            passive_data.headers,
            passive_data.meta_tags,
            passive_data.js_files
        )
        
        self.intelligence.passive = passive_data
        return passive_data
    
    def run_cheap_active_recon(self) -> CheapActiveReconData:
        """Run cheap active reconnaissance (robots.txt, sitemap.xml, security.txt, favicon)."""
        logger.info(f"Running cheap active reconnaissance on {self.domain}")
        print_status("Running cheap active reconnaissance...", "info")
        
        cheap_data = CheapActiveReconData()
        cheap_data.domain = self.domain
        
        # Check robots.txt
        robots_response = request_url(build_url(self.base_url, "robots.txt"), method="GET", timeout=5)
        if robots_response and robots_response.status_code == 200:
            cheap_data.robots_txt = robots_response.text
            cheap_data.robots_urls = self._parse_robots_txt(robots_response.text)
        
        # Check sitemap.xml
        sitemap_response = request_url(build_url(self.base_url, "sitemap.xml"), method="GET", timeout=5)
        if sitemap_response and sitemap_response.status_code == 200:
            cheap_data.sitemap_xml = sitemap_response.text
            cheap_data.sitemap_urls = self._parse_sitemap_xml(sitemap_response.text)
        
        # Check security.txt
        security_response = request_url(build_url(self.base_url, "security.txt"), method="GET", timeout=5)
        if security_response and security_response.status_code == 200:
            cheap_data.security_txt = security_response.text
        
        # Check favicon for framework detection
        favicon_response = request_url(build_url(self.base_url, "favicon.ico"), method="GET", timeout=5)
        if favicon_response and favicon_response.status_code == 200:
            cheap_data.favicon_hash = self._calculate_favicon_hash(favicon_response.content)
            cheap_data.possible_framework = self._identify_framework_by_favicon(cheap_data.favicon_hash)
        
        self.intelligence.cheap = cheap_data
        return cheap_data
    
    def run_deep_active_recon(self) -> DeepActiveReconData:
        """Run deep active reconnaissance (API discovery, WAF detection).

        NOTE: Admin-panel brute-forcing, backup-file enumeration and
        exposed-config discovery are intentionally omitted here because
        dedicated scan modules (misconfig, auth-logic, etc.) already
        cover them with richer logic.  Keeping them here would duplicate
        work and add 1 000+ slow HTTP requests to every scan.
        """
        logger.info(f"Running deep active reconnaissance on {self.domain}")
        print_status("Running deep active reconnaissance...", "info")
        
        deep_data = DeepActiveReconData()
        deep_data.domain = self.domain
        
        # Check for Swagger/OpenAPI endpoints (trimmed to high-value paths)
        swagger_paths = [
            "/swagger.json", "/swagger.yaml",
            "/api-docs", "/api/docs",
            "/swagger-ui.html", "/swagger-ui/",
            "/openapi.json", "/openapi.yaml",
            "/v1/api-docs", "/v2/api-docs", "/v3/api-docs",
            "/swagger/v1/swagger.json", "/swagger/v2/swagger.json",
        ]
        
        for path in swagger_paths:
            if path in self.tested_paths:
                continue
            self.tested_paths.add(path)
            
            response = request_url(build_url(self.base_url, path), method="GET", timeout=5)
            if response and response.status_code == 200:
                deep_data.swagger_endpoints.append(path)
                logger.info(f"Found Swagger endpoint: {path}")
                
                proof_token = _proof_token()
                evidence = _proof_evidence(response.text, ['swagger', 'openapi', 'api', 'paths'])
                
                print_status(f"Found Swagger endpoint: {path}", "success")
                print_status(f"  Proof Token: {proof_token}", "info")
                if evidence.get('snippet'):
                    print_status(f"  Evidence: {evidence['snippet']}", "info")
                
                self.result_manager.add_finding("Recon Swagger Endpoint", "", {
                    "url": build_url(self.base_url, path),
                    "path": path,
                    "status_code": response.status_code,
                    "proof_token": proof_token,
                    "poc_url": build_url(self.base_url, path),
                    "evidence": evidence,
                    "confirmations": ['swagger endpoint accessible', f'HTTP {response.status_code}'],
                    "injected": True,
                    "timestamp": datetime.now().isoformat(),
                })
        
        # Check for GraphQL endpoints (trimmed to high-value paths)
        graphql_paths = [
            "/graphql", "/api/graphql",
            "/graphiql", "/graphql/playground",
            "/v1/graphql", "/v2/graphql",
        ]
        
        for path in graphql_paths:
            if path in self.tested_paths:
                continue
            self.tested_paths.add(path)
            
            response = request_url(build_url(self.base_url, path), method="POST", 
                                   json={"query": "{ __schema { types { name } } }"}, timeout=5)
            if response and response.status_code == 200:
                deep_data.graphql_endpoints.append(path)
                logger.info(f"Found GraphQL endpoint: {path}")
                
                proof_token = _proof_token()
                evidence = _proof_evidence(response.text, ['__schema', 'types', 'graphql'])
                
                print_status(f"Found GraphQL endpoint: {path}", "success")
                print_status(f"  Proof Token: {proof_token}", "info")
                if evidence.get('snippet'):
                    print_status(f"  Evidence: {evidence['snippet']}", "info")
                
                self.result_manager.add_finding("Recon GraphQL Endpoint", "", {
                    "url": build_url(self.base_url, path),
                    "path": path,
                    "status_code": response.status_code,
                    "proof_token": proof_token,
                    "poc_url": build_url(self.base_url, path),
                    "evidence": evidence,
                    "confirmations": ['graphql endpoint accessible', f'HTTP {response.status_code}'],
                    "injected": True,
                    "timestamp": datetime.now().isoformat(),
                })
        
        # Detect WAF
        deep_data.waf_detected = self._detect_waf()
        
        self.intelligence.deep = deep_data
        return deep_data
    
    def run_full_recon(self) -> ReconIntelligence:
        """Run full three-tier reconnaissance."""
        logger.info(f"Running full reconnaissance on {self.domain}")
        print_status("Starting full reconnaissance...", "info")
        
        self.run_passive_recon()
        self.run_cheap_active_recon()
        self.run_deep_active_recon()
        
        print_status("Reconnaissance complete", "success")
        return self.intelligence
    
    def _extract_meta_tags(self, html: str) -> Dict[str, str]:
        """Extract meta tags from HTML."""
        meta_tags = {}
        patterns = [
            r'<meta\s+name=["\']([^"\']+)["\'][^>]*content=["\']([^"\']+)["\']',
            r'<meta\s+content=["\']([^"\']+)["\'][^>]*name=["\']([^"\']+)["\']',
            r'<meta\s+property=["\']([^"\']+)["\'][^>]*content=["\']([^"\']+)["\']'
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            for match in matches:
                key = match[0].lower()
                value = match[1]
                meta_tags[key] = value
        
        return meta_tags
    
    def _extract_html_comments(self, html: str) -> List[str]:
        """Extract HTML comments."""
        pattern = r'<!--(.*?)-->'
        comments = re.findall(pattern, html, re.DOTALL)
        return [comment.strip() for comment in comments if comment.strip()]
    
    def _extract_js_files(self, html: str, base_url: str) -> List[str]:
        """Extract JavaScript file URLs."""
        pattern = r'<script[^>]+src=["\']([^"\']+)["\']'
        js_files = re.findall(pattern, html, re.IGNORECASE)
        return [urljoin(base_url, js) for js in js_files]
    
    def _extract_css_files(self, html: str, base_url: str) -> List[str]:
        """Extract CSS file URLs."""
        pattern = r'<link[^>]+href=["\']([^"\']+\.css)["\']'
        css_files = re.findall(pattern, html, re.IGNORECASE)
        return [urljoin(base_url, css) for css in css_files]
    
    def _extract_forms(self, html: str) -> List[Dict[str, Any]]:
        """Extract HTML forms."""
        forms = []
        pattern = r'<form[^>]*>(.*?)</form>'
        form_matches = re.findall(pattern, html, re.IGNORECASE | re.DOTALL)
        
        for i, form_content in enumerate(form_matches):
            form = {
                "index": i,
                "action": "",
                "method": "GET",
                "inputs": []
            }
            
            # Extract action
            action_match = re.search(r'action=["\']([^"\']+)["\']', form_content, re.IGNORECASE)
            if action_match:
                form["action"] = action_match.group(1)
            
            # Extract method
            method_match = re.search(r'method=["\']([^"\']+)["\']', form_content, re.IGNORECASE)
            if method_match:
                form["method"] = method_match.group(1).upper()
            
            # Extract inputs
            input_pattern = r'<input[^>]*(?:name=["\']([^"\']+)["\'])?[^>]*(?:type=["\']([^"\']+)["\'])?'
            inputs = re.findall(input_pattern, form_content, re.IGNORECASE)
            for name, input_type in inputs:
                if name:
                    form["inputs"].append({
                        "name": name,
                        "type": input_type or "text"
                    })
            
            forms.append(form)
        
        return forms
    
    def _detect_technologies(self, headers: Dict[str, str], meta_tags: Dict[str, str], 
                            js_files: List[str]) -> Set[str]:
        """Detect technologies from headers, meta tags, and JS files."""
        technologies = set()
        
        # Check headers
        server = headers.get("Server", "").lower()
        if "nginx" in server:
            technologies.add("Nginx")
        if "apache" in server:
            technologies.add("Apache")
        if "iis" in server or "microsoft-iis" in server:
            technologies.add("IIS")
        if "cloudflare" in server:
            technologies.add("Cloudflare")
        
        x_powered_by = headers.get("X-Powered-By", "").lower()
        if "php" in x_powered_by:
            technologies.add("PHP")
        if "asp.net" in x_powered_by:
            technologies.add("ASP.NET")
        if "express" in x_powered_by:
            technologies.add("Express.js")
        
        # Check meta tags
        generator = meta_tags.get("generator", "").lower()
        if "wordpress" in generator:
            technologies.add("WordPress")
        if "drupal" in generator:
            technologies.add("Drupal")
        if "joomla" in generator:
            technologies.add("Joomla")
        
        # Check JS files
        js_patterns = {
            "jquery": r"jquery",
            "react": r"react",
            "vue": r"vue",
            "angular": r"angular",
            "bootstrap": r"bootstrap",
            "lodash": r"lodash",
            "axios": r"axios",
            "moment": r"moment",
            "chart": r"chart",
            "d3": r"d3",
            "three": r"three",
            "backbone": r"backbone",
            "ember": r"ember",
            "knockout": r"knockout",
            "polymer": r"polymer",
            "svelte": r"svelte",
            "next": r"next",
            "nuxt": r"nuxt",
            "gatsby": r"gatsby",
            "preact": r"preact",
            "alpine": r"alpine",
            "htmx": r"htmx",
            "stimulus": r"stimulus",
            "turbo": r"turbo",
        }
        
        for js_file in js_files:
            js_name = js_file.lower()
            for tech, pattern in js_patterns.items():
                if re.search(pattern, js_name):
                    technologies.add(tech.capitalize())
        
        return technologies
    
    def _parse_robots_txt(self, robots_txt: str) -> List[str]:
        """Parse robots.txt for disallowed/allowed URLs."""
        urls = []
        lines = robots_txt.split('\n')
        
        for line in lines:
            line = line.strip()
            if line.lower().startswith("disallow:") or line.lower().startswith("allow:"):
                parts = line.split(':', 1)
                if len(parts) > 1:
                    path = parts[1].strip()
                    if path:
                        urls.append(path)
        
        return urls
    
    def _parse_sitemap_xml(self, sitemap_xml: str) -> List[str]:
        """Parse sitemap.xml for URLs."""
        urls = []
        pattern = r'<loc>([^<]+)</loc>'
        matches = re.findall(pattern, sitemap_xml)
        urls.extend(matches)
        return urls
    
    def _calculate_favicon_hash(self, favicon_content: bytes) -> str:
        """Calculate MD5 hash of favicon."""
        return hashlib.md5(favicon_content).hexdigest()
    
    def _identify_framework_by_favicon(self, favicon_hash: str) -> Optional[str]:
        """Identify framework by favicon hash (simplified)."""
        # This is a simplified version - in production, use a comprehensive database
        # Common framework favicon hashes (examples)
        framework_hashes = {
            # WordPress
            "a4d5bba716b6c0b5d3b5c5d5b5c5d5b5": "WordPress",
            # Laravel
            "b5c5d5b5c5d5b5c5d5b5c5d5b5c5d5b5": "Laravel",
            # Django
            "c5d5b5c5d5b5c5d5b5c5d5b5c5d5b5c5": "Django",
        }
        
        return framework_hashes.get(favicon_hash)
    
    def _detect_waf(self) -> Optional[str]:
        """Detect WAF by analyzing responses."""
        # Send a suspicious request
        test_payload = "<script>alert('xss')</script>"
        response = request_url(build_url(self.base_url, "/"), method="GET", 
                              params={"q": test_payload}, timeout=5)
        
        if response:
            # Check for common WAF signatures in headers
            headers = response.headers
            
            if "cloudflare" in str(headers).lower():
                return "Cloudflare"
            if "akamai" in str(headers).lower():
                return "Akamai"
            if "aws" in str(headers).lower():
                return "AWS WAF"
            if "modsecurity" in str(headers).lower():
                return "ModSecurity"
            
            # Check for WAF-like behavior (blocking suspicious requests)
            if response.status_code in [403, 406, 503]:
                return "Unknown WAF"
        
        return None
