# Copyright (c) 2026 waymap developers
# See the file 'LICENSE' for copying permission.

"""Data models for the discovery layer."""

from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional
from enum import Enum


class EndpointType(Enum):
    """Types of discovered endpoints."""
    URL = "url"
    FORM = "form"
    API = "api"
    JS_ENDPOINT = "js_endpoint"
    GRAPHQL = "graphql"
    ROBOTS_TXT = "robots_txt"
    SITEMAP = "sitemap"
    META_REDIRECT = "meta_redirect"
    CANONICAL = "canonical"
    HTML_COMMENT = "html_comment"


class FormMethod(Enum):
    """HTTP form methods."""
    GET = "GET"
    POST = "POST"


@dataclass
class DiscoveredURL:
    """A discovered URL with metadata."""
    url: str
    source: EndpointType
    depth: int = 0
    has_params: bool = False
    params: List[str] = field(default_factory=list)
    content_type: Optional[str] = None
    status_code: Optional[int] = None
    parent_url: Optional[str] = None


@dataclass
class DiscoveredForm:
    """A discovered HTML form."""
    action: str
    method: FormMethod
    inputs: Dict[str, str] = field(default_factory=dict)
    hidden_inputs: Dict[str, str] = field(default_factory=dict)
    parent_url: Optional[str] = None
    depth: int = 0


@dataclass
class DiscoveredAPIEndpoint:
    """A discovered API endpoint."""
    endpoint: str
    method: str = "GET"
    source: str = "regex"  # regex, js, graphql, etc.
    params: List[str] = field(default_factory=list)
    parent_url: Optional[str] = None


@dataclass
class DiscoveredJSEndpoint:
    """A discovered JavaScript endpoint."""
    endpoint: str
    source: str  # fetch, axios, XHR, etc.
    parent_file: Optional[str] = None


@dataclass
class DiscoveryResults:
    """Container for all discovery results."""
    base_url: str
    domain: str
    
    # All discovered items
    urls: List[DiscoveredURL] = field(default_factory=list)
    forms: List[DiscoveredForm] = field(default_factory=list)
    api_endpoints: List[DiscoveredAPIEndpoint] = field(default_factory=list)
    js_endpoints: List[DiscoveredJSEndpoint] = field(default_factory=list)
    
    # Special sources
    robots_txt_urls: Set[str] = field(default_factory=set)
    sitemap_urls: Set[str] = field(default_factory=set)
    canonical_urls: Set[str] = field(default_factory=set)
    html_comment_urls: Set[str] = field(default_factory=set)
    
    # Statistics
    total_pages_crawled: int = 0
    total_js_files: int = 0
    
    def get_all_unique_urls(self) -> Set[str]:
        """Get all unique URLs from all sources."""
        all_urls = set()
        
        for url_obj in self.urls:
            all_urls.add(url_obj.url)
        
        for form in self.forms:
            all_urls.add(form.action)
        
        for api in self.api_endpoints:
            all_urls.add(api.endpoint)
        
        for js in self.js_endpoints:
            all_urls.add(js.endpoint)
        
        all_urls.update(self.robots_txt_urls)
        all_urls.update(self.sitemap_urls)
        all_urls.update(self.canonical_urls)
        all_urls.update(self.html_comment_urls)
        
        return all_urls
    
    def get_parameterized_urls(self) -> List[DiscoveredURL]:
        """Get URLs with query parameters."""
        return [u for u in self.urls if u.has_params]
    
    def get_forms(self) -> List[DiscoveredForm]:
        """Get all discovered forms."""
        return self.forms
    
    def get_api_endpoints(self) -> List[DiscoveredAPIEndpoint]:
        """Get all API endpoints."""
        return self.api_endpoints
    
    def get_summary(self) -> Dict[str, int]:
        """Get summary statistics."""
        return {
            "total_urls": len(self.urls),
            "parameterized_urls": len(self.get_parameterized_urls()),
            "forms": len(self.forms),
            "api_endpoints": len(self.api_endpoints),
            "js_endpoints": len(self.js_endpoints),
            "robots_txt_urls": len(self.robots_txt_urls),
            "sitemap_urls": len(self.sitemap_urls),
            "canonical_urls": len(self.canonical_urls),
            "html_comment_urls": len(self.html_comment_urls),
            "pages_crawled": self.total_pages_crawled,
            "js_files": self.total_js_files
        }
