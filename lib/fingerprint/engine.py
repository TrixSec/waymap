# Copyright (c) 2026 waymap developers
# See the file 'LICENSE' for copying permission.

"""Request Fingerprint Engine - Deduplication for vulnerability scanning."""

import hashlib
import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Any, Tuple
from urllib.parse import urlparse, parse_qs, urlunparse

from lib.core.logger import get_logger

logger = get_logger(__name__)


@dataclass
class RequestFingerprint:
    """Fingerprint of a request for deduplication."""
    url_hash: str
    method_hash: str
    headers_hash: str
    body_hash: str
    combined_hash: str
    url_pattern: str
    parameter_count: int
    
    def __str__(self) -> str:
        return f"{self.combined_hash[:16]}... ({self.url_pattern})"


@dataclass
class FingerprintCache:
    """Cache for request fingerprints to prevent duplicate scanning."""
    fingerprints: Set[str] = field(default_factory=set)
    url_patterns: Dict[str, Set[str]] = field(default_factory=dict)
    parameter_combinations: Dict[str, Set[Tuple[str, ...]]] = field(default_factory=dict)
    
    def add(self, fingerprint: RequestFingerprint) -> bool:
        """
        Add a fingerprint to cache.
        
        Returns:
            True if fingerprint is new (not duplicate), False if duplicate
        """
        if fingerprint.combined_hash in self.fingerprints:
            return False
        
        self.fingerprints.add(fingerprint.combined_hash)
        
        # Track URL patterns
        if fingerprint.url_pattern not in self.url_patterns:
            self.url_patterns[fingerprint.url_pattern] = set()
        self.url_patterns[fingerprint.url_pattern].add(fingerprint.combined_hash)
        
        return True
    
    def is_duplicate(self, fingerprint: RequestFingerprint) -> bool:
        """Check if fingerprint is a duplicate."""
        return fingerprint.combined_hash in self.fingerprints
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        return {
            "total_fingerprints": len(self.fingerprints),
            "unique_url_patterns": len(self.url_patterns),
            "avg_fingerprints_per_pattern": (
                sum(len(v) for v in self.url_patterns.values()) / len(self.url_patterns)
                if self.url_patterns else 0
            )
        }


class FingerprintEngine:
    """Request fingerprinting engine for deduplication."""
    
    def __init__(self):
        self.cache = FingerprintCache()
        self.ignore_headers = {
            'cookie', 'user-agent', 'referer', 'accept', 'accept-language',
            'accept-encoding', 'connection', 'content-length', 'host'
        }
        self.ignore_params = {
            'timestamp', 'nonce', 'csrf_token', 'authenticity_token',
            '_token', 'xsrf_token', 'anti-csrf-token'
        }
    
    def create_fingerprint(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None
    ) -> RequestFingerprint:
        """
        Create a fingerprint for a request.
        
        Args:
            url: Request URL
            method: HTTP method
            headers: Request headers
            body: Request body
            
        Returns:
            RequestFingerprint object
        """
        # Normalize URL
        normalized_url = self._normalize_url(url)
        
        # Create URL hash (normalized URL without parameter values)
        url_pattern = self._extract_url_pattern(normalized_url)
        url_hash = self._hash_string(url_pattern)
        
        # Create method hash
        method_hash = self._hash_string(method.upper())
        
        # Create headers hash (ignoring dynamic headers)
        normalized_headers = self._normalize_headers(headers or {})
        headers_hash = self._hash_string(json.dumps(normalized_headers, sort_keys=True))
        
        # Create body hash
        normalized_body = self._normalize_body(body or "")
        body_hash = self._hash_string(normalized_body)
        
        # Create combined hash
        combined_string = f"{url_hash}:{method_hash}:{headers_hash}:{body_hash}"
        combined_hash = self._hash_string(combined_string)
        
        # Count parameters
        parameter_count = self._count_parameters(normalized_url)
        
        return RequestFingerprint(
            url_hash=url_hash,
            method_hash=method_hash,
            headers_hash=headers_hash,
            body_hash=body_hash,
            combined_hash=combined_hash,
            url_pattern=url_pattern,
            parameter_count=parameter_count
        )
    
    def is_duplicate(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None
    ) -> bool:
        """
        Check if a request is a duplicate.
        
        Args:
            url: Request URL
            method: HTTP method
            headers: Request headers
            body: Request body
            
        Returns:
            True if duplicate, False if new
        """
        fingerprint = self.create_fingerprint(url, method, headers, body)
        return self.cache.is_duplicate(fingerprint)
    
    def add_request(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None
    ) -> bool:
        """
        Add a request to the fingerprint cache.
        
        Args:
            url: Request URL
            method: HTTP method
            headers: Request headers
            body: Request body
            
        Returns:
            True if request is new (not duplicate), False if duplicate
        """
        fingerprint = self.create_fingerprint(url, method, headers, body)
        return self.cache.add(fingerprint)
    
    def deduplicate_urls(
        self,
        urls: List[str],
        method: str = "GET"
    ) -> List[str]:
        """
        Deduplicate a list of URLs.
        
        Args:
            urls: List of URLs to deduplicate
            method: HTTP method for these URLs
            
        Returns:
            List of unique URLs
        """
        unique_urls = []
        for url in urls:
            if self.add_request(url, method):
                unique_urls.append(url)
        
        logger.info(f"Deduplicated {len(urls)} URLs to {len(unique_urls)} unique URLs")
        return unique_urls
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        return self.cache.get_stats()
    
    def clear_cache(self) -> None:
        """Clear the fingerprint cache."""
        self.cache = FingerprintCache()
        logger.info("Fingerprint cache cleared")
    
    def _normalize_url(self, url: str) -> str:
        """Normalize URL for fingerprinting."""
        parsed = urlparse(url)
        
        # Remove fragment
        parsed = parsed._replace(fragment='')
        
        # Sort query parameters
        if parsed.query:
            query_dict = parse_qs(parsed.query, keep_blank_values=True)
            # Remove ignored parameters
            for param in self.ignore_params:
                if param in query_dict:
                    del query_dict[param]
            
            sorted_query = '&'.join(
                f'{k}={v[0]}' if v else k 
                for k, v in sorted(query_dict.items())
            )
            parsed = parsed._replace(query=sorted_query)
        
        # Normalize path (remove trailing slash unless root)
        if parsed.path and parsed.path != '/' and parsed.path.endswith('/'):
            parsed = parsed._replace(path=parsed.path.rstrip('/'))
        
        return urlunparse(parsed)
    
    def _extract_url_pattern(self, url: str) -> str:
        """Extract URL pattern by replacing parameter values with placeholders."""
        parsed = urlparse(url)
        
        if not parsed.query:
            return url
        
        # Replace parameter values with *
        query_dict = parse_qs(parsed.query, keep_blank_values=True)
        pattern_params = []
        for k in sorted(query_dict.keys()):
            if k not in self.ignore_params:
                pattern_params.append(f'{k}=*')
        
        pattern_query = '&'.join(pattern_params)
        parsed = parsed._replace(query=pattern_query)
        
        return urlunparse(parsed)
    
    def _normalize_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Normalize headers by ignoring dynamic headers."""
        normalized = {}
        for key, value in headers.items():
            if key.lower() not in self.ignore_headers:
                normalized[key.lower()] = value
        return normalized
    
    def _normalize_body(self, body: str) -> str:
        """Normalize request body."""
        if not body:
            return ""
        
        # Try to parse as JSON and normalize
        try:
            body_dict = json.loads(body)
            # Remove ignored fields
            for field in self.ignore_params:
                if field in body_dict:
                    del body_dict[field]
            return json.dumps(body_dict, sort_keys=True)
        except (json.JSONDecodeError, ValueError):
            # Not JSON, return as-is (could be form data, etc.)
            return body
    
    def _hash_string(self, string: str) -> str:
        """Create MD5 hash of string."""
        return hashlib.md5(string.encode('utf-8')).hexdigest()
    
    def _count_parameters(self, url: str) -> int:
        """Count parameters in URL."""
        parsed = urlparse(url)
        if not parsed.query:
            return 0
        
        query_dict = parse_qs(parsed.query, keep_blank_values=True)
        # Count only non-ignored parameters
        count = sum(1 for k in query_dict.keys() if k not in self.ignore_params)
        return count
