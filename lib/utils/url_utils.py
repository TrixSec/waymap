# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.

"""URL utility functions."""

from urllib.parse import urlparse
from typing import Optional


def is_valid_url(url: str) -> bool:
    """
    Check if a URL is valid.
    
    Args:
        url: The URL to validate
        
    Returns:
        True if URL is valid, False otherwise
    """
    try:
        parsed = urlparse(url)
        return bool(parsed.netloc) and bool(parsed.scheme)
    except Exception:
        return False


def has_query_parameters(url: str) -> bool:
    """
    Check if URL has query parameters.
    
    Args:
        url: The URL to check
        
    Returns:
        True if URL has query parameters, False otherwise
    """
    return any(symbol in url for symbol in ['?', '&', '='])


def is_within_domain(url: str, base_domain: str) -> bool:
    """
    Check if URL belongs to the base domain.
    
    Args:
        url: The URL to check
        base_domain: The base domain to compare against
        
    Returns:
        True if URL is within domain, False otherwise
    """
    try:
        url_domain = urlparse(url).netloc
        if url_domain == base_domain:
            return True
            
        # Normalize domains by removing www. prefix
        u_domain = url_domain[4:] if url_domain.startswith("www.") else url_domain
        b_domain = base_domain[4:] if base_domain.startswith("www.") else base_domain
        
        return u_domain == b_domain
    except Exception:
        return False


def extract_domain(url: str) -> Optional[str]:
    """
    Extract domain from URL.
    
    Args:
        url: The URL to extract domain from
        
    Returns:
        Domain name or None if extraction fails
    """
    try:
        return url.split("//")[-1].split("/")[0]
    except Exception:
        return None


def normalize_url(url: str) -> str:
    """
    Normalize URL by removing fragments and trailing slashes.
    
    Args:
        url: The URL to normalize
        
    Returns:
        Normalized URL
    """
    try:
        parsed = urlparse(url)
        normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if parsed.query:
            normalized += f"?{parsed.query}"
        return normalized.rstrip('/')
    except Exception:
        return url
