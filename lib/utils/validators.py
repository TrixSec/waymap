# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.

"""Input validators."""

from typing import Tuple, Optional
from .url_utils import is_valid_url


class ValidationError(Exception):
    """Custom exception for validation errors."""
    pass


def validate_url(url: str) -> Tuple[bool, Optional[str]]:
    """
    Validate a URL.
    
    Args:
        url: URL to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not url:
        return False, "URL cannot be empty"
    
    if not isinstance(url, str):
        return False, "URL must be a string"
    
    if not is_valid_url(url):
        return False, "Invalid URL format"
    
    if not url.startswith(('http://', 'https://')):
        return False, "URL must start with http:// or https://"
    
    return True, None


def validate_crawl_depth(depth: int) -> Tuple[bool, Optional[str]]:
    """
    Validate crawl depth.
    
    Args:
        depth: Crawl depth value
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not isinstance(depth, int):
        return False, "Crawl depth must be an integer"
    
    if depth < 0:
        return False, "Crawl depth cannot be negative"
    
    if depth > 10:
        return False, "Crawl depth cannot exceed 10"
    
    return True, None


def validate_thread_count(threads: int, max_threads: int = 10) -> Tuple[bool, Optional[str]]:
    """
    Validate thread count.
    
    Args:
        threads: Number of threads
        max_threads: Maximum allowed threads
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not isinstance(threads, int):
        return False, "Thread count must be an integer"
    
    if threads < 1:
        return False, "Thread count must be at least 1"
    
    if threads > max_threads:
        return False, f"Thread count cannot exceed {max_threads}"
    
    return True, None


def validate_scan_type(scan_type: str) -> Tuple[bool, Optional[str]]:
    """
    Validate scan type.
    
    Args:
        scan_type: Type of scan
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    valid_scan_types = [
        'sqli', 'cmdi', 'ssti', 'xss', 'lfi',
        'open-redirect', 'crlf', 'cors', 'all'
    ]
    
    if not scan_type:
        return False, "Scan type cannot be empty"
    
    if scan_type not in valid_scan_types:
        return False, f"Invalid scan type. Must be one of: {', '.join(valid_scan_types)}"
    
    return True, None


def validate_profile_type(profile_type: Optional[str]) -> Tuple[bool, Optional[str]]:
    """
    Validate profile type.
    
    Args:
        profile_type: Type of profile
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if profile_type is None:
        return True, None
    
    valid_profiles = ['high-risk', 'critical-risk', 'deepscan']
    
    if profile_type not in valid_profiles:
        return False, f"Invalid profile type. Must be one of: {', '.join(valid_profiles)}"
    
    return True, None
