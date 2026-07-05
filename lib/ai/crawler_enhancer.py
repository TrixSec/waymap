from typing import Dict, Any, Optional, List, Set
from lib.ai.llm_provider import get_llm_provider, is_llm_available
from lib.ai.attack_surface import discover_attack_surface
from lib.core.logger import get_logger
from lib.ui import print_status
from urllib.parse import urljoin, urlparse
import re

logger = get_logger(__name__)


def extract_hidden_urls(html_content: str, base_url: str) -> List[str]:
    """Extract potential hidden URLs from HTML content using AI."""
    if not is_llm_available() or not html_content:
        return []
    
    print_status("Extracting hidden URLs from content...", "info")
    logger.info("Extracting hidden URLs using AI")
    
    system_prompt = """You are a URL extractor. Extract all potential URLs and endpoints from the 
provided HTML/JS content. Return only a JSON array of URLs.

Example: ["https://example.com/api", "/admin", "/hidden.php"]"""
    
    prompt = f"Extract URLs from this content (base URL: {base_url}):\n\n{html_content[:5000]}"
    
    json_schema = {
        "type": "object",
        "properties": {
            "urls": {"type": "array", "items": {"type": "string"}}
        },
        "required": ["urls"],
        "additionalProperties": False
    }
    
    try:
        provider = get_llm_provider()
        result = provider.generate(prompt, system_prompt, json_schema)
        extracted = result.get("urls", [])
        
        # Normalize URLs
        normalized = []
        for url in extracted:
            if url.startswith("/"):
                normalized.append(urljoin(base_url, url))
            elif url.startswith("http"):
                normalized.append(url)
        
        print_status(f"Extracted {len(normalized)} potential URLs!", "success")
        return normalized
        
    except Exception as e:
        print_status(f"Failed to extract hidden URLs: {str(e)}", "error")
        logger.error(f"Failed to extract hidden URLs: {e}")
        return []


def enhance_crawl_results(
    crawled_urls: List[str],
    base_url: str,
    html_contents: Optional[Dict[str, str]] = None
) -> List[str]:
    """
    Enhance crawl results with AI-discovered URLs.
    
    Args:
        crawled_urls: Original list of crawled URLs
        base_url: Base target URL
        html_contents: Dict of URL -> HTML content
        
    Returns:
        Enhanced list of URLs
    """
    if not is_llm_available():
        return crawled_urls
    
    enhanced = set(crawled_urls)
    
    # Use attack surface discovery on each crawled page
    for url in crawled_urls:
        html = html_contents.get(url) if html_contents else None
        surface = discover_attack_surface(url, html_content=html)
        
        if surface:
            for endpoint in surface.get("endpoints", []):
                if endpoint.startswith("/"):
                    enhanced.add(urljoin(base_url, endpoint))
                elif endpoint.startswith("http"):
                    enhanced.add(endpoint)
    
    return list(enhanced)
