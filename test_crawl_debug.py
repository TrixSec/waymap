# Copyright (c) 2026 waymap developers
# See the file 'LICENSE' for copying permission.

"""Debug crawling failure."""

import sys
import os

# Add lib to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'lib'))

from lib.discovery.engine import DiscoveryEngine
from lib.core import http
from lib.core.config import get_config

def test_http_request():
    """Test basic HTTP request to target."""
    print("Testing HTTP request to https://glorycollege.edu.bd...")
    
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        response = http.get(
            "https://glorycollege.edu.bd",
            timeout=30,
            allow_redirects=True,
            verify=False,
            headers=headers
        )
        
        print(f"Status Code: {response.status_code}")
        print(f"Final URL: {response.url}")
        print(f"Content-Type: {response.headers.get('Content-Type', 'N/A')}")
        print(f"Content Length: {len(response.text)}")
        print(f"First 500 chars:\n{response.text[:500]}")
        
    except Exception as e:
        print(f"HTTP Request failed: {e}")
        import traceback
        traceback.print_exc()

def test_discovery_engine():
    """Test DiscoveryEngine directly."""
    print("\n" + "="*60)
    print("Testing DiscoveryEngine...")
    print("="*60)
    
    try:
        engine = DiscoveryEngine(
            base_url="https://glorycollege.edu.bd",
            max_depth=1,
            thread_count=1
        )
        engine.show_progress = True
        
        results = engine.run()
        
        print(f"\n" + "="*60)
        print("Discovery Results:")
        print("="*60)
        print(f"Total pages crawled: {results.total_pages_crawled}")
        print(f"Total URLs found: {len(results.urls)}")
        print(f"Parameterized URLs: {len([u for u in results.urls if u.has_params])}")
        print(f"Forms found: {len(results.forms)}")
        print(f"API endpoints: {len(results.api_endpoints)}")
        
        if results.urls:
            print("\nFirst few URLs:")
            for url in results.urls[:5]:
                print(f"  - {url.url} (params: {url.has_params})")
        
        summary = results.get_summary()
        print(f"\nSummary: {summary}")
        
    except Exception as e:
        print(f"DiscoveryEngine failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_http_request()
    test_discovery_engine()
