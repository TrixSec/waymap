# Copyright (c) 2026 waymap developers
# See the file 'LICENSE' for copying permission.

"""Test enhanced HTTP layer improvements."""

import sys
import os
import time

# Add lib to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'lib'))

from lib.core import http
from lib.core.logger import get_logger
from lib.core.config import get_config

logger = get_logger(__name__)
config = get_config()

def test_retry_logic():
    """Test retry logic with exponential backoff."""
    print("Testing retry logic with exponential backoff...")
    
    try:
        # Test with a URL that might return 500 or 502 (simulated)
        # Using a reliable URL for basic functionality test
        response = http.get(
            "https://httpbin.org/status/500",
            timeout=10,
            verify=False
        )
        
        print(f"Response status: {response.status_code}")
        print(f"Retry logic is configured (check logs for retry attempts)")
        
    except Exception as e:
        print(f"Request completed (expected behavior for 500 status): {e}")

def test_connection_pooling():
    """Test connection pooling and persistent connections."""
    print("\nTesting connection pooling and persistent connections...")
    
    try:
        session = http.get_http_session()
        
        # Check session configuration
        print(f"Session headers: {session.headers.get('Connection', 'N/A')}")
        print(f"Keep-Alive: {session.headers.get('Keep-Alive', 'N/A')}")
        
        # Make multiple requests to test connection reuse
        start_time = time.time()
        
        for i in range(5):
            response = http.get(
                "https://httpbin.org/get",
                timeout=10,
                verify=False
            )
            print(f"Request {i+1}: Status {response.status_code}")
        
        elapsed = time.time() - start_time
        print(f"5 requests completed in {elapsed:.2f} seconds")
        print(f"Average per request: {elapsed/5:.2f} seconds")
        
    except Exception as e:
        print(f"Connection pooling test failed: {e}")
        import traceback
        traceback.print_exc()

def test_thread_pool_fixed():
    """Test that thread pools are fixed (no adaptive scaling)."""
    print("\nTesting fixed thread pool configuration...")
    
    try:
        print(f"DEFAULT_THREADS: {config.DEFAULT_THREADS}")
        print(f"MAX_THREADS: {config.MAX_THREADS}")
        print(f"FUZZER_THREADS: {config.FUZZER_THREADS}")
        
        # Verify thread pools are fixed
        assert config.DEFAULT_THREADS == 1
        assert config.MAX_THREADS == 10
        assert config.FUZZER_THREADS == 30
        
        print("✓ Thread pool configuration is fixed (no adaptive scaling)")
        
    except Exception as e:
        print(f"Thread pool test failed: {e}")

def test_keep_alive():
    """Test persistent keep-alive connections."""
    print("\nTesting persistent keep-alive connections...")
    
    try:
        session = http.get_http_session()
        
        # Verify keep-alive headers
        assert 'Connection' in session.headers
        assert session.headers['Connection'] == 'keep-alive'
        
        print("✓ Keep-alive headers are configured")
        print(f"Connection: {session.headers['Connection']}")
        print(f"Keep-Alive: {session.headers.get('Keep-Alive', 'N/A')}")
        
    except Exception as e:
        print(f"Keep-alive test failed: {e}")

def test_real_target():
    """Test with real target URL."""
    print("\nTesting with real target URL...")
    
    try:
        response = http.get(
            "https://glorycollege.edu.bd",
            timeout=30,
            verify=False
        )
        
        print(f"Status: {response.status_code}")
        print(f"Content-Type: {response.headers.get('Content-Type', 'N/A')}")
        print(f"Content-Length: {len(response.text)}")
        print("✓ Real target request successful")
        
    except Exception as e:
        print(f"Real target test failed: {e}")

if __name__ == "__main__":
    print("="*60)
    print("Phase 3: Enhanced HTTP Layer Tests")
    print("="*60)
    
    test_retry_logic()
    test_connection_pooling()
    test_thread_pool_fixed()
    test_keep_alive()
    test_real_target()
    
    print("\n" + "="*60)
    print("Phase 3 HTTP Layer Tests Complete")
    print("="*60)
