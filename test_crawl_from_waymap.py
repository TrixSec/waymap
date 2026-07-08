# Copyright (c) 2026 waymap developers
# See the file 'LICENSE' for copying permission.

"""Test crawler exactly as waymap.py calls it."""

import sys
import os

# Add lib to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'lib'))

from lib.waymapcrawlers.crawler import run_crawler

def test_run_crawler():
    """Test run_crawler exactly as waymap.py calls it."""
    print("Testing run_crawler as called by waymap.py...")
    
    try:
        urls = run_crawler(
            start_url="https://glorycollege.edu.bd",
            max_depth=2,
            thread_count=1,
            no_prompt=True,
            use_ai=False  # Disable AI to avoid prompts
        )
        
        print(f"\n" + "="*60)
        print("Crawler Results:")
        print("="*60)
        print(f"Total URLs returned: {len(urls)}")
        
        if urls:
            print("\nFirst few URLs:")
            for url in urls[:10]:
                print(f"  - {url}")
        else:
            print("No URLs returned!")
            
    except Exception as e:
        print(f"Crawler failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_run_crawler()
