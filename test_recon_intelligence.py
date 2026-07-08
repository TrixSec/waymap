# Copyright (c) 2026 waymap developers
# See the file 'LICENSE' for copying permission.

"""Test reconnaissance intelligence module."""

import sys
import os

# Add lib to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'lib'))

from lib.recon.intelligence import ReconIntelligenceEngine

def test_recon_intelligence():
    """Test reconnaissance intelligence on target."""
    print("="*60)
    print("Phase 5: Reconnaissance Intelligence Test")
    print("="*60)
    
    target = "https://glorycollege.edu.bd"
    
    try:
        print(f"\nTesting reconnaissance on {target}")
        print("-" * 60)
        
        recon_engine = ReconIntelligenceEngine(target)
        
        # Test passive recon
        print("\n1. Testing Passive Reconnaissance...")
        passive_data = recon_engine.run_passive_recon()
        print(f"   Server: {passive_data.server}")
        print(f"   Headers: {len(passive_data.headers)}")
        print(f"   Cookies: {len(passive_data.cookies)}")
        print(f"   Meta tags: {len(passive_data.meta_tags)}")
        print(f"   JS files: {len(passive_data.js_files)}")
        print(f"   CSS files: {len(passive_data.css_files)}")
        print(f"   Forms: {len(passive_data.forms)}")
        print(f"   Technologies: {passive_data.technologies}")
        print(f"   Powered by: {passive_data.powered_by}")
        
        # Test cheap active recon
        print("\n2. Testing Cheap Active Reconnaissance...")
        cheap_data = recon_engine.run_cheap_active_recon()
        print(f"   Robots.txt: {'Found' if cheap_data.robots_txt else 'Not found'}")
        print(f"   Robots URLs: {len(cheap_data.robots_urls)}")
        print(f"   Sitemap.xml: {'Found' if cheap_data.sitemap_xml else 'Not found'}")
        print(f"   Sitemap URLs: {len(cheap_data.sitemap_urls)}")
        print(f"   Security.txt: {'Found' if cheap_data.security_txt else 'Not found'}")
        print(f"   Favicon hash: {cheap_data.favicon_hash}")
        print(f"   Possible framework: {cheap_data.possible_framework}")
        
        # Test deep active recon
        print("\n3. Testing Deep Active Reconnaissance...")
        deep_data = recon_engine.run_deep_active_recon()
        print(f"   Swagger endpoints: {len(deep_data.swagger_endpoints)}")
        print(f"   GraphQL endpoints: {len(deep_data.graphql_endpoints)}")
        print(f"   API endpoints: {len(deep_data.api_endpoints)}")
        print(f"   Admin panels: {len(deep_data.admin_panels)}")
        print(f"   Backup files: {len(deep_data.backup_files)}")
        print(f"   Exposed configs: {len(deep_data.exposed_configs)}")
        print(f"   WAF detected: {deep_data.waf_detected}")
        
        # Get full intelligence summary
        print("\n4. Full Intelligence Summary...")
        intelligence = recon_engine.intelligence
        summary = intelligence.get_summary()
        
        print("\n" + "="*60)
        print("RECONNAISSANCE SUMMARY")
        print("="*60)
        print(f"Domain: {summary['domain']}")
        print(f"\nPassive Recon:")
        print(f"  Headers: {summary['passive']['headers_count']}")
        print(f"  Cookies: {summary['passive']['cookies_count']}")
        print(f"  Meta tags: {summary['passive']['meta_tags_count']}")
        print(f"  JS files: {summary['passive']['js_files_count']}")
        print(f"  Technologies: {summary['passive']['technologies']}")
        print(f"  Server: {summary['passive']['server']}")
        print(f"  Powered by: {summary['passive']['powered_by']}")
        
        print(f"\nCheap Active Recon:")
        print(f"  Robots URLs: {summary['cheap']['robots_urls_count']}")
        print(f"  Sitemap URLs: {summary['cheap']['sitemap_urls_count']}")
        print(f"  Security.txt: {summary['cheap']['security_txt']}")
        print(f"  Favicon hash: {summary['cheap']['favicon_hash']}")
        print(f"  Possible framework: {summary['cheap']['possible_framework']}")
        
        print(f"\nDeep Active Recon:")
        print(f"  Swagger endpoints: {summary['deep']['swagger_endpoints_count']}")
        print(f"  GraphQL endpoints: {summary['deep']['graphql_endpoints_count']}")
        print(f"  API endpoints: {summary['deep']['api_endpoints_count']}")
        print(f"  Admin panels: {summary['deep']['admin_panels_count']}")
        print(f"  Framework version: {summary['deep']['framework_version']}")
        print(f"  WAF detected: {summary['deep']['waf_detected']}")
        
        print("\n" + "="*60)
        print("✓ Reconnaissance Intelligence Test Complete")
        print("="*60)
        
    except Exception as e:
        print(f"\n✗ Test failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_recon_intelligence()
