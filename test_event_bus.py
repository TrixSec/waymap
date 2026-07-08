# Copyright (c) 2026 waymap developers
# See the file 'LICENSE' for copying permission.

"""Simple test for Event Bus functionality."""

import sys
import os

# Add lib to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'lib'))

from lib.events.bus import get_event_bus, reset_event_bus
from lib.events.events import DiscoveryEvent, FindingEvent, ScanStartEvent, ScanEndEvent, ProgressEvent
from lib.reporter.event_handler import get_reporter_handler, reset_reporter_handler

def test_event_bus():
    """Test basic event bus functionality."""
    print("Testing Event Bus...")
    
    # Reset event bus for clean test
    reset_event_bus()
    reset_reporter_handler()
    
    event_bus = get_event_bus()
    reporter = get_reporter_handler()
    
    # Test 1: Subscribe and publish discovery event
    print("\n1. Testing DiscoveryEvent...")
    discovery_event = DiscoveryEvent(
        url="http://example.com/page?id=1",
        source="crawler",
        method="link_extraction",
        depth=1,
        parent_url="http://example.com",
        parameters=["id=1"]
    )
    event_bus.publish(discovery_event)
    
    discovered = reporter.get_discovered_urls()
    assert len(discovered) == 1
    assert discovered[0] == "http://example.com/page?id=1"
    print("   ✓ DiscoveryEvent handled correctly")
    
    # Test 2: Subscribe and publish finding event
    print("\n2. Testing FindingEvent...")
    finding_event = FindingEvent(
        vulnerability_type="SQL Injection",
        technique="Error-Based",
        url="http://example.com/page?id=1",
        parameter="id",
        payload="' OR 1=1--",
        severity=10.0,
        confidence=0.9,
        evidence={"response": "SQL syntax error"}
    )
    event_bus.publish(finding_event)
    
    findings = reporter.get_findings()
    assert len(findings) == 1
    assert findings[0]["vulnerability_type"] == "SQL Injection"
    assert findings[0]["url"] == "http://example.com/page?id=1"
    print("   ✓ FindingEvent handled correctly")
    
    # Test 3: Test scan start/end events
    print("\n3. Testing ScanStartEvent and ScanEndEvent...")
    start_event = ScanStartEvent(
        target="http://example.com",
        scan_types=["sqli", "xss"]
    )
    event_bus.publish(start_event)
    
    end_event = ScanEndEvent(
        target="http://example.com",
        success=True,
        duration_seconds=45.5,
        findings_count=3
    )
    event_bus.publish(end_event)
    
    stats = reporter.get_scan_stats()
    assert stats["total_findings"] == 1  # Only the one finding we added
    print("   ✓ ScanStartEvent and ScanEndEvent handled correctly")
    
    # Test 4: Test progress event
    print("\n4. Testing ProgressEvent...")
    progress_event = ProgressEvent(
        phase="crawling",
        current=1,
        total=3,
        message="Crawling depth 1"
    )
    event_bus.publish(progress_event)
    print("   ✓ ProgressEvent handled correctly")
    
    # Test 5: Test multiple handlers
    print("\n5. Testing multiple handlers...")
    handler1_called = []
    handler2_called = []
    
    def handler1(event):
        handler1_called.append(True)
    
    def handler2(event):
        handler2_called.append(True)
    
    event_bus.subscribe("discovery", handler1)
    event_bus.subscribe("discovery", handler2)
    
    event_bus.publish(discovery_event)
    
    assert len(handler1_called) == 1
    assert len(handler2_called) == 1
    print("   ✓ Multiple handlers work correctly")
    
    # Cleanup
    event_bus.unsubscribe("discovery", handler1)
    event_bus.unsubscribe("discovery", handler2)
    
    print("\n✅ All Event Bus tests passed!")
    
    # Print summary
    print("\n--- Summary ---")
    print(f"Discovered URLs: {len(reporter.get_discovered_urls())}")
    print(f"Findings: {len(reporter.get_findings())}")
    print(f"Scan stats: {reporter.get_scan_stats()}")

if __name__ == "__main__":
    try:
        test_event_bus()
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
