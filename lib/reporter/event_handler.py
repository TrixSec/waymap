# Copyright (c) 2026 waymap developers
# See the file 'LICENSE' for copying permission.

"""Event handler for reporter to consume scan events."""

from typing import Dict, List, Any
from lib.core.logger import get_logger
from lib.events.bus import get_event_bus
from lib.events.events import DiscoveryEvent, FindingEvent, ScanStartEvent, ScanEndEvent, ProgressEvent

logger = get_logger(__name__)


class ReporterEventHandler:
    """Event handler for reporter to consume and process scan events."""
    
    def __init__(self):
        self.event_bus = get_event_bus()
        self.discovered_urls: List[str] = []
        self.findings: List[Dict[str, Any]] = []
        self.scan_stats: Dict[str, Any] = {
            "start_time": None,
            "end_time": None,
            "duration": 0,
            "total_findings": 0
        }
        
        # Subscribe to events
        self._subscribe_to_events()
    
    def _subscribe_to_events(self) -> None:
        """Subscribe to relevant event types."""
        self.event_bus.subscribe("discovery", self._handle_discovery)
        self.event_bus.subscribe("finding", self._handle_finding)
        self.event_bus.subscribe("scan_start", self._handle_scan_start)
        self.event_bus.subscribe("scan_end", self._handle_scan_end)
        self.event_bus.subscribe("progress", self._handle_progress)
        logger.debug("ReporterEventHandler subscribed to all event types")
    
    def _handle_discovery(self, event: DiscoveryEvent) -> None:
        """Handle discovery events."""
        self.discovered_urls.append(event.url)
        logger.debug(f"Discovery event: {event.url} (source: {event.source})")
    
    def _handle_finding(self, event: FindingEvent) -> None:
        """Handle finding events."""
        finding = {
            "vulnerability_type": event.vulnerability_type,
            "technique": event.technique,
            "url": event.url,
            "parameter": event.parameter,
            "payload": event.payload,
            "severity": event.severity,
            "confidence": event.confidence,
            "evidence": event.evidence,
            "timestamp": event.timestamp.isoformat()
        }
        self.findings.append(finding)
        self.scan_stats["total_findings"] += 1
        logger.info(f"Finding event: {event.vulnerability_type} on {event.url}")
    
    def _handle_scan_start(self, event: ScanStartEvent) -> None:
        """Handle scan start events."""
        self.scan_stats["start_time"] = event.timestamp
        logger.info(f"Scan started: {event.target} (types: {event.scan_types})")
    
    def _handle_scan_end(self, event: ScanEndEvent) -> None:
        """Handle scan end events."""
        self.scan_stats["end_time"] = event.timestamp
        self.scan_stats["duration"] = event.duration_seconds
        logger.info(f"Scan ended: {event.target} (duration: {event.duration_seconds}s, findings: {event.findings_count})")
    
    def _handle_progress(self, event: ProgressEvent) -> None:
        """Handle progress events."""
        logger.debug(f"Progress: {event.phase} - {event.current}/{event.total} - {event.message}")
    
    def get_discovered_urls(self) -> List[str]:
        """Get all discovered URLs."""
        return self.discovered_urls.copy()
    
    def get_findings(self) -> List[Dict[str, Any]]:
        """Get all findings."""
        return self.findings.copy()
    
    def get_scan_stats(self) -> Dict[str, Any]:
        """Get scan statistics."""
        return self.scan_stats.copy()
    
    def reset(self) -> None:
        """Reset handler state."""
        self.discovered_urls.clear()
        self.findings.clear()
        self.scan_stats = {
            "start_time": None,
            "end_time": None,
            "duration": 0,
            "total_findings": 0
        }
        logger.debug("ReporterEventHandler reset")
    
    def unsubscribe(self) -> None:
        """Unsubscribe from all events."""
        self.event_bus.unsubscribe("discovery", self._handle_discovery)
        self.event_bus.unsubscribe("finding", self._handle_finding)
        self.event_bus.unsubscribe("scan_start", self._handle_scan_start)
        self.event_bus.unsubscribe("scan_end", self._handle_scan_end)
        self.event_bus.unsubscribe("progress", self._handle_progress)
        logger.debug("ReporterEventHandler unsubscribed from all events")


# Global handler instance
_global_handler: ReporterEventHandler = None


def get_reporter_handler() -> ReporterEventHandler:
    """Get the global reporter event handler."""
    global _global_handler
    if _global_handler is None:
        _global_handler = ReporterEventHandler()
    return _global_handler


def reset_reporter_handler() -> None:
    """Reset the global reporter event handler."""
    global _global_handler
    if _global_handler is not None:
        _global_handler.unsubscribe()
        _global_handler = None
