# Copyright (c) 2026 waymap developers
# See the file 'LICENSE' for copying permission.

"""Event type definitions for Waymap components."""

from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional
from datetime import datetime

from lib.events.bus import Event


@dataclass
class DiscoveryEvent(Event):
    """Event emitted when crawler discovers new URLs."""
    event_type: str = "discovery"
    
    # Discovery metadata
    url: str = ""
    source: str = ""  # e.g., "crawler", "ai_agent"
    method: str = ""  # e.g., "link_extraction", "parameter_manipulation"
    
    # Additional discovery data
    depth: int = 0
    parent_url: Optional[str] = None
    parameters: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        """Initialize event type and timestamp."""
        if not self.event_type:
            self.event_type = "discovery"
        if not self.timestamp:
            self.timestamp = datetime.utcnow()
        self.data = {
            "url": self.url,
            "source": self.source,
            "method": self.method,
            "depth": self.depth,
            "parent_url": self.parent_url,
            "parameters": self.parameters
        }


@dataclass
class FindingEvent(Event):
    """Event emitted when scanner finds a vulnerability."""
    event_type: str = "finding"
    
    # Finding metadata
    vulnerability_type: str = ""  # e.g., "SQL Injection", "XSS"
    technique: str = ""  # e.g., "Error-Based", "Boolean"
    url: str = ""
    parameter: Optional[str] = None
    
    # Finding details
    payload: Optional[str] = None
    severity: float = 0.0
    confidence: float = 0.0
    
    # Additional evidence
    evidence: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Initialize event type and timestamp."""
        if not self.event_type:
            self.event_type = "finding"
        if not self.timestamp:
            self.timestamp = datetime.utcnow()
        self.data = {
            "vulnerability_type": self.vulnerability_type,
            "technique": self.technique,
            "url": self.url,
            "parameter": self.parameter,
            "payload": self.payload,
            "severity": self.severity,
            "confidence": self.confidence,
            "evidence": self.evidence
        }


@dataclass
class ScanStartEvent(Event):
    """Event emitted when a scan starts."""
    event_type: str = "scan_start"
    
    target: str = ""
    scan_types: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        """Initialize event type and timestamp."""
        if not self.event_type:
            self.event_type = "scan_start"
        if not self.timestamp:
            self.timestamp = datetime.utcnow()
        self.data = {
            "target": self.target,
            "scan_types": self.scan_types
        }


@dataclass
class ScanEndEvent(Event):
    """Event emitted when a scan ends."""
    event_type: str = "scan_end"
    
    target: str = ""
    success: bool = True
    duration_seconds: float = 0.0
    findings_count: int = 0
    
    def __post_init__(self):
        """Initialize event type and timestamp."""
        if not self.event_type:
            self.event_type = "scan_end"
        if not self.timestamp:
            self.timestamp = datetime.utcnow()
        self.data = {
            "target": self.target,
            "success": self.success,
            "duration_seconds": self.duration_seconds,
            "findings_count": self.findings_count
        }


@dataclass
class ProgressEvent(Event):
    """Event emitted for scan progress updates."""
    event_type: str = "progress"
    
    phase: str = ""  # e.g., "crawling", "scanning"
    current: int = 0
    total: int = 0
    message: str = ""
    
    def __post_init__(self):
        """Initialize event type and timestamp."""
        if not self.event_type:
            self.event_type = "progress"
        if not self.timestamp:
            self.timestamp = datetime.utcnow()
        self.data = {
            "phase": self.phase,
            "current": self.current,
            "total": self.total,
            "message": self.message
        }
