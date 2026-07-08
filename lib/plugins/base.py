# Copyright (c) 2026 waymap developers
# See the file 'LICENSE' for copying permission.

"""Base plugin interface for Waymap scan plugins."""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

from lib.app.context import ScanContext


@dataclass
class PluginMetadata:
    """Metadata for a scan plugin."""
    name: str
    version: str
    description: str
    author: str
    scan_types: List[str]
    dependencies: List[str] = None
    
    def __post_init__(self):
        if self.dependencies is None:
            self.dependencies = []


@dataclass
class ScanResult:
    """Result from a scan plugin."""
    success: bool
    findings: List[Dict[str, Any]]
    errors: List[str]
    metadata: Dict[str, Any]


class ScanPlugin(ABC):
    """Base class for scan plugins."""
    
    @abstractmethod
    def metadata(self) -> PluginMetadata:
        """Return plugin metadata."""
        pass
    
    @abstractmethod
    def scan(self, urls: List[str], context: ScanContext) -> ScanResult:
        """
        Execute the scan.
        
        Args:
            urls: URLs to scan
            context: Scan context with dependencies
            
        Returns:
            ScanResult with findings and errors
        """
        pass
    
    @abstractmethod
    def payloads(self) -> List[str]:
        """Return list of payloads used by this plugin."""
        pass
    
    def dependencies(self) -> List[str]:
        """Return list of plugin dependencies."""
        return self.metadata().dependencies
    
    def validate_context(self, context: ScanContext) -> bool:
        """Validate that context has required dependencies."""
        return context.http_client is not None
