# Copyright (c) 2026 waymap developers
# See the file 'LICENSE' for copying permission.

"""Scan context - per-scan state management with dependency injection."""

import threading
import uuid
from dataclasses import dataclass, field
from typing import Set, Tuple, Dict, Any, Optional
from urllib.parse import urlparse

from lib.core.config import get_config
from lib.core.logger import get_logger
from lib.core.result_manager import ResultManager
from lib.core.http import get_http_session

config = get_config()
logger = get_logger(__name__)


@dataclass
class ScanConfig:
    """Per-scan configuration."""
    thread_count: int = 1
    timeout: int = 10
    crawl_depth: int = 2
    max_threads: int = 10
    no_prompt: bool = False
    ai_payloads: bool = False
    ai_discovery: bool = False
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ScanConfig':
        return cls(**{k: v for k, v in data.items() if k in cls.__annotations__})


@dataclass
class ScanContext:
    """Per-scan context with all dependencies and state."""
    
    # Identification
    scan_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    target: str = ""
    
    # Configuration
    config: ScanConfig = field(default_factory=ScanConfig)
    
    # Dependencies
    http_client: Optional[Any] = None  # requests.Session
    result_store: Optional[ResultManager] = None
    
    # Domain
    domain: str = ""
    
    # Scan-specific state (replaces globals)
    stop_event: threading.Event = field(default_factory=threading.Event)
    vulnerable_pairs: Set[Tuple[str, str]] = field(default_factory=set)
    processed_domains: Set[str] = field(default_factory=set)
    processed_url_params: Set[Tuple[str, str]] = field(default_factory=set)
    
    # Knowledge base (will be expanded in later phases)
    knowledge: Dict[str, Any] = field(default_factory=dict)
    
    # Reconnaissance intelligence (Phase 5)
    recon_intelligence: Optional[Any] = None  # ReconIntelligence from lib.recon.intelligence
    
    def __post_init__(self):
        """Initialize dependencies after creation."""
        if not self.domain and self.target:
            self.domain = urlparse(self.target).netloc
        
        if self.http_client is None:
            self.http_client = get_http_session()
        
        if self.result_store is None and self.domain:
            self.result_store = ResultManager(self.domain)
    
    def mark_vulnerable(self, url: str, parameter: str) -> None:
        """Mark a (url, parameter) pair as vulnerable."""
        self.vulnerable_pairs.add((url, parameter))
    
    def is_vulnerable(self, url: str, parameter: str) -> bool:
        """Check if a (url, parameter) pair is already marked vulnerable."""
        return (url, parameter) in self.vulnerable_pairs
    
    def mark_domain_processed(self, domain: str) -> None:
        """Mark a domain as processed for database extraction."""
        self.processed_domains.add(domain)
    
    def is_domain_processed(self, domain: str) -> bool:
        """Check if a domain has been processed."""
        return domain in self.processed_domains
    
    def mark_url_param_processed(self, url: str, param: str) -> None:
        """Mark a (url, param) pair as processed."""
        self.processed_url_params.add((url, param))
    
    def is_url_param_processed(self, url: str, param: str) -> bool:
        """Check if a (url, param) pair has been processed."""
        return (url, param) in self.processed_url_params
    
    def should_stop(self) -> bool:
        """Check if the scan should stop."""
        return self.stop_event.is_set()
    
    def stop(self) -> None:
        """Signal the scan to stop."""
        self.stop_event.set()
    
    def reset(self) -> None:
        """Reset scan state for reuse."""
        self.stop_event.clear()
        self.vulnerable_pairs.clear()
        self.processed_domains.clear()
        self.processed_url_params.clear()
