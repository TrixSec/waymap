# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.

"""Enhanced logging module for waymap."""

import logging
import os
from typing import Optional
from datetime import datetime
from lib.core.config import get_config


class WaymapLogger:
    """Enhanced logger for waymap."""
    
    def __init__(self, name: str, domain: Optional[str] = None):
        """
        Initialize logger.
        
        Args:
            name: Logger name
            domain: Optional domain for domain-specific logging
        """
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.INFO)
        self.domain = domain
        
        # Remove existing handlers
        self.logger.handlers = []
        
        # Setup handlers
        self._setup_console_handler()
        if domain:
            self._setup_file_handler(domain)
    
    def _setup_console_handler(self) -> None:
        """Setup console handler with formatting."""
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.WARNING)
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)
    
    def _setup_file_handler(self, domain: str) -> None:
        """Setup file handler for domain-specific logging."""
        config = get_config()
        domain_dir = config.get_domain_session_dir(domain)
        log_file = os.path.join(domain_dir, 'logs.txt')
        
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(logging.INFO)
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)
    
    def info(self, message: str) -> None:
        """Log info message."""
        self.logger.info(message)
    
    def warning(self, message: str) -> None:
        """Log warning message."""
        self.logger.warning(message)
    
    def error(self, message: str, exc_info: bool = False) -> None:
        """Log error message."""
        self.logger.error(message, exc_info=exc_info)
    
    def debug(self, message: str) -> None:
        """Log debug message."""
        self.logger.debug(message)
    
    def critical(self, message: str) -> None:
        """Log critical message."""
        self.logger.critical(message)
    
    def log_scan_start(self, target: str, scan_type: str) -> None:
        """Log scan start."""
        self.info(f'Starting {scan_type} scan on {target}')
    
    def log_scan_end(self, target: str, scan_type: str) -> None:
        """Log scan end."""
        self.info(f'Finished {scan_type} scan on {target}')
    
    def log_vulnerability_found(self, vuln_type: str, url: str, details: str = "") -> None:
        """Log vulnerability found."""
        msg = f'Vulnerability found: {vuln_type} at {url}'
        if details:
            msg += f' - {details}'
        self.info(msg)


def get_logger(name: str, domain: Optional[str] = None) -> WaymapLogger:
    """
    Get a logger instance.
    
    Args:
        name: Logger name
        domain: Optional domain for domain-specific logging
        
    Returns:
        WaymapLogger instance
    """
    return WaymapLogger(name, domain)
