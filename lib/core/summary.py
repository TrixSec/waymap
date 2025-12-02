# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.

"""Scan summary and reporting utilities."""

import os
import json
from datetime import datetime
from typing import Dict, List, Any, Optional
from lib.core.config import get_config
from lib.ui import print_header, print_status, colored, print_separator

config = get_config()

class ScanSummary:
    """Track and display scan summary."""
    
    def __init__(self, target: str):
        self.target = target
        self.start_time = datetime.now()
        self.end_time = None
        self.urls_scanned = 0
        self.vulnerabilities_found = []
        self.scan_types = []
        
    def add_scan_type(self, scan_type: str):
        """Add a scan type to the summary."""
        if scan_type not in self.scan_types:
            self.scan_types.append(scan_type)
    
    def add_vulnerability(self, vuln_type: str, severity: str, url: str, details: str):
        """Add a vulnerability to the summary."""
        self.vulnerabilities_found.append({
            'type': vuln_type,
            'severity': severity,
            'url': url,
            'details': details
        })
    
    def increment_urls_scanned(self, count: int = 1):
        """Increment the count of scanned URLs."""
        self.urls_scanned += count
    
    def finalize(self):
        """Mark the scan as complete."""
        self.end_time = datetime.now()
    
    def get_duration(self) -> str:
        """Get scan duration as formatted string."""
        if not self.end_time:
            self.end_time = datetime.now()
        
        duration = self.end_time - self.start_time
        minutes, seconds = divmod(duration.total_seconds(), 60)
        
        if minutes > 0:
            return f"{int(minutes)}m {int(seconds)}s"
        return f"{int(seconds)}s"
    
    def get_severity_counts(self) -> Dict[str, int]:
        """Get count of vulnerabilities by severity."""
        counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        for vuln in self.vulnerabilities_found:
            severity = vuln.get('severity', 'INFO').upper()
            if severity in counts:
                counts[severity] += 1
        return counts
    
    def print_summary(self):
        """Print a formatted scan summary."""
        self.finalize()
        
        print()
        print_separator("═", "cyan", 70)
        print_header("SCAN SUMMARY REPORT", "cyan")
        
        # Basic info
        print(colored(f"Target:          {self.target}", "white"))
        print(colored(f"Duration:        {self.get_duration()}", "white"))
        print(colored(f"Scan Types:      {', '.join(self.scan_types) if self.scan_types else 'N/A'}", "white"))
        print(colored(f"URLs Scanned:    {self.urls_scanned}", "white"))
        print()
        
        # Vulnerability summary
        severity_counts = self.get_severity_counts()
        total_vulns = len(self.vulnerabilities_found)
        
        print(colored(f"Vulnerabilities Found: {total_vulns}", "yellow" if total_vulns > 0 else "green"))
        
        if total_vulns > 0:
            print()
            if severity_counts['CRITICAL'] > 0:
                print(colored(f"  [CRITICAL] {severity_counts['CRITICAL']}", "red"))
            if severity_counts['HIGH'] > 0:
                print(colored(f"  [HIGH]     {severity_counts['HIGH']}", "red"))
            if severity_counts['MEDIUM'] > 0:
                print(colored(f"  [MEDIUM]   {severity_counts['MEDIUM']}", "yellow"))
            if severity_counts['LOW'] > 0:
                print(colored(f"  [LOW]      {severity_counts['LOW']}", "blue"))
            if severity_counts['INFO'] > 0:
                print(colored(f"  [INFO]     {severity_counts['INFO']}", "cyan"))
            
            print()
            print(colored("Vulnerability Details:", "yellow"))
            print()
            
            for i, vuln in enumerate(self.vulnerabilities_found[:10], 1):  # Show first 10
                severity_color = {
                    'CRITICAL': 'red',
                    'HIGH': 'red',
                    'MEDIUM': 'yellow',
                    'LOW': 'blue',
                    'INFO': 'cyan'
                }.get(vuln.get('severity', 'INFO').upper(), 'white')
                
                print(colored(f"  {i}. [{vuln.get('severity', 'INFO')}] {vuln.get('type', 'Unknown')}", severity_color))
                print(colored(f"     URL: {vuln.get('url', 'N/A')}", "grey"))
                if vuln.get('details'):
                    print(colored(f"     Details: {vuln.get('details', '')[:80]}", "grey"))
                print()
            
            if total_vulns > 10:
                print(colored(f"  ... and {total_vulns - 10} more vulnerabilities", "grey"))
                print()
        else:
            print(colored("  ✓ No vulnerabilities detected", "green"))
            print()
        
        # Results location
        domain = self.target.split("//")[-1].split("/")[0]
        session_dir = config.get_domain_session_dir(domain)
        results_file = os.path.join(session_dir, "waymap_full_results.json")
        
        if os.path.exists(results_file):
            print(colored(f"Full Report: {results_file}", "cyan"))
        
        print_separator("═", "cyan", 70)
        print()


def load_vulnerabilities_from_session(domain: str) -> List[Dict[str, Any]]:
    """Load vulnerabilities from session file."""
    session_dir = config.get_domain_session_dir(domain)
    results_file = os.path.join(session_dir, "waymap_full_results.json")
    
    vulnerabilities = []
    
    if not os.path.exists(results_file):
        return vulnerabilities
    
    try:
        with open(results_file, 'r') as f:
            data = json.load(f)
        
        for scan in data.get('scans', []):
            # Handle different scan result formats
            if isinstance(scan, dict):
                for scan_type, results in scan.items():
                    if isinstance(results, list):
                        for result in results:
                            vulnerabilities.append({
                                'type': scan_type,
                                'severity': result.get('Severity', result.get('severity', 'INFO')),
                                'url': result.get('Vulnerable URL', result.get('url', 'N/A')),
                                'details': result.get('Payload', result.get('payload', ''))
                            })
                    elif isinstance(results, dict):
                        for sub_type, sub_results in results.items():
                            if isinstance(sub_results, list):
                                for result in sub_results:
                                    vulnerabilities.append({
                                        'type': f"{scan_type} - {sub_type}",
                                        'severity': result.get('Severity', result.get('severity', 'INFO')),
                                        'url': result.get('Vulnerable URL', result.get('url', 'N/A')),
                                        'details': result.get('Payload', result.get('payload', ''))
                                    })
    except Exception as e:
        print_status(f"Error loading vulnerabilities: {e}", "warning")
    
    return vulnerabilities
