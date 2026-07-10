#!/usr/bin/env python3
"""
API Security Scanner for Waymap
Supports REST, GraphQL, and SOAP API testing
"""

import os
import secrets
import requests
from lib.core import http
import json
from typing import Dict, List, Optional, Any
from urllib.parse import urljoin, urlparse
import time
from datetime import datetime

from lib.core.config import get_config
from lib.core.logger import get_logger
from lib.ui import print_status, print_header, print_separator, ask_continue_scanning
from lib.core.state import stop_scan
from lib.core.result_manager import ResultManager
from lib.parse.random_headers import generate_random_headers

config = get_config()
logger = get_logger(__name__)

EVIDENCE_WINDOW = 90


def _domain(url: str) -> str:
    """Extract domain from URL."""
    return urlparse(url).netloc or "unknown_domain"


def _proof_token() -> str:
    """Generate a unique proof token for API testing."""
    return f"waymap_api_{secrets.token_hex(4)}"


def _evidence_snippet(response_text: str) -> str:
    """Extract evidence snippet from response text."""
    if not response_text:
        return ""
    if len(response_text) <= EVIDENCE_WINDOW * 2:
        return response_text
    return response_text[:EVIDENCE_WINDOW] + "..." + response_text[-EVIDENCE_WINDOW:]


def _proof_evidence(response_text: str, expected_indicators: List[str]) -> Dict[str, Any]:
    """Generate proof evidence for API vulnerability."""
    found_indicators = [ind for ind in expected_indicators if ind in response_text]
    
    return {
        "confirmed": len(found_indicators) > 0,
        "found_indicators": found_indicators,
        "indicator_count": len(found_indicators),
        "snippet": _evidence_snippet(response_text),
    }


class APIScanner:
    """Scan APIs for security vulnerabilities"""
    
    def __init__(self, base_url: str, auth_session: Optional[requests.Session] = None):
        """
        Initialize API scanner
        
        Args:
            base_url: Base URL of the API
            auth_session: Optional authenticated session
        """
        self.base_url = base_url
        self.session = auth_session if auth_session else requests.Session()
        self.vulnerabilities = []
        self.result_manager = ResultManager(_domain(base_url))
        self.tested_combinations = set()
        self.baseline_responses = {}
        
    def scan_rest_api(self, endpoints: List[str], methods: Optional[List[str]] = None,
                     verbose: bool = False) -> List[Dict[str, Any]]:
        """
        Scan REST API endpoints
        
        Args:
            endpoints: List of API endpoints
            methods: HTTP methods to test (default: GET, POST, PUT, DELETE)
            verbose: Enable verbose output
            
        Returns:
            List of vulnerabilities found
        """
        print_header("REST API Security Scan", color="cyan")
        
        if methods is None:
            methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']
            
        print_status(f"Scanning {len(endpoints)} endpoints", "info")
        print_status(f"Testing methods: {', '.join(methods)}", "info")
        print_separator()
        
        for endpoint in endpoints:
            if stop_scan.is_set():
                break
                
            url = urljoin(self.base_url, endpoint)
            
            if verbose:
                print_status(f"Testing endpoint: {endpoint}", "debug")
            
            # Capture baseline response for false positive prevention
            try:
                baseline_response = http.get(url, timeout=10, verify=False)
                self.baseline_responses[url] = {
                    'status': baseline_response.status_code,
                    'text': baseline_response.text[:1000],  # Store first 1000 chars
                    'headers': dict(baseline_response.headers),
                }
                if verbose:
                    print_status(f"Captured baseline for {url}: HTTP {baseline_response.status_code}", "debug")
            except Exception as e:
                if verbose:
                    print_status(f"Failed to capture baseline: {e}", "debug")
                
            # Test each HTTP method
            for method in methods:
                if stop_scan.is_set():
                    break
                    
                try:
                    self._test_rest_endpoint(url, method, verbose)
                except Exception as e:
                    logger.error(f"Error testing {method} {url}: {e}")
                    
        print_separator()
        print_status(f"REST API scan completed. Found {len(self.vulnerabilities)} issues", "info")
        return self.vulnerabilities
        
    def _test_rest_endpoint(self, url: str, method: str, verbose: bool = False) -> None:
        """Test a single REST endpoint with proof of concept"""
        
        # Check for duplicate test
        combo_key = (url, method, 'missing_auth')
        if combo_key in self.tested_combinations:
            return
        self.tested_combinations.add(combo_key)
        
        # Test for missing authentication
        try:
            response = http.request(method, url, timeout=10, verify=False)
            
            if response.status_code == 200 and 'Authorization' not in self.session.headers:
                # False positive prevention: check against baseline
                baseline = self.baseline_responses.get(url, {})
                if baseline and baseline.get('status') == 200:
                    # If baseline also returns 200, this might be a public endpoint
                    # Only report if response content differs significantly
                    if response.text[:500] == baseline.get('text', '')[:500]:
                        if verbose:
                            print_status(f"Skipping: response identical to baseline (likely public endpoint)", "debug")
                        return
                
                # Check for duplicate finding
                is_duplicate = self.result_manager.has_duplicate(
                    "API Missing Authentication",
                    ["url", "method"],
                    {"url": url, "method": method}
                )
                
                if is_duplicate:
                    if verbose:
                        print_status(f"Skipping duplicate: {method} {url}", "debug")
                    return
                
                proof_token = _proof_token()
                evidence = _proof_evidence(response.text, ['200', 'success', 'data'])
                
                vuln = {
                    'type': 'Missing Authentication',
                    'url': url,
                    'method': method,
                    'severity': 'High',
                    'details': f'{method} request succeeded without authentication',
                    'proof_token': proof_token,
                    'evidence': evidence,
                    'response': response,
                    'headers': response.headers,
                }
                self.vulnerabilities.append(vuln)
                
                print_status(f"Missing auth: {method} {url}", "success")
                print_status(f"  Proof Token: {proof_token}", "info")
                if evidence.get('snippet'):
                    print_status(f"  Evidence: {evidence['snippet']}", "info")
                
                # Add to result manager
                self.result_manager.add_finding("API Missing Authentication", "", {
                    "url": url,
                    "method": method,
                    "proof_token": proof_token,
                    "poc_url": url,
                    "evidence": evidence,
                    "confirmations": ['request succeeded without authentication'],
                    "injected": True,
                    "timestamp": datetime.now().isoformat(),
                })
                
        except Exception as e:
            if verbose:
                print_status(f"Request error: {e}", "debug")
                
        # Test for excessive data exposure
        try:
            response = self.session.request(method, url, timeout=10, verify=False)
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    # Check for sensitive fields
                    sensitive_fields = ['password', 'secret', 'token', 'api_key', 'private_key']
                    for field in sensitive_fields:
                        if self._check_nested_dict(data, field):
                            # False positive prevention: check if field was in baseline
                            baseline = self.baseline_responses.get(url, {})
                            baseline_text = baseline.get('text', '')
                            if field in baseline_text:
                                if verbose:
                                    print_status(f"Field {field} found in baseline, skipping as false positive", "debug")
                                continue
                            
                            # Check for duplicate
                            combo_key = (url, method, f'data_exposure_{field}')
                            if combo_key in self.tested_combinations:
                                continue
                            self.tested_combinations.add(combo_key)
                            
                            is_duplicate = self.result_manager.has_duplicate(
                                "API Data Exposure",
                                ["url", "method", "sensitive_field"],
                                {"url": url, "method": method, "sensitive_field": field}
                            )
                            
                            if is_duplicate:
                                if verbose:
                                    print_status(f"Skipping duplicate data exposure: {field}", "debug")
                                continue
                            
                            proof_token = _proof_token()
                            evidence = _proof_evidence(response.text, [field])
                            
                            vuln = {
                                'type': 'Excessive Data Exposure',
                                'url': url,
                                'method': method,
                                'severity': 'Medium',
                                'details': f'Response contains sensitive field: {field}',
                                'proof_token': proof_token,
                                'evidence': evidence,
                                'response': response,
                                'headers': response.headers,
                            }
                            self.vulnerabilities.append(vuln)
                            
                            print_status(f"Data exposure: {field} in {url}", "success")
                            print_status(f"  Proof Token: {proof_token}", "info")
                            if evidence.get('snippet'):
                                print_status(f"  Evidence: {evidence['snippet']}", "info")
                            
                            # Add to result manager
                            self.result_manager.add_finding("API Data Exposure", "", {
                                "url": url,
                                "method": method,
                                "sensitive_field": field,
                                "proof_token": proof_token,
                                "poc_url": url,
                                "evidence": evidence,
                                "confirmations": [f'sensitive field {field} exposed in response'],
                                "injected": True,
                                "timestamp": datetime.now().isoformat(),
                            })
                            
                            break
                except (ValueError, json.JSONDecodeError):
                    pass
                    
        except Exception as e:
            if verbose:
                print_status(f"Data exposure test error: {e}", "debug")
                
        # Test for IDOR (Insecure Direct Object Reference)
        if method in ['GET', 'PUT', 'DELETE']:
            try:
                # Try accessing with different IDs
                test_ids = ['1', '2', '999', 'admin']
                for test_id in test_ids:
                    test_url = f"{url}/{test_id}" if not url.endswith('/') else f"{url}{test_id}"
                    
                    # Check for duplicate
                    combo_key = (test_url, method, f'idor_{test_id}')
                    if combo_key in self.tested_combinations:
                        continue
                    self.tested_combinations.add(combo_key)
                    
                    response = self.session.request(method, test_url, timeout=10, verify=False)
                    
                    if response.status_code == 200:
                        is_duplicate = self.result_manager.has_duplicate(
                            "API IDOR",
                            ["url", "method", "test_id"],
                            {"url": test_url, "method": method, "test_id": test_id}
                        )
                        
                        if is_duplicate:
                            if verbose:
                                print_status(f"Skipping duplicate IDOR: {test_id}", "debug")
                            continue
                        
                        proof_token = _proof_token()
                        evidence = _proof_evidence(response.text, ['200', 'data', 'id'])
                        
                        vuln = {
                            'type': 'Potential IDOR',
                            'url': test_url,
                            'method': method,
                            'severity': 'High',
                            'details': f'Direct object access without proper authorization check',
                            'proof_token': proof_token,
                            'evidence': evidence,
                            'response': response,
                            'headers': response.headers,
                        }
                        self.vulnerabilities.append(vuln)
                        
                        print_status(f"Potential IDOR: {method} {test_url}", "success")
                        print_status(f"  Proof Token: {proof_token}", "info")
                        if evidence.get('snippet'):
                            print_status(f"  Evidence: {evidence['snippet']}", "info")
                        
                        # Add to result manager
                        self.result_manager.add_finding("API IDOR", "", {
                            "url": test_url,
                            "method": method,
                            "test_id": test_id,
                            "proof_token": proof_token,
                            "poc_url": test_url,
                            "evidence": evidence,
                            "confirmations": ['direct object access without authorization'],
                            "injected": True,
                            "timestamp": datetime.now().isoformat(),
                        })
                        
                        break
                        
            except Exception as e:
                if verbose:
                    print_status(f"IDOR test error: {e}", "debug")
                    
    def scan_graphql(self, endpoint: str, verbose: bool = False) -> List[Dict[str, Any]]:
        """
        Scan GraphQL API for vulnerabilities
        
        Args:
            endpoint: GraphQL endpoint URL
            verbose: Enable verbose output
            
        Returns:
            List of vulnerabilities found
        """
        print_header("GraphQL API Security Scan", color="cyan")
        
        url = urljoin(self.base_url, endpoint)
        print_status(f"Scanning GraphQL endpoint: {url}", "info")
        print_separator()
        
        # Test introspection
        introspection_query = {
            "query": """
            {
                __schema {
                    types {
                        name
                        fields {
                            name
                        }
                    }
                }
            }
            """
        }
        
        try:
            response = self.session.post(url, json=introspection_query, timeout=10, verify=False)
            
            if response.status_code == 200 and 'data' in response.json():
                proof_token = _proof_token()
                evidence = _proof_evidence(response.text, ['__schema', 'types', 'fields'])
                
                vuln = {
                    'type': 'GraphQL Introspection Enabled',
                    'url': url,
                    'method': 'POST',
                    'severity': 'Medium',
                    'details': 'GraphQL introspection is enabled, exposing schema information',
                    'proof_token': proof_token,
                    'evidence': evidence,
                    'response': response,
                    'headers': response.headers,
                }
                self.vulnerabilities.append(vuln)
                
                print_status("GraphQL introspection enabled", "success")
                print_status(f"  Proof Token: {proof_token}", "info")
                if evidence.get('snippet'):
                    print_status(f"  Evidence: {evidence['snippet']}", "info")
                
                # Add to result manager
                self.result_manager.add_finding("GraphQL Introspection", "", {
                    "url": url,
                    "method": "POST",
                    "proof_token": proof_token,
                    "poc_url": url,
                    "evidence": evidence,
                    "confirmations": ['GraphQL introspection query successful', 'schema information exposed'],
                    "injected": True,
                    "timestamp": datetime.now().isoformat(),
                })
                
                if verbose:
                    schema_data = response.json().get('data', {}).get('__schema', {})
                    types_count = len(schema_data.get('types', []))
                    print_status(f"Found {types_count} types in schema", "debug")
                    
        except Exception as e:
            if verbose:
                print_status(f"Introspection test error: {e}", "debug")
                
        # Test for query depth limit
        deep_query = {
            "query": """
            {
                user {
                    posts {
                        comments {
                            author {
                                posts {
                                    comments {
                                        author {
                                            id
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            """
        }
        
        try:
            response = self.session.post(url, json=deep_query, timeout=10, verify=False)
            
            if response.status_code == 200:
                proof_token = _proof_token()
                evidence = _proof_evidence(response.text, ['data', 'user', 'posts'])
                
                vuln = {
                    'type': 'No Query Depth Limit',
                    'url': url,
                    'method': 'POST',
                    'severity': 'Medium',
                    'details': 'GraphQL allows deeply nested queries (DoS risk)',
                    'proof_token': proof_token,
                    'evidence': evidence,
                    'response': response,
                    'headers': response.headers,
                }
                self.vulnerabilities.append(vuln)
                
                print_status("No query depth limit detected", "success")
                print_status(f"  Proof Token: {proof_token}", "info")
                if evidence.get('snippet'):
                    print_status(f"  Evidence: {evidence['snippet']}", "info")
                
                # Add to result manager
                self.result_manager.add_finding("GraphQL No Depth Limit", "", {
                    "url": url,
                    "method": "POST",
                    "proof_token": proof_token,
                    "poc_url": url,
                    "evidence": evidence,
                    "confirmations": ['deeply nested query successful', 'potential DoS vulnerability'],
                    "injected": True,
                    "timestamp": datetime.now().isoformat(),
                })
                
        except Exception as e:
            if verbose:
                print_status(f"Depth limit test error: {e}", "debug")
                
        print_separator()
        print_status(f"GraphQL scan completed. Found {len(self.vulnerabilities)} issues", "info")
        return self.vulnerabilities
        
    def test_rate_limiting(self, endpoint: str, requests_count: int = 100,
                          verbose: bool = False) -> bool:
        """
        Test for rate limiting
        
        Args:
            endpoint: API endpoint to test
            requests_count: Number of requests to send
            verbose: Enable verbose output
            
        Returns:
            True if rate limiting is detected
        """
        print_header("Rate Limiting Test", color="cyan")
        
        url = urljoin(self.base_url, endpoint)
        print_status(f"Testing rate limiting: {url}", "info")
        print_status(f"Sending {requests_count} requests...", "info")
        
        rate_limited = False
        success_count = 0
        
        for i in range(requests_count):
            if stop_scan.is_set():
                break
                
            try:
                response = self.session.get(url, timeout=5, verify=False)
                
                if response.status_code == 429:  # Too Many Requests
                    rate_limited = True
                    print_status(f"Rate limiting detected after {i+1} requests", "success")
                    break
                elif response.status_code == 200:
                    success_count += 1
                    
                if verbose and (i + 1) % 10 == 0:
                    print_status(f"Sent {i+1}/{requests_count} requests", "debug")
                    
            except Exception as e:
                if verbose:
                    print_status(f"Request {i+1} error: {e}", "debug")
                    
        if not rate_limited and success_count >= requests_count * 0.9:
            proof_token = _proof_token()
            evidence = _proof_evidence(f"{success_count} successful requests", ['success', '200'])
            
            vuln = {
                'type': 'No Rate Limiting',
                'url': url,
                'method': 'GET',
                'severity': 'Medium',
                'details': f'No rate limiting detected after {requests_count} requests',
                'proof_token': proof_token,
                'evidence': evidence,
                'success_count': success_count,
            }
            self.vulnerabilities.append(vuln)
            
            print_status(f"No rate limiting detected ({success_count} successful requests)", "success")
            print_status(f"  Proof Token: {proof_token}", "info")
            
            # Add to result manager
            self.result_manager.add_finding("API No Rate Limiting", "", {
                "url": url,
                "method": "GET",
                "requests_sent": requests_count,
                "successful_requests": success_count,
                "proof_token": proof_token,
                "poc_url": url,
                "evidence": evidence,
                "confirmations": [f'{success_count} successful requests without rate limiting'],
                "injected": True,
                "timestamp": datetime.now().isoformat(),
            })
        elif rate_limited:
            print_status("Rate limiting is properly configured", "info")
            
        return rate_limited
        
    def test_authentication(self, endpoint: str, verbose: bool = False) -> Dict[str, Any]:
        """
        Test API authentication mechanisms
        
        Args:
            endpoint: API endpoint to test
            verbose: Enable verbose output
            
        Returns:
            Dictionary with test results
        """
        print_header("API Authentication Test", color="cyan")
        
        url = urljoin(self.base_url, endpoint)
        results = {
            'endpoint': url,
            'tests': []
        }
        
        # Test without authentication
        try:
            response = http.get(url, timeout=10, verify=False)
            
            if response.status_code == 200:
                proof_token = _proof_token()
                evidence = _proof_evidence(response.text, ['200', 'data', 'success'])
                
                results['tests'].append({
                    'test': 'No Authentication',
                    'result': 'Vulnerable',
                    'details': 'Endpoint accessible without authentication'
                })
                
                vuln = {
                    'type': 'Missing Authentication',
                    'url': url,
                    'method': 'GET',
                    'severity': 'Critical',
                    'details': 'API endpoint accessible without authentication',
                    'proof_token': proof_token,
                    'evidence': evidence,
                    'response': response,
                    'headers': response.headers,
                }
                self.vulnerabilities.append(vuln)
                
                print_status("Endpoint accessible without auth", "success")
                print_status(f"  Proof Token: {proof_token}", "info")
                if evidence.get('snippet'):
                    print_status(f"  Evidence: {evidence['snippet']}", "info")
                
                # Add to result manager
                self.result_manager.add_finding("API Missing Authentication", "", {
                    "url": url,
                    "method": "GET",
                    "proof_token": proof_token,
                    "poc_url": url,
                    "evidence": evidence,
                    "confirmations": ['endpoint accessible without authentication'],
                    "injected": True,
                    "timestamp": datetime.now().isoformat(),
                })
            else:
                results['tests'].append({
                    'test': 'No Authentication',
                    'result': 'Protected',
                    'details': f'Returned {response.status_code}'
                })
                if verbose:
                    print_status(f"Auth required (HTTP {response.status_code})", "debug")
                    
        except Exception as e:
            if verbose:
                print_status(f"Auth test error: {e}", "debug")
                
        return results
        
    def _check_nested_dict(self, data: Any, key: str) -> bool:
        """Recursively check for key in nested dictionary"""
        if isinstance(data, dict):
            if key in data:
                return True
            for value in data.values():
                if self._check_nested_dict(value, key):
                    return True
        elif isinstance(data, list):
            for item in data:
                if self._check_nested_dict(item, key):
                    return True
        return False
        
    def get_vulnerabilities(self) -> List[Dict[str, Any]]:
        """Get all found vulnerabilities"""
        return self.vulnerabilities


def perform_api_scan(base_url: str, api_type: str = 'rest', 
                    endpoints: Optional[List[str]] = None,
                    auth_session: Optional[requests.Session] = None,
                    verbose: bool = False) -> List[Dict[str, Any]]:
    """
    Perform API security scan
    
    Args:
        base_url: Base URL of the API
        api_type: Type of API (rest, graphql)
        endpoints: List of endpoints to scan
        auth_session: Optional authenticated session
        verbose: Enable verbose output
        
    Returns:
        List of vulnerabilities found
    """
    scanner = APIScanner(base_url, auth_session)
    
    try:
        if api_type.lower() == 'rest':
            if not endpoints:
                endpoints = ['/api/users', '/api/data', '/api/admin']
                print_status("No endpoints provided, using default endpoints", "warning")
                
            return scanner.scan_rest_api(endpoints, verbose=verbose)
            
        elif api_type.lower() == 'graphql':
            endpoint = endpoints[0] if endpoints else '/graphql'
            return scanner.scan_graphql(endpoint, verbose=verbose)
            
        else:
            print_status(f"Unsupported API type: {api_type}", "error")
            return []
            
    except KeyboardInterrupt:
        from lib.core.interrupt import exit_clean
        exit_clean()
    except Exception as e:
        logger.error(f"API scan error: {e}")
        print_status(f"API scan error: {e}", "error")
        return scanner.get_vulnerabilities()
