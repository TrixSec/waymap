#!/usr/bin/env python3
"""
API Security Scanner for Waymap
Supports REST, GraphQL, and SOAP API testing
"""

import requests
import json
from typing import Dict, List, Optional, Any
from urllib.parse import urljoin, urlparse
import time

from lib.core.logger import get_logger
from lib.ui import print_status, print_header, print_separator
from lib.core.state import stop_scan

logger = get_logger(__name__)


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
        """Test a single REST endpoint"""
        
        # Test for missing authentication
        try:
            response = requests.request(method, url, timeout=10, verify=False)
            
            if response.status_code == 200 and 'Authorization' not in self.session.headers:
                self.vulnerabilities.append({
                    'type': 'Missing Authentication',
                    'url': url,
                    'method': method,
                    'severity': 'High',
                    'details': f'{method} request succeeded without authentication'
                })
                print_status(f"Missing auth: {method} {url}", "success")
                
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
                            self.vulnerabilities.append({
                                'type': 'Excessive Data Exposure',
                                'url': url,
                                'method': method,
                                'severity': 'Medium',
                                'details': f'Response contains sensitive field: {field}'
                            })
                            print_status(f"Data exposure: {field} in {url}", "success")
                            break
                except:
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
                    response = self.session.request(method, test_url, timeout=10, verify=False)
                    
                    if response.status_code == 200:
                        self.vulnerabilities.append({
                            'type': 'Potential IDOR',
                            'url': test_url,
                            'method': method,
                            'severity': 'High',
                            'details': f'Direct object access without proper authorization check'
                        })
                        print_status(f"Potential IDOR: {method} {test_url}", "success")
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
                self.vulnerabilities.append({
                    'type': 'GraphQL Introspection Enabled',
                    'url': url,
                    'method': 'POST',
                    'severity': 'Medium',
                    'details': 'GraphQL introspection is enabled, exposing schema information'
                })
                print_status("GraphQL introspection enabled", "success")
                
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
                self.vulnerabilities.append({
                    'type': 'No Query Depth Limit',
                    'url': url,
                    'method': 'POST',
                    'severity': 'Medium',
                    'details': 'GraphQL allows deeply nested queries (DoS risk)'
                })
                print_status("No query depth limit detected", "success")
                
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
            self.vulnerabilities.append({
                'type': 'No Rate Limiting',
                'url': url,
                'method': 'GET',
                'severity': 'Medium',
                'details': f'No rate limiting detected after {requests_count} requests'
            })
            print_status(f"No rate limiting detected ({success_count} successful requests)", "success")
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
            response = requests.get(url, timeout=10, verify=False)
            
            if response.status_code == 200:
                results['tests'].append({
                    'test': 'No Authentication',
                    'result': 'Vulnerable',
                    'details': 'Endpoint accessible without authentication'
                })
                self.vulnerabilities.append({
                    'type': 'Missing Authentication',
                    'url': url,
                    'method': 'GET',
                    'severity': 'Critical',
                    'details': 'API endpoint accessible without authentication'
                })
                print_status("Endpoint accessible without auth", "success")
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
        stop_scan.set()
        print_status("API scan interrupted", "warning")
        return scanner.get_vulnerabilities()
    except Exception as e:
        logger.error(f"API scan error: {e}")
        print_status(f"API scan error: {e}", "error")
        return scanner.get_vulnerabilities()
