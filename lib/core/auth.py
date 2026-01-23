#!/usr/bin/env python3
"""
Authentication Manager for Waymap
Supports form-based, HTTP Basic/Digest, Bearer token, and OAuth authentication
"""

import requests
from typing import Dict, Optional, Any
from urllib.parse import urljoin, urlparse
import base64
import json

from lib.core.logger import get_logger
from lib.ui import print_status, print_header

logger = get_logger(__name__)


class AuthenticationManager:
    """Manage authentication for scanning authenticated areas"""
    
    def __init__(self):
        """Initialize authentication manager"""
        self.session = requests.Session()
        self.auth_type = None
        self.authenticated = False
        self.credentials = {}
        
    def login_form(self, login_url: str, username: str, password: str, 
                   username_field: str = "username", password_field: str = "password",
                   submit_field: Optional[str] = None, extra_data: Optional[Dict] = None) -> bool:
        """
        Perform form-based authentication
        
        Args:
            login_url: URL of login form
            username: Username/email
            password: Password
            username_field: Name of username field
            password_field: Name of password field
            submit_field: Optional submit button name
            extra_data: Optional additional form data
            
        Returns:
            True if authentication successful
        """
        print_header("Form-Based Authentication", color="cyan")
        
        try:
            # Prepare form data
            form_data = {
                username_field: username,
                password_field: password
            }
            
            if submit_field:
                form_data[submit_field] = "Login"
                
            if extra_data:
                form_data.update(extra_data)
                
            print_status(f"Attempting login at: {login_url}", "info")
            
            # Perform login
            response = self.session.post(login_url, data=form_data, allow_redirects=True)
            
            # Check if login was successful
            if response.status_code == 200:
                # Store credentials
                self.auth_type = "form"
                self.credentials = {
                    'username': username,
                    'password': password,
                    'login_url': login_url
                }
                self.authenticated = True
                
                print_status("Form authentication successful", "success")
                logger.info(f"Form authentication successful for {username}")
                return True
            else:
                print_status(f"Authentication failed: HTTP {response.status_code}", "error")
                logger.error(f"Form authentication failed: {response.status_code}")
                return False
                
        except Exception as e:
            print_status(f"Authentication error: {e}", "error")
            logger.error(f"Form authentication error: {e}")
            return False
            
    def login_basic(self, username: str, password: str) -> bool:
        """
        Set up HTTP Basic authentication
        
        Args:
            username: Username
            password: Password
            
        Returns:
            True if credentials set
        """
        print_header("HTTP Basic Authentication", color="cyan")
        
        try:
            from requests.auth import HTTPBasicAuth
            
            self.session.auth = HTTPBasicAuth(username, password)
            self.auth_type = "basic"
            self.credentials = {'username': username, 'password': password}
            self.authenticated = True
            
            print_status("HTTP Basic auth configured", "success")
            logger.info(f"HTTP Basic auth configured for {username}")
            return True
            
        except Exception as e:
            print_status(f"Basic auth error: {e}", "error")
            logger.error(f"Basic auth error: {e}")
            return False
            
    def login_digest(self, username: str, password: str) -> bool:
        """
        Set up HTTP Digest authentication
        
        Args:
            username: Username
            password: Password
            
        Returns:
            True if credentials set
        """
        print_header("HTTP Digest Authentication", color="cyan")
        
        try:
            from requests.auth import HTTPDigestAuth
            
            self.session.auth = HTTPDigestAuth(username, password)
            self.auth_type = "digest"
            self.credentials = {'username': username, 'password': password}
            self.authenticated = True
            
            print_status("HTTP Digest auth configured", "success")
            logger.info(f"HTTP Digest auth configured for {username}")
            return True
            
        except Exception as e:
            print_status(f"Digest auth error: {e}", "error")
            logger.error(f"Digest auth error: {e}")
            return False
            
    def login_bearer(self, token: str) -> bool:
        """
        Set up Bearer token authentication
        
        Args:
            token: Bearer token
            
        Returns:
            True if token set
        """
        print_header("Bearer Token Authentication", color="cyan")
        
        try:
            self.session.headers.update({
                'Authorization': f'Bearer {token}'
            })
            self.auth_type = "bearer"
            self.credentials = {'token': token}
            self.authenticated = True
            
            print_status("Bearer token configured", "success")
            logger.info("Bearer token authentication configured")
            return True
            
        except Exception as e:
            print_status(f"Bearer auth error: {e}", "error")
            logger.error(f"Bearer auth error: {e}")
            return False
            
    def login_api_key(self, api_key: str, header_name: str = "X-API-Key") -> bool:
        """
        Set up API key authentication
        
        Args:
            api_key: API key
            header_name: Header name for API key
            
        Returns:
            True if API key set
        """
        print_header("API Key Authentication", color="cyan")
        
        try:
            self.session.headers.update({
                header_name: api_key
            })
            self.auth_type = "api_key"
            self.credentials = {'api_key': api_key, 'header': header_name}
            self.authenticated = True
            
            print_status(f"API key configured in {header_name}", "success")
            logger.info(f"API key authentication configured")
            return True
            
        except Exception as e:
            print_status(f"API key auth error: {e}", "error")
            logger.error(f"API key auth error: {e}")
            return False
            
    def set_custom_headers(self, headers: Dict[str, str]) -> None:
        """
        Set custom headers for requests
        
        Args:
            headers: Dictionary of headers
        """
        self.session.headers.update(headers)
        print_status(f"Custom headers set: {len(headers)} headers", "info")
        logger.info(f"Custom headers configured: {list(headers.keys())}")
        
    def set_cookies(self, cookies: Dict[str, str]) -> None:
        """
        Set cookies for session
        
        Args:
            cookies: Dictionary of cookies
        """
        for name, value in cookies.items():
            self.session.cookies.set(name, value)
        print_status(f"Cookies set: {len(cookies)} cookies", "info")
        logger.info(f"Cookies configured: {list(cookies.keys())}")
        
    def maintain_session(self) -> bool:
        """
        Check if session is still valid
        
        Returns:
            True if session is valid
        """
        return self.authenticated and self.session is not None
        
    def get_session(self) -> requests.Session:
        """
        Get the authenticated session
        
        Returns:
            Requests session object
        """
        return self.session
        
    def logout(self, logout_url: Optional[str] = None) -> None:
        """
        Logout and clear session
        
        Args:
            logout_url: Optional logout URL
        """
        if logout_url:
            try:
                self.session.get(logout_url)
                print_status(f"Logged out from: {logout_url}", "info")
            except Exception as e:
                logger.error(f"Logout error: {e}")
                
        self.session.close()
        self.authenticated = False
        self.auth_type = None
        self.credentials = {}
        print_status("Session cleared", "info")
        logger.info("Authentication session cleared")
        
    def test_authentication(self, test_url: str) -> bool:
        """
        Test if authentication is working
        
        Args:
            test_url: URL to test authentication against
            
        Returns:
            True if authentication is valid
        """
        print_status(f"Testing authentication at: {test_url}", "info")
        
        try:
            response = self.session.get(test_url)
            
            # Check for common authentication failure indicators
            if response.status_code == 401:
                print_status("Authentication test failed: 401 Unauthorized", "error")
                return False
            elif response.status_code == 403:
                print_status("Authentication test failed: 403 Forbidden", "warning")
                return False
            elif response.status_code == 200:
                print_status("Authentication test successful", "success")
                return True
            else:
                print_status(f"Authentication test returned: {response.status_code}", "warning")
                return response.status_code < 400
                
        except Exception as e:
            print_status(f"Authentication test error: {e}", "error")
            logger.error(f"Authentication test error: {e}")
            return False
            
    def get_auth_info(self) -> Dict[str, Any]:
        """
        Get current authentication information
        
        Returns:
            Dictionary with auth info
        """
        return {
            'authenticated': self.authenticated,
            'auth_type': self.auth_type,
            'has_session': self.session is not None,
            'cookies_count': len(self.session.cookies) if self.session else 0,
            'headers_count': len(self.session.headers) if self.session else 0
        }


def setup_authentication(auth_config: Dict[str, Any]) -> Optional[AuthenticationManager]:
    """
    Setup authentication based on configuration
    
    Args:
        auth_config: Authentication configuration dictionary
        
    Returns:
        Configured AuthenticationManager or None
    """
    auth_manager = AuthenticationManager()
    
    auth_type = auth_config.get('type', '').lower()
    
    try:
        if auth_type == 'form':
            success = auth_manager.login_form(
                login_url=auth_config['login_url'],
                username=auth_config['username'],
                password=auth_config['password'],
                username_field=auth_config.get('username_field', 'username'),
                password_field=auth_config.get('password_field', 'password'),
                extra_data=auth_config.get('extra_data')
            )
        elif auth_type == 'basic':
            success = auth_manager.login_basic(
                username=auth_config['username'],
                password=auth_config['password']
            )
        elif auth_type == 'digest':
            success = auth_manager.login_digest(
                username=auth_config['username'],
                password=auth_config['password']
            )
        elif auth_type == 'bearer':
            success = auth_manager.login_bearer(
                token=auth_config['token']
            )
        elif auth_type == 'api_key':
            success = auth_manager.login_api_key(
                api_key=auth_config['api_key'],
                header_name=auth_config.get('header_name', 'X-API-Key')
            )
        else:
            print_status(f"Unknown auth type: {auth_type}", "error")
            return None
            
        if success:
            # Set custom headers if provided
            if 'headers' in auth_config:
                auth_manager.set_custom_headers(auth_config['headers'])
                
            # Set cookies if provided
            if 'cookies' in auth_config:
                auth_manager.set_cookies(auth_config['cookies'])
                
            # Test authentication if test URL provided
            if 'test_url' in auth_config:
                if not auth_manager.test_authentication(auth_config['test_url']):
                    print_status("Authentication test failed", "warning")
                    
            return auth_manager
        else:
            return None
            
    except KeyError as e:
        print_status(f"Missing required auth config: {e}", "error")
        logger.error(f"Missing auth config key: {e}")
        return None
    except Exception as e:
        print_status(f"Authentication setup error: {e}", "error")
        logger.error(f"Authentication setup error: {e}")
        return None
