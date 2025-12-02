# Copyright (c) 2024 waymap developers 
# See the file 'LICENSE' for copying permission.

"""Enhanced error handling for waymap."""

import os
import socket
import sys
from typing import List, Optional
from lib.ui import print_status, print_table
from lib.core.logger import get_logger

logger = get_logger(__name__)


class WaymapError(Exception):
    """Base exception for waymap errors."""
    pass


class NetworkError(WaymapError):
    """Network-related errors."""
    pass


class ValidationError(WaymapError):
    """Input validation errors."""
    pass


class ConfigurationError(WaymapError):
    """Configuration errors."""
    pass


class FileSystemError(WaymapError):
    """File system errors."""
    pass


def check_internet_connection(timeout: int = 3) -> bool:
    """
    Check if internet connection is available.
    
    Args:
        timeout: Connection timeout in seconds
        
    Returns:
        True if connected, False otherwise
    """
    try:
        socket.create_connection(("8.8.8.8", 53), timeout=timeout)
        return True
    except OSError as e:
        logger.error(f"Internet connection check failed: {e}")
        return False


def check_required_files(data_dir: str, required_files: List[str]) -> List[str]:
    """
    Check for required files.
    
    Args:
        data_dir: Directory containing data files
        required_files: List of required file names
        
    Returns:
        List of missing files
    """
    missing_files = []
    for file_name in required_files:
        full_path = os.path.join(data_dir, file_name)
        if not os.path.exists(full_path):
            missing_files.append(file_name)
            logger.warning(f"Missing required file: {file_name}")
    return missing_files


def check_required_directories(directories: List[str]) -> List[str]:
    """
    Check for required directories.
    
    Args:
        directories: List of required directory paths
        
    Returns:
        List of missing directories
    """
    missing_dirs = []
    for directory in directories:
        if not os.path.exists(directory):
            missing_dirs.append(directory)
            logger.warning(f"Missing required directory: {directory}")
    return missing_dirs


def handle_error(message: str, error_type: Optional[type] = None, exit_code: int = 1) -> None:
    """
    Handle errors with proper logging and display.
    
    Args:
        message: Error message
        error_type: Optional error type to raise
        exit_code: Exit code for sys.exit
    """
    print_status(f"Error: {message}", "error")
    logger.error(message)
    
    if error_type:
        raise error_type(message)
    else:
        sys.exit(exit_code)


def validate_environment() -> bool:
    """
    Validate the environment before running waymap.
    
    Returns:
        True if environment is valid, False otherwise
    """
    from lib.core.config import get_config
    
    config = get_config()
    
    # Check internet connection
    if not check_internet_connection():
        print_status("No internet connection detected", "warning")
        logger.warning("Running without internet connection")
    
    # Check required files
    required_files = [
        'cmdipayload.txt', 'basicxsspayload.txt', 'filtersbypassxss.txt',
        'lfipayload.txt', 'openredirectpayloads.txt', 'waymap_dirfuzzlist.txt', 
        'waymap_dirfuzzlist2.txt', 'openredirectparameters.txt', 'crlfpayload.txt', 
        'corspayload.txt', 'sstipayload.txt', 'jsvulnpattern.json', 'wafsig.json', 
        'ua.txt', 'cmdi.xml', 'error_based.xml', 'cveinfo.py', 'headers.json'
    ]
    
    missing_files = check_required_files(config.DATA_DIR, required_files)
    if missing_files:
        print_table(["Missing Files"], [[f] for f in missing_files], ["red"])
        handle_error(f"Missing {len(missing_files)} required files")
        return False
    
    # Check required directories
    required_directories = [config.DATA_DIR, config.SESSION_DIR]
    missing_dirs = check_required_directories(required_directories)
    if missing_dirs:
        print_table(["Missing Directories"], [[d] for d in missing_dirs], ["red"])
        handle_error(f"Missing {len(missing_dirs)} required directories")
        return False
    
    print_status("Environment validation passed", "success")
    logger.info("Environment validation completed successfully")
    return True


def safe_execute(func, *args, error_message: str = "Operation failed", **kwargs):
    """
    Safely execute a function with error handling.
    
    Args:
        func: Function to execute
        *args: Positional arguments
        error_message: Error message prefix
        **kwargs: Keyword arguments
        
    Returns:
        Function result or None on error
    """
    try:
        return func(*args, **kwargs)
    except Exception as e:
        logger.error(f"{error_message}: {e}", exc_info=True)
        print_status(f"{error_message}: {str(e)}", "error")
        return None
