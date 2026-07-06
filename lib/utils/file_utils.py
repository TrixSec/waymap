# Copyright (c) 2026 waymap developers
# See the file 'LICENSE' for copying permission.

"""File utility functions."""

import os
from functools import lru_cache
from typing import List, Tuple
import logging

logger = logging.getLogger(__name__)


@lru_cache(maxsize=None)
def _load_lines_cached(file_path: str) -> Tuple[str, ...]:
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return tuple(line.strip() for line in f if line.strip())
    except FileNotFoundError:
        logger.error(f"File {file_path} not found")
        return ()
    except Exception as e:
        logger.error(f"Error loading file {file_path}: {e}")
        return ()


def load_payloads(file_path: str) -> List[str]:
    """Load payloads from a file."""
    return list(_load_lines_cached(file_path))


def load_file_lines(file_path: str) -> List[str]:
    """Load stripped non-empty lines from a file."""
    return list(_load_lines_cached(file_path))


def save_to_file(file_path: str, data: List[str], mode: str = 'w') -> bool:
    """
    Save data to a file.
    
    Args:
        file_path: Path to save the file
        data: List of strings to save
        mode: File mode ('w' for write, 'a' for append)
        
    Returns:
        True if successful, False otherwise
    """
    try:
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, mode, encoding='utf-8') as f:
            for item in data:
                f.write(f"{item}\n")
        return True
    except Exception as e:
        logger.error(f"Error saving to file {file_path}: {e}")
        return False


def ensure_directory(directory: str) -> bool:
    """
    Ensure a directory exists, create if it doesn't.
    
    Args:
        directory: Directory path
        
    Returns:
        True if directory exists or was created
    """
    try:
        os.makedirs(directory, exist_ok=True)
        return True
    except Exception as e:
        logger.error(f"Error creating directory {directory}: {e}")
        return False


def file_exists(file_path: str) -> bool:
    """
    Check if a file exists.
    
    Args:
        file_path: Path to the file
        
    Returns:
        True if file exists, False otherwise
    """
    return os.path.isfile(file_path)


def directory_exists(directory: str) -> bool:
    """
    Check if a directory exists.
    
    Args:
        directory: Directory path
        
    Returns:
        True if directory exists, False otherwise
    """
    return os.path.isdir(directory)
