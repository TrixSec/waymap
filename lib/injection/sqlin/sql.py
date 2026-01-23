# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.

"""SQL Injection Scanner Orchestrator."""

from typing import List

from lib.injection.sqlin.boolean import process_urls as process_boolean_urls
from lib.injection.sqlin.error import process_urls as process_error_urls
from lib.injection.sqlin.timeblind import process_urls as process_time_blind_urls
from lib.core.logger import get_logger
from lib.core.state import stop_scan

logger = get_logger(__name__)

def run_sql_tests(urls: List[str], thread_count: int) -> None:
    """Run all SQL injection tests."""
    stop_scan.clear()
    
    # We pass the full list to the processors if they support it, 
    # or iterate if we want granular control. 
    # Given the original code's structure, let's try to pass the list if possible,
    # but the original code iterated.
    
    # Let's trust the sub-modules to handle a list of URLs.
    # We'll pass the full list.
    
    if stop_scan.is_set(): return
    try:
        process_boolean_urls(urls, thread_count)
    except Exception as e:
        logger.error(f"Error in boolean SQLi: {e}")

    if stop_scan.is_set(): return
    try:
        process_error_urls(urls, thread_count)
    except Exception as e:
        logger.error(f"Error in error-based SQLi: {e}")

    if stop_scan.is_set(): return
    try:
        process_time_blind_urls(urls, thread_count)
    except Exception as e:
        logger.error(f"Error in time-blind SQLi: {e}")

def run_boolean_sqli(urls: List[str], thread_count: int) -> None:
    stop_scan.clear()
    process_boolean_urls(urls, thread_count)

def run_error_sqli(urls: List[str], thread_count: int) -> None:
    stop_scan.clear()
    process_error_urls(urls, thread_count)

def run_time_blind_sqli(urls: List[str], thread_count: int) -> None:
    stop_scan.clear()
    process_time_blind_urls(urls, thread_count)