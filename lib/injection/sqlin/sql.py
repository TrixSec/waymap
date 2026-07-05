# Copyright (c) 2026 waymap developers
# See the file 'LICENSE' for copying permission.

"""SQL Injection Scanner Orchestrator."""

from typing import List, Set, Tuple

from lib.injection.sqlin.boolean import process_urls as process_boolean_urls
from lib.injection.sqlin.error import process_urls as process_error_urls
from lib.injection.sqlin.timeblind import process_urls as process_time_blind_urls
from lib.injection.sqlin.union import process_urls as process_union_urls
from lib.injection.sqlin.inline import process_urls as process_inline_urls
from lib.injection.sqlin.stacked import process_urls as process_stacked_urls
from lib.injection.sqlin.db_fetcher import fetch_databases_once
from lib.core.logger import get_logger
from lib.core.state import stop_scan
from lib.utils import filter_urls_with_params
from lib.ui import print_separator, print_header

logger = get_logger(__name__)

# Shared set to track vulnerable (url, parameter) pairs to avoid duplicate DB fetching
vulnerable_pairs: Set[Tuple[str, str]] = set()

def _parameterized_urls(urls: List[str]) -> List[str]:
    """Filter to URLs with injectable query parameters."""
    return filter_urls_with_params(urls)

def run_sql_tests(urls: List[str], thread_count: int) -> None:
    """Run all SQL injection tests."""
    global vulnerable_pairs
    vulnerable_pairs.clear()  # Reset for new scan
    
    urls = _parameterized_urls(urls)
    if not urls:
        return

    stop_scan.clear()
    
    if stop_scan.is_set(): return
    try:
        process_error_urls(urls, thread_count)
    except Exception as e:
        logger.error(f"Error in error-based SQLi: {e}")

    if stop_scan.is_set(): return
    try:
        process_union_urls(urls, thread_count)
    except Exception as e:
        logger.error(f"Error in union-based SQLi: {e}")

    if stop_scan.is_set(): return
    try:
        process_inline_urls(urls, thread_count)
    except Exception as e:
        logger.error(f"Error in inline query SQLi: {e}")

    if stop_scan.is_set(): return
    try:
        process_stacked_urls(urls, thread_count)
    except Exception as e:
        logger.error(f"Error in stacked queries SQLi: {e}")

    if stop_scan.is_set(): return
    try:
        process_boolean_urls(urls, thread_count)
    except Exception as e:
        logger.error(f"Error in boolean SQLi: {e}")

    if stop_scan.is_set(): return
    try:
        process_time_blind_urls(urls, thread_count)
    except Exception as e:
        logger.error(f"Error in time-blind SQLi: {e}")
        
    # After all tests, fetch databases for each unique vulnerable URL/param pair
    if vulnerable_pairs:
        for url, param in vulnerable_pairs:
            if stop_scan.is_set(): break
            try:
                fetch_databases_once(url, param)
            except Exception as e:
                logger.error(f"Error fetching databases for {url}: {e}")

def _run_single_sql_technique(urls: List[str], thread_count: int, process_func) -> None:
    """Run single SQLi technique and keep vulnerable_pairs intact, and fetch DBs at end if needed (only for individual technique calls)."""
    global vulnerable_pairs
    # Don't clear vulnerable_pairs when running individual techniques (they may be run in sequence)
    urls = _parameterized_urls(urls)
    if not urls:
        return
    stop_scan.clear()
    process_func(urls, thread_count)

def run_boolean_sqli(urls: List[str], thread_count: int) -> None:
    _run_single_sql_technique(urls, thread_count, process_boolean_urls)

def run_error_sqli(urls: List[str], thread_count: int) -> None:
    _run_single_sql_technique(urls, thread_count, process_error_urls)

def run_time_blind_sqli(urls: List[str], thread_count: int) -> None:
    _run_single_sql_technique(urls, thread_count, process_time_blind_urls)

def run_union_sqli(urls: List[str], thread_count: int) -> None:
    _run_single_sql_technique(urls, thread_count, process_union_urls)

def run_inline_sqli(urls: List[str], thread_count: int) -> None:
    _run_single_sql_technique(urls, thread_count, process_inline_urls)

def run_stacked_sqli(urls: List[str], thread_count: int) -> None:
    _run_single_sql_technique(urls, thread_count, process_stacked_urls)
