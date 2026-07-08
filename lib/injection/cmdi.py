# Copyright (c) 2026 waymap developers
# See the file 'LICENSE' for copying permission.

"""Commix-inspired command injection scanner."""

import os
import re
import statistics
import time
import secrets
import requests
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from defusedxml import ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed

from lib.core import http
from lib.core.config import get_config
from lib.core.logger import get_logger
from lib.core.result_manager import ResultManager
from lib.core.state import stop_scan
from lib.parse.random_headers import generate_random_headers
from lib.ui import print_header, print_status, ask_continue_scanning

config = get_config()
logger = get_logger(__name__)

RESULT_SEPARATORS = (";", "&&", "|", "\n")
RESULT_PREFIXES = ("", "'", '"')
RESULT_SUFFIXES = ("", "#", "//")
TIME_SEPARATORS = (";", "&&", "|", "\n")
TIME_DELAY = 4
TIME_CONFIRM_MARGIN = 2.5
MAX_RESULT_PAYLOADS = 24


@dataclass(frozen=True)
class CmdiAttempt:
    technique: str
    payload: str
    expected: str
    os_hint: str = "Unix/Linux"


def _domain(url: str) -> str:
    return urlparse(url).netloc or "unknown_domain"


def _params(url: str) -> Dict[str, str]:
    return {key: values[0] if values else "" for key, values in parse_qs(urlparse(url).query, keep_blank_values=True).items()}


def _build_url(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [value]
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(qs, doseq=True), parsed.fragment))


def _request(url: str):
    started = time.perf_counter()
    response = http.get(url, headers=generate_random_headers(), timeout=max(config.REQUEST_TIMEOUT, TIME_DELAY + 3), verify=False)
    return response, time.perf_counter() - started


def _token() -> str:
    return f"WAYMAP_CMDI_{secrets.token_hex(4)}"


def _evidence_snippet(text: str, marker: str, window: int = 90) -> str:
    position = text.find(marker)
    if position < 0:
        return ""
    start = max(0, position - window)
    end = min(len(text), position + len(marker) + window)
    return text[start:end].replace("\r", " ").replace("\n", " ").strip()


@lru_cache(maxsize=None)
def _load_cmdi_errors(xml_file: str) -> Dict[str, List[str]]:
    errors: Dict[str, List[str]] = {}
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
        for error in root.findall("error"):
            errors[error.attrib["value"]] = [pattern.attrib["regexp"] for pattern in error.findall("pattern")]
    except Exception as e:
        logger.debug(f"Error loading CMDi error signatures: {e}")
    return errors


def _detect_error(text: str, errors: Dict[str, List[str]]) -> Optional[str]:
    for name, patterns in errors.items():
        for pattern in patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return name
    return None


def _classic_attempts(marker: str) -> List[CmdiAttempt]:
    expected = f"{marker}1337{marker}"
    command = f"echo {expected}"
    attempts: List[CmdiAttempt] = []
    for separator in RESULT_SEPARATORS:
        for prefix in RESULT_PREFIXES:
            for suffix in RESULT_SUFFIXES:
                if prefix and suffix in ("#", "//"):
                    continue
                attempts.append(CmdiAttempt("classic result-based", f"{prefix}{separator}{command}{suffix}", expected))
                if len(attempts) >= MAX_RESULT_PAYLOADS:
                    return attempts
    return attempts


def _eval_attempts(marker: str) -> List[CmdiAttempt]:
    expected = f"{marker}7331{marker}"
    return [
        CmdiAttempt("eval-based", f"print(`echo {expected}`)", expected),
        CmdiAttempt("eval-based", f"'.print(`echo {expected}`).'", expected),
        CmdiAttempt("eval-based", f"';print(`echo {expected}`);//", expected),
        CmdiAttempt("eval-based", f"\";print(`echo {expected}`);//", expected),
    ]


def _time_attempts() -> List[CmdiAttempt]:
    return [CmdiAttempt("time-based blind", f"{separator}sleep {TIME_DELAY}", "") for separator in TIME_SEPARATORS]


def _attempts() -> List[CmdiAttempt]:
    marker = _token()
    return _classic_attempts(marker) + _eval_attempts(marker) + _time_attempts()


def _calibrate(url: str) -> float:
    samples = []
    for _ in range(2):
        if stop_scan.is_set():
            break
        try:
            _, elapsed = _request(url)
            samples.append(elapsed)
        except requests.RequestException:
            pass
    return statistics.median(samples) if samples else 0.0


def _inject_value(original: str, payload: str) -> str:
    return f"{original}{payload}" if original else payload


def _test_attempt(url: str, parameter: str, original: str, attempt: CmdiAttempt, baseline: float, errors: Dict[str, List[str]]) -> Dict[str, Any]:
    if stop_scan.is_set():
        return {"vulnerable": False}

    injected = _inject_value(original, attempt.payload)
    test_url = _build_url(url, parameter, injected)
    try:
        response, elapsed = _request(test_url)
    except requests.RequestException as e:
        logger.debug(f"CMDi request failed for {test_url}: {e}")
        return {"vulnerable": False}

    error_name = _detect_error(response.text, errors)
    if attempt.technique == "time-based blind":
        threshold = baseline + TIME_CONFIRM_MARGIN
        if elapsed >= threshold and elapsed >= TIME_DELAY - 0.5:
            return {
                "vulnerable": True,
                "url": test_url,
                "parameter": parameter,
                "payload": injected,
                "technique": attempt.technique,
                "evidence": f"baseline={baseline:.2f}s delayed={elapsed:.2f}s threshold={threshold:.2f}s",
                "headers": dict(response.headers),
            }
    elif attempt.expected and attempt.expected in response.text:
        return {
            "vulnerable": True,
            "url": test_url,
            "parameter": parameter,
            "payload": injected,
            "technique": attempt.technique,
            "expected": attempt.expected,
            "evidence": _evidence_snippet(response.text, attempt.expected),
            "headers": dict(response.headers),
        }
    elif error_name:
        return {
            "vulnerable": True,
            "url": test_url,
            "parameter": parameter,
            "payload": injected,
            "technique": "error-based",
            "evidence": error_name,
            "headers": dict(response.headers),
        }

    return {"vulnerable": False}


def _technology(headers: Dict[str, str]) -> str:
    lower = {key.lower(): value for key, value in headers.items()}
    return lower.get("x-powered-by", lower.get("server", "Unknown"))


def perform_cmdi_scan(crawled_urls: List[str], thread_count: int = 1, no_prompt: bool = False, verbose: bool = False) -> None:
    """Perform Commix-style command injection scan."""
    if not crawled_urls:
        print_status("No URLs to scan", "warning")
        return

    stop_scan.clear()
    thread_count = max(1, min(thread_count, config.MAX_THREADS))
    print_header("Command Injection Scan", color="cyan")
    print_status(f"Scanning {len(crawled_urls)} URLs", "info")

    errors = _load_cmdi_errors(os.path.join(config.DATA_DIR, "cmdi.xml"))
    detected_tech = None

    for url in crawled_urls:
        if stop_scan.is_set():
            break

        params = _params(url)
        if not params:
            if verbose:
                print_status(f"No parameters in {url}, skipping", "debug")
            continue

        result_manager = ResultManager(_domain(url))
        baseline = _calibrate(url)
        if verbose:
            print_status(f"Baseline response time: {baseline:.2f}s", "debug")

        futures = {}
        with ThreadPoolExecutor(max_workers=thread_count) as executor:
            for param, original in params.items():
                for attempt in _attempts():
                    if stop_scan.is_set():
                        break
                    future = executor.submit(_test_attempt, url, param, original, attempt, baseline, errors)
                    futures[future] = (param, attempt.technique)

            total_tasks = len(futures)
            completed_tasks = 0
            reported_params = set()
            for future in as_completed(futures):
                if stop_scan.is_set():
                    break
                completed_tasks += 1
                if completed_tasks % 100 == 0 or completed_tasks == total_tasks:
                    print_status(f"Progress: {completed_tasks}/{total_tasks}", "info")
                try:
                    result = future.result()
                except Exception as e:
                    logger.error(f"CMDi worker error: {e}")
                    continue

                if not result.get("vulnerable"):
                    continue

                param = result["parameter"]
                if param in reported_params:
                    continue
                reported_params.add(param)

                if not detected_tech:
                    detected_tech = _technology(result.get("headers", {}))
                    print_status(f"Web Technology: {detected_tech}", "info")

                print_status("Vulnerability Found!", "success")
                print_status(f"  URL: {result['url']}", "info")
                print_status(f"  Parameter: {param}", "info")
                print_status(f"  Technique: {result['technique']}", "info")
                print_status(f"  Payload: {result['payload']}", "info")
                print_status(f"  Evidence: {result['evidence']}", "info")

                result_manager.add_finding("Command Injection", "", {
                    "url": result["url"],
                    "parameter": param,
                    "payload": result["payload"],
                    "technique": result["technique"],
                    "evidence": result["evidence"],
                    "confirmations": [
                        "Commix-style separator/prefix payload generated",
                        "safe echo/time proof used",
                        "unique marker or timing threshold confirmed",
                    ],
                })

                if not no_prompt:
                    if not ask_continue_scanning():
                        print_status("Stopping scan...", "warning")
                        stop_scan.set()
                        return

    print_status("CMDi Scan completed", "info")
