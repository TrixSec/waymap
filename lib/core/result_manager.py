# Copyright (c) 2026 waymap developers
# See the file 'LICENSE' for copying permission.

"""Thread-safe result manager for waymap."""

import os
import json
import sys
import atexit
from typing import Dict, Any, Iterable, List, Optional
from lib.core.config import get_config
from lib.core.logger import get_logger
from lib.events.bus import get_event_bus
from lib.events.events import FindingEvent

config = get_config()
logger = get_logger(__name__)

_RESULT_CACHE: Dict[str, Dict[str, Any]] = {}
_DIRTY_RESULTS = set()


def flush_pending_results() -> None:
    """Write buffered result files to disk."""
    for file_path in list(_DIRTY_RESULTS):
        data = _RESULT_CACHE.get(file_path)
        if data is None:
            continue
        try:
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4)
            _DIRTY_RESULTS.discard(file_path)
        except Exception as e:
            logger.error(f"Failed to flush buffered results to {file_path}: {e}")


atexit.register(flush_pending_results)

_FIELD_ALIASES = {
    "url": ("url", "Vulnerable URL"),
    "parameter": ("parameter", "Parameter"),
    "payload": ("payload", "Payload"),
}


def _get_field(record: Dict[str, Any], key: str) -> Any:
    for alias in _FIELD_ALIASES.get(key, (key,)):
        if alias in record:
            return record[alias]
    return None


def _findings_match(existing: Dict[str, Any], finding: Dict[str, Any]) -> bool:
    if existing == finding:
        return True
    match_keys = ("url", "parameter", "payload")
    compared = False
    for key in match_keys:
        existing_value = _get_field(existing, key)
        finding_value = _get_field(finding, key)
        if existing_value is None or finding_value is None:
            continue
        compared = True
        if existing_value != finding_value:
            return False
    return compared


def _normalize_vulnerability(scan_type: str, result: Dict[str, Any], sub_type: str = "") -> Dict[str, Any]:
    """Normalize stored findings into report-friendly vulnerability dicts."""
    severity = result.get("severity") or result.get("Severity") or "Medium"
    if isinstance(severity, (int, float)):
        if severity >= 9:
            severity = "Critical"
        elif severity >= 7:
            severity = "High"
        elif severity >= 4:
            severity = "Medium"
        else:
            severity = "Low"

    vuln_type = scan_type
    if sub_type:
        vuln_type = f"{scan_type} - {sub_type}"

    return {
        "type": vuln_type,
        "url": _get_field(result, "url") or "N/A",
        "parameter": _get_field(result, "parameter") or "",
        "payload": _get_field(result, "payload") or "",
        "severity": str(severity),
        "details": result.get("details") or result.get("expected_response") or "",
    }


def format_results_for_report(domain: str) -> List[Dict[str, Any]]:
    """Convert session JSON into the structure expected by ReportGenerator."""
    from datetime import datetime

    data = ResultManager(domain).get_results()
    formatted: List[Dict[str, Any]] = []

    for entry in data.get("scans", []):
        if not isinstance(entry, dict):
            continue
        for scan_type, results in entry.items():
            vulnerabilities: List[Dict[str, Any]] = []
            if isinstance(results, list):
                for item in results:
                    if isinstance(item, dict):
                        vulnerabilities.append(_normalize_vulnerability(scan_type, item))
            elif isinstance(results, dict):
                for sub_type, sub_results in results.items():
                    if isinstance(sub_results, list):
                        for item in sub_results:
                            if isinstance(item, dict):
                                vulnerabilities.append(_normalize_vulnerability(scan_type, item, sub_type))
            if vulnerabilities:
                formatted.append({
                    "scan_type": scan_type,
                    "vulnerabilities": vulnerabilities,
                    "timestamp": datetime.now().isoformat(),
                })

    return formatted


class ResultManager:
    """Thread-safe result manager to handle saving findings."""

    def __init__(self, domain: str):
        self.domain = domain
        self.session_dir = config.get_domain_session_dir(domain)
        self.file_path = os.path.join(self.session_dir, "waymap_full_results.json")
        self.lock_file = self.file_path + ".lock"
        # Ensure the session directory exists
        os.makedirs(self.session_dir, exist_ok=True)

    def _acquire_lock(self):
        """Acquire a file lock (cross-platform)."""
        if sys.platform == "win32":
            import msvcrt
            self.lock_fd = open(self.lock_file, "w")
            try:
                msvcrt.locking(self.lock_fd.fileno(), msvcrt.LK_LOCK, 1)
            except Exception as e:
                logger.error(f"Failed to acquire lock: {e}")
                raise
        else:
            import fcntl
            self.lock_fd = open(self.lock_file, "w")
            try:
                fcntl.flock(self.lock_fd, fcntl.LOCK_EX)
            except Exception as e:
                logger.error(f"Failed to acquire lock: {e}")
                raise

    def _release_lock(self):
        """Release the file lock."""
        try:
            if sys.platform == "win32":
                import msvcrt
                msvcrt.locking(self.lock_fd.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.lock_fd, fcntl.LOCK_UN)
            self.lock_fd.close()
            # Try to remove the lock file (best effort)
            try:
                os.remove(self.lock_file)
            except OSError as e:
                logger.debug(f"Could not remove lock file {self.lock_file}: {e}")
        except Exception as e:
            logger.error(f"Failed to release lock: {e}")

    def _read_data(self) -> Dict[str, Any]:
        """Read existing data from file."""
        if self.file_path in _RESULT_CACHE:
            return _RESULT_CACHE[self.file_path]
        if not os.path.exists(self.file_path):
            data = {"scans": []}
            _RESULT_CACHE[self.file_path] = data
            return data
        try:
            with open(self.file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                _RESULT_CACHE[self.file_path] = data
                return data
        except json.JSONDecodeError as e:
            logger.error(f"Failed to decode JSON from {self.file_path}: {e}")
            data = {"scans": []}
            _RESULT_CACHE[self.file_path] = data
            return data
        except Exception as e:
            logger.error(f"Failed to read {self.file_path}: {e}")
            data = {"scans": []}
            _RESULT_CACHE[self.file_path] = data
            return data

    def _write_data(self, data: Dict[str, Any]):
        """Write data to file."""
        _RESULT_CACHE[self.file_path] = data
        _DIRTY_RESULTS.add(self.file_path)

    def add_finding(self, scan_category: str, finding_key: str, finding: Dict[str, Any]):
        """
        Add a finding to the results.
        
        Args:
            scan_category: Main scan category (e.g., "SQL Injection", "XSS", "ssrf")
            finding_key: Sub-key for the finding type (e.g., "Technique: Boolean", can be empty)
            finding: The finding data to save
        """
        self._acquire_lock()
        try:
            data = self._read_data()

            # Find or create the scan category block
            scan_block = None
            for entry in data.get("scans", []):
                if scan_category in entry:
                    scan_block = entry[scan_category]
                    break

            if scan_block is None:
                if finding_key:
                    scan_block = {}
                else:
                    scan_block = []
                data["scans"].append({scan_category: scan_block})

            # Handle case where finding_key is empty (just append to scan_block list)
            if not finding_key:
                # If scan_block is not a list, convert it (shouldn't happen)
                if not isinstance(scan_block, list):
                    scan_block = []
                # Check for duplicates
                duplicate = False
                for existing in scan_block:
                    if isinstance(existing, dict) and _findings_match(existing, finding):
                        duplicate = True
                        break
                if not duplicate:
                    scan_block.append(finding)
                    self._write_data(data)
                    logger.info(f"Saved finding to {self.file_path}")
                    # Emit finding event
                    self._emit_finding_event(scan_category, finding_key, finding)
            else:
                # Normal case with finding_key
                if not isinstance(scan_block, dict):
                    scan_block = {}
                if finding_key not in scan_block:
                    scan_block[finding_key] = []
                # Check for duplicates
                duplicate = False
                for existing in scan_block[finding_key]:
                    if isinstance(existing, dict) and _findings_match(existing, finding):
                        duplicate = True
                        break
                if not duplicate:
                    scan_block[finding_key].append(finding)
                    self._write_data(data)
                    logger.info(f"Saved finding to {self.file_path}")
                    # Emit finding event
                    self._emit_finding_event(scan_category, finding_key, finding)

        finally:
            self._release_lock()
    
    def _emit_finding_event(self, scan_category: str, finding_key: str, finding: Dict[str, Any]) -> None:
        """Emit a FindingEvent to the event bus."""
        try:
            event_bus = get_event_bus()
            
            # Convert confidence string to float
            confidence_str = finding.get("confidence") or finding.get("Confidence") or "1.0"
            if isinstance(confidence_str, str):
                confidence_map = {
                    "high": 0.9, "High": 0.9, "HIGH": 0.9,
                    "medium": 0.7, "Medium": 0.7, "MEDIUM": 0.7,
                    "low": 0.5, "Low": 0.5, "LOW": 0.5
                }
                confidence = confidence_map.get(confidence_str, 1.0)
            else:
                confidence = float(confidence_str) if confidence_str else 1.0
            
            event = FindingEvent(
                vulnerability_type=scan_category,
                technique=finding_key,
                url=_get_field(finding, "url") or "",
                parameter=_get_field(finding, "parameter"),
                payload=_get_field(finding, "payload"),
                severity=float(finding.get("severity") or finding.get("Severity") or 0),
                confidence=confidence,
                evidence=finding
            )
            event_bus.publish(event)
        except Exception as e:
            logger.error(f"Failed to emit finding event: {e}")

    def append_sql_injection(
        self,
        url: str,
        parameter: str,
        details: str,
        extra: Optional[Dict[str, Any]] = None,
    ) -> None:
        finding = {
            "url": url,
            "parameter": parameter,
            "details": details,
        }
        if extra:
            finding.update(extra)
        self.add_finding("SQL Injection", "Database Extraction", finding)

    def get_results(self) -> Dict[str, Any]:
        """Get all results."""
        self._acquire_lock()
        try:
            return self._read_data()
        finally:
            self._release_lock()

    def has_duplicate(
        self,
        scan_category: str,
        match_keys: Iterable[str],
        values: Dict[str, Any],
        finding_key: str = "",
    ) -> bool:
        """Check whether a finding with matching key fields already exists."""
        data = self._read_data()
        for entry in data.get("scans", []):
            if scan_category not in entry:
                continue
            block = entry[scan_category]
            if finding_key:
                if not isinstance(block, dict):
                    continue
                items = block.get(finding_key, [])
            elif isinstance(block, list):
                items = block
            else:
                items = []
            for existing in items:
                if not isinstance(existing, dict):
                    continue
                if all(_get_field(existing, key) == values.get(key) for key in match_keys):
                    return True
        return False

    def replace_all(self, data: Dict[str, Any]) -> None:
        """Replace the entire results file (thread-safe)."""
        self._acquire_lock()
        try:
            if "scans" not in data or not isinstance(data.get("scans"), list):
                data = {"scans": []}
            self._write_data(data)
        finally:
            self._release_lock()
            
    def flush(self) -> None:
        """Delete all findings and start fresh (thread-safe)."""
        self._acquire_lock()
        try:
            _RESULT_CACHE.pop(self.file_path, None)
            _DIRTY_RESULTS.discard(self.file_path)
            if os.path.exists(self.file_path):
                os.remove(self.file_path)
                logger.info(f"Flushed/removed results file: {self.file_path}")
            if os.path.exists(self.lock_file):
                try:
                    os.remove(self.lock_file)
                except OSError as e:
                    logger.debug(f"Could not remove lock file during flush: {e}")
        finally:
            self._release_lock()
