# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.

"""Legacy settings module. Use lib.core.config instead."""

from lib.core.config import get_config

config = get_config()

# Map config values to module-level constants for backward compatibility
CRAWLING_EXCLUDE_EXTENSIONS = config.CRAWLING_EXCLUDE_EXTENSIONS
DEFAULT_THREADS = config.DEFAULT_THREADS
MAX_THREADS = config.MAX_THREADS
TIMEOUT = config.TIMEOUT
DEFAULT_INPUT = config.DEFAULT_INPUT
WAYMAP_VERSION = config.VERSION
AUTHOR = config.AUTHOR
COPYRIGHT = config.COPYRIGHT
CVE_DB_URL = config.CVE_DB_URL
FUZZER_THREADS = config.FUZZER_THREADS
FUZZER_TIMEOUT = config.FUZZER_TIMEOUT
BACKUP_TIMEOUT = config.BACKUP_TIMEOUT
HEADERS_TIMEOUT = config.HEADERS_TIMEOUT
BACKUP_CRAWLER_THREADS = config.BACKUP_CRAWLER_THREADS
DISSALLOWED_EXT = config.DISSALLOWED_EXT
VALID_EXTENSIONS = config.VALID_EXTENSIONS
WAFPAYLOADS = config.WAFPAYLOADS
JS_VERSION_PATTERN = config.JS_VERSION_PATTERN
