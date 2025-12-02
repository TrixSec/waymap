# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.

"""Configuration management for waymap."""

import os
from typing import Optional, Tuple, Dict
from dataclasses import dataclass, field


@dataclass
class WaymapConfig:
    """Waymap configuration settings."""
    
    # Version
    VERSION: str = "7.0.0"  # Updated to reflect major refactor
    AUTHOR: str = "Trix Cyrus (Vicky)"
    COPYRIGHT: str = "Copyright © 2024 - 25 Trixsec Org"
    
    # Paths
    DATA_DIR: str = os.path.join(os.getcwd(), 'data')
    SESSION_DIR: str = os.path.join(os.getcwd(), 'sessions')
    CONFIG_DIR: str = os.path.join('config', 'waymap')
    
    # Threading
    DEFAULT_THREADS: int = 1
    MAX_THREADS: int = 10
    FUZZER_THREADS: int = 30
    BACKUP_CRAWLER_THREADS: int = 200
    
    # Timeouts
    TIMEOUT: int = 30
    FUZZER_TIMEOUT: int = 10
    BACKUP_TIMEOUT: int = 10
    HEADERS_TIMEOUT: int = 10
    REQUEST_TIMEOUT: int = 10
    
    # Input
    DEFAULT_INPUT: str = 'n'
    
    # URLs
    VERSION_CHECK_URL: str = "https://raw.githubusercontent.com/TrixSec/waymap/main/VERSION"
    CVE_DB_URL: str = "https://cvedb.shodan.io/cve/{cve_id}"
    
    # Extensions and Patterns
    CRAWLING_EXCLUDE_EXTENSIONS: Tuple[str, ...] = (
        "3ds", "3g2", "3gp", "7z", "DS_Store", "a", "aac", "adp", "ai", "aif", "aiff", "apk", "ar", "asf", "au", "avi", 
        "bak", "bin", "bk", "bmp", "btif", "bz2", "cab", "caf", "cgm", "cmx", "cpio", "cr2", "css", "dat", "deb", "djvu", 
        "dll", "dmg", "dmp", "dng", "doc", "docx", "dot", "dotx", "dra", "dsk", "dts", "dtshd", "dvb", "dwg", "dxf", "ear", 
        "ecelp4800", "ecelp7470", "ecelp9600", "egg", "eol", "eot", "epub", "exe", "f4v", "fbs", "fh", "fla", "flac", "fli", 
        "flv", "fpx", "fst", "fvt", "g3", "gif", "gz", "h261", "h263", "h264", "ico", "ief", "image", "img", "ipa", "iso", 
        "jar", "jpeg", "jpg", "jpgv", "jpm", "js", "jxr", "ktx", "lvp", "lz", "lzma", "lzo", "m3u", "m4a", "m4v", "mar", 
        "mdi", "mid", "mj2", "mka", "mkv", "mmr", "mng", "mov", "movie", "mp3", "mp4", "mp4a", "mpeg", "mpg", "mpga", "mxu", 
        "nef", "npx", "o", "oga", "ogg", "ogv", "otf", "pbm", "pcx", "pdf", "pea", "pgm", "pic", "png", "pnm", "ppm", "pps", 
        "ppt", "pptx", "ps", "psd", "pya", "pyc", "pyo", "pyv", "qt", "rar", "ras", "raw", "rgb", "rip", "rlc", "rz", "s3m", 
        "s7z", "scm", "scpt", "sgi", "shar", "sil", "smv", "so", "sub", "swf", "tar", "tbz2", "tga", "tgz", "tif", "tiff", 
        "tlz", "ts", "ttf", "uvh", "uvi", "uvm", "uvp", "uvs", "uvu", "viv", "vob", "war", "wav", "wax", "wbmp", "wdp", 
        "weba", "webm", "webp", "whl", "wm", "wma", "wmv", "wmx", "woff", "woff2", "wvx", "xbm", "xif", "xls", "xlsx", 
        "xlt", "xm", "xpi", "xpm", "xwd", "xz", "z", "zip", "zipx"
    )
    
    DISSALLOWED_EXT: Tuple[str, ...] = (
        ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".svg", ".pdf", ".xls", ".xlsx", ".doc", ".ico"
    )
    
    VALID_EXTENSIONS: Tuple[str, ...] = (".php", ".asp", ".aspx", ".htm", ".html", "/")
    
    JS_VERSION_PATTERN: str = r"(?i)([a-zA-Z0-9\s\-.:@]+?)(?:\s*[-:]?\s*v?)(\d+\.\d+\.\d+(?:-\w+)?)"
    
    WAFPAYLOADS: Dict[str, str] = field(default_factory=lambda: {
        "xss": r'<script>alert("XSS");</script>',
        "sqli": r'UNION SELECT ALL FROM information_schema AND " or SLEEP(5) or "',
        "lfi": r'../../etc/passwd',
        "rce": r'/bin/cat /etc/passwd; ping 127.0.0.1; curl google.com',
        "xxe": r'<!ENTITY xxe SYSTEM "file:///etc/shadow">]><pwn>&hack;</pwn>'
    })

    def __post_init__(self):
        """Ensure directories exist."""
        os.makedirs(self.DATA_DIR, exist_ok=True)
        os.makedirs(self.SESSION_DIR, exist_ok=True)
        os.makedirs(self.CONFIG_DIR, exist_ok=True)
    
    def get_domain_session_dir(self, domain: str) -> str:
        """Get session directory for a specific domain."""
        path = os.path.join(self.SESSION_DIR, domain)
        os.makedirs(path, exist_ok=True)
        return path
    
    def get_config_path(self) -> str:
        """Get configuration file path."""
        return os.path.join(self.CONFIG_DIR, 'mode.cfg')


# Global configuration instance
config = WaymapConfig()


def get_config() -> WaymapConfig:
    """
    Get the global configuration instance.
    
    Returns:
        WaymapConfig instance
    """
    return config


def update_config(**kwargs) -> None:
    """
    Update configuration values.
    
    Args:
        **kwargs: Configuration key-value pairs to update
    """
    global config
    for key, value in kwargs.items():
        if hasattr(config, key):
            setattr(config, key, value)


def reset_config() -> None:
    """Reset configuration to default values."""
    global config
    config = WaymapConfig()
