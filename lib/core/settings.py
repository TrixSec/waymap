# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.


# TAKEN FROM SQLMAP
CRAWLING_EXCLUDE_EXTENSIONS = ("3ds", "3g2", "3gp", "7z", "DS_Store", "a", "aac", "adp", "ai", "aif", "aiff", "apk", "ar", "asf", "au", "avi", "bak", "bin", "bk", "bmp", "btif", "bz2", "cab", "caf", "cgm", "cmx", "cpio", "cr2", "css", "dat", "deb", "djvu", "dll", "dmg", "dmp", "dng", "doc", "docx", "dot", "dotx", "dra", "dsk", "dts", "dtshd", "dvb", "dwg", "dxf", "ear", "ecelp4800", "ecelp7470", "ecelp9600", "egg", "eol", "eot", "epub", "exe", "f4v", "fbs", "fh", "fla", "flac", "fli", "flv", "fpx", "fst", "fvt", "g3", "gif", "gz", "h261", "h263", "h264", "ico", "ief", "image", "img", "ipa", "iso", "jar", "jpeg", "jpg", "jpgv", "jpm", "js", "jxr", "ktx", "lvp", "lz", "lzma", "lzo", "m3u", "m4a", "m4v", "mar", "mdi", "mid", "mj2", "mka", "mkv", "mmr", "mng", "mov", "movie", "mp3", "mp4", "mp4a", "mpeg", "mpg", "mpga", "mxu", "nef", "npx", "o", "oga", "ogg", "ogv", "otf", "pbm", "pcx", "pdf", "pea", "pgm", "pic", "png", "pnm", "ppm", "pps", "ppt", "pptx", "ps", "psd", "pya", "pyc", "pyo", "pyv", "qt", "rar", "ras", "raw", "rgb", "rip", "rlc", "rz", "s3m", "s7z", "scm", "scpt", "sgi", "shar", "sil", "smv", "so", "sub", "swf", "tar", "tbz2", "tga", "tgz", "tif", "tiff", "tlz", "ts", "ttf", "uvh", "uvi", "uvm", "uvp", "uvs", "uvu", "viv", "vob", "war", "wav", "wax", "wbmp", "wdp", "weba", "webm", "webp", "whl", "wm", "wma", "wmv", "wmx", "woff", "woff2", "wvx", "xbm", "xif", "xls", "xlsx", "xlt", "xm", "xpi", "xpm", "xwd", "xz", "z", "zip", "zipx")

# default threads
DEFAULT_THREADS = 1

# max threads
MAX_THREADS = 10

# req timeout
TIMEOUT = 30

# default no prompt input 
DEFAULT_INPUT = 'n'

# current waymap version downloaded
WAYMAP_VERSION = "6.2.8"

# waymap scanner owner
AUTHOR = "Trix Cyrus (Vicky)"

# waymap scanner copyrights
COPYRIGHT = "Copyright © 2024 - 25 Trixsec Org"

# url for getting vuln cve data 
CVE_DB_URL = "https://cvedb.shodan.io/cve/{cve_id}"

# threads used by fuzzer
FUZZER_THREADS = 30

# timeout for fuzzer
FUZZER_TIMEOUT = 10

# threads used by backup file checker 
BACKUP_TIMEOUT = 10

# timeout used in headers deepscan scanning
HEADERS_TIMEOUT = 10

# backup files url crawler threads
BACKUP_CRAWLER_THREADS = 200

# dissallowed extentions in backup file crawler
DISSALLOWED_EXT = (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".svg", ".pdf", ".xls", ".xlsx", ".doc", ".ico")

# valid extentions for js crawler
VALID_EXTENSIONS = (".php", ".asp", ".aspx", ".htm", ".html", "/")

# payloads used in waf detections

WAFPAYLOADS = {
    "xss": r'<script>alert("XSS");</script>',
    "sqli": r'UNION SELECT ALL FROM information_schema AND " or SLEEP(5) or "',
    "lfi": r'../../etc/passwd',
    "rce": r'/bin/cat /etc/passwd; ping 127.0.0.1; curl google.com',
    "xxe": r'<!ENTITY xxe SYSTEM "file:///etc/shadow">]><pwn>&hack;</pwn>'
}

# regex for js versions
JS_VERSION_PATTERN = r"(?i)([a-zA-Z0-9\s\-.:@]+?)(?:\s*[-:]?\s*v?)(\d+\.\d+\.\d+(?:-\w+)?)"
