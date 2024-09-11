import requests

CRAWL_EXCLUDE_EXTENSIONS = (
    "3ds", "3g2", "3gp", "7z", "DS_Store", "a", "aac", "adp", "ai", "aif", 
    "aiff", "apk", "ar", "asf", "au", "avi", "bak", "bin", "bk", "bmp", 
    "btif", "bz2", "cab", "caf", "cgm", "cmx", "cpio", "cr2", "dat", "deb", 
    "djvu", "dll", "dmg", "dmp", "dng", "doc", "docx", "dot", "dotx", "dra", 
    "dsk", "dts", "dtshd", "dvb", "dwg", "dxf", "ear", "ecelp4800", 
    "ecelp7470", "ecelp9600", "egg", "eol", "eot", "epub", "exe", "f4v", 
    "fbs", "fh", "fla", "flac", "fli", "flv", "fpx", "fst", "fvt", "g3", 
    "gif", "gz", "h261", "h263", "h264", "ico", "ief", "image", "img", "ipa", 
    "iso", "jar", "jpeg", "jpg", "jpgv", "jpm", "jxr", "ktx", "lvp", "lz", 
    "lzma", "lzo", "m3u", "m4a", "m4v", "mar", "mdi", "mid", "mj2", "mka", 
    "mkv", "mmr", "mng", "mov", "movie", "mp3", "mp4", "mp4a", "mpeg", "mpg", 
    "mpga", "mxu", "nef", "npx", "o", "oga", "ogg", "ogv", "otf", "pbm", 
    "pcx", "pdf", "pea", "pgm", "pic", "png", "pnm", "ppm", "pps", "ppt", 
    "pptx", "ps", "psd", "pya", "pyc", "pyo", "pyv", "qt", "rar", "ras", 
    "raw", "rgb", "rip", "rlc", "rz", "s3m", "s7z", "scm", "scpt", "sgi", 
    "shar", "sil", "smv", "so", "sub", "swf", "tar", "tbz2", "tga", "tgz", 
    "tif", "tiff", "tlz", "ts", "ttf", "uvh", "uvi", "uvm", "uvp", "uvs", 
    "uvu", "viv", "vob", "war", "wav", "wax", "wbmp", "wdp", "weba", "webm", 
    "webp", "whl", "wm", "wma", "wmv", "wmx", "woff", "woff2", "wvx", "xbm", 
    "xif", "xls", "xlsx", "xlt", "xm", "xpi", "xpm", "xwd", "xz", "z", "zip", 
    "zipx"
)

VALID_SYMBOLS = ["=", "&", "?", "'", '"', "(", ")", ";", "--", "/*", "*/", "+", "%", "\\"]

def contains_valid_symbol(url):
    """Check if the URL contains any of the valid symbols for filtering."""
    for symbol in VALID_SYMBOLS:
        if symbol in url:
            return True
    return False

def fetch_archive_urls(domain, output_file):
    """Fetch URLs from archive.org and filter by status code 200 and valid parameters."""
    url = f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=txt&fl=original&collapse=urlkey&page=/"
    response = requests.get(url)
    if response.status_code == 200:
        urls = response.text.splitlines()

        valid_urls = []
        for url in urls:
            if not url.endswith(CRAWL_EXCLUDE_EXTENSIONS) and contains_valid_symbol(url):
                head_response = requests.head(url)
                if head_response.status_code == 200:
                    valid_urls.append(url)

        with open(output_file, 'a') as f:
            for valid_url in valid_urls:
                f.write(valid_url + "\n")
