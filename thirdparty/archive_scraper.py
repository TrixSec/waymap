import requests
import os

# Extensions to exclude
CRAWL_EXCLUDE_EXTENSIONS = ("3ds", "3g2", "3gp", "7z", "DS_Store", "a", "aac", "adp", "ai", "aif", "aiff", "apk", "ar",
                            "asf", "au", "avi", "bak", "bin", "bk", "bmp", "bz2", "cab", "caf", "cgm", "cmx", "cpio", 
                            "cr2", "dat", "deb", "djvu", "dll", "dmg", "dmp", "dng", "doc", "docx", "dot", "dotx", "dra",
                            "dsk", "dts", "dtshd", "dvb", "dwg", "dxf", "ear", "ecelp4800", "ecelp7470", "ecelp9600",
                            "egg", "eol", "eot", "epub", "exe", "f4v", "fbs", "fh", "fla", "flac", "fli", "flv", "fpx", 
                            "fst", "fvt", "g3", "gif", "gz", "h261", "h263", "h264", "ico", "ief", "image", "img", "ipa", 
                            "iso", "jar", "jpeg", "jpg", "jpgv", "jpm", "jxr", "ktx", "lvp", "lz", "lzma", "lzo", "m3u", 
                            "m4a", "m4v", "mar", "mdi", "mid", "mj2", "mka", "mkv", "mmr", "mng", "mov", "movie", "mp3", 
                            "mp4", "mp4a", "mpeg", "mpg", "mpga", "mxu", "nef", "npx", "o", "oga", "ogg", "ogv", "otf", 
                            "pbm", "pcx", "pdf", "pea", "pgm", "pic", "png", "pnm", "ppm", "pps", "ppt", "pptx", "ps", 
                            "psd", "pya", "pyc", "pyo", "pyv", "qt", "rar", "ras", "raw", "rgb", "rip", "rlc", "rz", "s3m", 
                            "s7z", "scm", "scpt", "sgi", "shar", "sil", "smv", "so", "sub", "swf", "tar", "tbz2", "tga", 
                            "tgz", "tif", "tiff", "tlz", "ts", "ttf", "uvh", "uvi", "uvm", "uvp", "uvs", "uvu", "viv", "vob", 
                            "war", "wav", "wax", "wbmp", "wdp", "weba", "webm", "webp", "whl", "wm", "wma", "wmv", "wmx", 
                            "woff", "woff2", "wvx", "xbm", "xif", "xls", "xlsx", "xlt", "xm", "xpi", "xpm", "xwd", "xz", "z", "zip", "zipx")

ARCHIVE_URL = "http://web.archive.org/cdx/search/cdx?url={domain}/*&output=txt&fl=original&collapse=urlkey&page=/"

def fetch_archive_urls(domain, output_file):
    """Fetches URLs from archive.org and saves the valid ones to output file."""
    try:
        url = ARCHIVE_URL.format(domain=domain)
        response = requests.get(url)
        response.raise_for_status()

        urls = response.text.splitlines()

        with open(output_file, 'a') as f:
            for url in urls:
                if not url.lower().endswith(CRAWL_EXCLUDE_EXTENSIONS):
                    # Check if URL responds with status code 200
                    try:
                        head = requests.head(url)
                        if head.status_code == 200:
                            f.write(url + "\n")
                    except requests.RequestException:
                        pass

        print(f"[INFO] Archive.org scraper: {len(urls)} URLs fetched and saved to {output_file}")
    except requests.RequestException as e:
        print(f"[ERROR] Failed to fetch URLs from archive.org: {str(e)}")
