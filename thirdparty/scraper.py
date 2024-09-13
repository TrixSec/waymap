import scrapy
import re

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
    if not url:
        return False
    for symbol in VALID_SYMBOLS:
        if symbol is None:
            raise ValueError("VALID_SYMBOLS contains a null element")
        if symbol in url:
            return True
    return False

class UrlSpider(scrapy.Spider):
    name = "url_spider"
    
    def __init__(self, domain, crawl_depth, output_file, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.start_urls = [domain]
        self.crawl_depth = crawl_depth
        self.output_file = output_file

    def parse(self, response):
        current_depth = response.meta.get('depth', 1)

        # Save valid URLs only
        with open(self.output_file, 'a') as f:
            for link in response.css('a::attr(href)').getall():
                absolute_url = response.urljoin(link)
                
                # Filter out media links and check for valid symbols
                if not absolute_url.endswith(CRAWL_EXCLUDE_EXTENSIONS) and contains_valid_symbol(absolute_url):
                    f.write(absolute_url + "\n")

        # Recursively follow links up to the crawl depth
        if current_depth < self.crawl_depth:
            for link in response.css('a::attr(href)').getall():
                next_page = response.urljoin(link)
                if next_page is not None:
                    yield scrapy.Request(next_page, callback=self.parse, meta={'depth': current_depth + 1})

