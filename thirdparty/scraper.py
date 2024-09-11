import scrapy
from scrapy.linkextractors import LinkExtractor
from scrapy.spiders import CrawlSpider, Rule
from tempfile import NamedTemporaryFile
import os

# Extensions to exclude during scraping
CRAWL_EXCLUDE_EXTENSIONS = ("3ds", "3g2", "3gp", "7z", "DS_Store", "a", "aac", "adp", "ai", "aif", 
                            "aiff", "apk", "ar", "asf", "au", "avi", "bak", "bin", "bk", "bmp", 
                            "btif", "bz2", "cab", "caf", "cgm", "cmx", "cpio", "cr2", "dat", 
                            "deb", "djvu", "dll", "dmg", "dmp", "dng", "doc", "docx", "dot", 
                            "dotx", "dra", "dsk", "dts", "dtshd", "dvb", "dwg", "dxf", "ear", 
                            "ecelp4800", "ecelp7470", "ecelp9600", "egg", "eol", "eot", "epub", 
                            "exe", "f4v", "fbs", "fh", "fla", "flac", "fli", "flv", "fpx", "fst", 
                            "fvt", "g3", "gif", "gz", "h261", "h263", "h264", "ico", "ief", 
                            "image", "img", "ipa", "iso", "jar", "jpeg", "jpg", "jpgv", "jpm", 
                            "jxr", "ktx", "lvp", "lz", "lzma", "lzo", "m3u", "m4a", "m4v", "mar", 
                            "mdi", "mid", "mj2", "mka", "mkv", "mmr", "mng", "mov", "movie", "mp3", 
                            "mp4", "mp4a", "mpeg", "mpg", "mpga", "mxu", "nef", "npx", "o", "oga", 
                            "ogg", "ogv", "otf", "pbm", "pcx", "pdf", "pea", "pgm", "pic", "png", 
                            "pnm", "ppm", "pps", "ppt", "pptx", "ps", "psd", "pya", "pyc", "pyo", 
                            "pyv", "qt", "rar", "ras", "raw", "rgb", "rip", "rlc", "rz", "s3m", 
                            "s7z", "scm", "scpt", "sgi", "shar", "sil", "smv", "so", "sub", "swf", 
                            "tar", "tbz2", "tga", "tgz", "tif", "tiff", "tlz", "ts", "ttf", "uvh", 
                            "uvi", "uvm", "uvp", "uvs", "uvu", "viv", "vob", "war", "wav", "wax", 
                            "wbmp", "wdp", "weba", "webm", "webp", "whl", "wm", "wma", "wmv", 
                            "wmx", "woff", "woff2", "wvx", "xbm", "xif", "xls", "xlsx", "xlt", 
                            "xm", "xpi", "xpm", "xwd", "xz", "z", "zip", "zipx")

class MySpider(CrawlSpider):
    name = 'waymap_spider'
    allowed_domains = []  # Set the domain here
    start_urls = []  # The URL to start crawling
    
    rules = (
        Rule(LinkExtractor(deny_extensions=CRAWL_EXCLUDE_EXTENSIONS), callback='parse_item', follow=True),
    )

    def __init__(self, *args, **kwargs):
        self.temp_file = NamedTemporaryFile(delete=False, mode='w')
        super().__init__(*args, **kwargs)

    def parse_item(self, response):
        url = response.url
        # Write to tempfile if not already present
        if url not in self.temp_file.read():
            self.temp_file.write(url + "\n")
            print(f"[*] URL saved: {url}")

    def close(self, reason):
        # Close the temp file when scraping is done
        self.temp_file.close()

# Utility function to run the scrapy spider
def run_scrapy():
    os.system('scrapy crawl waymap_spider')
