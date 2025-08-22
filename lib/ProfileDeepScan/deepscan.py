# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.
# deepscan.py

from lib.ProfileDeepScan.headerdeepscan import headersdeepscan
from lib.ProfileDeepScan.waymap_dirfuzz import dirfuzz
from lib.ProfileDeepScan.waymap_backupfilefinder import backupfiles
from lib.ProfileDeepScan.waymap_jsdeepscan import jsscan

def deepscan(profile_url):
    if isinstance(profile_url, str):  
        profile_url = [profile_url]
    
    for url in profile_url:
        try:
            headersdeepscan(url)
        except Exception as e:
            print(f"[ERROR] Headers Analysis failed for {url}: {e}\n")

        try:
            backupfiles(url)
        except Exception as e:
            print(f"[ERROR] Backup Finder failed for {url}: {e}\n")

        try:
            jsscan(url)
        except Exception as e:
            print(f"[ERROR] Javascript failed for {url}: {e}\n")

        try:
            dirfuzz(url)
        except Exception as e:
            print(f"[ERROR] Directory Fuzzing failed for {url}: {e}\n")

def run_headers_scan(urls):
    if isinstance(urls, str):  
        urls = [urls]
    
    for url in urls:
        try:
            headersdeepscan(url)
        except Exception as e:
            print(f"[ERROR] Headers Analysis failed for {url}: {e}\n")

def run_backupfile_scan(urls):
    if isinstance(urls, str):  
        urls = [urls]
    
    for url in urls:
        try:
            backupfiles(url)
        except Exception as e:
            print(f"[ERROR] Backup Finder failed for {url}: {e}\n")

def run_dirfuzz_scan(urls):
    if isinstance(urls, str):  
        urls = [urls]
    
    for url in urls:
        try:
            dirfuzz(url)
        except Exception as e:
            print(f"[ERROR] Directory Fuzzing failed for {url}: {e}\n")

def run_js_scan(urls):
    if isinstance(urls, str):  
        urls = [urls]
    
    for url in urls:
        try:
            jsscan(url)
        except Exception as e:
            print(f"[ERROR] Javascript scan failed for {url}: {e}\n")