# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.
# sql.py (new logic)

from lib.injection.sqlin.boolean import process_urls as process_boolean_urls
from lib.injection.sqlin.error import process_urls as process_error_urls

def run_sql_tests(urls):
    for url in urls:

        print(f"Starting Boolean-based SQL Injection tests for URL: {url}")
        process_boolean_urls([url]) 
        print(f"Boolean-based SQL Injection tests completed for URL: {url}\n")

        print(f"Starting Error-based SQL Injection tests for URL: {url}")
        process_error_urls([url])  
        print(f"Error-based SQL Injection tests completed for URL: {url}\n")
