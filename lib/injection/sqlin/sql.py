# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.
# sql.py (new logic)

abort_all_tests = False

from lib.injection.sqlin.boolean import process_urls as process_boolean_urls
from lib.injection.sqlin.error import process_urls as process_error_urls
from lib.injection.sqlin.timeblind import process_urls as process_time_blind_urls

def run_sql_tests(urls):
    global abort_all_tests
    for url in urls:
        if abort_all_tests:
            break

        process_boolean_urls([url])

        if abort_all_tests:
            break

        process_error_urls([url])
        if abort_all_tests:
            break

        process_time_blind_urls([url])

def run_boolean_sqli(urls):
    global abort_all_tests
    for url in urls:
        if abort_all_tests:
            break
        process_boolean_urls([url])

def run_error_sqli(urls):
    global abort_all_tests
    for url in urls:
        if abort_all_tests:
            break
        process_error_urls([url])

def run_time_blind_sqli(urls):
    global abort_all_tests
    for url in urls:
        if abort_all_tests:
            break
        process_time_blind_urls([url])