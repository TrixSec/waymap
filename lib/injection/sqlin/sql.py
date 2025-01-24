# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.
# sql.py (new logic)

abort_all_tests = False

from lib.injection.sqlin.boolean import process_urls as process_boolean_urls
from lib.injection.sqlin.error import process_urls as process_error_urls

def run_sql_tests(urls):
    global abort_all_tests
    for url in urls:
        if abort_all_tests:
            break

        process_boolean_urls([url])

        if abort_all_tests:
            break

        process_error_urls([url])