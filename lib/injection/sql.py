# Copyright (c) 2024 waymap developers 
# See the file 'LICENSE' for copying permission.
# sql.py new version handler

from lib.injection.error import run_error_based_tests
from colorama import Fore, Style

def run_sql_injection_test(target_url):
    print(f"{Fore.YELLOW}Starting Error-Based SQL Injection Test on {target_url}{Style.RESET_ALL}")
    run_error_based_tests(target_url)
    print(f"{Fore.GREEN}Error-Based SQL Injection Testing Completed for {target_url}{Style.RESET_ALL}")

