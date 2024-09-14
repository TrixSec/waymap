import time
from lib import logging
from core.connection import test_connection

def retry_connection(url, retry_interval=10, timeout=30, retries=3):
    """
    Continuously attempt to reconnect to the target URL if the connection is lost.

    Args:
        url (str): The target URL.
        retry_interval (int): Time (in seconds) to wait between retry attempts. Default is 10 seconds.
        timeout (int): Timeout for the request in seconds. Default is 30 seconds.
        retries (int): Number of retry attempts before declaring failure in a single round. Default is 3.

    Returns:
        bool: True if connection is restored, False if retries fail.
    """
    while True:
        # Attempt to test the connection with retry logic
        if test_connection(url, timeout, retries):
            logging.log_message(f"Connection restored to {url}", "success")
            return True
        else:
            logging.log_message(f"Connection to {url} failed. Retrying in {retry_interval} seconds...", "warning")
            time.sleep(retry_interval)  # Wait before attempting to reconnect again
