import requests
from lib import logging

def test_connection(url, timeout=30, retries=3):
    """
    Test the connection to the target URL with a specified timeout and retry count.

    Args:
        url (str): Target URL to test the connection.
        timeout (int): Timeout for the request in seconds. Default is 30 seconds.
        retries (int): Number of retry attempts if the connection fails. Default is 3.

    Returns:
        bool: True if connection is successful, False if all retries fail.
    """
    logging.log_message(f"Testing connection to the target URL", "info") 
    
    for attempt in range(1, retries + 1):
        logging.log_message(f"Attempt {attempt}/{retries}", "info")
        
        try:
            response = requests.get(url, timeout=timeout)
            
            if response.status_code == 200:
                logging.log_message(f"Connection successful (Status code: {response.status_code})", "success")
                return True
            else:
                logging.log_message(f"Received status code {response.status_code}. Retrying...", "warning")

        except requests.exceptions.Timeout:
            logging.log_message("Connection timed out. Retrying...", "warning")
        except requests.exceptions.RequestException as e:
            logging.log_message(f"Error: {e}. Retrying...", "error")

    logging.log_message("Failed to connect after multiple attempts.", "critical")
    return False
