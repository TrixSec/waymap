import subprocess
import re
from lib import logging

def check_waf(url):
    """
    Use identYwaf to check if a Web Application Firewall (WAF) is present for the given URL.

    Args:
        url (str): Target URL to check for WAF.

    Returns:
        bool: True if a WAF is detected, False otherwise.
    """
    logging.log_message(f"Checking for WAF on {url}", "info")
    
    try:
        # Run identYwaf.py script with the target URL as an argument
        result = subprocess.run(
            ['python3', './thirdparty/identYwaf/identYwaf.py', '-u', url],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Capture and process the output from identYwaf
        output = result.stdout.strip()
        
        # Regex pattern to extract WAF names from the output
        waf_names = re.findall(r"\[+] blind match: '([^']+)'", output)
        
        if waf_names:
            for name in waf_names:
                logging.log_message(f"WAF detected: {name}", "info")
                
            # Ask the user whether to continue or abort the scan
            user_input = input(f"WAF detected on {url}. Do you want to continue the scan? (y/n): ")
            if user_input.lower() == 'n':
                logging.log_message("User chose to abort the scan due to WAF detection.", "info")
                exit(0)  # Aborts the scan
            else:
                logging.log_message("User chose to continue the scan despite WAF detection.", "warning")
            
            return True
        else:
            logging.log_message(f"No WAF detected on {url}.", "info")
            return False

    except Exception as e:
        logging.log_message(f"Error running identYwaf: {e}", "critical")
        return False
