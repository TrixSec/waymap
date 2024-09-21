import random
import requests
import re
import os
from termcolor import colored
from xml.etree import ElementTree as ET

data_dir = os.path.join(os.getcwd(), 'data')

# Load the DBMS error patterns from errors.xml
def load_dbms_errors(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()
    dbms_errors = {}
    for dbms in root.findall('dbms'):
        dbms_name = dbms.attrib['value']
        errors = [error.attrib['regexp'] for error in dbms.findall('error')]
        dbms_errors[dbms_name] = errors
    return dbms_errors

# Detect the backend DBMS based on the response content
def detect_dbms(response_content, dbms_errors):
    for dbms_name, patterns in dbms_errors.items():
        for pattern in patterns:
            if re.search(pattern, response_content, re.IGNORECASE):
                return dbms_name
    return None

# Detect web application technology (e.g., by analyzing headers)
def detect_web_tech(headers):
    if 'x-powered-by' in headers:
        return headers['x-powered-by']
    elif 'server' in headers:
        return headers['server']
    return 'Unknown'

# Send a request to the URL with a payload and check for vulnerabilities
def test_payload(url, payload, user_agent, dbms_errors):
    headers = {'User-Agent': user_agent}
    try:
        # Send the request with the payload
        response = requests.get(url, headers=headers, timeout=10)
        response_content = response.text

        # Check for DBMS-specific error messages in the response
        dbms = detect_dbms(response_content, dbms_errors)
        if dbms:
            return {'vulnerable': True, 'dbms': dbms, 'response': response_content, 'headers': response.headers}

    except requests.RequestException as e:
        print(colored(f"[×] Error testing payload on {url}: {e}", 'red'))

    return {'vulnerable': False}

# Perform SQL injection scan
def perform_sqli_scan(crawled_urls, sql_payloads, user_agents):
    dbms_errors = load_dbms_errors(os.path.join(data_dir, 'errors.xml'))
    detected_tech = None  # Store the web tech after the first detection
    user_decision = None  # To store the user's decision to continue scanning

    try:
        for url in crawled_urls:
            print(colored(f"\n[•] Testing URL: {url}", 'yellow'))

            # Choose 10 random payloads
            payloads_to_test = random.sample(sql_payloads, 10)
            
            # Test each payload
            for payload in payloads_to_test:
                user_agent = random.choice(user_agents)  # Random user agent for each request
                full_url = f"{url}{payload}"  # Inject the payload into the URL
                
                # Test the URL with the payload
                result = test_payload(full_url, payload, user_agent, dbms_errors)

                if result['vulnerable']:
                    # Detect web tech only once for the first vulnerable URL
                    if not detected_tech:
                        detected_tech = detect_web_tech(result['headers'])
                        print(colored(f"[•] Web Technology: {detected_tech or 'Unknown'}", 'magenta'))
                    
                    print(colored(f"[★] Vulnerable URL found: {full_url}", 'white', attrs=['bold']))
                    print(colored(f"[•] Vulnerable Parameter: {url.split('?')[1] if '?' in url else 'N/A'}", 'green'))
                    print(colored(f"[•] Payload: {payload}", 'green'))
                    print(colored(f"[•] Backend DBMS: {result['dbms']}", 'blue'))
                    
                    # Ask the user if they want to continue testing other URLs (only once)
                    if user_decision is None:
                        user_input = input(colored("\n[?] Vulnerable URL found. Do you want to continue testing other URLs? (y/n): ", 'yellow')).strip().lower()
                        if user_input == 'n':
                            print(colored("[•] Stopping further scans as per user's decision.", 'red'))
                            return  # Stop further scans if the user chooses 'no'
                        user_decision = (user_input == 'y')
                    
                    # If user decides to continue, break and move to the next URL
                    break

            print(colored(f"[×] No vulnerabilities found on: {url}", 'red'))

    except KeyboardInterrupt:
        print(colored("\n[!] Scan interrupted by user. Exiting cleanly...", 'red'))

