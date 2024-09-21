import random
import requests
import re
import os
from termcolor import colored
from xml.etree import ElementTree as ET

data_dir = os.path.join(os.getcwd(), 'data')

# Load the command injection error patterns from cmdi.xml
def load_cmdi_errors(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()
    cmdi_errors = {}
    for error in root.findall('error'):
        error_name = error.attrib['value']
        patterns = [pattern.attrib['regexp'] for pattern in error.findall('pattern')]
        cmdi_errors[error_name] = patterns
    return cmdi_errors

# Detect command injection patterns based on the response content
def detect_cmdi(response_content, cmdi_errors):
    for error_name, patterns in cmdi_errors.items():
        for pattern in patterns:
            if re.search(pattern, response_content, re.IGNORECASE):
                return error_name
    return None

# Detect web application technology (e.g., by analyzing headers)
def detect_web_tech(headers):
    if 'x-powered-by' in headers:
        return headers['x-powered-by']
    elif 'server' in headers:
        return headers['server']
    return 'Unknown'

# Send a request to the URL with a payload and check for command injection vulnerabilities
def test_cmdi_payload(url, payload, user_agent, cmdi_errors):
    headers = {'User-Agent': user_agent}
    try:
        # Send the request with the payload
        response = requests.get(url, headers=headers, timeout=10)
        response_content = response.text

        # Check for command injection-specific error patterns in the response
        cmdi_error = detect_cmdi(response_content, cmdi_errors)
        if cmdi_error:
            return {'vulnerable': True, 'cmdi_error': cmdi_error, 'response': response_content, 'headers': response.headers}

    except requests.RequestException as e:
        print(colored(f"[×] Error testing payload on {url}: {e}", 'red'))

    return {'vulnerable': False}

# Perform Command Injection scan
def perform_cmdi_scan(crawled_urls, cmdi_payloads, user_agents):
    cmdi_errors = load_cmdi_errors(os.path.join(data_dir, 'cmdi.xml'))
    detected_tech = None  # Store the web tech after the first detection
    user_decision = None  # To store the user's decision to continue scanning

    try:
        for url in crawled_urls:
            print(colored(f"\n[•] Testing URL: {url}", 'yellow'))

            # Choose 10 random payloads
            payloads_to_test = random.sample(cmdi_payloads, 10)
            
            # Test each payload
            for payload in payloads_to_test:
                user_agent = random.choice(user_agents)  # Random user agent for each request
                full_url = f"{url}{payload}"  # Inject the payload into the URL
                
                # Test the URL with the payload
                result = test_cmdi_payload(full_url, payload, user_agent, cmdi_errors)

                if result['vulnerable']:
                    # Detect web tech only once for the first vulnerable URL
                    if not detected_tech:
                        detected_tech = detect_web_tech(result['headers'])
                        print(colored(f"[•] Web Technology: {detected_tech or 'Unknown'}", 'magenta'))
                    
                    print(colored(f"[★] Vulnerable URL found: {full_url}", 'white', attrs=['bold']))
                    print(colored(f"[•] Vulnerable Parameter: {url.split('?')[1] if '?' in url else 'N/A'}", 'green'))
                    print(colored(f"[•] Payload: {payload}", 'green'))
                    print(colored(f"[•] Command Injection Error Pattern: {result['cmdi_error']}", 'blue'))
                    
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

