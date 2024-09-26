import random
import requests
import re
import os
from termcolor import colored
from xml.etree import ElementTree as ET

data_dir = os.path.join(os.getcwd(), 'data')

# Load CMDI error patterns from XML
def load_cmdi_errors(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()
    cmdi_errors = {}
    for error in root.findall('error'):
        error_name = error.attrib['value']
        patterns = [pattern.attrib['regexp'] for pattern in error.findall('pattern')]
        cmdi_errors[error_name] = patterns
    return cmdi_errors

# Detect CMDI based on error patterns in response content
def detect_cmdi(response_content, cmdi_errors):
    for error_name, patterns in cmdi_errors.items():
        for pattern in patterns:
            if re.search(pattern, response_content, re.IGNORECASE):
                return error_name
    return None

# Detect web technology from HTTP headers
def detect_web_tech(headers):
    if 'x-powered-by' in headers:
        return headers['x-powered-by']
    elif 'server' in headers:
        return headers['server']
    return 'Unknown'

# Test CMDI payload against a URL and check if it's vulnerable
def test_cmdi_payload(url, payload, user_agent, cmdi_errors):
    headers = {'User-Agent': user_agent}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response_content = response.text

        # Check for CMDI-related errors
        cmdi_error = detect_cmdi(response_content, cmdi_errors)
        if cmdi_error:
            return {'vulnerable': True, 'cmdi_error': cmdi_error, 'response': response_content, 'headers': response.headers}

    except requests.RequestException as e:
        print(colored(f"[×] Error testing payload on {url}: {e}", 'red'))

    return {'vulnerable': False}

# Perform CMDI scan on crawled URLs
def perform_cmdi_scan(crawled_urls, cmdi_payloads, user_agents):
    cmdi_errors = load_cmdi_errors(os.path.join(data_dir, 'cmdi.xml'))  # Load CMDI error patterns
    detected_tech = None  # Store the detected web technology
    user_decision = None  # Store the user's decision for continuing after finding a vulnerability

    try:
        for url in crawled_urls:
            print(colored(f"\n[•] Testing URL: {url}", 'yellow'))

            # Randomly select 10 payloads to test on each URL
            payloads_to_test = random.sample(cmdi_payloads, 10)
            found_vulnerability = False  # Track if a vulnerability is found

            for payload in payloads_to_test:
                user_agent = random.choice(user_agents)  # Randomly choose a user agent
                full_url = f"{url}{payload}"  # Construct the URL with the payload

                result = test_cmdi_payload(full_url, payload, user_agent, cmdi_errors)

                if result['vulnerable']:
                    found_vulnerability = True

                    # Detect web technology from the response headers
                    if not detected_tech:
                        detected_tech = detect_web_tech(result['headers'])
                        print(colored(f"[•] Web Technology: {detected_tech or 'Unknown'}", 'magenta'))

                    # Print vulnerability details
                    print(colored(f"[★] Vulnerable URL found: {full_url}", 'white', attrs=['bold']))
                    print(colored(f"[•] Vulnerable Parameter: {url.split('?')[1] if '?' in url else 'N/A'}", 'green'))
                    print(colored(f"[•] Payload: {payload}", 'green'))
                    print(colored(f"[•] Command Injection Error Pattern: {result['cmdi_error']}", 'blue'))

                    # Ask user if they want to continue scanning other URLs
                    if user_decision is None:
                        user_input = input(colored("\n[?] Vulnerable URL found. Do you want to continue testing other URLs? (y/n): ", 'yellow')).strip().lower()
                        if user_input == 'n':
                            print(colored("[•] Stopping further scans as per user's decision.", 'red'))
                            return  # Stop further scans if the user chooses 'no'
                        user_decision = (user_input == 'y')  # Remember user decision

                    break  # Stop testing further payloads for this URL once a vulnerability is found

            # If no vulnerabilities were found for the URL
            if not found_vulnerability:
                print(colored(f"[×] No vulnerabilities found on: {url}", 'red'))

    except KeyboardInterrupt:
        print(colored("\n[!] Scan interrupted by user. Exiting cleanly...", 'red'))