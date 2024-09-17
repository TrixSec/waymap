import os
import requests
from urllib.parse import urlparse, parse_qs, urlencode
import random

# Load SQLi payloads from file
def load_payloads(file_name):
    if os.path.exists(file_name):
        with open(file_name, 'r') as f:
            return [line.strip() for line in f.readlines()]
    else:
        print(f"Payload file {file_name} not found.")
        return []

# Load user-agents from ua.txt
def load_user_agents(file_name):
    if os.path.exists(file_name):
        with open(file_name, 'r') as f:
            return [line.strip() for line in f.readlines()]
    else:
        print(f"User-agent file {file_name} not found.")
        return []

# Load URLs from crawl.txt
def load_urls(domain):
    file_path = f'/waymap/session/{domain}/crawl.txt'
    if os.path.exists(file_path):
        with open(file_path, 'r') as f:
            return [url.strip() for url in f.readlines()]
    else:
        print(f"No crawl file found for domain: {domain}")
        return []

# Select a random user-agent from the list
def get_random_user_agent(user_agents):
    return random.choice(user_agents)

# Inject payload into URL parameters
def inject_payload(url, payload):
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)

    # Inject payload into each parameter
    injected_urls = []
    for param in query_params:
        injected_params = query_params.copy()
        injected_params[param] = payload
        new_query = urlencode(injected_params, doseq=True)
        injected_url = parsed_url._replace(query=new_query).geturl()
        injected_urls.append(injected_url)

    return injected_urls

# Send HTTP request with random user-agent
def send_request(url, user_agents):
    headers = {'User-Agent': get_random_user_agent(user_agents)}
    try:
        response = requests.get(url, headers=headers, timeout=5)
        return response.text, response.status_code
    except requests.RequestException as e:
        print(f"Request failed for {url}: {e}")
        return None, None

# Check if the parameter is dynamic by analyzing response
def is_parameter_dynamic(response, payload):
    return payload in response

# Check if the response is potentially vulnerable to SQL injection
def is_sql_injection_vulnerable(response):
    error_messages = [
        "you have an error in your sql syntax",
        "warning: mysql",
        "unclosed quotation mark",
        "quoted string not properly terminated",
        "error in your SQL syntax",
        "SQLSTATE",
    ]
    return any(error.lower() in response.lower() for error in error_messages)

# Inject payloads and check for dynamic or vulnerable parameters
def test_injection(domain):
    urls = load_urls(domain)
    if not urls:
        return

    # Load payloads and user-agents
    sql_payloads = load_payloads('sqlipayload.txt')
    cmd_payloads = load_payloads('cmdipayload.txt')
    user_agents = load_user_agents('ua.txt')

    for url in urls:
        print(f"Testing URL: {url}")
        
        # Test SQLi payloads
        for payload in sql_payloads:
            injected_urls = inject_payload(url, payload)

            for injected_url in injected_urls:
                print(f"Injecting SQLi payload: {payload} into {injected_url}")
                response_text, status_code = send_request(injected_url, user_agents)

                if response_text and status_code == 200:
                    # Check if the parameter is dynamic
                    if is_parameter_dynamic(response_text, payload):
                        print(f"[DYNAMIC] Parameter reflected in response: {injected_url}")

                    # Check if the URL is vulnerable to SQL injection
                    if is_sql_injection_vulnerable(response_text):
                        print(f"[VULNERABLE] SQL Injection detected: {injected_url}")
                        save_vulnerable_url(domain, injected_url)

        # Test command injection payloads
        for payload in cmd_payloads:
            injected_urls = inject_payload(url, payload)

            for injected_url in injected_urls:
                print(f"Injecting CMD payload: {payload} into {injected_url}")
                response_text, status_code = send_request(injected_url, user_agents)

                if response_text and status_code == 200:
                    # Check if the parameter is dynamic
                    if is_parameter_dynamic(response_text, payload):
                        print(f"[DYNAMIC] Parameter reflected in response: {injected_url}")
                    
                    # Command injection detection can be added here
                    # Example: You might look for typical command execution results or errors

# Save vulnerable URLs to vulnurls.txt
def save_vulnerable_url(domain, vulnerable_url):
    file_path = f'/waymap/session/{domain}/vulnurls.txt'
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, 'a') as f:
        f.write(vulnerable_url + '\n')
