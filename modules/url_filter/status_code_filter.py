import requests

def filter_status_200(input_file, output_file):
    """
    Filter URLs that return a 200 status code and save them to the output file.
    Supports partial saving in case the user interrupts (Ctrl+C).
    """
    try:
        with open(input_file, 'r') as src, open(output_file, 'a') as dest:
            urls = src.readlines()

            for url in urls:
                url = url.strip()
                try:
                    response = requests.get(url)
                    if response.status_code == 200:
                        dest.write(f"{url}\n")
                        print(f"[*] {url} - Status 200 OK")
                    else:
                        print(f"[!] {url} - Status {response.status_code}")
                except requests.exceptions.RequestException as e:
                    print(f"[!] {url} - Request failed: {str(e)}")
    
    except KeyboardInterrupt:
        print("[!] Process interrupted by user. Partial data saved.")
    
    except Exception as e:
        print(f"Error filtering URLs: {str(e)}")

# Usage example:
# filter_status_200("sessions/example.com/unique_urls.txt", "sessions/example.com/status_200_urls.txt")
