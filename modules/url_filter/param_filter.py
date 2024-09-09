def filter_urls_with_parameters(input_file, output_file):
    """
    Filter out URLs that don't have valid parameters (like '=' or '?') and save valid URLs to the output file.
    """
    try:
        with open(input_file, 'r') as src, open(output_file, 'w') as dest:
            urls = src.readlines()
            for url in urls:
                url = url.strip()
                # Check if the URL contains parameters
                if '=' in url or '?' in url:
                    dest.write(f"{url}\n")
                    print(f"[*] {url} - Contains valid parameters")
                else:
                    print(f"[!] {url} - No valid parameters found")
    
    except Exception as e:
        print(f"Error filtering URLs: {str(e)}")

# Usage example:
# filter_urls_with_parameters("sessions/example.com/unique_urls.txt", "sessions/example.com/urls_with_parameters.txt")
