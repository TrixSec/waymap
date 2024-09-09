def remove_duplicates(input_file, output_file):
    """
    Remove duplicate URLs from the input file and save the unique URLs to the output file.
    """
    try:
        with open(input_file, 'r') as f:
            urls = f.readlines()

        # Remove duplicates by converting to a set and preserving order
        unique_urls = list(dict.fromkeys(url.strip() for url in urls))

        with open(output_file, 'w') as f:
            for url in unique_urls:
                f.write(f"{url}\n")

        print(f"[*] Duplicate URLs removed. {len(unique_urls)} unique URLs saved to {output_file}.")
    
    except Exception as e:
        print(f"Error removing duplicates: {str(e)}")

# Usage example:
# remove_duplicates("sessions/example.com/all_urls.txt", "sessions/example.com/unique_urls.txt")
