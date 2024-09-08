def remove_duplicates(input_file, output_file):
    """Remove duplicate URLs from the input file and save the unique URLs."""
    try:
        # Read URLs from the input file
        with open(input_file, 'r') as f:
            urls = f.readlines()

        # Remove duplicates by converting to a set
        unique_urls = list(set(url.strip() for url in urls))

        # Write unique URLs to the output file
        with open(output_file, 'w') as f:
            for url in unique_urls:
                f.write(f"{url}\n")

        print(f"[*] Duplicate URLs removed. {len(unique_urls)} unique URLs saved to {output_file}.")

    except Exception as e:
        print(f"Error processing file: {str(e)}")
