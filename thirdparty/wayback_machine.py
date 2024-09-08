import subprocess

def run_wayback_machine(domain, output_file):
    """Run Wayback Machine to scrape archived URLs for the given domain."""
    try:
        # Replace with actual Wayback Machine scraper command
        cmd = f"wayback_machine_scraper {domain} --output wayback_output.txt"
        subprocess.run(cmd, shell=True)

        # Assuming output is stored in a file (wayback_output.txt)
        with open("wayback_output.txt", 'r') as src:
            urls = src.readlines()

        with open(output_file, 'a') as dest:
            for url in urls:
                if not any(url.endswith(ext) for ext in ['.jpg', '.jpeg', '.png', '.pdf', '.js', '.css']):
                    dest.write(f"{url.strip()}\n")

        print(f"[*] URLs from Wayback Machine appended to {output_file}")

    except Exception as e:
        print(f"Error running Wayback Machine scraper: {str(e)}")
