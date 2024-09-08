import subprocess

def run_spiderfoot(domain, output_file):
    """Run SpiderFoot tool on the given domain and append output to the file."""
    try:
        cmd = f"spiderfoot-cli {domain} --output spiderfoot_output.json"
        subprocess.run(cmd, shell=True)
        
        # Assuming output is stored in a JSON file, read and extract URLs
        with open("spiderfoot_output.json", 'r') as src:
            urls = src.readlines()  # Example, adjust based on SpiderFoot's output format

        with open(output_file, 'a') as dest:
            for url in urls:
                if not any(url.endswith(ext) for ext in ['.jpg', '.jpeg', '.png', '.pdf', '.js', '.css']):
                    dest.write(f"{url.strip()}\n")

        print(f"[*] URLs from SpiderFoot appended to {output_file}")
    
    except Exception as e:
        print(f"Error running SpiderFoot: {str(e)}")
