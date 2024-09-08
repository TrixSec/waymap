import subprocess

def run_httrack(domain, output_file):
    """Run HTTrack to mirror the website and append URLs to the file."""
    try:
        cmd = f"httrack {domain} --mirror"
        subprocess.run(cmd, shell=True)
        
        # Assuming output is stored in a file (httrack_output.txt)
        with open("httrack_output.txt", 'r') as src:
            urls = src.readlines()

        with open(output_file, 'a') as dest:
            for url in urls:
                if not any(url.endswith(ext) for ext in ['.jpg', '.jpeg', '.png', '.pdf', '.js', '.css']):
                    dest.write(f"{url.strip()}\n")

        print(f"[*] URLs from HTTrack appended to {output_file}")
    
    except Exception as e:
        print(f"Error running HTTrack: {str(e)}")
