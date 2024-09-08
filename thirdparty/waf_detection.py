import subprocess

def run_waf_detection(domain):
    """Run WAF Detector tool to detect WAF and print output in SQLMap-like style."""
    try:
        # Define the command to run identYwaf
        cmd = f"python3 thirdparty/waf_detector/identYwaf.py -u {domain}"

        # Run the command and capture output
        result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = result.stdout.decode('utf-8')
        error = result.stderr.decode('utf-8')

        # Check if WAF was detected and print SQLMap-style output
        if "waf detected" in output.lower():
            print(f"[WAF Detection] WAF detected for {domain}!")
            print(output.strip())  # Print the detailed output of WAF detection
        else:
            print(f"[WAF Detection] No WAF detected for {domain}.")
            if error:
                print(f"[Error] {error}")

    except Exception as e:
        print(f"Error running WAF Detector: {str(e)}")
