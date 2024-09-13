import subprocess
# import sqlparse

def run_waf_detection(domain):
    """Run WAF Detector tool to detect WAF and print output in SQLMap-like style.

    :param domain: The domain to run WAF detection on.
    :type domain: str
    """
    try:
        # Run WAF Detector and capture output
        result = subprocess.run(
            ["python3", "thirdparty/waf_detector/identYwaf.py", "-u", domain],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        output = result.stdout
        error = result.stderr

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
