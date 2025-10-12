# Features of Waymap

Waymap is a powerful web security tool designed for automated scanning and vulnerability detection. Below is a comprehensive list of its major and minor features:

## Major Features

### 1. Automated Vulnerability Scanning
Waymap performs a wide range of automated checks implemented in the codebase. Each item below names the vulnerability type, a brief behavior description, and the primary module(s) where it is implemented.

- SQL Injection (SQLi)
	- Detects error-based, boolean blind and time-based SQL injection techniques; uses payload lists and response analysis.
	- Implemented in: `lib/injection/sqlin/sql.py`, `lib/injection/sqlin/error.py`, `lib/injection/sqlin/boolean.py`, `lib/injection/sqlin/timeblind.py`.

- Cross-Site Scripting (XSS)
	- Tests reflected/stored XSS vectors using payloads and response/DOM inspection.
	- Implemented in: `lib/injection/xss.py`; payloads and bypass lists in `data/` (e.g. `filtersbypassxss.txt`).

- Local File Inclusion (LFI)
	- Tries directory traversal/wrapper payloads to read server-side files.
	- Implemented in: `lib/injection/lfi.py`.

- Command Injection (CMDi)
	- Tests command execution with curated payloads and matches error patterns from `cmdi.xml`.
	- Implemented in: `lib/injection/cmdi.py` (uses `data/cmdi.xml`, `data/cmdipayload.txt`).

- Server-Side Template Injection (SSTI)
	- Injects template payloads and checks for evaluated output in responses.
	- Implemented in: `lib/injection/ssti.py`.

- Open Redirect
	- Validates redirect parameters and common redirect payloads for unsafe behavior.
	- Implemented in: `lib/injection/openredirect.py` (uses `data/openredirectpayloads.txt`, `data/openredirectparameters.txt`).

- CRLF Injection
	- Sends CRLF payloads to detect header/log injection and header splitting.
	- Implemented in: `lib/injection/crlf.py` (uses `data/crlfpayload.txt`).

- CORS Misconfiguration
	- Probes endpoints with crafted `Origin` headers to detect permissive `Access-Control-Allow-Origin` responses.
	- Implemented in: `lib/injection/cors.py` (uses `data/corspayload.txt`).

- Directory & Backup File Discovery
	- Performs directory fuzzing and looks for backup files (.bak, .zip, common names) using wordlists.
	- Implemented in: `lib/ProfileDeepScan/waymap_dirfuzz.py`, `lib/ProfileDeepScan/waymap_backupfilefinder.py` (wordlists in `data/`).

- JavaScript/Asset Deep Scan
	- Crawls JS assets to find hard-coded endpoints, tokens, and extra attack surface.
	- Implemented in: `lib/ProfileDeepScan/waymap_jsdeepscan.py`, `waymapcrawlers/jscrawler.py`.

- Header Analysis & Randomized Headers
	- Generates randomized headers and inspects responses for header misconfigurations.
	- Implemented in: `lib/parse/random_headers.py`, `lib/ProfileDeepScan/headerdeepscan.py`.

- WAF Detection
	- Fingerprints common WAFs to report blocking/protection mechanisms.
	- Implemented in: `lib/core/wafdetector.py`.

- Crawling & Multi-target Scanning
	- Recursive crawling, multi-target orchestration, and threaded execution to scale scans.
	- Implemented across: `waymap.py`, `waymapcrawlers/crawler.py`, and many modules using `ThreadPoolExecutor`.

- Result Storage & Reporting
	- Saves findings to `sessions/<domain>/waymap_full_results.json` and prints colorized summaries.
	- Implemented via `save_results()` helpers in injection modules and JSON session files under `sessions/`.

How these map to the codebase:

- Payloads and wordlists live in `data/` (e.g. `cmdipayload.txt`, `crlfpayload.txt`, `corspayload.txt`, `waymap_dirfuzzlist.txt`, `filtersbypassxss.txt`).
- Concurrency is controlled by values in `lib/core/settings.py` (e.g. `DEFAULT_THREADS`, `MAX_THREADS`).
- Interactive prompts and default fallbacks use `DEFAULT_INPUT` so scans can run interactively or non-interactively.
- Each module writes incremental results through standardized `save_results()` helpers to avoid overwriting previous session data.

...existing code...

### 2. Web Application Firewall (WAF) Detection
Waymap can detect the presence of Web Application Firewalls (WAFs) protecting a target application. It provides detailed information about the detected WAF, such as its type and configuration, enabling users to adapt their testing strategies to bypass these defenses.

### 3. Multi-Target Scanning
Waymap supports scanning multiple targets simultaneously, making it efficient for large-scale assessments. By leveraging threading capabilities, it ensures faster scans without compromising accuracy. This feature is particularly useful for penetration testers working on multiple domains or subdomains.

### 4. Deep Scanning Modules
Waymap includes specialized modules for in-depth analysis:
- **JavaScript Deep Scan**: Analyzes JavaScript files for vulnerabilities, sensitive information, and potential attack vectors.
- **Header Deep Scan**: Examines HTTP headers for misconfigurations, security issues, and potential leaks.
- **Backup File Finder**: Searches for backup files that may contain sensitive data, such as source code or configuration files.
- **Directory Fuzzing**: Discovers hidden directories and files by brute-forcing common paths, helping to uncover unprotected resources.

### 5. Profile-Based Scanning
Waymap offers different scanning profiles tailored to specific needs:
- **Critical Profile**: Focuses on identifying high-priority vulnerabilities quickly, ideal for time-sensitive assessments.
- **Deep Scan Profile**: Conducts a thorough and detailed analysis of the target application, uncovering less obvious vulnerabilities.
- **High Profile**: Balances between speed and thoroughness, making it suitable for general-purpose scans.

### 6. Randomized HTTP Headers
To bypass basic security mechanisms, Waymap generates randomized HTTP headers during scans. This feature helps evade detection by intrusion prevention systems and WAFs, ensuring that scans are not easily blocked.

### 7. Open Redirect Detection
Waymap identifies open redirect vulnerabilities, which can be exploited to redirect users to malicious websites. These vulnerabilities are often used in phishing attacks and can compromise user trust.

### 8. Command Injection Detection
Waymap detects command injection vulnerabilities by testing with a variety of payloads. This ensures comprehensive coverage of potential attack vectors, helping to identify critical security flaws.

### 9. Cross-Origin Resource Sharing (CORS) Misconfiguration Detection
Waymap identifies insecure CORS configurations that could allow unauthorized access to sensitive data or enable cross-site attacks. This feature ensures that web applications adhere to best practices for secure CORS implementation.

### 10. User-Agent Spoofing
Waymap uses randomized user-agent strings to mimic different browsers and devices. This helps evade detection during scans and simulates real-world scenarios, making the tool more effective in identifying vulnerabilities.

## Minor Features

### 1. Update Checker
- Automatically checks for updates to ensure the tool is up-to-date.

### 2. System Checks
- Verifies the presence of required files and directories before starting a scan.

### 3. Interactive Prompts
- Provides user-friendly prompts during scans, making the tool accessible even to less experienced users.

### 4. Detailed Reporting
- Generates comprehensive JSON reports of scan results, including detailed information about detected vulnerabilities.

### 5. Colorized Output
- Enhances readability with colorized terminal output, making it easier to interpret scan results.

### 6. Modular Design
- Organized into modules for easy customization and extension, allowing users to adapt the tool to their specific needs.

### 7. Error Handling
- Manages network issues and missing dependencies gracefully, ensuring that scans can continue even in challenging environments.

### 8. Compatibility
- Works seamlessly with Python 3.6 and above, making it accessible to a wide range of users.

### 9. Lightweight
- Minimal dependencies for easy installation and usage, ensuring that the tool can be quickly deployed in various environments.

### 10. Open Source
- Licensed under GPL-3.0, allowing for community contributions and modifications to enhance the tool's capabilities.

---

Waymap continues to evolve with new features and improvements. Stay tuned for updates!