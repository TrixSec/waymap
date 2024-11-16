# Waymap - Web Vulnerability Scanner.

**Current Version**: 5.4.1
**Author**: Trix Cyrus  
**Copyright**: © 2024 Trixsec Org  
**Maintained**: Yes

## What is Waymap?
Waymap is a fast and optimized And Automated web vulnerability scanner designed for penetration testers. It effectively identifies vulnerabilities by testing against a variety of payloads.

### Demo Video
Check out this video to see Waymap in action:

![Waymap Demo](https://github.com/TrixSec/waymap/blob/main/demo/lv_0_20240921113323.mp4?raw=true)

### Vulnerability Examples
- **SQL Injection**  
  ![SQL Injection](https://github.com/TrixSec/waymap/blob/main/demo/sqli-demo.png?raw=true)

- **Command Injection**  
  ![Command Injection](https://github.com/TrixSec/waymap/blob/main/demo/cmdi-demo.png?raw=true)

- **Server Side Template Injection**  
  ![Command Injection](https://github.com/TrixSec/waymap/blob/main/demo/ssti-demo.png?raw=true)

  **Can't add more screenshot it'll increase the size of readme.md**



## Features Overview
---

### Latest Update
#### v5.2.1

- New Sql Injection Scanning Module
- High Accuracy And Less False Positive 
- Access it using:  --scan sqli

#### v5.3.1
- Added Boolean Based Sqli Testing (OWN LOGIC)
- High Accuracy, Can Give False Positive Sometimes
- Access it using:  --scan sqli

#### v5.4.1
- Updated CVE Testing Logic in Profile-Critical CMS-Wordpress
- Added a More Better Logic 

### Waymap Features

1. **Vulnerability Scanning Modules:**
   - SQL Injection (SQLi)
   - Command Injection
   - Server-Side Template Injection (SSTI) with threading support
   - Cross-Site Scripting (XSS) with filter bypass payload testing and threading support
   - Local File Inclusion (LFI) with threading support
   - Open Redirect with custom thread count
   - Carriage Return and Line Feed (CRLF) with custom threading
   - Cross-Origin Resource Sharing (CORS) with threading support
   - Critical and High-Risk Scan Profiles using CVE exploits (32 CVEs: WordPress - 19, Drupal - 4, Joomla - 7, Generic/Others - 2)

2. **Web Crawling:**
   - Initial crawling functionality
   - Enhanced crawler to operate within target domain boundaries and handle URL redirection
   - Advanced crawler capable of any-depth crawling
   - Improved v3 crawler (competitive with SQLmap crawler)

3. **Concurrency & Threading:**
   - Concurrency to utilize multiple CPU threads for faster scans
   - Custom thread count for Open Redirect, CRLF, and CORS scans
   - New argument `--threads/-T` for global threading count (no prompt for threads)

4. **Multi-Target Scanning:**
   - Support for scanning multiple URLs with `--multi-target {targetfilename}.txt`
   - Ability to scan URLs directly without crawling using `--url/-u` and `--multi-url/-mu` arguments

5. **Automation and Convenience:**
   - Auto-update functionality (version-dependent)
   - New argument `--check-updates` to check for and perform updates
   - New argument `--random-agent` to randomize user-agents
   - Header usage to make requests appear more legitimate and reduce detection/blocking
   - Argument `--no-prompt/-np` to disable prompts (default input = 'n')

6. **Scan Profiles & Severity-Based Scanning:**
   - New critical and high-risk scan profiles (`--scan critical-risk` and `--scan high-risk`) using severity-based CVE exploits
   - Argument `--profile critical-risk/high-risk` with `--profileurl` for streamlined scanning based on CVE severity

7. **Logging and Stability:**
   - Logging functionality for scan sessions
   - Various bug fixes and optimizations for stability and processing speed

---

## Installation and Usage

### Clone the repository:
```bash
git clone https://github.com/TrixSec/waymap.git
```

### Install the required dependencies:
```bash
pip install .
```

### Run Waymap:
```bash
python waymap.py --crawl 1 --scan sql/cmdi/ssti/xss/lfi/open-redirect/crlf/cors/all --target/--multi-target https://example.com/{filename}.txt
```
```bash
python waymap.py --scan sql/cmdi/ssti/xss/lfi/open-redirect/crlf/cors/all --url/--mutli-url https://example.com/index.php?id=1/{filename}.txt
```
### Check Help
```bash
python waymap.py -h

```

#### Credits
- Thanks SQLMAP For Payloads Xml File

### IF There's Any Issue In Waymay Then Submit The Issues Here: https://github.com/TrixSec/waymap/issues

#### Also Star The Repo And Fork It

### Follow Us on Telegram
Stay updated with the latest tools and hacking resources. Join our Telegram Channel by clicking the logo below:

[![Telegram](https://upload.wikimedia.org/wikipedia/commons/thumb/8/82/Telegram_logo.svg/240px-Telegram_logo.svg.png)](https://t.me/Trixsec)

### Happy Hacking!
