# Waymap - Web Vulnerability Scanner.

**Current Version**: 5.7.2
**Author**: Trix Cyrus  
**Copyright**: © 2024 Trixsec Org  
**Maintained**: Yes

## What is Waymap?
**Waymap** is a fast and optimized web vulnerability scanner designed to identify security flaws in web applications. With support for multiple scan types and customizable configurations, it is a versatile tool for ethical hackers, penetration testers, and security enthusiasts. And Is Able To Scan For **75+ Web Vulnerabilities**

## Features Overview
---

### Latest Update

#### v5.5.1 
- Added 45 CVEs Vulnerability Detections Logics
- 11 Critical-Risk CVEs And 34 High-Risk CVEs
- For CVEs Info Read The CVEVULN.md File 

#### v5.6.1 
- Added New 19 CVEs Vulnerability Detections Logics
- 8 Critical-Risk CVEs And 11 High-Risk CVEs
- For CVEs Info Read The CVEVULN.md File 

#### v5.7.1
- Removed arg --random-agent, now waymap will by default use different headers for every requests
- Added IP Spoofing for more anonymity
- Updated Wp Plugin Checking Logic In Both High Profile And Critical Profile
- some minor bug fix

#### v5.7.2 
- Added New Logic To Update Waymap
---

## 🚀 **Features**

### 1. **Flexible Scanning Options**
   - **Target-based scanning:** 
     Scan single or multiple targets using `--target` or `--multi-target` options (Requires Crawling).
   - **Direct URL scanning:** 
     Use `--url` or `--multi-url` to scan specific URLs without crawling.
   - **Profile-based scanning:** 
     Supports high-risk and critical-risk scan profiles for targeted assessments.

### 2. **Supported Scan Types**
   - **SQL Injection (SQLi):**  
     Detect vulnerabilities related to SQL injection.
   - **Command Injection (CMDi):**  
     Identify potential command execution vulnerabilities.
   - **Server-Side Template Injection (SSTI):**  
     Scan for template injection risks in server-side frameworks.
   - **Cross-Site Scripting (XSS):**  
     Check for reflective XSS vulnerabilities.
   - **Local File Inclusion (LFI):**  
     Locate file inclusion vulnerabilities.
   - **Open Redirect:**  
     Identify redirect-related issues.
   - **Carriage Return and Line Feed (CRLF):**  
     Scan for CRLF injection flaws.
   - **Cross-Origin Resource Sharing (CORS):**  
     Check for misconfigurations in CORS policies.
   - **All-in-one scanning:**  
     Perform all available scans in a single command.

### 3. **Profile-based Scanning**
   - **High-Risk Profile:**  
   - **Critical-Risk Profile:**  
     Focuses on severe vulnerabilities, such as CVE-based attacks.

### 4. **Crawling Capabilities**
   - Crawl target websites with customizable depth (`--crawl`).
   - Automatically discover and extract URLs for scanning.

### 5. **Threaded Scanning**
   - Speed up scans with multithreading (`--threads`).

### 6. **User-Agent Randomization**
   - Randomize requests using different user agents (`--random-agent`).

### 7. **Automation Features**
   - Skip prompts using the `--no-prompt` option.
   - Automatically handle missing directories, files, and session data.

### 8. **Update Checker**
   - Easily check for the latest updates (`--check-updates`).

---

## 🛠️ **How to Use**

### Basic Commands
1. **Scan a single target:**
   ```bash
   python waymap.py --crawl 3 --target https://example.com --scan {scan_type}
   ```
2. **Scan multiple targets from a file:**
   ```bash
   python waymap.py --crawl 3 --multi-target targets.txt --scan {scan_type}
   ```
3. **Directly scan a single URL:**
   ```bash
   python waymap.py --url https://example.com/page?id=1 --scan {scan_type}
   ```
4. **Profile-based scanning:**
   ```bash
   python waymap.py --profileurl https://example.com --profile high-risk/critical-risk
   ```

### Thread Configuration
1. **Use threading for faster scans:**
   ```bash
   python waymap.py --crawl 3 --target https://example.com --scan ssti --threads 10
   ```

### Update Check
1. **Ensure you have the latest version:**
   ```bash
   python waymap.py --check-updates
   ```

### Check Help
```bash
python waymap.py -h

```

---


### Waymap makes web vulnerability scanning efficient and accessible. Start securing your applications today! 🎯


#### Credits
- Thanks SQLMAP For Payloads Xml File

### IF There's Any Issue In Waymay Then Submit The Issues Here: https://github.com/TrixSec/waymap/issues

#### Also Star The Repo And Fork It

### Follow Us on Telegram
Stay updated with the latest tools and hacking resources. Join our Telegram Channel by clicking the logo below:

[![Telegram](https://upload.wikimedia.org/wikipedia/commons/thumb/8/82/Telegram_logo.svg/240px-Telegram_logo.svg.png)](https://t.me/Trixsec)

### Happy Hacking!
