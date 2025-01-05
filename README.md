# Waymap - Web Vulnerability Scanner.

**Current Version**: 6.1.6
**Author**: Trix Cyrus  
**Copyright**: © 2024 Trixsec Org  
**Maintained**: Yes

## What is Waymap?
**Waymap** is a fast and optimized web vulnerability scanner designed to identify security flaws in web applications. With support for multiple scan types and customizable configurations, it is a versatile tool for ethical hackers, penetration testers, and security enthusiasts. And Is Able To Scan For **75+ Web Vulnerabilities**

## Features Overview
---

### Latest Update

#### v5.9.4
- Removed Old Error Based Sql Method Use the new one by --scan sqli
- Updated The Open Redirect Vuln Testing In Waymap
- Updated The Crawler To v4
- Added 249 High Risk Cves Data In Waymap
- Total Count: 390

#### v6.0.4 
- Added New Scan Profile 'deepscan' use using --profile deepscan
- Features in Deepscan: Scan for 25+ Types of Headers Vuln , Do Massive Directory Fuzzing, Find Backup Files On The Server
- Fixed Scan Type 'cors' Error
- minor bug fixed

#### v6.0.5 
- fixed issue regaring waymap updates

#### v6.1.6
- Added New Module In Deepscan Profile : Vulnerable Javascript Library And Files Scanner
- Added WAF/IPS Detector In Waymap Can Detect More Than 160 Types of Waf
- Usage: --check-waf/--waf https://example.com

--- New Crazy Updates Soon

## 🚀 **Features**

### 1. **Flexible Scanning Options**
   - **Target-based scanning:** 
     Scan single or multiple targets using `--target` or `--multi-target` options 
   - **Profile-based scanning:** 
     Supports high-risk, critical-risk and deepscan scan profiles for targeted assessments.

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
   - **deepscan Profile:**
     Focuses on severe vulnerabilities, such as CVE-based attacks.

### 4. **Crawling Capabilities**
   - Crawl target websites with customizable depth (`--crawl`).
   - Automatically discover and extract URLs for scanning.

### 5. **Threaded Scanning**
   - Speed up scans with multithreading (`--threads`).

### 6. **Automation Features**
   - Skip prompts using the `--no-prompt` option.
   - Automatically handle missing directories, files, and session data.

### 7. **Update Checker**
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
3. **Directly scan a single Target Without Crawling:**
   ```bash
   python waymap.py --target https://example.com/page?id=1 --scan {scan_type}

2. **Directly Scan multiple targets from a file:**
   ```bash
   python waymap.py  --multi-target targets.txt --scan {scan_type}(example url type: https://example.com/page?id=1 )

   ```
4. **Profile-based scanning:**
   ```bash
   python waymap.py --target https://example.com --profile high-risk/critical-risk/deepscan
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

**Repository Views** ![Views](https://profile-counter.glitch.me/waymap/count.svg)

### Waymap makes web vulnerability scanning efficient and accessible. Start securing your applications today! 🎯


#### Credits
- Thanks SQLMAP For Payloads Xml File

### IF There's Any Issue In Waymay Then Submit The Issues Here: https://github.com/TrixSec/waymap/issues

#### Also Star The Repo And Fork It

### Follow Us on Telegram
Stay updated with the latest tools and hacking resources. Join our Telegram Channel by clicking the logo below:

[![Telegram](https://upload.wikimedia.org/wikipedia/commons/thumb/8/82/Telegram_logo.svg/240px-Telegram_logo.svg.png)](https://t.me/Trixsec)

### Happy Hacking!
