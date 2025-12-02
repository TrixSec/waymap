# Waymap - Web Vulnerability Scanner

**Current Version**: 7.0.0  
**Author**: Trix Cyrus (Vicky)  
**Copyright**: © 2024-25 Trixsec Org   
**Maintained**: Yes   

![Waymap Logo](https://waymapscanner.github.io/images/waymap.jpg)

## What is Waymap?
**Waymap** is a fast and optimized web vulnerability scanner designed to identify security flaws in web applications. With support for multiple scan types and customizable configurations, it is a versatile tool for ethical hackers, penetration testers, and security enthusiasts. Capable of scanning for **75+ Web Vulnerabilities** with a completely standardized, professional UI/UX.

---

## 🆕 Latest Updates

### v7.0.0 - Major UI/UX Overhaul & Stability Release 🎉
**Release Date**: December 2024

This is a **major release** focused on consistency, stability, and professional user experience.

#### 🎨 Complete UI/UX Standardization
- ✅ **Unified Interface**: All 15 scan modules now have consistent output formatting
- ✅ **Professional Headers**: Every scan starts with a cyan-colored header banner
- ✅ **Standardized Messages**: Consistent icons and colors across all modules
  - `[•]` Cyan - Information messages
  - `[✓]` Green - Vulnerabilities found
  - `[⚠]` Yellow - Warnings and prompts
  - `[✗]` Red - Errors
  - `[⚙]` Blue - Debug/verbose output
- ✅ **Uniform Prompts**: Consistent user interaction across all scan types
- ✅ **Completion Messages**: Every scan properly indicates completion status

#### 🔧 Core Improvements
- ✅ **Fixed Critical Bugs**: Resolved JSON structure inconsistencies causing crashes
- ✅ **Circular Import Resolution**: Fixed module dependency issues
- ✅ **Enhanced Threading**: Consistent thread management across all modules
- ✅ **Graceful Exit Handling**: Proper KeyboardInterrupt handling everywhere
- ✅ **Verbose Mode**: Standardized debug output with `--verbose` flag
- ✅ **Result Saving**: Fixed and standardized result saving across all scan types

#### 📦 Modules Standardized (15/15)
**Injection Scans (7)**
- LFI (Local File Inclusion)
- CMDi (Command Injection)
- SSTI (Server-Side Template Injection)
- CRLF (CRLF Injection)
- CORS (CORS Misconfiguration)
- Open Redirect
- XSS (Cross-Site Scripting)

**SQL Injection (3)**
- Boolean-based SQLi
- Error-based SQLi
- Time-based SQLi

**Profile Scans (3)**
- High-Risk Profile (CMS-specific scans)
- Critical-Risk Profile (Critical CVE scans)
- Deep Scan Profile (Headers, Backups, JS, Directory Fuzzing)

**Orchestrators (2)**
- SQL Injection Orchestrator
- XSS Scanner

#### 🐛 Bug Fixes
- Fixed `TypeError: list indices must be integers` in result saving
- Fixed missing `verbose` parameter in LFI and CMDi scans
- Fixed circular import issues with `stop_scan` event
- Fixed missing dependencies and module exports
- Fixed inconsistent JSON structure across scan types
- Added missing `datetime` import in error-based SQLi

#### 📚 Documentation
- Created comprehensive standardization documentation
- Added UI/UX guidelines for future development
- Updated command reference with all options
- Created testing reports and progress tracking

---

### Previous Updates

#### v6.2.11
- Install Waymap using `pip install waymap`

#### v6.2.10
- Multi-threading in SQLi

#### v6.2.9
- Bug Fixed
- Optimised
- Reduced Lag

#### v6.2.8
- Added Time Based SQLi Scanning Logic
- Added Scan Results Saving Logic
- Added Interactive Prompt Based And Argument Based Scanning Logic
- Updated The UI

#### v6.1.8
- Updated the SQL Injection Exiting logic
- Minor bug fixes

#### v6.1.7
- XSS payload file missing error fix
- Some minor bugs fix

#### v6.1.6
- Added New Module In Deepscan Profile: Vulnerable Javascript Library And Files Scanner
- Added WAF/IPS Detector In Waymap Can Detect More Than 160 Types of WAF
- Usage: `--check-waf` / `--waf https://example.com`

#### v5.9.4
- Removed Old Error Based SQL Method Use the new one by `--scan sqli`
- Updated The Open Redirect Vuln Testing In Waymap
- Updated The Crawler To v4
- Added 249 High Risk CVEs Data In Waymap
- Total Count: 390

---

## 🚀 Features

### 1. **Flexible Scanning Options**
   - **Target-based scanning:** Scan single or multiple targets using `--target` or `--multi-target` options
   - **Profile-based scanning:** Supports high-risk, critical-risk and deepscan scan profiles for targeted assessments
   - **No-prompt mode:** Automated scanning with `--no-prompt` flag
   - **Verbose mode:** Detailed debug output with `--verbose` flag

### 2. **Supported Scan Types**
   - **SQL Injection (SQLi):** Detect vulnerabilities related to SQL injection (Boolean, Error-based, Time-based)
   - **Command Injection (CMDi):** Identify potential command execution vulnerabilities
   - **Server-Side Template Injection (SSTI):** Scan for template injection risks in server-side frameworks
   - **Cross-Site Scripting (XSS):** Check for reflective XSS vulnerabilities
   - **Local File Inclusion (LFI):** Locate file inclusion vulnerabilities
   - **Open Redirect:** Identify redirect-related issues
   - **Carriage Return and Line Feed (CRLF):** Scan for CRLF injection flaws
   - **Cross-Origin Resource Sharing (CORS):** Check for misconfigurations in CORS policies
   - **All-in-one scanning:** Perform all available scans in a single command

### 3. **Profile-based Scanning**
   - **High-Risk Profile:** CMS-specific high-risk vulnerability scanning (WordPress, Drupal)
   - **Critical-Risk Profile:** Critical CVE-based vulnerability scanning
   - **DeepScan Profile:** Comprehensive deep scanning (Headers, Backup Files, JS Analysis, Directory Fuzzing)

### 4. **Crawling Capabilities**
   - Crawl target websites with customizable depth (`--crawl`)
   - Automatically discover and extract URLs for scanning

### 5. **Threaded Scanning**
   - Speed up scans with multithreading (`--threads`)
   - Optimized thread management for better performance

### 6. **Automation Features**
   - Skip prompts using the `--no-prompt` option
   - Automatically handle missing directories, files, and session data
   - Consistent result saving in JSON format

### 7. **Update Checker**
   - Easily check for the latest updates (`--check-updates`)
   - Auto-notification of new versions

### 8. **WAF Detection**
   - Detect 160+ types of WAF/IPS systems
   - Usage: `--check-waf https://example.com`

---

## 🛠️ How to Use

### Basic Commands

1. **Scan a single target:**
   ```bash
   python waymap.py --crawl 3 --target https://example.com --scan {scan_type}
   ```

2. **Scan multiple targets from a file:**
   ```bash
   python waymap.py --crawl 3 --multi-target targets.txt --scan {scan_type}
   ```

3. **Directly scan a single target without crawling:**
   ```bash
   python waymap.py --target https://example.com/page?id=1 --scan {scan_type}
   ```

4. **Directly scan multiple targets from a file:**
   ```bash
   python waymap.py --multi-target targets.txt --scan {scan_type}
   ```
   *(Example URL type: https://example.com/page?id=1)*

5. **Profile-based scanning:**
   ```bash
   python waymap.py --target https://example.com --profile high-risk
   python waymap.py --target https://example.com --profile critical-risk
   python waymap.py --target https://example.com --profile deepscan
   ```

6. **Verbose mode for detailed output:**
   ```bash
   python waymap.py --target https://example.com --scan xss --verbose
   ```

7. **No-prompt mode for automation:**
   ```bash
   python waymap.py --multi-target targets.txt --scan cors --no-prompt
   ```

### Thread Configuration

1. **Use threading for faster scans:**
   ```bash
   python waymap.py --crawl 3 --target https://example.com --scan ssti --threads 10
   ```

### SQL Injection Techniques

1. **Boolean-based SQLi:**
   ```bash
   python waymap.py --target https://example.com --scan sqli --technique B
   ```

2. **Error-based SQLi:**
   ```bash
   python waymap.py --target https://example.com --scan sqli --technique E
   ```

3. **Time-based SQLi:**
   ```bash
   python waymap.py --target https://example.com --scan sqli --technique T
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

## 📊 What's New in v7.0.0

### Before v7.0.0:
- Inconsistent output formatting across modules
- Different color themes for different scans
- Varying prompt styles
- Threading inconsistencies
- Result saving bugs

### After v7.0.0:
- ✅ **100% Consistent UI/UX** across all 15 modules
- ✅ **Professional Output** with standardized colors and icons
- ✅ **Reliable Threading** with proper stop_scan event handling
- ✅ **Fixed Result Saving** with consistent JSON structure
- ✅ **Graceful Exit** handling everywhere
- ✅ **Verbose Mode** for debugging
- ✅ **Production Ready** with polished user experience

---

**Repository Views** ![Views](https://profile-counter.glitch.me/waymap/count.svg) (After 05-01-2025)

### Waymap makes web vulnerability scanning efficient and accessible. Start securing your applications today! 🎯

---

## Credits
- Thanks SQLMAP For Payloads XML File

## Support & Issues

If you face any issues in Waymap, please submit them here: https://github.com/TrixSec/waymap/issues

### ⭐ Star The Repo And Fork It

---

## Follow Us on Telegram

Stay updated with the latest tools and hacking resources. Join our Telegram Channel by clicking the logo below:

[![Telegram](https://upload.wikimedia.org/wikipedia/commons/thumb/8/82/Telegram_logo.svg/240px-Telegram_logo.svg.png)](https://t.me/Trixsec)

---

### Happy Hacking! 🎯
