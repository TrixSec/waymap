# Waymap - Web Vulnerability Scanner

**Current Version**: 7.1.0  
**Author**: Trix Cyrus (Vicky)  
**Copyright**: © 2024-25 Trixsec Org   
**Maintained**: Yes   

![Waymap Logo](https://waymapscanner.github.io/images/waymap.jpg)

## What is Waymap?
**Waymap** is a fast and optimized web vulnerability scanner designed to identify security flaws in web applications. With support for multiple scan types and customizable configurations, it is a versatile tool for ethical hackers, penetration testers, and security enthusiasts. Capable of scanning for **75+ Web Vulnerabilities** with a completely standardized, professional UI/UX.

---

## 🆕 Latest Updates

### v7.1.0 - API Security, Auth & Reporting 🚀
**Release Date**: December 2024

**Fast, Optimized, and Comprehensive Web Vulnerability Scanner**

Waymap v7.1.0 introduces powerful new capabilities for API security testing, advanced authentication, and professional reporting.

#### 🌟 What's New?

##### 🔌 API Security Testing
- **REST API Scanning**: Test endpoints for missing auth, IDOR, and rate limiting.
- **GraphQL Support**: Detect introspection, query depth issues, and schema exposure.
- **Method Testing**: Automated testing of GET, POST, PUT, DELETE, PATCH methods.

##### 🔐 Advanced Authentication
- **Multi-Protocol Support**: Form-based, HTTP Basic, Digest, Bearer Token, and API Key.
- **Session Management**: Maintain authenticated sessions across scans.
- **Custom Headers**: Inject custom authentication headers.

##### 📊 Professional Reporting
- **HTML Reports**: Interactive dashboards with charts and detailed findings.
- **CSV Exports**: Spreadsheet-compatible data for analysis.
- **Markdown**: Documentation-ready reports.
- **PDF Reports**: Professional PDF summaries.

---

### Previous Updates

#### v7.0.0 - Major UI/UX Overhaul & Stability Release 🎉
**Release Date**: December 2024

This is a **major release** focused on consistency, stability, and professional user experience.

##### 🎨 Complete UI/UX Standardization
- ✅ **Unified Interface**: All 15 scan modules now have consistent output formatting
- ✅ **Professional Headers**: Every scan starts with a cyan-colored header banner
- ✅ **Standardized Messages**: Consistent icons and colors across all modules
- ✅ **Uniform Prompts**: Consistent user interaction across all scan types
- ✅ **Completion Messages**: Every scan properly indicates completion status

##### 🔧 Core Improvements
- ✅ **Fixed Critical Bugs**: Resolved JSON structure inconsistencies causing crashes
- ✅ **Circular Import Resolution**: Fixed module dependency issues
- ✅ **Enhanced Threading**: Consistent thread management across all modules
- ✅ **Graceful Exit Handling**: Proper KeyboardInterrupt handling everywhere
- ✅ **Verbose Mode**: Standardized debug output with `--verbose` flag
- ✅ **Result Saving**: Fixed and standardized result saving across all scan types

##### 📦 Modules Standardized
- **Injection Scans**: LFI, CMDi, SSTI, CRLF, CORS, Open Redirect, XSS
- **SQL Injection**: Boolean, Error, Time-based
- **Profile Scans**: WordPress Vulnerability Scan (WPScan API)
- **Orchestrators**: SQLi, XSS

##### 🐛 Bug Fixes
- Fixed `TypeError` in result saving
- Fixed missing `verbose` parameters
- Fixed circular imports
- Fixed missing dependencies
- Fixed inconsistent JSON structures

##### 📚 Documentation
- Comprehensive standardization documentation
- UI/UX guidelines
- Updated command reference
- Testing reports

---

## 🚀 Features

   - **WordPress Vulnerability Profile:** WPScan API-based WordPress core/plugin/theme vulnerability lookup

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

### 4. **New v7.1.0 Arguments**

#### **API Scanning**
- `--scan api`: Enable API scanning mode
- `--api-type`: Specify API type (`rest` or `graphql`)
- `--api-endpoints`: Comma-separated list of endpoints (e.g., `/api/v1/users,/api/v1/login`)

#### **Authentication**
- `--auth-type`: Authentication type (`form`, `basic`, `digest`, `bearer`, `api_key`)
- `--auth-url`: Login URL (for form auth)
- `--username` / `-u`: Username
- `--password` / `-pw`: Password
- `--token`: Bearer token or API key
- `--auth-header`: Custom header name for API key (default: `X-API-Key`)

#### **Reporting**
- `--report-format`: Output formats (`html`, `csv`, `markdown`, `pdf`)
- `--output-dir`: Directory to save reports (default: `reports/`)

### 5. **Example Usage**

**Standard Scan:**
```bash
python waymap.py --target http://testphp.vulnweb.com --scan xss
```

**API Scan (REST):**
```bash
python waymap.py --target http://api.example.com --scan api --api-type rest --token "eyJhbG..."
```

**Authenticated Scan:**
```bash
python waymap.py --target http://example.com --auth-type form -u admin -pw secret --scan all
```

**Generate Reports:**
```bash
python waymap.py --target http://example.com --scan all --report-format html,pdf
```
### 6. **Profile-based scanning**
   ```bash
   python waymap.py --target https://example.com --profile wordpress
   ```

### 7. **Verbose mode for detailed output**
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
