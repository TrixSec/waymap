# Waymap - Web Vulnerability Scanner

**Current Version**: 1.2.1 
**Author**: Trix Cyrus  
**Contributions**: Yash (0day-Yash) & Jennin (@JeninSutradhar)
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
### v1.0.3 (First Version)
- SQL Injection
- Command Injection
- Web Crawling

### v1.0.4 
- Updated crawler to operate within target domain boundaries and handle URL redirection.
- Added auto-update functionality for the scanner (please reclone the repo if using v1.0.4).

### v1.0.5
- Fixed minor bugs (please reclone the repo if using v1.0.4).

### v1.0.6
- Enhanced the auto-update feature; no need to reclone the repo after this update. Please reclone if using v1.0.5.

### v1.0.7
- Fixed minor bugs and added support for scanning multiple URLs using `--multi-target {targetfilename}.txt` (ensure the file has one URL per line).
- Auto-update enabled; no need to reclone unless on version v1.0.5 or older.

### v1.0.8
- Added concurrency to utilize more CPU threads, speeding up SQL injection scans.
- Improved stability.
- Added logging functionality.

### v1.0.9
- minor bug fix

### v1.1.0
- added a new scan type : Server Side Template Injection: --scan ssti
- now you can do all type scan in one command using : --scan all
- Added Threading In SSTI(Server Side Template Injection)

### v1.1.1
- fixed ssti exiting error

### v1.2.1
- added new scanning module: xss(cross site scripting) --scan xss
- added xss filters bypass payload testing
- added threading in xss testing
- added new scanning module: LFI(Local File Inclusion) --scan lfi
- added threading in lfi testing

### v1.3.1
- added new scanning module: --scan open-redirect (check for open redirection vulnerability)
- added custom threads count in open redirect testing
- fixed minor bugs

--NEW--UPDATES--SOON--

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
python waymap.py --crawl 1 --scan sql/cmdi/ssti/xss/lfi/open-redirect/all --target/--multi-target https://example.com/{filename}.txt
```

### Check Help
```bash
python waymap.py -h
```

### Follow Us on Telegram
Stay updated with the latest tools and hacking resources. Join our Telegram Channel by clicking the logo below:

[![Telegram](https://upload.wikimedia.org/wikipedia/commons/thumb/8/82/Telegram_logo.svg/240px-Telegram_logo.svg.png)](https://t.me/Trixsec)

### Happy Hacking!
