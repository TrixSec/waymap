# Waymap - Web Vulnerability Scanner.

**Current Version**: 3.8.7
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

### v2.4.1
- added new scanning module: --scan crlf(Carriage Return and Line Feed)
- added custom threading count in crlf 
- added a more advanced crawler to waymap can crawl at any depth 
- added custom threading in crawling
- added new user-agents in ua.txt
- fixed major bugs/errors

### v2.5.2
- added new scan type: --scan cors(cross-origin resource sharing)
- added threading in cors scan
- fixed crlf bug
- fixed minor bugs

### v2.5.3
- fixed scanning exiting error

### v2.5.4
- fixed bug in open-redirect, crlf, cors

### v2.5.5
- updated sqli module to handle multiple parameter 
- added new arg --random-agent : now waymap will use random useragent only when this arg is used
- updated Waymap To Use Headers During Scan To make your requests to the server look more legitimate and reduce the chance of being flagged or blocked.

### v2.5.6
- bugs fixed
- no ssl verify update
--NEW--UPDATES--SOON--

### v3.5.6
- New Web Crawler(v2.5) With extended Scope
- fix the injections modules testing errors

### v3.6.6
- Better v3 Crawler, 
(I think At this point Waymap Crawler Is Better Than Sqlmap Crawler)
- added new arguments : --url/-u and --multi-url/-mu to scan url/urls without crawling them 
- bug fixes

### V3.7.6
- ADDED new arg --threads/-T (no more prompting for threads)
- optimised waymap

### v3.7.7
- fixed bug/error

### v3.8.7
- ADDED new arg --no-prompt/ -np (it will not prompt for any input during scan default input = 'n' )
- bug fixed

### v4.8.7
- Big Update In Waymap
- Added New Scan Profiles -- Critical and High -- access with --scan critical-risk, --scan high-risk 
- these profiles will do the scan using cve scanners and exploits added in waymap according to the severity of NVD 
- for now there are 32 CVES Exploits and scanners added for now 
- WordPress: 19 CVEs
- Drupal: 4 CVEs
- Joomla: 7 CVEs
- Generic/Others : 2 CVEs

- More details about these cves will be shared soon...

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
### IF There's Any Issue In Waymay Then Submit The Issues Here: https://github.com/TrixSec/waymap/issues

#### Also Star The Repo And Fork It

### Follow Us on Telegram
Stay updated with the latest tools and hacking resources. Join our Telegram Channel by clicking the logo below:

[![Telegram](https://upload.wikimedia.org/wikipedia/commons/thumb/8/82/Telegram_logo.svg/240px-Telegram_logo.svg.png)](https://t.me/Trixsec)

### Happy Hacking!
