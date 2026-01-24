# Waymap v7.2.0 - Web Vulnerability Scanner & Web Application Security Toolkit

**Current Version**: 7.2.0

**Waymap** is a fast, practical **web vulnerability scanner** and **web application security testing** toolkit for:

- **SQL Injection (SQLi)** testing (Boolean-based, Error-based, Time-based)
- **XSS** scanning (reflected payload testing)
- **Command Injection / RCE** scanning (safe marker-based checks)
- **LFI**, **CRLF Injection**, **CORS misconfiguration**, **Open Redirect**
- **API Security Testing** for **REST** and **GraphQL** (auth checks, introspection, basic abuse checks)
- **WordPress vulnerability scanning** (WPScan API batch lookups for core/plugins/themes)

Waymap focuses on automation-friendly scanning with consistent output, session-based result saving, and secrets management.

---

## What’s New in v7.2.0

### Discovery & Target Acquisition (Google Dorking)

- **SearchAPI-powered Google dork discovery** via `--dork`
- **Pagination support** (`page` parameter) to fetch all available result pages
- **Domain blacklist** support using `config/waymap/domain_blacklist.txt`
- Saves only **parameterized URLs** (must include `?` and `=`) for scan-ready targets

### Secrets Management (API Keys)

Waymap supports storing secrets outside code:

- `config/waymap/secrets.json`
  - `searchapi_api_key`
  - `wpscan_api_token`

Keys can be supplied via:

- CLI (ex: `--dork-api-key`, `--wpscan-token`)
- env vars (ex: `SEARCHAPI_API_KEY`, `WPSCAN_API_TOKEN`)
- secrets file (preferred)

### WordPress Vulnerability Profile (WPScan API)

- Single profile: `--profile wordpress`
- Lightweight WordPress detection gate before calling WPScan
- Uses **WPScan API v3 batch** (`POST /batch`) with multiple lookup items
- Saves output (including failures) to `sessions/<domain>/waymap_full_results.json`

### RCE / Command Injection Scanner

- New scan type: `--scan rce`
- Safe marker-based payloads (no destructive commands)
- Works on parameterized URLs
- Saves results to `sessions/<domain>/waymap_full_results.json`

---

## Installation

```bash
pip install -r requirements.txt
```

---

## Quick Start

### 1) Scan a target (standard web vulnerability scanning)

```bash
python waymap.py --target https://example.com --scan xss --crawl 2
```

### 2) RCE / Command Injection scan

```bash
python waymap.py --target "https://example.com/page.php?id=1" --scan rce
```

### 3) WordPress vulnerability scan (WPScan profile)

```bash
python waymap.py --target https://example.com --profile wordpress
```

### 4) Discover targets using Google dorks (SearchAPI)

```bash
python waymap.py --dork "inurl:.php?id="
```

By default results are saved to `dork_targets.txt` (or to a domain session if `--target` is also provided).

---

## Configuration

### Secrets file

Create/edit:

`config/waymap/secrets.json`

```json
{
  "searchapi_api_key": "",
  "wpscan_api_token": ""
}
```

### Domain blacklist for discovery

Edit:

`config/waymap/domain_blacklist.txt`

One domain per line (subdomains are matched too).

---

## Supported Scan Types

Use `--scan` with one of:

- `sqli`
- `xss`
- `cmdi`
- `rce`
- `ssti`
- `lfi`
- `open-redirect`
- `crlf`
- `cors`
- `api`
- `all`

---

## API Security Testing (REST / GraphQL)

```bash
python waymap.py --target https://api.example.com --scan api --api-type rest
python waymap.py --target https://api.example.com/graphql --scan api --api-type graphql
```

Optional:

- `--api-endpoints /users,/login` (REST)

---

## Authentication Support

Supported `--auth-type` values:

- `form`
- `basic`
- `digest`
- `bearer`
- `api_key`

Example:

```bash
python waymap.py --target https://example.com --auth-type bearer --token "YOUR_TOKEN" --scan all
```

---

## Reporting

```bash
python waymap.py --target https://example.com --scan all --report-format html,csv,markdown --output-dir reports
```

---

## Results / Output Files

Waymap stores scan output per target domain:

- `sessions/<domain>/waymap_full_results.json`

This includes findings from:

- Standard vulnerability scans
- WordPress profile scans
- RCE scan

---

## Help

```bash
python waymap.py --help
```

---

## Legal / Disclaimer

Waymap is intended for **authorized security testing** and educational use only.

---

## Support

Issues: https://github.com/TrixSec/waymap/issues
