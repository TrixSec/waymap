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

## Full CLI Usage

See [usage.md](usage.md) for every CLI option and example commands.

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
- `recon`
- `misconfig`
- `redirect`
- `injection-advanced`
- `graphql-suite`
- `auth-logic`
- `cache-smuggling`
- `wordpress-extras`
- `optional`

---

## Vulnerability Coverage (What Waymap Actually Checks)

Waymap is designed as a practical HTTP scanner. Many checks are **best-effort** and depend on:

- Target behavior
- Response content
- Available endpoints
- Whether a URL has parameters (`?a=b`) where required

All findings are saved per target domain to:

- `sessions/<domain>/waymap_full_results.json`

### `--scan recon` (Foundation Recon)

Recon is focused on identifying technologies, attack surface, and low-effort exposure signals.

- **Tech fingerprinting**
  - Server and framework hints from headers (ex: `Server`, `X-Powered-By`, generator tags)
- **CMS fingerprinting**
  - Pattern matching for common CMS assets (ex: WordPress/Joomla/Drupal/Magento)
- **Robots + sitemap enumeration**
  - Fetches `robots.txt` and common sitemap endpoints and extracts listed paths/URLs
- **Sitemap endpoint enumeration**
  - Tries common sitemap locations to discover hidden endpoints
- **Parameter mining**
  - Extracts and deduplicates query parameter names from crawled URLs
- **Content discovery (wordlist-lite)**
  - Probes common paths for exposed resources
- **Virtual host fuzzing (best-effort)**
  - Sends requests with a crafted `Host` header and compares response similarity
- **Subdomain takeover signals (best-effort)**
  - Matches common takeover error fingerprints in HTML
- **Open bucket detection (best-effort)**
  - Looks for bucket listing responses and directory-index patterns
- **DNS zone transfer checks (best-effort)**
  - Runs limited `nslookup` checks to detect transfer-like responses

### `--scan misconfig` (Misconfiguration & Exposure)

Misconfig scans are aimed at common, high-impact web hardening issues.

- **Security headers audit**
  - Detects missing headers such as CSP/HSTS/XFO/XCTO/Referrer-Policy/Permissions-Policy
- **CSP analysis**
  - Records CSP presence/value for review
- **HSTS audit**
  - Records HSTS presence/value
- **Clickjacking signals**
  - Flags missing `X-Frame-Options` and missing `frame-ancestors` in CSP
- **Cookie security flags**
  - Extracts `Set-Cookie` and reports Secure/HttpOnly/SameSite presence per cookie
- **Version disclosure**
  - Flags version-like patterns in headers such as `Server`, `X-Powered-By`, `X-AspNet-Version`
- **Admin panel discovery**
  - Probes common admin/login paths
- **Debug endpoint discovery**
  - Probes common debug/status/profiler/phpinfo endpoints
- **Sensitive file exposure**
  - Probes common secrets/config paths (ex: `/.git/config`, `/.env`, `wp-config.php`, `composer.lock`)
- **Secrets exposure (aggregated)**
  - Records hits from sensitive files and env exposure under a shared secrets key
- **Backup file exposure**
  - Probes common backup/archive filenames
- **Directory listing checks**
  - Detects directory index patterns (ex: “Index of /”)
- **Swagger/OpenAPI exposure**
  - Probes common `swagger.json`, `openapi.json`, `swagger-ui/` locations
- **SOAP/WSDL exposure**
  - Probes common `?wsdl` / `/wsdl` endpoints
- **CSRF token presence (heuristic)**
  - If the page contains forms but no obvious CSRF token field names
- **CORS (advanced quick check)**
  - Sends an `OPTIONS` request with an attacker Origin and flags permissive allow-origin + credentials
- **TLS/SSL audit (best-effort)**
  - Captures TLS version and cipher for HTTPS targets
- **TRACE method exposure (best-effort)**
  - Attempts a TRACE request and records 200 responses
- **File upload form discovery (heuristic)**
  - Detects HTML `<input type="file">` fields (useful for prioritizing upload testing)

### `--scan redirect` (Redirect / Header Injection)

- **Host header injection (best-effort)**
  - Sends a crafted `Host` and checks for reflection via `Location` or response body
- **Open redirect (advanced quick check)**
  - For parameterized URLs, replaces common parameters and checks `Location` reflection
- **CRLF injection / HTTP response splitting (best-effort)**
  - Injects CRLF payloads and checks for injected header reflection
- **Request splitting (best-effort)**
  - Recorded when CRLF/header injection signals are detected

### `--scan injection-advanced` (Advanced Injection Expansion)

- **SSRF**
  - Tests common internal targets (localhost/127.0.0.1/cloud metadata) and looks for response keywords
- **Cloud metadata SSRF**
  - Special-cases metadata endpoints and stores separately when detected
- **XXE (best-effort)**
  - Attempts a basic XML payload on URLs that look XML-related and matches file-content keywords
- **HTTP Parameter Pollution (HPP) (heuristic)**
  - Compares baseline response length vs polluted values for large deltas
- **HTTP method tampering (best-effort)**
  - Reads `Allow` header from OPTIONS and flags risky methods
- **HTTP PUT upload / WebDAV hints (best-effort)**
  - Flags if methods suggest upload capability; records DAV headers
- **Path traversal**
  - Tests common traversal payloads and matches OS file markers
- **Remote File Inclusion (RFI) (heuristic)**
  - Attempts a safe external include marker and checks for expected content
- **SSTI (advanced heuristic)**
  - Injects simple expressions and checks for evaluation signals
- **RCE (advanced marker-based)**
  - Injects safe echo markers and checks for reflection
- **LFI -> RCE chain (best-effort)**
  - Attempts `/proc/self/environ` style inclusion with a UA marker
- **NoSQL injection (heuristic)**
  - Injects a simple `$ne` payload and flags large response deltas
- **Prototype pollution (heuristic)**
  - Tries `__proto__` payloads and looks for simple reflection signals
- **Email header injection / SMTP injection (best-effort)**
  - Targets email-like parameters with CRLF payloads and checks reflection
- **Reflected file download (best-effort)**
  - Looks for attacker-controlled filenames reflected in `Content-Disposition`

### `--scan graphql-suite` (GraphQL Security Suite)

- **Endpoint discovery**
  - Probes common GraphQL paths
- **Introspection exposure**
  - Attempts introspection queries and flags successful schema responses
- **Unauthenticated access signals**
  - Records if GraphQL responds successfully without auth
- **Batching checks (best-effort)**
  - Attempts basic batching behavior probes
- **Depth/complexity signals (best-effort)**
  - Tries deeper queries and records error/success signals
- **Schema dump (best-effort)**
  - Stores returned schema payloads when available
- **Subscriptions checks (best-effort)**
  - Probes subscription capability signals

### `--scan auth-logic` (Auth & API Logic)

Logic checks focus on patterns indicating missing authorization or broken access control.

- **IDOR (heuristic)**
  - Flags endpoints/parameters that look like object identifiers for prioritization
- **Broken access control signals (heuristic)**
  - Records suspicious patterns in responses and endpoint behavior
- **Mass assignment signals (heuristic)**
  - Records endpoints that likely accept JSON bodies for model binding
- **NoSQL injection signals (heuristic)**
  - Lightweight payload testing for common NoSQL patterns
- **OAuth misconfiguration signals (best-effort)**
  - Attempts to detect obvious OAuth endpoint patterns
- **JWT checks (best-effort)**
  - Detects obvious JWT usage patterns and records configuration hints
- **Basic auth bruteforce safety (non-destructive)**
  - Only reports presence/signals; does not perform aggressive brute force

### `--scan cache-smuggling` (Cache & Request Smuggling)

- **Cache poisoning signals (best-effort)**
  - Sends header variants and checks for caching-related response differences
- **Cache deception signals (best-effort)**
  - Probes cacheable-looking paths and records caching behavior hints
- **Web cache routing signals (best-effort)**
  - Probes for routing headers and caching indicators
- **HTTP desync/smuggling indicators (best-effort)**
  - Performs lightweight probes and records suspicious responses

### `--scan wordpress-extras` (WordPress Add-ons)

- **User enumeration (best-effort)**
  - Checks common enum patterns (ex: author archives)
- **XML-RPC exposure**
  - Detects if `xmlrpc.php` is reachable and provides capability hints
- **Readme exposure**
  - Checks common WP readme endpoints
- **Backup/config exposure**
  - Probes WP-specific config/backup filenames
- **Plugin/theme enumeration (best-effort)**
  - Tries to identify common plugin/theme paths
- **Hardening audit (best-effort)**
  - Records presence/absence of common security controls for WP targets

### `--scan optional` (Optional Checks)

- **WebSocket security checks (best-effort)**
  - Detects websocket endpoints/signals
- **WAF detection (extended)**
  - Records WAF fingerprints and blocking behavior
- **Redirect chain inspection**
  - Records redirect sequences that may hide endpoint transitions

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
