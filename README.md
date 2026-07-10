# Waymap v8.1.1 — Web Vulnerability Scanner & Security Toolkit

**Current Version:** 8.1.1  
**Author:** Trix Cyrus (Vicky)  
**License:** GPLv3

Waymap is a fast, practical **web vulnerability scanner** for authorized security testing. It automates SQLi, XSS, command injection, SSTI, LFI, CORS, CRLF, open redirect, API, recon, misconfiguration, and WordPress checks—with session-based results, multi-threading, crawling, authentication, reporting, Google dork discovery, and **AI-powered vulnerability analysis**.

---

## What’s New in v8.1.1

### 🚀 Optimized Active Reconnaissance
- **No More Redundant Directory Fuzzing:** Removed time-consuming brute-force checks for Admin Panels (~140 paths), Backup Files (~810 paths), and Exposed Configs (~50 paths) from the reconnaissance engine, avoiding duplicates with dedicated modules (`misconfig` and `auth-logic`). This saves over 1000 slow, synchronous requests.
- **Enhanced Swagger & GraphQL detection:** Maintained lightweight API discovery probes and updated the scanner summary output to directly list identified Swagger/OpenAPI and GraphQL endpoints.

### 🛡️ Enhanced SSTI Scan & Engine Detection
- **Detailed Engine Signatures:** Added comprehensive detection signatures for various template engines.
- **False Positive Prevention:** Incorporated timing baseline and content verification techniques.

### 🐛 Scanner Module Hardening
- Improved validations and security checks across CORS, CRLF, LFI, and Open Redirect scan modules.
- **Bug Fix:** Restored missing `exit_clean` import in `prompt_line()` to fix interactive UI Ctrl+C handlers.

---

## What’s New in v8.0.0

### 🤖 AI/LLM Integration (Major Release)

**AI-Powered Vulnerability Analysis:**
- **AI Adaptive Payload Generation** — Uses LLMs to generate context-aware, WAF-evading payloads for SQLi, XSS, CMDi, and other injection attacks
- **AI False Positive Reduction** — Analyzes findings with AI to reduce false positives and provide confidence scores
- **AI Attack Surface Discovery** — Leverages AI to discover hidden endpoints, parameters, and attack vectors from HTML/JavaScript
- **AI Crawler Enhancer** — Extracts hidden URLs and API endpoints using AI analysis of page content
- **AI Result Analysis** — Provides detailed severity justification, impact assessment, and remediation steps for findings
- **AI Chain Analysis** — Identifies potential vulnerability chains that could lead to more severe exploits

**Supported LLM Providers:**
- **Groq** (default, fastest) — llama-4-scout, compound, compound-mini models
- **Cerebras** — gpt-oss-120b, zai-glm-4.7, gemma-4-31b
- **OpenAI** — GPT-5.5, GPT-5, GPT-5 mini, GPT-5 nano
- **Anthropic** — Claude Opus 4.8, Claude Sonnet 5, Claude Haiku 4.5
- **Ollama** — Local models (llama3.1, etc.)
- **NVIDIA** — nemotron-3-super-120b-a12b

**AI Usage:**
```bash
# Enable all AI features
python waymap.py --target https://example.com --scan xss --use-ai

# Individual AI features
python waymap.py --target https://example.com --scan xss --ai-payloads    # AI-generated payloads
python waymap.py --target https://example.com --scan xss --ai-discovery   # AI attack surface discovery
python waymap.py --target https://example.com --scan xss --analyze        # AI result analysis
python waymap.py --target https://example.com --scan xss --ai-report      # AI-enhanced reports
```

### 🏗️ Architecture Improvements

**Event Bus System:**
- New event-driven architecture for finding events
- Real-time finding emission to subscribers
- Improved result tracking and reporting

**Reconnaissance Intelligence Engine:**
- Passive recon (subdomain enumeration, technology detection)
- Cheap active recon (robots.txt, sitemap.xml, meta tags)
- Deep active recon (admin panel discovery, WAF detection)
- Comprehensive reconnaissance reporting

**Fingerprint Engine:**
- Intelligent request deduplication
- Pattern-based URL normalization
- Reduced redundant scanning

**Enhanced HTTP Layer:**
- Retry logic with exponential backoff
- Connection pooling optimization
- Persistent keep-alive headers
- Improved error handling

### 🔧 Scanner Improvements

**XSS Scanner:**
- Fixed URL filtering for parameterized URLs
- Improved deduplication logic
- Enhanced DOM XSS detection
- Better confidence scoring

**SQLi Scanner:**
- Added support for new SQLi techniques: **Union-Based**, **Stacked-Queries**, and **Inline-Query** injections
- Added **Database Enumeration** support (database extraction engine)
- Improved payload injection accuracy
- Better baseline timing for time-based SQLi
- Enhanced error detection patterns
- Fixed boolean SQLi parameter handling

**Crawler & Discovery Engine:**
- Improved crawling efficiency and high-speed page discovery
- Better target parameter extraction and deduplication mapping

**General Improvements:**
- Fixed confidence/severity string-to-float conversion
- Enhanced admin panel discovery and display
- Improved result manager event emission
- Better session management
- Enhanced reporting capabilities

### 📊 Performance & Reliability

- **Fixed thread pools** — No adaptive scaling, consistent performance
- **Improved rate limiting** — Better handling of API rate limits
- **Enhanced error handling** — More robust error recovery
- **Better logging** — Improved debug and error messages

---

## What’s New in v7.2.1

### Stability & Security Hardening

- **Thread-safe result saving** — New `ResultManager` with file locking; all injection, recon, and profile modules now save findings safely under concurrent scans.
- **Fixed SQLi payload injection** — Boolean SQLi correctly injects into URL parameters instead of appending to the URL.
- **Fixed error-based SQLi** — Removed logic that stripped single quotes from payloads.
- **Fixed config paths** — Data/session paths resolve relative to the project root, not the current working directory.
- **Secure XML parsing** — SQLi and CMDi modules use `defusedxml` to prevent XXE.
- **Time-based SQLi baseline** — Baseline request timing reduces false positives.
- **CRLF detection** — Checks both response headers and body for injected markers.
- **Open redirect** — Uses `requests` instead of `curl` (works on Windows without external tools).
- **CMDi URL building** — Proper query-string reconstruction instead of fragile string replace.
- **Report loading fixed** — Session JSON is correctly parsed for HTML/CSV/Markdown/PDF reports.
- **WAF module import fixed** — `--check-waf` uses the correct module path.
- **Windows Unicode fix** — Banner and UI render correctly on Windows terminals.
- **Dependency check** — `defusedxml` is required and listed in `requirements.txt`.

### Scanner Modules Updated in v7.2.1

All of the following now use `ResultManager`:

`sqli` · `xss` · `lfi` · `cmdi` · `ssti` · `cors` · `crlf` · `open-redirect` · `advanced` · `wpscan` · `recon/misconfig`

---

## What’s New in v7.2.0 (Previous Release)

- SearchAPI Google dork discovery (`--dork`)
- WPScan API WordPress profile (`--profile wordpress`)
- Commix-style command injection scan (`--scan cmdi`)
- Secrets file support (`config/waymap/secrets.json`)
- Domain blacklist for dork discovery

---

## Installation

```bash
git clone https://github.com/TrixSec/waymap.git
cd waymap
pip install -r requirements.txt
```

Verify installation:

```bash
python waymap.py --version
python waymap.py --help
```

---

## Quick Start

```bash
# Single URL — XSS scan with crawl
python waymap.py --target https://example.com --scan xss --crawl 2

# Parameterized URL — SQLi (all techniques)
python waymap.py --target "https://example.com/page.php?id=1" --scan sqli

# Full scan — no prompts, 4 threads, reports
python waymap.py --target https://example.com --scan all --crawl 2 --threads 4 --no-prompt \
  --report-format html,csv,markdown --output-dir reports

# Interactive mode (no arguments)
python waymap.py
```

---

## CLI Reference

### Target

| Flag | Short | Description |
|------|-------|-------------|
| `--target` | `-t` | Single target URL |
| `--multi-target` | `-mt` | File with one URL per line |

### Scan Configuration

| Flag | Short | Description |
|------|-------|-------------|
| `--scan` | `-s` | Scan type (see [Scan Types](#scan-types)) |
| `--crawl` | `-c` | Crawl depth `0–10` (finds parameterized URLs) |
| `--technique` | `-k` | SQLi techniques: `B` boolean, `E` error, `T` time, `U` union, `I` inline, `S` stacked (e.g. `BETUIS`) |
| `--profile` | `-p` | Scan profile: `wordpress` |
| `--threads` | | Worker threads (default: `1`, max: `10`) |
| `--no-prompt` | | Skip interactive prompts (CI/automation) |
| `--verbose` | `-v` | Verbose output |

### Utilities

| Flag | Description |
|------|-------------|
| `--check-waf` | Detect WAF on `--target` |
| `--waf URL` | Detect WAF on a specific URL |
| `--check-updates` | Check GitHub for new version |
| `--version` | Print version and exit |

### Reporting

| Flag | Description |
|------|-------------|
| `--report-format` | Comma-separated: `html`, `csv`, `markdown`, `pdf` |
| `--output-dir` | Report output directory (default: `reports`) |

### Authentication

| Flag | Short | Description |
|------|-------|-------------|
| `--auth-type` | | `form`, `basic`, `digest`, `bearer`, `api_key` |
| `--auth-url` | | Login URL (form auth) |
| `--username` | `-u` | Username |
| `--password` | `-pw` | Password |
| `--token` | | Bearer token or API key |
| `--auth-header` | | API key header name (default: `X-API-Key`) |

### API Scanning

| Flag | Description |
|------|-------------|
| `--api-type` | `rest` (default) or `graphql` |
| `--api-endpoints` | Comma-separated REST paths (e.g. `/users,/login`) |

### Discovery (SearchAPI)

| Flag | Description |
|------|-------------|
| `--dork` | Google dork query |
| `--dork-api-key` | SearchAPI key (or `SEARCHAPI_API_KEY` env) |
| `--dork-output` | Save discovered URLs to file |

### WPScan

| Flag | Description |
|------|-------------|
| `--wpscan-token` | WPScan API token (or `WPSCAN_API_TOKEN` env) |

---

## Scan Types

Use with `--scan` / `-s`:

| Scan | Description |
|------|-------------|
| `sqli` | SQL injection (boolean, error, time-based) |
| `xss` | Context-aware cross-site scripting |
| `cmdi` | Commix-style command injection (result, eval, blind time) |
| `ssti` | Server-side template injection |
| `lfi` | Local file inclusion |
| `open-redirect` | Open redirect |
| `crlf` | CRLF / header injection |
| `cors` | CORS misconfiguration |
| `api` | REST or GraphQL API security |
| `all` | Run every standard vulnerability scan |
| `recon` | Technology fingerprinting, sitemap, DNS, buckets |
| `misconfig` | Security headers, admin panels, sensitive files |
| `redirect` | Host header injection, redirect, CRLF |
| `injection-advanced` | SSRF, XXE, HPP, NoSQL, prototype pollution, etc. |
| `graphql-suite` | GraphQL introspection, batching, depth checks |
| `auth-logic` | IDOR, JWT, OAuth, access control signals |
| `cache-smuggling` | Cache poisoning, HTTP desync indicators |
| `wordpress-extras` | WP user enum, xmlrpc, readme exposure |
| `optional` | WebSocket, extended WAF, redirect chains |

---

## Usage Examples

### Basic vulnerability scans

Each command below can be combined with `--threads N`, `--no-prompt`, and `-v` / `--verbose`.

```bash
# SQL injection — all techniques (default)
python waymap.py -t "https://example.com/item?id=1" -s sqli

# SQL injection — specific techniques
python waymap.py -t "https://example.com/item?id=1" -s sqli -k B      # boolean only
python waymap.py -t "https://example.com/item?id=1" -s sqli -k E      # error only
python waymap.py -t "https://example.com/item?id=1" -s sqli -k T      # time-based only
python waymap.py -t "https://example.com/item?id=1" -s sqli -k BE     # boolean + error
python waymap.py -t "https://example.com/item?id=1" -s sqli -k BET    # boolean, error, time
python waymap.py -t "https://example.com/item?id=1" -s sqli -k BETUIS # all SQLi techniques

# XSS
python waymap.py -t "https://example.com/search?q=test" -s xss

# Command injection
python waymap.py -t "https://example.com/ping?host=127.0.0.1" -s cmdi

# SSTI
python waymap.py -t "https://example.com/render?name=test" -s ssti

# LFI
python waymap.py -t "https://example.com/view?file=index.php" -s lfi

# Open redirect
python waymap.py -t "https://example.com/redirect?url=https://example.com" -s open-redirect

# CRLF injection
python waymap.py -t "https://example.com/redirect?path=/home" -s crlf

# CORS misconfiguration
python waymap.py -t "https://example.com/api/data" -s cors
```

### Crawling + scanning

When the target has no query parameters, use `--crawl` to discover parameterized URLs first.

```bash
# Crawl depth 1–3 is typical for single-app scans
python waymap.py -t https://example.com -s xss -c 1
python waymap.py -t https://example.com -s sqli -c 2 -k BET
python waymap.py -t https://example.com -s all -c 3 --threads 4

# Crawl + specific scan + automation
python waymap.py -t https://example.com -s lfi -c 2 --threads 6 --no-prompt -v
```

### Multi-threading combinations

```bash
python waymap.py -t "https://example.com/page?id=1" -s sqli --threads 2
python waymap.py -t "https://example.com/page?id=1" -s xss  --threads 4
python waymap.py -t https://example.com -s all -c 2 --threads 8 --no-prompt
```

### Full / comprehensive scans

```bash
# Every injection + recon module (excludes --scan api)
python waymap.py -t https://example.com -s all -c 2

# Recon + misconfig + advanced (manual pipeline)
python waymap.py -t https://example.com -s recon
python waymap.py -t https://example.com -s misconfig
python waymap.py -t https://example.com -s injection-advanced -c 1

# Redirect / header injection bundle
python waymap.py -t https://example.com -s redirect -c 1
```

### Multi-target scanning

```bash
# targets.txt — one URL per line
python waymap.py --multi-target targets.txt -s sqli --no-prompt
python waymap.py --multi-target targets.txt -s xss  -c 1 --threads 4
python waymap.py --multi-target targets.txt -s all  -c 2 --threads 4 --no-prompt
```

### API security testing

```bash
# REST API (default)
python waymap.py -t https://api.example.com -s api --api-type rest

# REST with explicit endpoints
python waymap.py -t https://api.example.com -s api --api-type rest \
  --api-endpoints /users,/login,/admin

# GraphQL
python waymap.py -t https://api.example.com/graphql -s api --api-type graphql

# GraphQL suite (standalone scan type)
python waymap.py -t https://api.example.com/graphql -s graphql-suite

# Auth logic checks on API URLs
python waymap.py -t https://api.example.com -s auth-logic
```

### Authentication + scanning

```bash
# Bearer token
python waymap.py -t https://example.com -s all --auth-type bearer --token "YOUR_JWT" --no-prompt

# API key header
python waymap.py -t https://api.example.com -s api --auth-type api_key \
  --token "YOUR_KEY" --auth-header "X-API-Key"

# HTTP Basic
python waymap.py -t https://example.com -s xss --auth-type basic \
  -u admin -pw "password" --no-prompt

# Form login
python waymap.py -t https://example.com -s all --auth-type form \
  -u admin -pw "password" --auth-url https://example.com/login --no-prompt
```

### WordPress

```bash
# WPScan API profile (core, plugins, themes CVE lookup)
python waymap.py -t https://wordpress-site.com --profile wordpress

# With explicit token
python waymap.py -t https://wordpress-site.com --profile wordpress \
  --wpscan-token "YOUR_WPSCAN_TOKEN"

# WordPress-specific extras (xmlrpc, user enum, etc.)
python waymap.py -t https://wordpress-site.com -s wordpress-extras -c 1
```

### Google dork discovery

```bash
# Discover parameterized URLs via SearchAPI
python waymap.py --dork "inurl:.php?id=" --dork-api-key "YOUR_KEY"

# Save to custom file
python waymap.py --dork "inurl:product.php?cat=" --dork-output discovered.txt

# Dork + auto SQLi scan on discovered URLs
python waymap.py --dork "inurl:.php?id=" --dork-api-key "YOUR_KEY" -s sqli --no-prompt
```

### WAF detection

```bash
python waymap.py --check-waf -t https://example.com
python waymap.py --waf https://example.com/login
```

### Reporting combinations

```bash
# HTML only
python waymap.py -t https://example.com -s all -c 1 \
  --report-format html --output-dir reports

# All formats
python waymap.py -t https://example.com -s all -c 2 --no-prompt \
  --report-format html,csv,markdown,pdf --output-dir reports

# Scan + report (reports load from session JSON automatically)
python waymap.py -t https://example.com -s sqli -k BET \
  --report-format html,csv --output-dir ./scan-results
```

### Recommended real-world combinations

```bash
# Bug bounty — fast parameterized URL test
python waymap.py -t "https://target.com/vuln?id=1" -s sqli -k BET --threads 4 --no-prompt -v

# Internal pentest — crawl + full scan + reports
python waymap.py -t https://app.internal -s all -c 3 --threads 6 --no-prompt \
  --report-format html,markdown,pdf --output-dir pentest-reports

# CI/CD pipeline (non-interactive)
python waymap.py -t "$TARGET_URL" -s sqli -k BE --threads 2 --no-prompt \
  --report-format csv --output-dir ci-artifacts

# API assessment
python waymap.py -t https://api.target.com -s api --api-type rest \
  --auth-type bearer --token "$API_TOKEN" --no-prompt -v

# WordPress engagement
python waymap.py -t https://client-wp.com --profile wordpress --wpscan-token "$WPSCAN_TOKEN"
python waymap.py -t https://client-wp.com -s wordpress-extras -c 1 --no-prompt
```

---

## Configuration

### Secrets file

Create `config/waymap/secrets.json`:

```json
{
  "searchapi_api_key": "YOUR_SEARCHAPI_KEY",
  "wpscan_api_token": "YOUR_WPSCAN_TOKEN"
}
```

Environment variables (override secrets file):

| Variable | Used by |
|----------|---------|
| `SEARCHAPI_API_KEY` | `--dork` discovery |
| `WPSCAN_API_TOKEN` | `--profile wordpress` |
| `WAYMAP_NO_PROMPT` | Set automatically with `--no-prompt` |

### Domain blacklist (dork discovery)

Edit `config/waymap/domain_blacklist.txt` — one domain per line.

### Payloads & wordlists

Located in `data/` (e.g. `lfipayload.txt`, `sstipayload.txt`). XSS and CMDi payloads are generated from their scanner logic.

---

## Results & Output

All findings are saved per domain:

```
sessions/<domain>/waymap_full_results.json
```

Reports (when `--report-format` is set) are written to `--output-dir` (default: `reports/`).

Result structure:

```json
{
  "scans": [
    { "XSS": { "Findings": [ { "url": "...", "parameter": "...", "payload": "..." } ] } },
    { "SQL Injection": { "Technique: Boolean": [ ... ] } },
    { "Command Injection": [ ... ] }
  ]
}
```

---

## Project Structure

```
waymap/
├── waymap.py              # Main CLI entry point
├── VERSION                # Current version (8.1.1)
├── requirements.txt
├── data/                  # Payloads and wordlists
├── config/waymap/         # Secrets, blacklist, mode config
├── sessions/              # Per-domain scan results
├── lib/
│   ├── injection/         # XSS, SQLi, CMDi, SSTI, LFI, etc.
│   ├── recon/             # Recon, misconfig, redirects
│   ├── api/               # REST/GraphQL/auth logic
│   ├── core/              # Config, ResultManager, reporting
│   └── scanner/           # WaymapScanner orchestrator
└── reports/               # Generated reports (default)
```

---

## Requirements

- Python 3.8+
- See `requirements.txt` for packages (`requests`, `beautifulsoup4`, `defusedxml`, etc.)

---

## Help & Updates

```bash
python waymap.py --help
python waymap.py --version
python waymap.py --check-updates
```

---

## Legal / Disclaimer

Waymap is intended for **authorized security testing and educational use only**. Only scan systems you own or have explicit permission to test. The authors are not responsible for misuse.

---

## Support

- **Issues:** https://github.com/TrixSec/waymap/issues
- **Telegram:** https://t.me/Trixsec

---

## Changelog Summary

| Version | Highlights |
|---------|------------|
| **8.1.1** | Hotfix: Restored missing exit_clean import in prompt_line() |
| **8.1.0** | Optimized Active Recon (removed redundant fuzzing), Enhanced SSTI scan & engine detection, scanner module hardening |
| **8.0.0** | AI integration, Union/Stacked/Inline SQLi techniques, Database Enumeration support, Crawler improvements and many more  |
| **7.2.1** | Thread-safe results, SQLi/CMDi/CRLF fixes, defusedxml, Windows UI fix, report loading fix |
| **7.2.0** | Google dork discovery, WPScan profile, secrets management |
| **7.1.0** | API scanning, auth support, HTML/CSV/Markdown/PDF reports |

![Views](https://komarev.com/ghpvc/?username=waymap)
