# Waymap CLI Usage

This guide documents every Waymap CLI option with usage examples.

## Quick Command Patterns

```bash
# Basic scan
a) python waymap.py --target https://example.com --scan xss --crawl 2

# Full scan with reports
b) python waymap.py --target https://example.com --scan all --report-format html,csv --output-dir reports

# Multi-target scan
c) python waymap.py --multi-target targets.txt --scan sqli

# API scan (REST / GraphQL)
d) python waymap.py --target https://api.example.com --scan api --api-type rest
e) python waymap.py --target https://api.example.com/graphql --scan api --api-type graphql

# WordPress profile
f) python waymap.py --target https://example.com --profile wordpress

# Google dork discovery
g) python waymap.py --dork "inurl:.php?id="
```

## Full CLI Synopsis

```bash
python waymap.py [--target URL | --multi-target FILE] [--scan TYPE] [--crawl N] [--threads N]
                [--profile wordpress]
                [--technique BETUIS]
                [--api-type rest|graphql] [--api-endpoints /users,/login]
                [--auth-type form|basic|digest|bearer|api_key]
                [--auth-url URL] [--username USER] [--password PASS]
                [--token TOKEN] [--auth-header HEADER]
                [--report-format html,csv,markdown,pdf] [--output-dir DIR]
                [--dork "query"] [--dork-api-key KEY] [--dork-output FILE]
                [--wpscan-token TOKEN]
                [--check-waf] [--waf URL] [--check-updates]
                [--no-prompt] [--verbose]
```

---

## Target Options

### `--target`, `-t`
Single target URL to scan.

```bash
python waymap.py --target https://example.com --scan recon
```

### `--multi-target`, `-mt`
File containing one target URL per line.

```bash
python waymap.py --multi-target targets.txt --scan misconfig
```

---

## Scan Configuration

### `--scan`, `-s`
Select a scan type.

**Standard / Core scans:**
- `sqli`
- `xss`
- `cmdi`
- `ssti`
- `lfi`
- `open-redirect`
- `crlf`
- `cors`
- `api`
- `all`

**Module-based scans:**
- `recon`
- `misconfig`
- `redirect`
- `injection-advanced`
- `graphql-suite`
- `auth-logic`
- `cache-smuggling`
- `wordpress-extras`
- `optional`

Examples:
```bash
python waymap.py --target https://example.com --scan recon
python waymap.py --target https://example.com --scan injection-advanced
python waymap.py --target https://example.com --scan cache-smuggling
```

### `--crawl`, `-c`
Crawl depth for target discovery (0–10).

```bash
python waymap.py --target https://example.com --scan xss --crawl 3
```

### `--threads`
Thread count for scan operations.

```bash
python waymap.py --target https://example.com --scan all --threads 4
```

### `--technique`, `-k`
SQLi technique string:
- `B` (boolean)
- `E` (error)
- `T` (time)

```bash
python waymap.py --target "https://example.com/page.php?id=1" --scan sqli --technique BET
python waymap.py --target "https://example.com/page.php?id=1" --scan sqli --technique BETUIS
```

### `--profile`, `-p`
Run a scan profile.

- `wordpress`

```bash
python waymap.py --target https://example.com --profile wordpress
```

---

## Authentication Options

### `--auth-type`
Supported auth modes:
- `form`
- `basic`
- `digest`
- `bearer`
- `api_key`

### `--auth-url`
Login URL for form authentication.

### `--username`, `-u` / `--password`, `-pw`
Credentials for form/basic/digest auth.

### `--token`
Bearer token or API key value.

### `--auth-header`
Header name for API key authentication (default: `X-API-Key`).

Examples:
```bash
# Form auth
python waymap.py --target https://example.com --scan all \
  --auth-type form --auth-url https://example.com/login \
  --username admin --password pass

# Bearer token
python waymap.py --target https://example.com --scan api \
  --auth-type bearer --token "YOUR_TOKEN"

# API key
python waymap.py --target https://example.com --scan api \
  --auth-type api_key --token "API_KEY" --auth-header "X-API-Key"
```

---

## API Scanning

### `--scan api`
Enable the API scanner.

### `--api-type`
- `rest`
- `graphql`

### `--api-endpoints`
Comma-separated REST endpoints.

Examples:
```bash
# REST API scan
python waymap.py --target https://api.example.com --scan api --api-type rest

# GraphQL API scan
python waymap.py --target https://api.example.com/graphql --scan api --api-type graphql

# REST scan with explicit endpoints
python waymap.py --target https://api.example.com --scan api --api-type rest \
  --api-endpoints /users,/login,/tokens
```

---

## Discovery (Google Dorks)

### `--dork`
Run a SearchAPI-powered Google dork.

### `--dork-api-key`
SearchAPI key override. If omitted, Waymap looks in:
- `SEARCHAPI_API_KEY` env var
- `config/waymap/secrets.json` (`searchapi_api_key`)

### `--dork-output`
Save discovered URLs to a custom file.

Examples:
```bash
python waymap.py --dork "inurl:.php?id="
python waymap.py --dork "site:example.com inurl:?" --dork-output custom_targets.txt
```

---

## WPScan API

### `--wpscan-token`
Token for WPScan API usage in WordPress profiles.

```bash
python waymap.py --target https://example.com --profile wordpress --wpscan-token "TOKEN"
```

---

## WAF Detection

### `--check-waf`
Detect WAF on `--target`.

### `--waf`
Check WAF for a specific URL.

```bash
python waymap.py --target https://example.com --check-waf
python waymap.py --waf https://example.com
```

---

## Reporting

### `--report-format`
Comma-separated formats: `html`, `csv`, `markdown`, `pdf`.

### `--output-dir`
Directory to store reports (default: `reports`).

```bash
python waymap.py --target https://example.com --scan all \
  --report-format html,csv,markdown --output-dir reports
```

---

## Utility & UX

### `--check-updates`
Check for new Waymap versions.

```bash
python waymap.py --check-updates
```

### `--no-prompt`
Disable interactive confirmation prompts.

```bash
python waymap.py --target https://example.com --scan all --no-prompt
```

### `--verbose`, `-v`
Verbose output.

```bash
python waymap.py --target https://example.com --scan recon --verbose
```

---

## Results & Output

- Session data is stored in:
  - `sessions/<domain>/waymap_full_results.json`

---

## Help

```bash
python waymap.py --help
```
