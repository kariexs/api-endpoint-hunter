# AI-Powered API Endpoint Hunter

![Python](https://img.shields.io/badge/python-3.9%2B-blue?style=flat-square)
![Asyncio](https://img.shields.io/badge/asyncio-aiohttp-green?style=flat-square)
![Bug Bounty](https://img.shields.io/badge/BugBounty-Ready-orange?style=flat-square)

> **Smart API endpoint and sensitive path discovery tool for bug bounty, penetration testing, and security research.**  
> Deeply analyzes JavaScript, open directories, robots.txt, sitemaps, OpenAPI/Swagger, and brute-forces critical paths—all with colored console output and multiple export formats.

---

## 🚩 Overview

**AI-Powered API Endpoint Hunter** is a modern, context-aware endpoint enumeration tool that simulates the deep-dive techniques used by experienced bug bounty hunters and professional pentesters.

It scans a target website for exposed API endpoints and sensitive files by:
- Parsing external and inline JavaScript,
- Checking robots.txt and sitemap.xml,
- Detecting and parsing OpenAPI/Swagger definitions,
- Brute-forcing dozens of high-risk admin/config/debug files,
- Contextual filtering to reduce false positives,
- Reporting status codes and endpoint parameters.

The tool is asynchronous, fast, export-friendly, and ready for use in real-world bounty and assessment workflows.

---

## ✨ Features

- **Deep JavaScript Parsing:** Detects fetch, axios, jQuery, XHR, $http, and template literal endpoint usage, even in modern SPA frameworks.
- **Contextual API Filtering:** Prioritizes endpoints with API/auth-related keywords and interesting parameters.
- **Sensitive Path Bruteforce:** Tests dozens of common risky files (admin panels, configs, .env, .git, .well-known, backup, logs, etc.)
- **robots.txt and sitemap.xml Integration:** Extracts any hidden or restricted files/paths.
- **OpenAPI/Swagger/REST Discovery:** Auto-detects and parses `/swagger.json`, `/openapi.json` for extra endpoints.
- **Parameter Awareness:** Flags endpoints with sensitive parameters (tokens, keys, session, etc).
- **False Positive/Negative Filtering:** Smarter output, less noise.
- **Colored, Bounty-Style Output:** See at a glance which endpoints are live, forbidden, or interesting.
- **Export to TXT, CSV, or PDF:** For reports, Burp/ZAP import, or sharing with teams.
- **Highly Customizable:** Selective output by status code, custom headers, method, concurrency, timeouts, delay, etc.
- **Pure Python, Well-Documented:** Clean, professional, production-ready code.
- **No external dependencies except `aiohttp`, `beautifulsoup4`, `fpdf` (for PDF export only).**

---

## 🛠 Installation

1. **Python 3.9 or newer is required.**
2. Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```

---

## 🎛️ Command Line Arguments (All Long-form, Explicit)

| Argument                    | Description |
|-----------------------------|-------------|
| `target`                    | The target URL to scan. **(Required)**<br>Example: `https://example.com` |
| `--output`                  | Output file path. The file extension determines the format: `.txt`, `.csv`, or `.pdf`.<br>Default: `hunter_out.txt` |
| `--output-code`             | Only endpoints with these HTTP status codes will be saved to the output file.<br>Example: `--output-code 200 403` |
| `--output-not-code`         | Endpoints with these HTTP status codes will NOT be saved to the output file.<br>Example: `--output-not-code 404 301` |
| `--console-block-code`      | These HTTP status codes will not appear in the console output.<br>Example: `--console-block-code 404` |
| `--header`                  | Add custom HTTP headers for endpoint status checks.<br>Example: `--header "Authorization: Bearer ..." "X-Api-Key: key"` |
| `--http-method`             | HTTP method used for endpoint checks (GET, POST, etc).<br>Default: `GET` |
| `--timeout`                 | Timeout (in seconds) for each HTTP request.<br>Default: `7` |
| `--delay`                   | Delay (in seconds) between endpoint requests.<br>Default: `0` |
| `--max-concurrency`         | Maximum number of concurrent endpoint requests.<br>Default: `10` |

---

## 🚀 Usage Examples

### **Basic Scan and Save Results as TXT**

```bash
python api-endpoint-hunter.py https://target.com --output endpoints.txt
```

## TUTORIAL Only Save 200 and 403 Endpoints, Exclude 404 from Console and File

python api-endpoint-hunter.py https://target.com \
  --output endpoints.csv \
  --output-code 200 403 \
  --output-not-code 404 \
  --console-block-code 404


## TUTORIAL Add Custom Headers and Use POST Method

python api-endpoint-hunter.py https://target.com \
  --header "Authorization: Bearer supersecrettoken" \
  --http-method POST


## TUTORIAL Advanced: PDF Export, Delay and Concurrency Tuning

python api-endpoint-hunter.py https://target.com \
  --output report.pdf \
  --timeout 6 \
  --delay 0.3 \
  --max-concurrency 4


## 🦠 Burp Suite/OWASP ZAP Integration
Export as CSV with --output endpoints.csv

Import endpoints into Burp/ZAP as active scan targets.

Example CSV (see /examples/burp-example.csv):

url,status,reason,params,sensitive
https://target.com/api/login,200,OK,"{'user':'admin'}",False
https://target.com/admin/config,403,Forbidden,{},True


📄 License
MIT License

