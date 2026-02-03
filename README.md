# SubHunter 🎯
 
 **Fast Subdomain Enumeration Tool v5.0**
 
 ```
 ╔═╗╦ ╦╔╗ ╦ ╦╦ ╦╔╗╔╔╦╗╔═╗╦═╗
 ╚═╗║ ║╠╩╗╠═╣║ ║║║║ ║ ║╣ ╠╦╝
 ╚═╝╚═╝╚═╝╩ ╩╚═╝╝╚╝ ╩ ╚═╝╩╚═  v5.0 PRO
 ```
 
 **Built By:** MIHx0 (Mizaz Haider)  
 **Powered By:** The PenTrix
 
 [![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
 [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
 
 ---
 
 ## ✨ What's New in v5.0
 
 | Feature | Description |
 |---------|-------------|
 | 🎮 **Interactive Mode** | Beautiful TUI menu when run without arguments |
 | 🎯 **Takeover Check** | Detection for 20+ vulnerable cloud services (S3, Heroku, etc.) |
 | 🌐 **VHost Discovery** | Find hidden virtual hosts on shared IPs |
 | 📜 **JS Parsing** | Extract API endpoints and secrets from JavaScript files |
 | 🧠 **Wildcard Detection** | Automatically detect and filter wildcard DNS responses |
 | 🔄 **Recursive Mode** | Discover sub-subdomains (e.g., `dev.api.example.com`) |
 | ☁️ **Cloud Detection** | Identify AWS, Azure, GCP, Cloudflare, and 8 more cloud providers |
 | 📸 **Screenshots** | Capture screenshots (Playwright or Selenium) |
 | 📊 **Pro Reports** | Enhanced HTML reports with new security findings |
 
 ---
 
 ## 📁 Architecture
 
 ```
 subhunter/
 ├── subhunter.py          # Dual-Mode Entry (CLI/TUI)
 ├── sources/              # Passive enumeration
 │   └── passive.py        # 6 sources
 ├── core/                 # Core functionality
 │   ├── dns.py           # DNS resolution
 │   ├── probe.py         # HTTP probing
 │   ├── takeover.py      # Takeover detection (v5.0)
 │   ├── vhost.py         # VHost discovery (v5.0)
 │   ├── jsparse.py       # JS analysis (v5.0)
 │   ├── report.py        # Report generator
 │   └── ...              # Other core modules
 ├── utils/               # Utilities
 │   ├── menu.py          # Interactive TUI (v5.0)
 │   ├── display.py       # Colors & banner
 │   └── config.py        # Constants
 └── reports/             # Auto-saved reports
 ```
 
 ---
 
 ## Installation
 
 ```bash
 git clone https://github.com/mizazhaider-ceh/subhunter.git
 cd subhunter
 pip install -r requirements.txt
 ```

### 📸 Screenshots Setup (Optional)

SubHunter supports **two screenshot engines** with automatic fallback:

**Option 1: Playwright (Recommended)**
```bash
pip install playwright
playwright install chromium
```

**Option 2: Selenium (Fallback)**  
If Playwright fails (e.g., on Python 3.13 due to greenlet incompatibility):
```bash
pip install selenium webdriver-manager
```

> **Note:** SubHunter automatically detects which engine is available.

---

## Usage
 
 ### 🎮 Interactive Mode (NEW)
 Simply run without arguments:
 ```bash
 python subhunter.py
 ```
 
 ### Basic Scan
 ```bash
 python subhunter.py -d example.com
 ```
 
 ### With New Security Features (v5.0)
 ```bash
 # Check for takeovers
 python subhunter.py -d example.com --takeover
 
 # Thorough security audit
 python subhunter.py -d example.com --takeover --vhost --js-parse
 ```
 
 ### With Recursive Discovery
 ```bash
 python subhunter.py -d example.com --recursive
 ```
 
 ### Full Pro Scan
 ```bash
 python subhunter.py -d example.com --recursive --takeover --vhost --js-parse --screenshots
 ```
 
 ### Passive Only
 ```bash
 python subhunter.py -d example.com --no-brute --no-probe
 ```
 
 ### Disable Wildcard Filter
 ```bash
 python subhunter.py -d example.com --no-wildcard-filter
 ```

---

## Options

| Option | Description |
|--------|-------------|
| `-d, --domain` | Target domain (required) |
| `-w, --wordlist` | Custom wordlist file |
| `-o, --output` | Output file (.txt or .json) |
| `--ports` | Enable port scanning |
| `--screenshots` | Capture screenshots |
| `--recursive` | Enable recursive sub-subdomain discovery |
| `--recursive-depth` | Max recursion depth (default: 2) |
| `--no-brute` | Skip DNS brute-forcing |
| `--no-probe` | Skip HTTP probing |
| `--no-wildcard-filter` | Disable wildcard DNS filtering |
| `--resume` | Resume previous scan |
| `-c, --concurrency` | Concurrent queries (default: 100) |
| `-q, --quiet` | Quiet mode |

---

## 🧠 Wildcard Detection

SubHunter automatically detects wildcard DNS by resolving random subdomains. If all random queries return the same IP, it's filtered to avoid false positives.

---

## ☁️ Cloud Providers Detected (11)

| Provider | Detection Method |
|----------|------------------|
| AWS | CNAME, headers, IP ranges |
| Azure | CNAME, headers, IP ranges |
| GCP (Google Cloud) | CNAME, headers, IP ranges |
| Cloudflare | CNAME, headers, CF-Ray |
| DigitalOcean | CNAME, IP ranges |
| Heroku | CNAME |
| Netlify | CNAME, headers |
| Vercel | CNAME, headers |
| Fastly | CNAME, headers |
| Akamai | CNAME |
| GitHub Pages | CNAME |

---

## 🌐 Passive Sources (6)

| Source | Type |
|--------|------|
| crt.sh | Certificate Transparency |
| HackerTarget | DNS Records |
| AlienVault OTX | Threat Intelligence |
| urlscan.io | Web Scans |
| RapidDNS | DNS Database |
| WebArchive | Historical Data |

---

## 🔐 Ports Scanned (17)

```
21 (FTP), 22 (SSH), 23 (Telnet), 25 (SMTP), 53 (DNS), 
80 (HTTP), 110 (POP3), 143 (IMAP), 443 (HTTPS), 
445 (SMB), 993 (IMAPS), 995 (POP3S), 3306 (MySQL), 
3389 (RDP), 5432 (PostgreSQL), 8080, 8443
```

---

## Requirements

| Package | Required | Purpose |
|---------|----------|---------|
| Python 3.8+ | ✅ Yes | Runtime |
| httpx | ✅ Yes | HTTP client |
| aiodns | ✅ Yes | DNS resolution |
| playwright | ⭕ Optional | Screenshots (recommended) |
| selenium | ⭕ Optional | Screenshots (fallback) |

---

## Legal Disclaimer

⚠️ **For authorized testing only.**

---

## License

MIT License

---

**SubHunter v5.0 PRO** - *Hunt them all* 🎯  
Built By: **MIHx0** (Mizaz Haider) | Powered By: **The PenTrix**

---

## 🔮 Roadmap (v6.0+)

Coming soon in the next major release:

- 🛡️ **WAF Detection** (Cloudflare, Akamai, etc.)
- 📧 **Email Harvesting** (Extract contacts from pages)
- 🧬 **Permutation Scanning** (Generate variants like `dev-api`, `v1-test`)
- ...and more!
