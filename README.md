# SubHunter 🎯

**Fast Subdomain Enumeration Tool v4.0 PRO**

```
╔═╗╦ ╦╔╗ ╦ ╦╦ ╦╔╗╔╔╦╗╔═╗╦═╗
╚═╗║ ║╠╩╗╠═╣║ ║║║║ ║ ║╣ ╠╦╝
╚═╝╚═╝╚═╝╩ ╩╚═╝╝╚╝ ╩ ╚═╝╩╚═  v4.0 PRO
```

**Built By:** MIHx0 (Mizaz Haider)  
**Powered By:** The PenTrix

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## ✨ What's New in v4.0 PRO

| Feature | Description |
|---------|-------------|
| 🧠 **Wildcard Detection** | Automatically detect and filter wildcard DNS responses |
| 🔄 **Recursive Mode** | Discover sub-subdomains (e.g., `dev.api.example.com`) |
| ☁️ **Cloud Detection** | Identify AWS, Azure, GCP, Cloudflare, and 8 more cloud providers |
| 🔐 **Port Scanning** | Scan 17 common ports on discovered subdomains |
| 📸 **Screenshots** | Capture screenshots (Playwright or Selenium) |
| 📊 **Pro Reports** | Beautiful HTML reports with cloud distribution charts |

---

## 📁 Architecture

```
subhunter/
├── subhunter.py          # CLI entry point
├── sources/              # Passive enumeration
│   └── passive.py        # 6 sources
├── core/                 # Core functionality
│   ├── dns.py           # DNS resolution, brute-force & recursive
│   ├── probe.py         # HTTP probing, tech & cloud detection
│   ├── scanner.py       # Port scanning
│   ├── screenshot.py    # Screenshot capture
│   ├── report.py        # HTML report generator
│   ├── wildcard.py      # Wildcard DNS detection (v4.0)
│   └── cloud.py         # Cloud provider detection (v4.0)
├── utils/               # Utilities
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

### Basic Scan
```bash
python subhunter.py -d example.com
```

### With Recursive Discovery (v4.0)
```bash
python subhunter.py -d example.com --recursive
python subhunter.py -d example.com --recursive --recursive-depth 3
```

### With Port Scanning
```bash
python subhunter.py -d example.com --ports
```

### With Screenshots
```bash
python subhunter.py -d example.com --screenshots
```

### Full Pro Scan
```bash
python subhunter.py -d example.com --recursive --ports --screenshots
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

**SubHunter v4.0 PRO** - *Hunt them all* 🎯  
Built By: **MIHx0** (Mizaz Haider) | Powered By: **The PenTrix**
