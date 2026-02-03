# SubHunter 🎯

**Fast Subdomain Enumeration Tool v3.0**

```
╔═╗╦ ╦╔╗ ╦ ╦╦ ╦╔╗╔╔╦╗╔═╗╦═╗
╚═╗║ ║╠╩╗╠═╣║ ║║║║ ║ ║╣ ╠╦╝
╚═╝╚═╝╚═╝╩ ╩╚═╝╝╚╝ ╩ ╚═╝╩╚═  v3.0
```

**Built By:** MIHx0 (Mizaz Haider)  
**Powered By:** The PenTrix

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## ✨ What's New in v3.0

### Modular Architecture
```
subhunter/
├── subhunter.py          # CLI entry point
├── sources/              # Passive enumeration
│   └── passive.py        # 6 sources
├── core/                 # Core functionality
│   ├── dns.py           # DNS resolution & brute-force
│   ├── probe.py         # HTTP probing & tech detection
│   ├── scanner.py       # Port scanning
│   ├── screenshot.py    # Screenshot capture
│   └── report.py        # HTML report generator
├── utils/               # Utilities
│   ├── display.py       # Colors & banner
│   └── config.py        # Constants
└── reports/             # Auto-saved reports
```

### New Features

| Feature | Description |
|---------|-------------|
| 🔐 **Port Scanning** | Scan 17 common ports on discovered subdomains |
| 📸 **Screenshots** | Capture screenshots of live web hosts |
| 📊 **Auto Reports** | Reports auto-save to `reports/` with date + domain |
| 🏗️ **Modular** | Clean, maintainable code structure |

---

## Installation

```bash
git clone https://github.com/mizazhaider-ceh/subhunter.git
cd subhunter
pip install -r requirements.txt

# Optional: For screenshots
pip install playwright
playwright install chromium
```

---

## Usage

### Basic Scan (Auto-saves HTML report)
```bash
python subhunter.py -d example.com
```

### With Port Scanning
```bash
python subhunter.py -d example.com --ports
```

### With Screenshots
```bash
python subhunter.py -d example.com --screenshots
```

### Full Scan (All features)
```bash
python subhunter.py -d example.com --ports --screenshots
```

### Passive Only (No brute-force, no probe)
```bash
python subhunter.py -d example.com --no-brute --no-probe
```

### Resume Interrupted Scan
```bash
python subhunter.py -d example.com --resume
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
| `--no-brute` | Skip DNS brute-forcing |
| `--no-probe` | Skip HTTP probing |
| `--resume` | Resume previous scan |
| `-c, --concurrency` | Concurrent queries (default: 100) |
| `-q, --quiet` | Quiet mode |

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

## 📊 Report Auto-Save

Reports automatically save to `reports/` folder:
```
reports/
├── example.com_20240203_120000.html
├── hackerone.com_20240203_130000.html
└── target.com_screenshots/
    ├── www.target.com.png
    └── api.target.com.png
```

---

## Example Output

```
    ╔═╗╦ ╦╔╗ ╦ ╦╦ ╦╔╗╔╔╦╗╔═╗╦═╗
    ╚═╗║ ║╠╩╗╠═╣║ ║║║║ ║ ║╣ ╠╦╝
    ╚═╝╚═╝╚═╝╩ ╩╚═╝╝╚╝ ╩ ╚═╝╩╚═  v3.0

Target: hackerone.com

[*] Phase 1: Passive Enumeration
  [+] crt.sh: 156 subdomains
  [+] AlienVault: 45 subdomains
  Total from passive: 234

[*] Phase 2: DNS Brute-forcing
  [+] api.hackerone.com → 104.16.99.52
  Total from brute-force: 15

[*] Phase 3: HTTP Probing & Tech Detection
  ● [200] https://www.hackerone.com [Cloudflare, React]
  Alive: 187 / 249

[*] Phase 4: Port Scanning
  ● hackerone.com: 80, 443
  Hosts with open ports: 45

[+] HTML report saved to: reports/hackerone.com_20240203_120000.html

═════════════════════════════════════════════════════════════════
SUMMARY
  Domain: hackerone.com
  Total Subdomains: 249
  Alive (HTTP): 187
  Hosts with open ports: 45
═════════════════════════════════════════════════════════════════
```

---

## Requirements

- Python 3.8+
- httpx
- aiodns
- playwright (optional, for screenshots)

---

## Legal Disclaimer

⚠️ **For authorized testing only.**

---

## License

MIT License

---

**SubHunter v3.0** - *Hunt them all* 🎯  
Built By: **MIHx0** (Mizaz Haider) | Powered By: **The PenTrix**
