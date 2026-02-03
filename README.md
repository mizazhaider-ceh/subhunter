# SubHunter 🎯

**Fast Subdomain Enumeration Tool v2.0**

```
╔═╗╦ ╦╔╗ ╦ ╦╦ ╦╔╗╔╔╦╗╔═╗╦═╗
╚═╗║ ║╠╩╗╠═╣║ ║║║║ ║ ║╣ ╠╦╝
╚═╝╚═╝╚═╝╩ ╩╚═╝╝╚╝ ╩ ╚═╝╩╚═  v2.0
```

**Built By:** MIHx0 (Mizaz Haider)  
**Powered By:** The PenTrix

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## ✨ What's New in v2.0

| Feature | Description |
|---------|-------------|
| 🌐 **6 Passive Sources** | crt.sh, HackerTarget, AlienVault, urlscan.io, RapidDNS, WebArchive |
| 🔍 **HTTP Probing** | Check which subdomains are alive with status codes |
| 🏷️ **Tech Detection** | Detect 19+ technologies (WordPress, React, Nginx, AWS, etc.) |
| 📊 **HTML Reports** | Beautiful, dark-themed reports with charts |
| 📁 **Resume Scan** | Interrupt and resume scans anytime |

---

## Installation

```bash
git clone https://github.com/mizazhaider-ceh/subhunter.git
cd subhunter
pip install -r requirements.txt
```

---

## Usage

### Basic Scan
```bash
python subhunter.py -d example.com
```

### With HTTP Probing (Default in v2.0)
```bash
python subhunter.py -d example.com
```

### Generate HTML Report
```bash
python subhunter.py -d example.com --html report.html
```

### Passive Only (No Brute-force, No Probing)
```bash
python subhunter.py -d example.com --no-brute --no-probe
```

### Resume Interrupted Scan
```bash
python subhunter.py -d example.com --resume
```

### Save to JSON
```bash
python subhunter.py -d example.com -o results.json
```

### Custom Wordlist
```bash
python subhunter.py -d example.com -w /path/to/wordlist.txt
```

---

## Options

| Option | Description |
|--------|-------------|
| `-d, --domain` | Target domain (required) |
| `-w, --wordlist` | Custom wordlist file |
| `-o, --output` | Output file (.txt or .json) |
| `--html` | Generate HTML report |
| `--no-brute` | Skip DNS brute-forcing |
| `--no-probe` | Skip HTTP probing |
| `--resume` | Resume previous scan |
| `-c, --concurrency` | Concurrent queries (default: 100) |
| `-q, --quiet` | Quiet mode |

---

## 🌐 Passive Sources

| Source | Type |
|--------|------|
| crt.sh | Certificate Transparency |
| HackerTarget | DNS Records |
| AlienVault OTX | Threat Intelligence |
| urlscan.io | Web Scans |
| RapidDNS | DNS Database |
| WebArchive | Historical Data |

---

## 🏷️ Technologies Detected

WordPress, Nginx, Apache, Cloudflare, AWS, Azure, React, Vue.js, Angular, Laravel, Django, Node.js, PHP, ASP.NET, jQuery, Bootstrap, Shopify, Wix, Squarespace

---

## 📊 HTML Report Preview

The HTML report includes:
- Total subdomains found
- Alive vs dead count
- Technology distribution chart
- Status code breakdown
- Sortable results table
- Dark theme design

---

## Example Output

```
    ╔═╗╦ ╦╔╗ ╦ ╦╦ ╦╔╗╔╔╦╗╔═╗╦═╗
    ╚═╗║ ║╠╩╗╠═╣║ ║║║║ ║ ║╣ ╠╦╝
    ╚═╝╚═╝╚═╝╩ ╩╚═╝╝╚╝ ╩ ╚═╝╩╚═  v2.0

Target: hackerone.com
Started: 2024-02-03 12:00:00

[*] Phase 1: Passive Enumeration
    Querying 6 sources...

  [+] crt.sh: 156 subdomains
  [+] HackerTarget: 23 subdomains
  [+] AlienVault: 45 subdomains
  [+] urlscan.io: 67 subdomains
  [+] RapidDNS: 12 subdomains
  [+] WebArchive: 89 subdomains

  Total from passive: 234

[*] Phase 2: DNS Brute-forcing
    Using 75 words

  [+] api.hackerone.com → 104.16.99.52
  [+] docs.hackerone.com → 104.16.100.52

  Total from brute-force: 15

[*] Phase 3: HTTP Probing & Tech Detection
    Probing 249 subdomains...

  ● [200] https://www.hackerone.com [Cloudflare, React]
  ● [200] https://api.hackerone.com [Nginx]
  ● [301] https://docs.hackerone.com [Cloudflare]

  Alive: 187 / 249

═════════════════════════════════════════════════════════════════
SUMMARY
  Domain: hackerone.com
  Total Subdomains: 249
  Alive (HTTP): 187
═════════════════════════════════════════════════════════════════
```

---

## Requirements

- Python 3.8+
- httpx
- aiodns

---

## Legal Disclaimer

⚠️ **For authorized testing only.**

This tool is intended for security professionals with proper authorization. Always ensure you have permission before scanning any domain.

---

## License

MIT License - See [LICENSE](LICENSE) for details.

---

**SubHunter v2.0** - *Hunt them all* 🎯  
Built By: **MIHx0** (Mizaz Haider) | Powered By: **The PenTrix**
