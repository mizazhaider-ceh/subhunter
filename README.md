# SubHunter 🎯

**Fast Subdomain Enumeration Tool**

```
███████╗██╗   ██╗██████╗ ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ 
██╔════╝██║   ██║██╔══██╗██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
███████╗██║   ██║██████╔╝███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
╚════██║██║   ██║██╔══██╗██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
███████║╚██████╔╝██████╔╝██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
```

**Built By:** MIHx0 (Mizaz Haider)  
**Powered By:** The PenTrix

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## Features

- **Passive Enumeration** - Multiple sources (no detection)
  - Certificate Transparency (crt.sh)
  - HackerTarget API
  - ThreatCrowd API
  - urlscan.io
  
- **DNS Brute-forcing** - Built-in 100+ word list or custom
- **Async Resolution** - 100+ concurrent DNS queries
- **Multiple Output Formats** - TXT, JSON
- **Single Script** - No complex setup

---

## Installation

```bash
git clone https://github.com/YOUR-USERNAME/subhunter.git
cd subhunter
pip install -r requirements.txt
```

---

## Usage

### Basic Scan
```bash
python subhunter.py -d example.com
```

### With Custom Wordlist
```bash
python subhunter.py -d example.com -w wordlist.txt
```

### Passive Only (No Brute-force)
```bash
python subhunter.py -d example.com --no-brute
```

### Save Results
```bash
python subhunter.py -d example.com -o results.txt
python subhunter.py -d example.com -o results.json
```

### Quiet Mode (Only Subdomains)
```bash
python subhunter.py -d example.com -q
```

### High Concurrency
```bash
python subhunter.py -d example.com -c 200
```

---

## Options

| Option | Description |
|--------|-------------|
| `-d, --domain` | Target domain (required) |
| `-w, --wordlist` | Custom wordlist file |
| `-o, --output` | Output file (.txt or .json) |
| `--no-brute` | Skip DNS brute-forcing |
| `--no-resolve` | Skip DNS resolution |
| `-c, --concurrency` | Concurrent queries (default: 100) |
| `-q, --quiet` | Quiet mode - only output subdomains |

---

## Example Output

```
╔═══════════════════════════════════════════════════════════════╗
║ SubHunter - Fast Subdomain Enumeration              v1.0 ║
╚═══════════════════════════════════════════════════════════════╝

Target: example.com
Started: 2024-02-03 12:00:00

[*] Phase 1: Passive Enumeration
    Querying certificate transparency logs and APIs...

  [+] crt.sh: 45 subdomains
  [+] HackerTarget: 12 subdomains
  [+] ThreatCrowd: 8 subdomains
  [+] urlscan.io: 23 subdomains

  Total from passive: 67

[*] Phase 2: DNS Brute-forcing
    Using built-in wordlist (100 words)

  [+] www.example.com → 93.184.216.34
  [+] mail.example.com → 93.184.216.35
  [+] api.example.com → 93.184.216.36

  Total from brute-force: 3

═════════════════════════════════════════════════════════════════
SUMMARY
  Domain: example.com
  Total Subdomains: 70
═════════════════════════════════════════════════════════════════
```

---

## Data Sources

| Source | Type | Rate Limit |
|--------|------|------------|
| crt.sh | Certificate Transparency | None |
| HackerTarget | DNS Records | 100/day (free) |
| ThreatCrowd | Threat Intelligence | None |
| urlscan.io | Web Scans | None |

---

## Requirements

- Python 3.8+
- httpx
- aiodns

---

## Legal Disclaimer

⚠️ **For authorized testing only.**

This tool is designed for security professionals with proper authorization. Always ensure you have permission before scanning any domain.

---

## License

MIT License - See [LICENSE](LICENSE) for details.

---

**SubHunter v1.0** - *Hunt them all* 🎯
