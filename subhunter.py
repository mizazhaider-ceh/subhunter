#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║   ███████╗██╗   ██╗██████╗ ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ ║
║   ██╔════╝██║   ██║██╔══██╗██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗║
║   ███████╗██║   ██║██████╔╝███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝║
║   ╚════██║██║   ██║██╔══██╗██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗║
║   ███████║╚██████╔╝██████╔╝██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║║
║   ╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝║
║                                                                               ║
║   Fast Subdomain Enumeration Tool                                   v2.0     ║
║                                                                               ║
║   Built By  : MIHx0 (Mizaz Haider)                                           ║
║   Powered By: The PenTrix                                                    ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝

SubHunter v2.0 - Fast subdomain enumeration with:
- Multiple passive sources (crt.sh, HackerTarget, AlienVault, urlscan.io, etc.)
- HTTP probing with status codes
- Technology detection  
- HTML report generation
- Resume scan capability
- Async DNS brute-forcing

Author: MIHx0 (Mizaz Haider)
Powered By: The PenTrix
License: MIT
"""

import argparse
import asyncio
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Set, List, Optional, Dict, Any
from urllib.parse import urlparse
import warnings
warnings.filterwarnings("ignore")

# Check for required modules
try:
    import httpx
except ImportError:
    print("[-] httpx required: pip install httpx")
    sys.exit(1)

try:
    import aiodns
except ImportError:
    print("[-] aiodns required: pip install aiodns")
    sys.exit(1)

# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

VERSION = "2.0"
STATE_FILE = ".subhunter_state.json"

# Default subdomain wordlist
DEFAULT_WORDLIST = [
    "www", "mail", "ftp", "admin", "blog", "shop", "dev", "staging", "test",
    "api", "app", "m", "mobile", "beta", "portal", "secure", "vpn", "remote",
    "webmail", "email", "smtp", "pop", "imap", "ns1", "ns2", "ns3", "dns",
    "mx", "mx1", "mx2", "cdn", "static", "assets", "img", "images", "media",
    "video", "download", "upload", "files", "backup", "old", "new", "legacy",
    "demo", "stage", "uat", "qa", "prod", "production", "internal", "intranet",
    "extranet", "gateway", "proxy", "firewall", "auth", "login", "sso", "oauth",
    "dashboard", "panel", "control", "cpanel", "whm", "plesk", "admin2",
    "administrator", "manage", "manager", "cms", "wordpress", "wp", "joomla",
    "drupal", "magento", "store", "cart", "checkout", "pay", "payment", "billing",
    "invoice", "order", "orders", "customer", "customers", "client", "clients",
    "support", "help", "helpdesk", "ticket", "tickets", "forum", "community",
    "docs", "documentation", "wiki", "kb", "knowledge", "learn", "training",
    "status", "health", "monitor", "monitoring", "grafana", "prometheus", "kibana",
    "elastic", "elasticsearch", "logstash", "splunk", "jenkins", "ci", "cd",
    "gitlab", "github", "bitbucket", "git", "svn", "repo", "repository",
    "docker", "k8s", "kubernetes", "rancher", "vault", "consul", "terraform",
]

# Technology signatures
TECH_SIGNATURES = {
    "WordPress": [r"wp-content", r"wp-includes", r"wordpress"],
    "Nginx": [r"nginx", r"server: nginx"],
    "Apache": [r"apache", r"server: apache"],
    "Cloudflare": [r"cloudflare", r"cf-ray"],
    "AWS": [r"amazonaws", r"aws", r"x-amz"],
    "Azure": [r"azure", r"microsoft"],
    "React": [r"react", r"__NEXT_DATA__", r"_next"],
    "Vue.js": [r"vue", r"v-app"],
    "Angular": [r"ng-version", r"angular"],
    "Laravel": [r"laravel", r"x-powered-by: laravel"],
    "Django": [r"django", r"csrfmiddlewaretoken"],
    "Node.js": [r"express", r"x-powered-by: express"],
    "PHP": [r"x-powered-by: php", r"\.php"],
    "ASP.NET": [r"asp\.net", r"x-aspnet-version"],
    "jQuery": [r"jquery"],
    "Bootstrap": [r"bootstrap"],
    "Shopify": [r"shopify", r"cdn\.shopify"],
    "Wix": [r"wix\.com", r"wixsite"],
    "Squarespace": [r"squarespace"],
}

# Colors
class Colors:
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'

# ═══════════════════════════════════════════════════════════════════════════════
# SUBDOMAIN SOURCES
# ═══════════════════════════════════════════════════════════════════════════════

async def fetch_crtsh(domain: str) -> Set[str]:
    """Fetch subdomains from crt.sh."""
    subdomains = set()
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        async with httpx.AsyncClient(timeout=30.0, verify=False) as client:
            response = await client.get(url)
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name = entry.get("name_value", "")
                    for sub in name.split("\n"):
                        sub = sub.strip().lower()
                        if sub.endswith(domain) and "*" not in sub:
                            subdomains.add(sub)
    except:
        pass
    return subdomains


async def fetch_hackertarget(domain: str) -> Set[str]:
    """Fetch subdomains from HackerTarget."""
    subdomains = set()
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.get(url)
            if response.status_code == 200 and "error" not in response.text.lower():
                for line in response.text.strip().split("\n"):
                    if "," in line:
                        sub = line.split(",")[0].strip().lower()
                        if sub.endswith(domain):
                            subdomains.add(sub)
    except:
        pass
    return subdomains


async def fetch_alienvault(domain: str) -> Set[str]:
    """Fetch subdomains from AlienVault OTX."""
    subdomains = set()
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.get(url)
            if response.status_code == 200:
                data = response.json()
                for entry in data.get("passive_dns", []):
                    hostname = entry.get("hostname", "").strip().lower()
                    if hostname.endswith(domain):
                        subdomains.add(hostname)
    except:
        pass
    return subdomains


async def fetch_urlscan(domain: str) -> Set[str]:
    """Fetch subdomains from urlscan.io."""
    subdomains = set()
    url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}"
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.get(url)
            if response.status_code == 200:
                data = response.json()
                for result in data.get("results", []):
                    page = result.get("page", {})
                    sub = page.get("domain", "").strip().lower()
                    if sub.endswith(domain):
                        subdomains.add(sub)
    except:
        pass
    return subdomains


async def fetch_rapiddns(domain: str) -> Set[str]:
    """Fetch subdomains from RapidDNS."""
    subdomains = set()
    url = f"https://rapiddns.io/subdomain/{domain}?full=1"
    try:
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
            response = await client.get(url)
            if response.status_code == 200:
                # Extract subdomains from HTML
                pattern = rf'([a-zA-Z0-9][-a-zA-Z0-9]*\.)*{re.escape(domain)}'
                matches = re.findall(pattern, response.text)
                for match in matches:
                    if match:
                        full_match = re.search(rf'[\w.-]+\.{re.escape(domain)}', response.text)
                        if full_match:
                            sub = full_match.group().lower()
                            if sub.endswith(domain):
                                subdomains.add(sub)
    except:
        pass
    return subdomains


async def fetch_webarchive(domain: str) -> Set[str]:
    """Fetch subdomains from Web Archive."""
    subdomains = set()
    url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=txt&fl=original&collapse=urlkey"
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            response = await client.get(url)
            if response.status_code == 200:
                for line in response.text.strip().split("\n")[:500]:  # Limit
                    try:
                        parsed = urlparse(line)
                        if parsed.netloc.endswith(domain):
                            subdomains.add(parsed.netloc.lower())
                    except:
                        pass
    except:
        pass
    return subdomains

# ═══════════════════════════════════════════════════════════════════════════════
# DNS RESOLUTION
# ═══════════════════════════════════════════════════════════════════════════════

async def resolve_subdomain(resolver: aiodns.DNSResolver, subdomain: str) -> Optional[Dict]:
    """Resolve a subdomain."""
    try:
        result = await resolver.query(subdomain, "A")
        ips = [r.host for r in result]
        return {"subdomain": subdomain, "ips": ips}
    except:
        return None


async def bruteforce_subdomains(domain: str, wordlist: List[str], resolver: aiodns.DNSResolver, concurrency: int = 100, quiet: bool = False) -> Set[str]:
    """Brute-force subdomains."""
    found = set()
    semaphore = asyncio.Semaphore(concurrency)
    
    async def check(word: str):
        async with semaphore:
            subdomain = f"{word}.{domain}"
            result = await resolve_subdomain(resolver, subdomain)
            if result:
                found.add(subdomain)
                if not quiet:
                    print(f"  {Colors.GREEN}[+]{Colors.RESET} {subdomain} → {', '.join(result['ips'])}")
    
    tasks = [check(word) for word in wordlist]
    await asyncio.gather(*tasks, return_exceptions=True)
    return found

# ═══════════════════════════════════════════════════════════════════════════════
# HTTP PROBING (NEW in v2.0)
# ═══════════════════════════════════════════════════════════════════════════════

async def probe_http(subdomain: str, timeout: float = 5.0) -> Optional[Dict]:
    """Probe HTTP/HTTPS for a subdomain."""
    result = {"subdomain": subdomain, "alive": False, "url": None, "status": None, "title": None, "tech": [], "server": None}
    
    for protocol in ["https", "http"]:
        url = f"{protocol}://{subdomain}"
        try:
            async with httpx.AsyncClient(timeout=timeout, verify=False, follow_redirects=True) as client:
                response = await client.get(url)
                result["alive"] = True
                result["url"] = str(response.url)
                result["status"] = response.status_code
                result["server"] = response.headers.get("server", "")
                
                # Extract title
                title_match = re.search(r"<title[^>]*>([^<]+)</title>", response.text, re.IGNORECASE)
                if title_match:
                    result["title"] = title_match.group(1).strip()[:80]
                
                # Detect technologies
                content = response.text.lower() + str(response.headers).lower()
                for tech, patterns in TECH_SIGNATURES.items():
                    for pattern in patterns:
                        if re.search(pattern, content, re.IGNORECASE):
                            if tech not in result["tech"]:
                                result["tech"].append(tech)
                            break
                
                return result
        except:
            continue
    
    return result


async def probe_all(subdomains: Set[str], concurrency: int = 50, quiet: bool = False) -> List[Dict]:
    """Probe all subdomains for HTTP."""
    results = []
    semaphore = asyncio.Semaphore(concurrency)
    alive_count = 0
    
    async def probe(sub: str):
        nonlocal alive_count
        async with semaphore:
            result = await probe_http(sub)
            results.append(result)
            if result["alive"]:
                alive_count += 1
                if not quiet:
                    status_color = Colors.GREEN if result["status"] == 200 else Colors.YELLOW
                    tech_str = f" [{', '.join(result['tech'][:3])}]" if result["tech"] else ""
                    print(f"  {Colors.GREEN}●{Colors.RESET} [{status_color}{result['status']}{Colors.RESET}] {result['url']}{Colors.DIM}{tech_str}{Colors.RESET}")
    
    tasks = [probe(sub) for sub in subdomains]
    await asyncio.gather(*tasks, return_exceptions=True)
    return results

# ═══════════════════════════════════════════════════════════════════════════════
# HTML REPORT (NEW in v2.0)
# ═══════════════════════════════════════════════════════════════════════════════

def generate_html_report(domain: str, results: List[Dict], output_path: str):
    """Generate a beautiful HTML report."""
    alive = [r for r in results if r.get("alive")]
    dead = [r for r in results if not r.get("alive")]
    
    # Count technologies
    tech_counts = {}
    for r in alive:
        for tech in r.get("tech", []):
            tech_counts[tech] = tech_counts.get(tech, 0) + 1
    
    # Status code distribution
    status_counts = {}
    for r in alive:
        status = r.get("status", 0)
        status_counts[status] = status_counts.get(status, 0) + 1
    
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SubHunter Report - {domain}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: linear-gradient(135deg, #0f0f23 0%, #1a1a3e 100%); color: #e0e0e0; min-height: 100vh; }}
        .container {{ max-width: 1400px; margin: 0 auto; padding: 20px; }}
        .header {{ text-align: center; padding: 40px 0; border-bottom: 2px solid #00ff88; margin-bottom: 30px; }}
        .header h1 {{ font-size: 3em; color: #00ff88; text-shadow: 0 0 20px rgba(0,255,136,0.5); }}
        .header .domain {{ font-size: 1.5em; color: #888; margin-top: 10px; }}
        .header .meta {{ margin-top: 15px; color: #666; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }}
        .stat-card {{ background: rgba(255,255,255,0.05); border-radius: 15px; padding: 25px; text-align: center; border: 1px solid rgba(255,255,255,0.1); }}
        .stat-card .number {{ font-size: 3em; font-weight: bold; color: #00ff88; }}
        .stat-card .label {{ color: #888; margin-top: 5px; text-transform: uppercase; letter-spacing: 1px; font-size: 0.9em; }}
        .section {{ background: rgba(255,255,255,0.03); border-radius: 15px; padding: 25px; margin-bottom: 25px; border: 1px solid rgba(255,255,255,0.08); }}
        .section h2 {{ color: #00ff88; margin-bottom: 20px; font-size: 1.5em; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ padding: 12px 15px; text-align: left; border-bottom: 1px solid rgba(255,255,255,0.1); }}
        th {{ background: rgba(0,255,136,0.1); color: #00ff88; font-weight: 600; }}
        tr:hover {{ background: rgba(255,255,255,0.03); }}
        .status {{ padding: 4px 12px; border-radius: 20px; font-size: 0.85em; font-weight: 600; }}
        .status-200 {{ background: rgba(0,255,136,0.2); color: #00ff88; }}
        .status-301, .status-302 {{ background: rgba(255,193,7,0.2); color: #ffc107; }}
        .status-403, .status-404 {{ background: rgba(255,82,82,0.2); color: #ff5252; }}
        .tech-badge {{ display: inline-block; padding: 3px 10px; margin: 2px; border-radius: 12px; font-size: 0.8em; background: rgba(100,100,255,0.2); color: #8888ff; }}
        .footer {{ text-align: center; padding: 30px; color: #555; border-top: 1px solid rgba(255,255,255,0.1); margin-top: 30px; }}
        a {{ color: #00ff88; text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
        .chart {{ display: flex; gap: 10px; flex-wrap: wrap; margin-top: 15px; }}
        .chart-bar {{ padding: 8px 15px; border-radius: 8px; background: rgba(0,255,136,0.1); }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🎯 SubHunter Report</h1>
            <div class="domain">{domain}</div>
            <div class="meta">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | v{VERSION}</div>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <div class="number">{len(results)}</div>
                <div class="label">Total Found</div>
            </div>
            <div class="stat-card">
                <div class="number">{len(alive)}</div>
                <div class="label">Alive (HTTP)</div>
            </div>
            <div class="stat-card">
                <div class="number">{len(tech_counts)}</div>
                <div class="label">Technologies</div>
            </div>
            <div class="stat-card">
                <div class="number">{len([r for r in alive if r.get('status') == 200])}</div>
                <div class="label">HTTP 200</div>
            </div>
        </div>
        
        <div class="section">
            <h2>🔧 Technologies Detected</h2>
            <div class="chart">
                {"".join(f'<div class="chart-bar">{tech}: <strong>{count}</strong></div>' for tech, count in sorted(tech_counts.items(), key=lambda x: -x[1]))}
            </div>
        </div>
        
        <div class="section">
            <h2>🌐 Live Subdomains ({len(alive)})</h2>
            <table>
                <thead>
                    <tr>
                        <th>Subdomain</th>
                        <th>Status</th>
                        <th>Title</th>
                        <th>Technologies</th>
                        <th>Server</th>
                    </tr>
                </thead>
                <tbody>
                    {"".join(f'''<tr>
                        <td><a href="{r['url']}" target="_blank">{r['subdomain']}</a></td>
                        <td><span class="status status-{r['status']}">{r['status']}</span></td>
                        <td>{r.get('title', '-') or '-'}</td>
                        <td>{"".join(f'<span class="tech-badge">{t}</span>' for t in r.get('tech', []))}</td>
                        <td>{r.get('server', '-') or '-'}</td>
                    </tr>''' for r in sorted(alive, key=lambda x: x['subdomain']))}
                </tbody>
            </table>
        </div>
        
        <div class="footer">
            <p>Generated by <strong>SubHunter v{VERSION}</strong></p>
            <p>Built By: MIHx0 (Mizaz Haider) | Powered By: The PenTrix</p>
        </div>
    </div>
</body>
</html>"""
    
    Path(output_path).write_text(html, encoding="utf-8")

# ═══════════════════════════════════════════════════════════════════════════════
# RESUME SCAN (NEW in v2.0)
# ═══════════════════════════════════════════════════════════════════════════════

def save_state(domain: str, subdomains: Set[str], phase: str):
    """Save scan state for resume."""
    state = {
        "domain": domain,
        "subdomains": list(subdomains),
        "phase": phase,
        "timestamp": datetime.now().isoformat()
    }
    Path(STATE_FILE).write_text(json.dumps(state, indent=2))


def load_state() -> Optional[Dict]:
    """Load previous scan state."""
    if Path(STATE_FILE).exists():
        return json.loads(Path(STATE_FILE).read_text())
    return None


def clear_state():
    """Clear saved state."""
    if Path(STATE_FILE).exists():
        Path(STATE_FILE).unlink()

# ═══════════════════════════════════════════════════════════════════════════════
# BANNER
# ═══════════════════════════════════════════════════════════════════════════════

def print_banner():
    """Print the tool banner."""
    print(f"""
{Colors.CYAN}
    ╔═╗╦ ╦╔╗ ╦ ╦╦ ╦╔╗╔╔╦╗╔═╗╦═╗
    ╚═╗║ ║╠╩╗╠═╣║ ║║║║ ║ ║╣ ╠╦╝
    ╚═╝╚═╝╚═╝╩ ╩╚═╝╝╚╝ ╩ ╚═╝╩╚═  {Colors.YELLOW}v{VERSION}{Colors.CYAN}
{Colors.RESET}
    {Colors.GREEN}▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓{Colors.RESET}
    {Colors.GREEN}▓{Colors.RESET}  {Colors.BOLD}Fast Subdomain Enumeration Tool{Colors.RESET}               {Colors.GREEN}▓{Colors.RESET}
    {Colors.GREEN}▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓{Colors.RESET}
    {Colors.GREEN}▓{Colors.RESET}                                                {Colors.GREEN}▓{Colors.RESET}
    {Colors.GREEN}▓{Colors.RESET}   {Colors.MAGENTA}◆ Built By  :{Colors.RESET} {Colors.BOLD}MIHx0{Colors.RESET} (Mizaz Haider)           {Colors.GREEN}▓{Colors.RESET}
    {Colors.GREEN}▓{Colors.RESET}   {Colors.MAGENTA}◆ Powered By:{Colors.RESET} {Colors.BOLD}The PenTrix{Colors.RESET}                    {Colors.GREEN}▓{Colors.RESET}
    {Colors.GREEN}▓{Colors.RESET}                                                {Colors.GREEN}▓{Colors.RESET}
    {Colors.GREEN}▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓{Colors.RESET}
    
    {Colors.DIM}[ crt.sh • AlienVault • HackerTarget • urlscan • RapidDNS • WebArchive ]{Colors.RESET}
""")

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN HUNT
# ═══════════════════════════════════════════════════════════════════════════════

async def hunt(
    domain: str,
    wordlist_path: Optional[str] = None,
    bruteforce: bool = True,
    output: Optional[str] = None,
    probe: bool = True,
    concurrency: int = 100,
    quiet: bool = False,
    resume: bool = False,
    html_report: Optional[str] = None
) -> Set[str]:
    """Main hunting function."""
    
    all_subdomains: Set[str] = set()
    resolver = aiodns.DNSResolver()
    
    # Check for resume
    if resume:
        state = load_state()
        if state and state["domain"] == domain:
            all_subdomains = set(state["subdomains"])
            if not quiet:
                print(f"\n{Colors.YELLOW}[*] Resuming scan with {len(all_subdomains)} subdomains{Colors.RESET}")
    
    # ─────────────────────────────────────────────────────────────────────────
    # Phase 1: Passive Enumeration
    # ─────────────────────────────────────────────────────────────────────────
    if not resume or not all_subdomains:
        if not quiet:
            print(f"\n{Colors.YELLOW}[*] Phase 1: Passive Enumeration{Colors.RESET}")
            print(f"{Colors.DIM}    Querying 6 sources...{Colors.RESET}\n")
        
        sources = await asyncio.gather(
            fetch_crtsh(domain),
            fetch_hackertarget(domain),
            fetch_alienvault(domain),
            fetch_urlscan(domain),
            fetch_rapiddns(domain),
            fetch_webarchive(domain),
            return_exceptions=True
        )
        
        source_names = ["crt.sh", "HackerTarget", "AlienVault", "urlscan.io", "RapidDNS", "WebArchive"]
        
        for i, result in enumerate(sources):
            if isinstance(result, set):
                count = len(result)
                all_subdomains.update(result)
                if not quiet:
                    print(f"  {Colors.BLUE}[+]{Colors.RESET} {source_names[i]}: {count} subdomains")
        
        if not quiet:
            print(f"\n  {Colors.GREEN}Total from passive: {len(all_subdomains)}{Colors.RESET}")
        
        save_state(domain, all_subdomains, "passive")
    
    # ─────────────────────────────────────────────────────────────────────────
    # Phase 2: DNS Brute-forcing
    # ─────────────────────────────────────────────────────────────────────────
    if bruteforce:
        if not quiet:
            print(f"\n{Colors.YELLOW}[*] Phase 2: DNS Brute-forcing{Colors.RESET}")
        
        if wordlist_path and Path(wordlist_path).exists():
            wordlist = Path(wordlist_path).read_text().strip().split("\n")
        else:
            wordlist = DEFAULT_WORDLIST
        
        if not quiet:
            print(f"{Colors.DIM}    Using {len(wordlist)} words{Colors.RESET}\n")
        
        brute_found = await bruteforce_subdomains(domain, wordlist, resolver, concurrency, quiet)
        all_subdomains.update(brute_found)
        
        if not quiet:
            print(f"\n  {Colors.GREEN}Total from brute-force: {len(brute_found)}{Colors.RESET}")
        
        save_state(domain, all_subdomains, "bruteforce")
    
    # ─────────────────────────────────────────────────────────────────────────
    # Phase 3: HTTP Probing + Tech Detection
    # ─────────────────────────────────────────────────────────────────────────
    probe_results = []
    if probe and all_subdomains:
        if not quiet:
            print(f"\n{Colors.YELLOW}[*] Phase 3: HTTP Probing & Tech Detection{Colors.RESET}")
            print(f"{Colors.DIM}    Probing {len(all_subdomains)} subdomains...{Colors.RESET}\n")
        
        probe_results = await probe_all(all_subdomains, min(concurrency, 50), quiet)
        alive = [r for r in probe_results if r["alive"]]
        
        if not quiet:
            print(f"\n  {Colors.GREEN}Alive: {len(alive)} / {len(all_subdomains)}{Colors.RESET}")
    
    # ─────────────────────────────────────────────────────────────────────────
    # Output
    # ─────────────────────────────────────────────────────────────────────────
    if output:
        if output.endswith(".json"):
            data = {
                "domain": domain,
                "timestamp": datetime.now().isoformat(),
                "version": VERSION,
                "total": len(all_subdomains),
                "subdomains": sorted(list(all_subdomains)),
                "probed": probe_results if probe else []
            }
            Path(output).write_text(json.dumps(data, indent=2))
        else:
            Path(output).write_text("\n".join(sorted(all_subdomains)))
        
        if not quiet:
            print(f"\n{Colors.GREEN}[+] Results saved to: {output}{Colors.RESET}")
    
    # HTML Report
    if html_report and probe_results:
        generate_html_report(domain, probe_results, html_report)
        if not quiet:
            print(f"{Colors.GREEN}[+] HTML report saved to: {html_report}{Colors.RESET}")
    
    # Summary
    if not quiet:
        print(f"\n{Colors.CYAN}{'═' * 60}{Colors.RESET}")
        print(f"{Colors.BOLD}SUMMARY{Colors.RESET}")
        print(f"  Domain: {domain}")
        print(f"  Total Subdomains: {len(all_subdomains)}")
        if probe_results:
            alive = [r for r in probe_results if r["alive"]]
            print(f"  Alive (HTTP): {len(alive)}")
        print(f"{Colors.CYAN}{'═' * 60}{Colors.RESET}\n")
    
    clear_state()
    return all_subdomains

# ═══════════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description=f"SubHunter v{VERSION} - Fast Subdomain Enumeration Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python subhunter.py -d example.com
  python subhunter.py -d example.com --probe
  python subhunter.py -d example.com --html report.html
  python subhunter.py -d example.com --resume
        """
    )
    
    parser.add_argument("-d", "--domain", required=True, help="Target domain")
    parser.add_argument("-w", "--wordlist", help="Custom wordlist")
    parser.add_argument("-o", "--output", help="Output file (.txt or .json)")
    parser.add_argument("--html", help="Generate HTML report")
    parser.add_argument("--no-brute", action="store_true", help="Skip brute-forcing")
    parser.add_argument("--no-probe", action="store_true", help="Skip HTTP probing")
    parser.add_argument("--resume", action="store_true", help="Resume previous scan")
    parser.add_argument("-c", "--concurrency", type=int, default=100, help="Concurrency (default: 100)")
    parser.add_argument("-q", "--quiet", action="store_true", help="Quiet mode")
    
    args = parser.parse_args()
    
    domain = args.domain.lower().strip()
    if domain.startswith(("http://", "https://")):
        domain = urlparse(domain).netloc
    domain = domain.rstrip("/")
    
    if not args.quiet:
        print_banner()
        print(f"{Colors.BOLD}Target:{Colors.RESET} {domain}")
        print(f"{Colors.DIM}Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.RESET}")
    
    try:
        asyncio.run(hunt(
            domain=domain,
            wordlist_path=args.wordlist,
            bruteforce=not args.no_brute,
            output=args.output,
            probe=not args.no_probe,
            concurrency=args.concurrency,
            quiet=args.quiet,
            resume=args.resume,
            html_report=args.html
        ))
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Interrupted - state saved for resume{Colors.RESET}")
        sys.exit(1)


if __name__ == "__main__":
    main()
