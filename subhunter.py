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
║   Fast Subdomain Enumeration Tool                                   v1.0     ║
║                                                                               ║
║   Built By  : MIHx0 (M zaz Haider)                                           ║
║   Powered By: The PenTrix                                                    ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝

SubHunter - Fast subdomain enumeration using multiple sources:
- Certificate Transparency (crt.sh)
- DNS brute-forcing with wordlists
- Async resolution for speed

Author: MIHx0 (Mizaz Haider)
Powered By: The PenTrix
License: MIT
"""

import argparse
import asyncio
import json
import socket
import ssl
import sys
from datetime import datetime
from pathlib import Path
from typing import Set, List, Optional
from urllib.parse import urlparse

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

# Default subdomain wordlist (common subdomains)
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
    "aws", "azure", "gcp", "cloud", "s3", "storage", "db", "database", "mysql",
    "postgres", "postgresql", "mongo", "mongodb", "redis", "memcached", "cache",
    "queue", "rabbitmq", "kafka", "activemq", "mq", "analytics", "tracking",
    "metrics", "stats", "statistics", "report", "reports", "crm", "erp", "hr",
    "finance", "accounting", "sales", "marketing", "news", "press", "events",
    "calendar", "booking", "reservation", "hotel", "travel", "careers", "jobs",
    "about", "contact", "info", "legal", "privacy", "terms", "sitemap", "rss",
    "feed", "atom", "xml", "json", "graphql", "rest", "soap", "websocket", "ws",
    "wss", "socket", "io", "realtime", "live", "stream", "streaming", "rtmp",
    "hls", "dash", "video", "audio", "music", "podcast", "radio", "tv",
    "game", "games", "gaming", "play", "player", "chat", "messaging", "im",
    "slack", "teams", "zoom", "meet", "conference", "webinar", "call", "voice",
    "sip", "voip", "pbx", "asterisk", "freeswitch", "twilio", "plivo",
]

# Colors for terminal output
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
    """Fetch subdomains from crt.sh (Certificate Transparency logs)."""
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
    except Exception as e:
        print(f"{Colors.DIM}[!] crt.sh error: {e}{Colors.RESET}")
    
    return subdomains


async def fetch_hackertarget(domain: str) -> Set[str]:
    """Fetch subdomains from HackerTarget API."""
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
    except Exception as e:
        print(f"{Colors.DIM}[!] HackerTarget error: {e}{Colors.RESET}")
    
    return subdomains


async def fetch_threatcrowd(domain: str) -> Set[str]:
    """Fetch subdomains from ThreatCrowd API."""
    subdomains = set()
    url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}"
    
    try:
        async with httpx.AsyncClient(timeout=15.0, verify=False) as client:
            response = await client.get(url)
            if response.status_code == 200:
                data = response.json()
                for sub in data.get("subdomains", []):
                    sub = sub.strip().lower()
                    if sub.endswith(domain):
                        subdomains.add(sub)
    except Exception as e:
        pass  # Silently skip - ThreatCrowd often has SSL issues
    
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
    except Exception as e:
        print(f"{Colors.DIM}[!] urlscan.io error: {e}{Colors.RESET}")
    
    return subdomains

# ═══════════════════════════════════════════════════════════════════════════════
# DNS RESOLUTION
# ═══════════════════════════════════════════════════════════════════════════════

async def resolve_subdomain(resolver: aiodns.DNSResolver, subdomain: str) -> Optional[dict]:
    """Resolve a single subdomain and return its details."""
    try:
        result = await resolver.query(subdomain, "A")
        ips = [r.host for r in result]
        return {
            "subdomain": subdomain,
            "ips": ips,
            "status": "alive"
        }
    except aiodns.error.DNSError:
        return None
    except Exception:
        return None


async def bruteforce_subdomains(
    domain: str,
    wordlist: List[str],
    resolver: aiodns.DNSResolver,
    concurrency: int = 100
) -> Set[str]:
    """Brute-force subdomains using wordlist."""
    found = set()
    semaphore = asyncio.Semaphore(concurrency)
    
    async def check(word: str):
        async with semaphore:
            subdomain = f"{word}.{domain}"
            result = await resolve_subdomain(resolver, subdomain)
            if result:
                found.add(subdomain)
                print(f"  {Colors.GREEN}[+]{Colors.RESET} {subdomain} → {', '.join(result['ips'])}")
    
    # Create tasks
    tasks = [check(word) for word in wordlist]
    await asyncio.gather(*tasks, return_exceptions=True)
    
    return found


async def resolve_all(
    subdomains: Set[str],
    resolver: aiodns.DNSResolver,
    concurrency: int = 100
) -> List[dict]:
    """Resolve all discovered subdomains."""
    results = []
    semaphore = asyncio.Semaphore(concurrency)
    
    async def resolve(sub: str):
        async with semaphore:
            result = await resolve_subdomain(resolver, sub)
            if result:
                results.append(result)
    
    tasks = [resolve(sub) for sub in subdomains]
    await asyncio.gather(*tasks, return_exceptions=True)
    
    return results

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN HUNTER
# ═══════════════════════════════════════════════════════════════════════════════

def print_banner():
    """Print the tool banner."""
    print(f"""
{Colors.CYAN}
    ╔═╗╦ ╦╔╗ ╦ ╦╦ ╦╔╗╔╔╦╗╔═╗╦═╗
    ╚═╗║ ║╠╩╗╠═╣║ ║║║║ ║ ║╣ ╠╦╝
    ╚═╝╚═╝╚═╝╩ ╩╚═╝╝╚╝ ╩ ╚═╝╩╚═  {Colors.YELLOW}v1.0{Colors.CYAN}
{Colors.RESET}
    {Colors.GREEN}▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓{Colors.RESET}
    {Colors.GREEN}▓{Colors.RESET}  {Colors.BOLD}Fast Subdomain Enumeration Tool{Colors.RESET}           {Colors.GREEN}▓{Colors.RESET}
    {Colors.GREEN}▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓{Colors.RESET}
    {Colors.GREEN}▓{Colors.RESET}                                            {Colors.GREEN}▓{Colors.RESET}
    {Colors.GREEN}▓{Colors.RESET}   {Colors.MAGENTA}◆ Built By  :{Colors.RESET} {Colors.BOLD}MIHx0{Colors.RESET} (Mizaz Haider)       {Colors.GREEN}▓{Colors.RESET}
    {Colors.GREEN}▓{Colors.RESET}   {Colors.MAGENTA}◆ Powered By:{Colors.RESET} {Colors.BOLD}The PenTrix{Colors.RESET}                {Colors.GREEN}▓{Colors.RESET}
    {Colors.GREEN}▓{Colors.RESET}                                            {Colors.GREEN}▓{Colors.RESET}
    {Colors.GREEN}▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓{Colors.RESET}
    
    {Colors.DIM}[ crt.sh • HackerTarget • urlscan.io • DNS Brute ]{Colors.RESET}
""")

async def hunt(
    domain: str,
    wordlist_path: Optional[str] = None,
    bruteforce: bool = True,
    output: Optional[str] = None,
    resolve: bool = True,
    concurrency: int = 100,
    quiet: bool = False
) -> Set[str]:
    """Main hunting function - enumerate subdomains."""
    
    all_subdomains: Set[str] = set()
    
    # Create DNS resolver
    resolver = aiodns.DNSResolver()
    
    # ─────────────────────────────────────────────────────────────────────────
    # Phase 1: Passive Enumeration (Certificate Transparency, APIs)
    # ─────────────────────────────────────────────────────────────────────────
    if not quiet:
        print(f"\n{Colors.YELLOW}[*] Phase 1: Passive Enumeration{Colors.RESET}")
        print(f"{Colors.DIM}    Querying certificate transparency logs and APIs...{Colors.RESET}\n")
    
    # Gather from all sources concurrently
    sources = await asyncio.gather(
        fetch_crtsh(domain),
        fetch_hackertarget(domain),
        fetch_threatcrowd(domain),
        fetch_urlscan(domain),
        return_exceptions=True
    )
    
    source_names = ["crt.sh", "HackerTarget", "ThreatCrowd", "urlscan.io"]
    
    for i, result in enumerate(sources):
        if isinstance(result, set):
            count = len(result)
            all_subdomains.update(result)
            if not quiet:
                print(f"  {Colors.BLUE}[+]{Colors.RESET} {source_names[i]}: {count} subdomains")
        elif isinstance(result, Exception):
            if not quiet:
                print(f"  {Colors.RED}[-]{Colors.RESET} {source_names[i]}: failed")
    
    if not quiet:
        print(f"\n  {Colors.GREEN}Total from passive: {len(all_subdomains)}{Colors.RESET}")
    
    # ─────────────────────────────────────────────────────────────────────────
    # Phase 2: DNS Brute-forcing
    # ─────────────────────────────────────────────────────────────────────────
    if bruteforce:
        if not quiet:
            print(f"\n{Colors.YELLOW}[*] Phase 2: DNS Brute-forcing{Colors.RESET}")
        
        # Load wordlist
        if wordlist_path and Path(wordlist_path).exists():
            wordlist = Path(wordlist_path).read_text().strip().split("\n")
            if not quiet:
                print(f"{Colors.DIM}    Using wordlist: {wordlist_path} ({len(wordlist)} words){Colors.RESET}\n")
        else:
            wordlist = DEFAULT_WORDLIST
            if not quiet:
                print(f"{Colors.DIM}    Using built-in wordlist ({len(wordlist)} words){Colors.RESET}\n")
        
        brute_found = await bruteforce_subdomains(domain, wordlist, resolver, concurrency)
        all_subdomains.update(brute_found)
        
        if not quiet:
            print(f"\n  {Colors.GREEN}Total from brute-force: {len(brute_found)}{Colors.RESET}")
    
    # ─────────────────────────────────────────────────────────────────────────
    # Phase 3: Resolve All Subdomains
    # ─────────────────────────────────────────────────────────────────────────
    if resolve and all_subdomains:
        if not quiet:
            print(f"\n{Colors.YELLOW}[*] Phase 3: Resolving {len(all_subdomains)} subdomains{Colors.RESET}\n")
        
        resolved = await resolve_all(all_subdomains, resolver, concurrency)
        
        # Filter to only alive subdomains
        alive = {r["subdomain"] for r in resolved}
        
        if not quiet:
            print(f"\n  {Colors.GREEN}Alive: {len(alive)} / {len(all_subdomains)}{Colors.RESET}")
        
        # Print results
        if not quiet:
            print(f"\n{Colors.CYAN}{'═' * 60}{Colors.RESET}")
            print(f"{Colors.BOLD}RESULTS - {domain}{Colors.RESET}")
            print(f"{Colors.CYAN}{'═' * 60}{Colors.RESET}\n")
            
            for r in sorted(resolved, key=lambda x: x["subdomain"]):
                print(f"  {Colors.GREEN}●{Colors.RESET} {r['subdomain']}")
                for ip in r["ips"]:
                    print(f"    {Colors.DIM}└─ {ip}{Colors.RESET}")
    
    # ─────────────────────────────────────────────────────────────────────────
    # Save Output
    # ─────────────────────────────────────────────────────────────────────────
    if output:
        output_path = Path(output)
        
        if output.endswith(".json"):
            # JSON output
            data = {
                "domain": domain,
                "timestamp": datetime.now().isoformat(),
                "total": len(all_subdomains),
                "subdomains": sorted(list(all_subdomains))
            }
            output_path.write_text(json.dumps(data, indent=2))
        else:
            # Plain text output
            output_path.write_text("\n".join(sorted(all_subdomains)))
        
        if not quiet:
            print(f"\n{Colors.GREEN}[+] Results saved to: {output}{Colors.RESET}")
    
    # Summary
    if not quiet:
        print(f"\n{Colors.CYAN}{'═' * 60}{Colors.RESET}")
        print(f"{Colors.BOLD}SUMMARY{Colors.RESET}")
        print(f"  Domain: {domain}")
        print(f"  Total Subdomains: {len(all_subdomains)}")
        print(f"{Colors.CYAN}{'═' * 60}{Colors.RESET}\n")
    
    return all_subdomains

# ═══════════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="SubHunter - Fast Subdomain Enumeration Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python subhunter.py -d example.com
  python subhunter.py -d example.com -w wordlist.txt
  python subhunter.py -d example.com -o results.txt
  python subhunter.py -d example.com -o results.json --no-brute
        """
    )
    
    parser.add_argument(
        "-d", "--domain",
        required=True,
        help="Target domain to enumerate"
    )
    
    parser.add_argument(
        "-w", "--wordlist",
        help="Custom wordlist for brute-forcing"
    )
    
    parser.add_argument(
        "-o", "--output",
        help="Output file (supports .txt and .json)"
    )
    
    parser.add_argument(
        "--no-brute",
        action="store_true",
        help="Skip DNS brute-forcing (passive only)"
    )
    
    parser.add_argument(
        "--no-resolve",
        action="store_true",
        help="Skip DNS resolution"
    )
    
    parser.add_argument(
        "-c", "--concurrency",
        type=int,
        default=100,
        help="Concurrent DNS queries (default: 100)"
    )
    
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Quiet mode - only output subdomains"
    )
    
    args = parser.parse_args()
    
    # Clean domain (remove protocol if present)
    domain = args.domain.lower().strip()
    if domain.startswith(("http://", "https://")):
        domain = urlparse(domain).netloc
    domain = domain.rstrip("/")
    
    if not args.quiet:
        print_banner()
        print(f"{Colors.BOLD}Target:{Colors.RESET} {domain}")
        print(f"{Colors.DIM}Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.RESET}")
    
    # Run the hunt
    try:
        subdomains = asyncio.run(hunt(
            domain=domain,
            wordlist_path=args.wordlist,
            bruteforce=not args.no_brute,
            output=args.output,
            resolve=not args.no_resolve,
            concurrency=args.concurrency,
            quiet=args.quiet
        ))
        
        # If quiet mode, just print subdomains
        if args.quiet:
            for sub in sorted(subdomains):
                print(sub)
                
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Interrupted by user{Colors.RESET}")
        sys.exit(1)
    except Exception as e:
        print(f"{Colors.RED}[!] Error: {e}{Colors.RESET}")
        sys.exit(1)


if __name__ == "__main__":
    main()
