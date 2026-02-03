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
║   Fast Subdomain Enumeration Tool                                   v4.0     ║
║                                                                               ║
║   Built By  : MIHx0 (Mizaz Haider)                                           ║
║   Powered By: The PenTrix                                                    ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝

SubHunter v4.0 - Pro Edition
Features:
- 6 Passive Sources (crt.sh, HackerTarget, AlienVault, urlscan.io, RapidDNS, WebArchive)
- 🧠 Wildcard DNS Detection & Filtering
- 🔄 Recursive Sub-Subdomain Discovery
- ☁️ Cloud Provider Detection (AWS, Azure, GCP, Cloudflare, etc.)
- HTTP Probing with Tech Detection
- Port Scanning
- Screenshots (Playwright or Selenium)
- Beautiful HTML Reports
- Resume Capability

Author: MIHx0 (Mizaz Haider)
Powered By: The PenTrix
License: MIT
"""

import argparse
import asyncio
import json
import sys
import warnings
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

warnings.filterwarnings("ignore")

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent))

# Import modules
try:
    import httpx
    import aiodns
except ImportError:
    print("[-] Required: pip install httpx aiodns")
    sys.exit(1)

from utils.display import Colors, VERSION, print_banner
from utils.config import DEFAULT_WORDLIST, STATE_FILE, COMMON_PORTS
from sources.passive import fetch_all_sources
from core.dns import bruteforce_subdomains, resolve_all, recursive_bruteforce
from core.probe import probe_all
from core.scanner import scan_all_ports
from core.screenshot import take_all_screenshots, PLAYWRIGHT_AVAILABLE
from core.report import generate_html_report
from core.wildcard import detect_wildcard
from core.cloud import detect_cloud_provider
from core.takeover import check_takeover
from core.vhost import discover_vhosts
from core.jsparse import parse_js_files


def get_report_path(domain: str, extension: str = "html") -> Path:
    """Generate report path with date and domain."""
    reports_dir = Path("reports")
    reports_dir.mkdir(exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return reports_dir / f"{domain}_{timestamp}.{extension}"


def save_state(domain: str, subdomains: set, phase: str):
    """Save scan state for resume."""
    state = {
        "domain": domain,
        "subdomains": list(subdomains),
        "phase": phase,
        "timestamp": datetime.now().isoformat()
    }
    Path(STATE_FILE).write_text(json.dumps(state, indent=2))


def load_state():
    """Load previous scan state."""
    if Path(STATE_FILE).exists():
        return json.loads(Path(STATE_FILE).read_text())
    return None


def clear_state():
    """Clear saved state."""
    if Path(STATE_FILE).exists():
        Path(STATE_FILE).unlink()


async def hunt(
    domain: str,
    wordlist_path: str = None,
    bruteforce: bool = True,
    probe: bool = True,
    port_scan: bool = False,
    screenshots: bool = False,
    output: str = None,
    html_report: str = None,
    concurrency: int = 100,
    quiet: bool = False,
    resume: bool = False,
    recursive: bool = False,
    recursive_depth: int = 2,
    skip_wildcard_filter: bool = False,
    takeover: bool = False,
    vhost: bool = False,
    js_parse: bool = False
):
    """Main hunting function with v4.0 pro features."""
    
    all_subdomains = set()
    dns_results = {}
    resolver = aiodns.DNSResolver()
    wildcard_ips = set()
    
    # Check for resume
    if resume:
        state = load_state()
        if state and state["domain"] == domain:
            all_subdomains = set(state["subdomains"])
            if not quiet:
                print(f"\n{Colors.YELLOW}[*] Resuming scan with {len(all_subdomains)} subdomains{Colors.RESET}")
    
    # ─────────────────────────────────────────────────────────────────────────
    # Phase 0: Wildcard Detection (NEW in v4.0)
    # ─────────────────────────────────────────────────────────────────────────
    if not skip_wildcard_filter:
        if not quiet:
            print(f"\n{Colors.CYAN}[*] Phase 0: Wildcard Detection{Colors.RESET}")
        
        wildcard_result = await detect_wildcard(domain, resolver, quiet=quiet)
        
        if wildcard_result.is_wildcard:
            wildcard_ips = wildcard_result.wildcard_ips
            if not quiet:
                print(f"  {Colors.YELLOW}⚠{Colors.RESET}  Wildcard DNS detected - will filter false positives")
        elif not quiet:
            print(f"  {Colors.GREEN}✓{Colors.RESET}  No wildcard DNS detected")
    
    # ─────────────────────────────────────────────────────────────────────────
    # Phase 1: Passive Enumeration
    # ─────────────────────────────────────────────────────────────────────────
    if not all_subdomains:
        if not quiet:
            print(f"\n{Colors.YELLOW}[*] Phase 1: Passive Enumeration{Colors.RESET}")
            print(f"{Colors.DIM}    Querying 6 sources...{Colors.RESET}\n")
        
        passive_subs = await fetch_all_sources(domain, quiet)
        all_subdomains.update(passive_subs)
        
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
            wildcard_msg = f" (filtering wildcards)" if wildcard_ips else ""
            print(f"{Colors.DIM}    Using {len(wordlist)} words{wildcard_msg}{Colors.RESET}\n")
        
        brute_found, brute_results = await bruteforce_subdomains(
            domain, wordlist, resolver, concurrency, quiet, wildcard_ips
        )
        all_subdomains.update(brute_found)
        dns_results.update(brute_results)
        
        if not quiet:
            print(f"\n  {Colors.GREEN}Total from brute-force: {len(brute_found)}{Colors.RESET}")
        
        save_state(domain, all_subdomains, "bruteforce")
    
    # ─────────────────────────────────────────────────────────────────────────
    # Phase 2.5: Recursive Discovery (NEW in v4.0)
    # ─────────────────────────────────────────────────────────────────────────
    if recursive and all_subdomains:
        if not quiet:
            print(f"\n{Colors.CYAN}[*] Phase 2.5: Recursive Sub-Subdomain Discovery{Colors.RESET}")
            print(f"{Colors.DIM}    Depth: {recursive_depth} levels{Colors.RESET}")
        
        if wordlist_path and Path(wordlist_path).exists():
            wordlist = Path(wordlist_path).read_text().strip().split("\n")
        else:
            wordlist = DEFAULT_WORDLIST
        
        recursive_found, recursive_results = await recursive_bruteforce(
            domain, all_subdomains, wordlist, resolver,
            depth=recursive_depth, concurrency=concurrency,
            quiet=quiet, wildcard_ips=wildcard_ips
        )
        
        new_from_recursive = recursive_found - all_subdomains
        all_subdomains.update(recursive_found)
        dns_results.update(recursive_results)
        
        if not quiet:
            print(f"\n  {Colors.GREEN}New from recursive: {len(new_from_recursive)}{Colors.RESET}")
        
        save_state(domain, all_subdomains, "recursive")
    
    # ─────────────────────────────────────────────────────────────────────────
    # Phase 3: HTTP Probing + Tech Detection + Cloud Detection
    # ─────────────────────────────────────────────────────────────────────────
    probe_results = []
    if probe and all_subdomains:
        if not quiet:
            print(f"\n{Colors.YELLOW}[*] Phase 3: HTTP Probing, Tech & Cloud Detection{Colors.RESET}")
            print(f"{Colors.DIM}    Probing {len(all_subdomains)} subdomains...{Colors.RESET}\n")
        
        probe_results = await probe_all(all_subdomains, min(concurrency, 50), quiet, dns_results)
        alive = [r for r in probe_results if r["alive"]]
        
        # Count cloud providers
        cloud_counts = {}
        for r in alive:
            if r.get("cloud_provider"):
                provider = r["cloud_provider"]
                cloud_counts[provider] = cloud_counts.get(provider, 0) + 1
        
        if not quiet:
            print(f"\n  {Colors.GREEN}Alive: {len(alive)} / {len(all_subdomains)}{Colors.RESET}")
            if cloud_counts:
                cloud_str = ", ".join(f"{k}: {v}" for k, v in sorted(cloud_counts.items(), key=lambda x: -x[1]))
                print(f"  {Colors.CYAN}☁ Cloud: {cloud_str}{Colors.RESET}")
    
    # ─────────────────────────────────────────────────────────────────────────
    # Phase 4: Port Scanning
    # ─────────────────────────────────────────────────────────────────────────
    port_results = []
    if port_scan and all_subdomains:
        if not quiet:
            print(f"\n{Colors.YELLOW}[*] Phase 4: Port Scanning{Colors.RESET}")
            print(f"{Colors.DIM}    Scanning {len(COMMON_PORTS)} common ports on {len(all_subdomains)} hosts...{Colors.RESET}\n")
        
        port_results = await scan_all_ports(all_subdomains, COMMON_PORTS, concurrency, 1.0, quiet)
        open_hosts = [r for r in port_results if r.get("open_ports")]
        
        if not quiet:
            print(f"\n  {Colors.GREEN}Hosts with open ports: {len(open_hosts)}{Colors.RESET}")
    
    # ─────────────────────────────────────────────────────────────────────────
    # Phase 5: Screenshots
    # ─────────────────────────────────────────────────────────────────────────
    # Phase 5: Screenshots (Existing)
    screenshot_results = []
    if screenshots and probe_results:
        if not quiet:
            print(f"\n{Colors.YELLOW}[*] Phase 5: Taking Screenshots{Colors.RESET}")
        
        screenshot_dir = get_report_path(domain, "screenshots").parent / f"{domain}_screenshots"
        screenshot_results = await take_all_screenshots(probe_results, screenshot_dir, 5, quiet)
        
        if not quiet and screenshot_results:
            print(f"\n  {Colors.GREEN}Screenshots saved: {len(screenshot_results)}{Colors.RESET}")

    # ─────────────────────────────────────────────────────────────────────────
    # Phase 6: Subdomain Takeover (NEW v5.0)
    # ─────────────────────────────────────────────────────────────────────────
    takeover_results = []
    if takeover and all_subdomains:
        # We need A/CNAME info. If we ran brute, we might have it in dns_results.
        # But specifically we need to check the CNAMEs of the *alive* or *discovered* subs.
        # We'll pass the list of all subdomains to the checker.
        takeover_results = await check_takeover(domain, list(all_subdomains), resolver, quiet)

    # ─────────────────────────────────────────────────────────────────────────
    # Phase 7: VHost Discovery (NEW v5.0)
    # ─────────────────────────────────────────────────────────────────────────
    vhost_results = []
    if vhost and probe_results:
        vhost_results = await discover_vhosts(domain, probe_results, quiet)

    # ─────────────────────────────────────────────────────────────────────────
    # Phase 8: JS Parsing (NEW v5.0)
    # ─────────────────────────────────────────────────────────────────────────
    js_results = {}
    if js_parse and probe_results:
        js_results = await parse_js_files(domain, probe_results, quiet)

    
    # ─────────────────────────────────────────────────────────────────────────
    # Save Results
    # ─────────────────────────────────────────────────────────────────────────
    
    # Auto-save HTML report to reports/ folder
    if probe_results:
        html_path = get_report_path(domain, "html")
        generate_html_report(
            domain, 
            probe_results, 
            port_results, 
            screenshot_results, 
            str(html_path),
            takeover_results=takeover_results if 'takeover_results' in locals() else [],
            vhost_results=vhost_results if 'vhost_results' in locals() else [],
            js_results=js_results if 'js_results' in locals() else {}
        )
        if not quiet:
            print(f"\n{Colors.GREEN}[+] HTML report saved to: {html_path}{Colors.RESET}")
        
        # Also save to custom path if specified
        if html_report:
            generate_html_report(
                domain, 
                probe_results, 
                port_results, 
                screenshot_results, 
                html_report,
                takeover_results=takeover_results if 'takeover_results' in locals() else [],
                vhost_results=vhost_results if 'vhost_results' in locals() else [],
                js_results=js_results if 'js_results' in locals() else {}
            )
            if not quiet:
                print(f"{Colors.GREEN}[+] HTML report also saved to: {html_report}{Colors.RESET}")
    
    # Save output file
    if output:
        output_path = Path(output)
        if output.endswith(".json"):
            data = {
                "domain": domain,
                "timestamp": datetime.now().isoformat(),
                "version": VERSION,
                "wildcard_detected": bool(wildcard_ips),
                "wildcard_ips": list(wildcard_ips),
                "total": len(all_subdomains),
                "subdomains": sorted(list(all_subdomains)),
                "probed": probe_results if probe else [],
                "ports": port_results if port_scan else []
            }
            output_path.write_text(json.dumps(data, indent=2))
        else:
            output_path.write_text("\n".join(sorted(all_subdomains)))
        
        if not quiet:
            print(f"{Colors.GREEN}[+] Results saved to: {output}{Colors.RESET}")
    
    # Summary
    if not quiet:
        print(f"\n{Colors.CYAN}{'═' * 60}{Colors.RESET}")
        print(f"{Colors.BOLD}SUMMARY{Colors.RESET}")
        print(f"  Domain: {domain}")
        print(f"  Total Subdomains: {len(all_subdomains)}")
        if wildcard_ips:
            print(f"  {Colors.YELLOW}⚠ Wildcard DNS: Detected (filtered){Colors.RESET}")
        if probe_results:
            alive = [r for r in probe_results if r["alive"]]
            print(f"  Alive (HTTP): {len(alive)}")
            
            # Cloud summary
            cloud_counts = {}
            for r in alive:
                if r.get("cloud_provider"):
                    provider = r["cloud_provider"]
                    cloud_counts[provider] = cloud_counts.get(provider, 0) + 1
            if cloud_counts:
                print(f"  Cloud Providers: {', '.join(cloud_counts.keys())}")
        if port_results:
            open_hosts = [r for r in port_results if r.get("open_ports")]
            print(f"  Hosts with open ports: {len(open_hosts)}")
        print(f"{Colors.CYAN}{'═' * 60}{Colors.RESET}\n")
    
    clear_state()
    return all_subdomains


def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description=f"SubHunter v{VERSION} - Fast Subdomain Enumeration Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python subhunter.py -d example.com                  # Basic scan
  python subhunter.py -d example.com --ports          # With port scanning  
  python subhunter.py -d example.com --screenshots    # With screenshots
  python subhunter.py -d example.com --recursive      # Discover sub-subdomains
  python subhunter.py -d example.com --resume         # Resume interrupted scan
  python subhunter.py -d example.com -o results.json  # Save to JSON
        """
    )
    
    # Basic options
    parser.add_argument("-d", "--domain", required=True, help="Target domain")
    parser.add_argument("-w", "--wordlist", help="Custom wordlist for brute-forcing")
    parser.add_argument("-o", "--output", help="Output file (.txt or .json)")
    parser.add_argument("--html", help="Save HTML report to custom path")
    parser.add_argument("--no-brute", action="store_true", help="Skip DNS brute-forcing")
    parser.add_argument("--no-probe", action="store_true", help="Skip HTTP probing")
    parser.add_argument("--ports", action="store_true", help="Enable port scanning")
    parser.add_argument("--screenshots", action="store_true", help="Take screenshots of alive hosts")
    parser.add_argument("--resume", action="store_true", help="Resume previous scan")
    parser.add_argument("-c", "--concurrency", type=int, default=100, help="Concurrency (default: 100)")
    parser.add_argument("-q", "--quiet", action="store_true", help="Quiet mode")
    
    # v5.0 New Features
    parser.add_argument("--takeover", action="store_true", 
                       help="Check for subdomain takeover vulnerabilities")
    parser.add_argument("--vhost", action="store_true", 
                       help="Discover virtual hosts on same IP")
    parser.add_argument("--js-parse", action="store_true", 
                       help="Extract subdomains and secrets from JS files")
    parser.add_argument("--interactive", action="store_true", 
                       help="Force interactive mode")

    # Check if no args provided -> Interactive Mode
    if len(sys.argv) == 1:
        from utils.menu import interactive_menu
        try:
            config = interactive_menu()
            # Map config dict to namespace-like object or just use as kwargs
            # Create a simple class to mimic argparse Namespace
            class ConfigArgs:
                def __init__(self, **entries):
                    self.__dict__.update(entries)
            
            args = ConfigArgs(**config)
            
        except ImportError:
            # Fallback if menu module fails
            print(f"{Colors.YELLOW}[!] Interactive mode error. Use --help{Colors.RESET}")
            sys.exit(1)
    else:
        args = parser.parse_args()
        
        # Helper to handle interactive flag if passed explicitly
        if getattr(args, 'interactive', False):
            from utils.menu import interactive_menu
            config = interactive_menu()
            class ConfigArgs:
                def __init__(self, **entries):
                    self.__dict__.update(entries)
            args = ConfigArgs(**config)

    # Clean domain
    domain = args.domain.lower().strip()
    if domain.startswith(("http://", "https://")):
        domain = urlparse(domain).netloc
    domain = domain.rstrip("/")
    
    if not getattr(args, 'quiet', False):
        print_banner()
        print(f"{Colors.BOLD}Target:{Colors.RESET} {domain}")
        print(f"{Colors.DIM}Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.RESET}")
        
        # Show enabled features
        features = []
        if not getattr(args, 'no_wildcard_filter', False):
            features.append("🧠 Wildcard Detection")
        if getattr(args, 'recursive', False):
            features.append(f"🔄 Recursive (depth: {getattr(args, 'recursive_depth', 2)})")
        features.append("☁️ Cloud Detection")
        
        # v5.0 Features
        if getattr(args, 'takeover', False): features.append("🎯 Takeover Check")
        if getattr(args, 'vhost', False): features.append("🌐 VHost Discovery")
        if getattr(args, 'js_parse', False): features.append("📜 JS Parsing")
        
        print(f"{Colors.CYAN}Features: {', '.join(features)}{Colors.RESET}")
    
    try:
        asyncio.run(hunt(
            domain=domain,
            wordlist_path=getattr(args, 'wordlist', None),
            bruteforce=not getattr(args, 'no_brute', False),
            probe=not getattr(args, 'no_probe', False),
            port_scan=getattr(args, 'ports', False),
            screenshots=getattr(args, 'screenshots', False),
            output=getattr(args, 'output', None),
            html_report=getattr(args, 'html', None),
            concurrency=getattr(args, 'concurrency', 100),
            quiet=getattr(args, 'quiet', False),
            resume=getattr(args, 'resume', False),
            recursive=getattr(args, 'recursive', False),
            recursive_depth=getattr(args, 'recursive_depth', 2),
            skip_wildcard_filter=getattr(args, 'no_wildcard_filter', False),
            # New v5.0 kwargs
            takeover=getattr(args, 'takeover', False),
            vhost=getattr(args, 'vhost', False),
            js_parse=getattr(args, 'js_parse', False)
        ))
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Interrupted - state saved for resume{Colors.RESET}")
        sys.exit(1)


if __name__ == "__main__":
    main()
