
import re
import httpx
import asyncio
from typing import List, Dict, Set
from utils.display import Colors

# Regex patterns
REGEX = {
    "url": r'(https?://[a-zA-Z0-9.-]+)',
    "endpoint": r'["\'](/api/[^"\']+|/v1/[^"\']+|/graphql[^"\']*)["\']',
    "aws_key": r'((?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})',
    "subdomain": r'([a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]\.[a-zA-Z0-9-]+\.[a-zA-Z0-9-]+\.[a-zA-Z]{2,})' # Simple, refined below
}

async def parse_js_files(domain: str, probe_results: List[Dict], quiet: bool = False) -> Dict:
    """
    Fetch and parse JS files for secrets and subdomains.
    """
    if not quiet:
        print(f"\n{Colors.CYAN}[*] Phase 8: JavaScript Analysis{Colors.RESET}")
    
    js_urls = set()
    
    # 1. Collect JS URLs from probe results (if we had a real crawler, we'd have them. 
    # For now, we assume probe might have seen some, OR we just try /main.js, /app.js on alive hosts)
    # Since passive sources like Wayback might give us JS files, we can scan those too in future.
    # For now, let's try to extract src attributes if we saved body? No we didn't save body.
    # We will try a few common guesses on top alive hosts.
    
    alive_hosts = [r['url'] for r in probe_results if r.get('alive')]
    
    # Very basic "crawler" - purely guessing common chunks
    # Realistically we'd parse the HTML of alive_hosts to find <script src="...">
    # Let's do a lightweight fetch of HTML for top 10 hosts to find JS files
    
    targets = alive_hosts[:10] 
    
    async with httpx.AsyncClient(verify=False, timeout=5) as client:
        # Step A: Find JS files
        for url in targets:
            try:
                resp = await client.get(url)
                # Extract .js links
                found = re.findall(r'src=["\'](.*?\.js)["\']', resp.text)
                for f in found:
                    if f.startswith('//'):
                        js_urls.add(f"https:{f}")
                    elif f.startswith(('http', 'https')):
                        js_urls.add(f)
                    elif f.startswith('/'):
                        # construct absolute
                        base = url.rstrip('/')
                        js_urls.add(f"{base}{f}")
            except:
                pass
    
    if not quiet and js_urls:
        print(f"  {Colors.DIM}Found {len(js_urls)} JS files to analyze...{Colors.RESET}")
        
    results = {
        "endpoints": set(),
        "secrets": set(),
        "subdomains": set()
    }
    
    # Step B: Analyze content
    async with httpx.AsyncClient(verify=False, timeout=5) as client:
        for js_url in list(js_urls)[:50]: # limit to 50 files
            try:
                resp = await client.get(js_url)
                content = resp.text
                
                # Extract stuff
                keys = re.findall(REGEX["aws_key"], content)
                results["secrets"].update(keys)
                
                eps = re.findall(REGEX["endpoint"], content)
                results["endpoints"].update(eps)
                
                # Domain specific subdomains
                # looking for anything ending in .domain.com
                escaped_domain = re.escape(domain)
                sub_regex = fr'([a-zA-Z0-9.-]+\.{escaped_domain})'
                subs = re.findall(sub_regex, content)
                results["subdomains"].update(subs)
                
            except:
                pass

    if not quiet:
        if results["secrets"]:
            print(f"  {Colors.RED}[!] Found {len(results['secrets'])} POTENTIAL SECRETS ({', '.join(list(results['secrets'])[:3])}...){Colors.RESET}")
        if results["endpoints"]:
             print(f"  {Colors.GREEN}[+] Found {len(results['endpoints'])} API endpoints{Colors.RESET}")
        if results["subdomains"]:
             print(f"  {Colors.GREEN}[+] Found {len(results['subdomains'])} subdomains in JS{Colors.RESET}")
             
    return {
        "endpoints": list(results["endpoints"]),
        "secrets": list(results["secrets"]),
        "subdomains": list(results["subdomains"])
    }
