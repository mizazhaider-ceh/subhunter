
import asyncio
import httpx
from typing import List, Dict, Set
from utils.display import Colors

async def discover_vhosts(
    domain: str, 
    probe_results: List[Dict], 
    quiet: bool = False
) -> List[Dict]:
    """
    Discover hidden Virtual Hosts.
    Groups subdomains by IP, then fuzzes Host header for other subdomains on same IP.
    """
    if not quiet:
        print(f"\n{Colors.CYAN}[*] Phase 7: Virtual Host Discovery{Colors.RESET}")
        
    # Group by IP
    ip_map = {}
    for r in probe_results:
        if r.get('alive') and r.get('ip'):
            ip = r['ip']
            if ip not in ip_map:
                ip_map[ip] = []
            ip_map[ip].append(r['subdomain'])
            
    vhosts_found = []
    
    # We test each IP against *other* known subdomains + root domain
    # Logic: If IP(sub1) == IP(sub2), we check if requesting IP(sub1) with Host: sub2
    # gives different content than direct IP access, or if it matches sub2 content.
    # Actually, a common vhost technique is:
    # 1. Access IP directly -> Default page
    # 2. Access IP with Host: <hidden_dev_domain> -> Secret page
    
    # Here, we will try to find "Cross-VHosts":
    # For every IP found, try all *other* subdomains as Host headers.
    # This might reveal misconfigurations where internal vhosts are accessible via public IPs.
    
    targets = list(ip_map.keys())
    all_subs = [r['subdomain'] for r in probe_results if r.get('subdomain')]
    
    # Limit scope for performance
    if len(targets) > 50:
         if not quiet: print(f"  {Colors.DIM}Limiting VHost scan to top 50 IPs...{Colors.RESET}")
         targets = targets[:50]
         
    async with httpx.AsyncClient(verify=False, timeout=5) as client:
        for ip in targets:
            # Baseline request (IP only)
            try:
                base_resp = await client.get(f"http://{ip}")
                base_len = len(base_resp.content)
            except:
                continue
                
            # Fuzz with known subdomains + common variations
            # (Adding 'dev', 'internal', 'staging' variants of the main domain)
            
            candidates = all_subs[:20] # Check first 20 subdomains against this IP
            candidates.extend([
                f"dev.{domain}", f"staging.{domain}", f"internal.{domain}", 
                f"admin.{domain}", f"test.{domain}", f"api.{domain}"
            ])
            candidates = list(set(candidates)) # Unique
            
            for host in candidates:
                if host in ip_map[ip]: continue # Skip if this host actually resolves to this IP (normal)
                
                try:
                    # Request IP with Host header
                    resp = await client.get(f"http://{ip}", headers={"Host": host})
                    
                    # Detection logic:
                    # If response is significantly different from baseline IP response
                    # AND valid status code
                    
                    if resp.status_code not in [404, 403, 503] and abs(len(resp.content) - base_len) > 50:
                        vhosts_found.append({
                            "ip": ip,
                            "vhost": host,
                            "status": resp.status_code,
                            "len": len(resp.content),
                            "title": "Unknown" # simplified
                        })
                        if not quiet:
                            print(f"  {Colors.GREEN}[+] Possible VHost: {host} on {ip} (Status: {resp.status_code}){Colors.RESET}")
                except:
                    pass
    
    return vhosts_found
