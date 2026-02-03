"""
DNS resolution, brute-forcing, and recursive discovery - SubHunter v4.0

Enhanced with:
- CNAME resolution for cloud detection
- Recursive subdomain discovery
- Wildcard filtering integration
"""
import asyncio
from typing import Set, List, Optional, Dict, Tuple
from dataclasses import dataclass
import aiodns
from utils.display import Colors


@dataclass
class DNSResult:
    """Result of DNS resolution."""
    subdomain: str
    ips: List[str]
    cname: Optional[str] = None


async def resolve_subdomain(resolver: aiodns.DNSResolver, subdomain: str) -> Optional[DNSResult]:
    """Resolve a single subdomain with A and CNAME records."""
    ips = []
    cname = None
    
    # Try A record
    try:
        result = await resolver.query(subdomain, "A")
        ips = [r.host for r in result]
    except (aiodns.error.DNSError, Exception):
        pass
    
    # Try CNAME record
    try:
        result = await resolver.query(subdomain, "CNAME")
        if result:
            cname = result.cname
    except (aiodns.error.DNSError, Exception):
        pass
    
    if ips or cname:
        return DNSResult(subdomain=subdomain, ips=ips, cname=cname)
    return None


async def bruteforce_subdomains(
    domain: str,
    wordlist: List[str],
    resolver: aiodns.DNSResolver,
    concurrency: int = 100,
    quiet: bool = False,
    wildcard_ips: Set[str] = None
) -> Tuple[Set[str], Dict[str, DNSResult]]:
    """
    Brute-force subdomains using wordlist with wildcard filtering.
    
    Returns:
        Tuple of (found_subdomains, dns_results_dict)
    """
    found = set()
    results = {}
    semaphore = asyncio.Semaphore(concurrency)
    wildcard_ips = wildcard_ips or set()
    filtered_count = 0
    
    async def check(word: str):
        nonlocal filtered_count
        async with semaphore:
            subdomain = f"{word}.{domain}"
            result = await resolve_subdomain(resolver, subdomain)
            
            if result:
                # Filter out wildcard results
                if wildcard_ips and result.ips:
                    if set(result.ips).issubset(wildcard_ips):
                        filtered_count += 1
                        return
                
                found.add(subdomain)
                results[subdomain] = result
                
                if not quiet:
                    ips_str = ', '.join(result.ips) if result.ips else result.cname or ""
                    print(f"  {Colors.GREEN}[+]{Colors.RESET} {subdomain} → {ips_str}")
    
    tasks = [check(word) for word in wordlist]
    await asyncio.gather(*tasks, return_exceptions=True)
    
    if filtered_count > 0 and not quiet:
        print(f"  {Colors.DIM}Filtered {filtered_count} wildcard results{Colors.RESET}")
    
    return found, results


async def recursive_bruteforce(
    domain: str,
    base_subdomains: Set[str],
    wordlist: List[str],
    resolver: aiodns.DNSResolver,
    depth: int = 2,
    concurrency: int = 100,
    quiet: bool = False,
    wildcard_ips: Set[str] = None
) -> Tuple[Set[str], Dict[str, DNSResult]]:
    """
    Recursively discover sub-subdomains.
    
    For each found subdomain, tries prepending words from wordlist.
    E.g., api.example.com -> dev.api.example.com
    
    Args:
        domain: Original target domain
        base_subdomains: Initially discovered subdomains
        wordlist: Words to prepend
        resolver: DNS resolver
        depth: Maximum recursion depth (1 = one level of sub-subdomains)
        concurrency: Concurrent queries
        quiet: Suppress output
        wildcard_ips: IPs to filter as wildcards
        
    Returns:
        Tuple of (all_subdomains, all_dns_results)
    """
    all_found = set(base_subdomains)
    all_results = {}
    wildcard_ips = wildcard_ips or set()
    
    # Use shorter wordlist for recursion to avoid explosion
    recursive_wordlist = wordlist[:50] if len(wordlist) > 50 else wordlist
    
    current_level = base_subdomains
    
    for level in range(1, depth + 1):
        if not current_level:
            break
            
        if not quiet:
            print(f"\n  {Colors.CYAN}[↻]{Colors.RESET} Recursive level {level}: checking {len(current_level)} subdomains...")
        
        new_found = set()
        semaphore = asyncio.Semaphore(concurrency)
        
        async def check_recursive(base_sub: str, word: str):
            async with semaphore:
                subdomain = f"{word}.{base_sub}"
                
                # Skip if we already found this
                if subdomain in all_found:
                    return
                
                result = await resolve_subdomain(resolver, subdomain)
                
                if result:
                    # Filter wildcards
                    if wildcard_ips and result.ips:
                        if set(result.ips).issubset(wildcard_ips):
                            return
                    
                    new_found.add(subdomain)
                    all_found.add(subdomain)
                    all_results[subdomain] = result
                    
                    if not quiet:
                        ips_str = ', '.join(result.ips) if result.ips else result.cname or ""
                        print(f"    {Colors.GREEN}[+]{Colors.RESET} {subdomain} → {ips_str}")
        
        # Create tasks for all combinations
        tasks = []
        for base_sub in current_level:
            for word in recursive_wordlist:
                tasks.append(check_recursive(base_sub, word))
        
        await asyncio.gather(*tasks, return_exceptions=True)
        
        if not quiet and new_found:
            print(f"    {Colors.DIM}Found {len(new_found)} sub-subdomains at level {level}{Colors.RESET}")
        
        current_level = new_found
    
    return all_found, all_results


async def resolve_all(
    subdomains: Set[str],
    resolver: aiodns.DNSResolver,
    concurrency: int = 100
) -> List[Dict]:
    """Resolve all subdomains and return results as dicts."""
    results = []
    semaphore = asyncio.Semaphore(concurrency)
    
    async def resolve(sub: str):
        async with semaphore:
            result = await resolve_subdomain(resolver, sub)
            if result:
                results.append({
                    "subdomain": result.subdomain,
                    "ips": result.ips,
                    "cname": result.cname
                })
    
    tasks = [resolve(sub) for sub in subdomains]
    await asyncio.gather(*tasks, return_exceptions=True)
    return results
