"""
DNS resolution and brute-forcing
"""
import asyncio
from typing import Set, List, Optional, Dict
import aiodns
from utils.display import Colors


async def resolve_subdomain(resolver: aiodns.DNSResolver, subdomain: str) -> Optional[Dict]:
    """Resolve a single subdomain."""
    try:
        result = await resolver.query(subdomain, "A")
        ips = [r.host for r in result]
        return {"subdomain": subdomain, "ips": ips}
    except:
        return None


async def bruteforce_subdomains(
    domain: str,
    wordlist: List[str],
    resolver: aiodns.DNSResolver,
    concurrency: int = 100,
    quiet: bool = False
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
                if not quiet:
                    print(f"  {Colors.GREEN}[+]{Colors.RESET} {subdomain} → {', '.join(result['ips'])}")
    
    tasks = [check(word) for word in wordlist]
    await asyncio.gather(*tasks, return_exceptions=True)
    return found


async def resolve_all(
    subdomains: Set[str],
    resolver: aiodns.DNSResolver,
    concurrency: int = 100
) -> List[Dict]:
    """Resolve all subdomains."""
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
