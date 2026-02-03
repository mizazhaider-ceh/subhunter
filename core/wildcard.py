"""
Wildcard DNS Detection Module - SubHunter v4.0

Detects wildcard DNS configurations that return the same IP for any subdomain.
This helps filter out false positives during subdomain enumeration.
"""
import asyncio
import random
import string
from dataclasses import dataclass
from typing import Set, Tuple, Optional
import aiodns
from utils.display import Colors


@dataclass
class WildcardResult:
    """Result of wildcard detection."""
    is_wildcard: bool
    wildcard_ips: Set[str]
    tested_subdomains: int
    
    def __str__(self) -> str:
        if self.is_wildcard:
            return f"Wildcard detected: {', '.join(self.wildcard_ips)}"
        return "No wildcard detected"


def generate_random_subdomain(length: int = 12) -> str:
    """Generate a random subdomain string that's unlikely to exist."""
    chars = string.ascii_lowercase + string.digits
    return ''.join(random.choices(chars, k=length))


async def resolve_to_ips(resolver: aiodns.DNSResolver, subdomain: str) -> Set[str]:
    """Resolve a subdomain to its IP addresses."""
    try:
        result = await resolver.query(subdomain, "A")
        return {r.host for r in result}
    except (aiodns.error.DNSError, Exception):
        return set()


async def detect_wildcard(
    domain: str,
    resolver: aiodns.DNSResolver,
    test_count: int = 5,
    quiet: bool = False
) -> WildcardResult:
    """
    Detect if a domain has wildcard DNS configured.
    
    Wildcard DNS returns the same IP(s) for any subdomain query.
    We test by resolving multiple random subdomains - if they all
    resolve to the same IPs, it's a wildcard domain.
    
    Args:
        domain: Target domain to check
        resolver: DNS resolver instance
        test_count: Number of random subdomains to test
        quiet: Suppress output
        
    Returns:
        WildcardResult with detection status and wildcard IPs if found
    """
    if not quiet:
        print(f"  {Colors.DIM}Checking for wildcard DNS...{Colors.RESET}")
    
    # Generate random subdomains
    random_subs = [
        f"{generate_random_subdomain()}.{domain}" 
        for _ in range(test_count)
    ]
    
    # Resolve all random subdomains concurrently
    tasks = [resolve_to_ips(resolver, sub) for sub in random_subs]
    results = await asyncio.gather(*tasks)
    
    # Filter out empty results (subdomains that didn't resolve)
    resolved_ips = [ips for ips in results if ips]
    
    # No wildcard if none of the random subdomains resolved
    if not resolved_ips:
        return WildcardResult(
            is_wildcard=False,
            wildcard_ips=set(),
            tested_subdomains=test_count
        )
    
    # Wildcard detected if ALL random subdomains resolved to the SAME IPs
    first_ips = resolved_ips[0]
    is_wildcard = all(ips == first_ips for ips in resolved_ips)
    
    if is_wildcard and not quiet:
        print(f"  {Colors.YELLOW}[!]{Colors.RESET} Wildcard DNS detected: {Colors.DIM}{', '.join(first_ips)}{Colors.RESET}")
    
    return WildcardResult(
        is_wildcard=is_wildcard,
        wildcard_ips=first_ips if is_wildcard else set(),
        tested_subdomains=test_count
    )


def filter_wildcard_results(
    subdomains: Set[str],
    resolved_data: dict,
    wildcard_ips: Set[str]
) -> Tuple[Set[str], int]:
    """
    Filter out subdomains that only resolve to wildcard IPs.
    
    Args:
        subdomains: Set of discovered subdomains
        resolved_data: Dict mapping subdomain -> set of IPs
        wildcard_ips: Set of IPs that indicate wildcard response
        
    Returns:
        Tuple of (filtered_subdomains, count_removed)
    """
    if not wildcard_ips:
        return subdomains, 0
    
    filtered = set()
    removed = 0
    
    for subdomain in subdomains:
        ips = resolved_data.get(subdomain, set())
        
        # Keep subdomain if it has at least one non-wildcard IP
        if ips and not ips.issubset(wildcard_ips):
            filtered.add(subdomain)
        elif ips:
            removed += 1
        else:
            # Keep if we don't have IP info (will be verified later)
            filtered.add(subdomain)
    
    return filtered, removed
