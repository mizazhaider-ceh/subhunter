"""
Passive subdomain enumeration sources
"""
import asyncio
import re
from typing import Set
from urllib.parse import urlparse
import httpx


async def fetch_crtsh(domain: str) -> Set[str]:
    """Fetch from crt.sh (Certificate Transparency)."""
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
    """Fetch from HackerTarget API."""
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
    """Fetch from AlienVault OTX."""
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
    """Fetch from urlscan.io."""
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
    """Fetch from RapidDNS."""
    subdomains = set()
    url = f"https://rapiddns.io/subdomain/{domain}?full=1"
    try:
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
            response = await client.get(url)
            if response.status_code == 200:
                pattern = rf'[\w.-]+\.{re.escape(domain)}'
                matches = re.findall(pattern, response.text, re.IGNORECASE)
                for match in matches:
                    sub = match.lower()
                    if sub.endswith(domain):
                        subdomains.add(sub)
    except:
        pass
    return subdomains


async def fetch_webarchive(domain: str) -> Set[str]:
    """Fetch from Web Archive."""
    subdomains = set()
    url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=txt&fl=original&collapse=urlkey"
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            response = await client.get(url)
            if response.status_code == 200:
                for line in response.text.strip().split("\n")[:500]:
                    try:
                        parsed = urlparse(line)
                        if parsed.netloc.endswith(domain):
                            subdomains.add(parsed.netloc.lower())
                    except:
                        pass
    except:
        pass
    return subdomains


async def fetch_all_sources(domain: str, quiet: bool = False):
    """Fetch from all sources concurrently."""
    from utils.display import Colors
    
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
    all_subs = set()
    
    for i, result in enumerate(sources):
        if isinstance(result, set):
            count = len(result)
            all_subs.update(result)
            if not quiet:
                print(f"  {Colors.BLUE}[+]{Colors.RESET} {source_names[i]}: {count} subdomains")
    
    return all_subs
