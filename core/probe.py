"""
HTTP probing and technology detection - Enhanced with more details
"""
import asyncio
import re
import socket
import time
from typing import Set, List, Optional, Dict
import httpx
from utils.display import Colors
from utils.config import TECH_SIGNATURES


async def resolve_ip(subdomain: str) -> str:
    """Resolve subdomain to IP address."""
    try:
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, socket.gethostbyname, subdomain)
        return result
    except:
        return ""


async def probe_http(subdomain: str, timeout: float = 5.0) -> Dict:
    """Probe HTTP/HTTPS for a subdomain with detailed info."""
    
    # First resolve IP
    ip = await resolve_ip(subdomain)
    
    result = {
        "subdomain": subdomain,
        "ip": ip,
        "alive": False,
        "url": None,
        "final_url": None,
        "status": None,
        "title": None,
        "tech": [],
        "server": None,
        "content_type": None,
        "content_length": 0,
        "response_time": 0,
        "headers": {},
        "redirect_chain": [],
        "cookies": [],
        "meta_description": None,
        "protocol": None
    }
    
    for protocol in ["https", "http"]:
        url = f"{protocol}://{subdomain}"
        try:
            start_time = time.time()
            async with httpx.AsyncClient(timeout=timeout, verify=False, follow_redirects=True) as client:
                response = await client.get(url)
                end_time = time.time()
                
                result["alive"] = True
                result["url"] = url
                result["final_url"] = str(response.url)
                result["status"] = response.status_code
                result["protocol"] = protocol.upper()
                result["response_time"] = round((end_time - start_time) * 1000)  # ms
                
                # Headers
                result["server"] = response.headers.get("server", "")
                result["content_type"] = response.headers.get("content-type", "")
                result["content_length"] = len(response.content)
                
                # Store important headers
                important_headers = ["x-powered-by", "x-frame-options", "x-xss-protection", 
                                   "content-security-policy", "strict-transport-security",
                                   "x-content-type-options", "access-control-allow-origin"]
                for h in important_headers:
                    if h in response.headers:
                        result["headers"][h] = response.headers[h]
                
                # Cookies
                for cookie in response.cookies.jar:
                    result["cookies"].append({
                        "name": cookie.name,
                        "secure": cookie.secure,
                        "httponly": "httponly" in str(cookie).lower()
                    })
                
                # Redirect chain
                if response.history:
                    for r in response.history:
                        result["redirect_chain"].append({
                            "url": str(r.url),
                            "status": r.status_code
                        })
                
                # Extract title
                title_match = re.search(r"<title[^>]*>([^<]+)</title>", response.text, re.IGNORECASE)
                if title_match:
                    result["title"] = title_match.group(1).strip()[:100]
                
                # Extract meta description
                desc_match = re.search(r'<meta[^>]*name=["\']description["\'][^>]*content=["\']([^"\']+)["\']', response.text, re.IGNORECASE)
                if desc_match:
                    result["meta_description"] = desc_match.group(1).strip()[:200]
                
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
    """Probe all subdomains."""
    results = []
    semaphore = asyncio.Semaphore(concurrency)
    
    async def probe(sub: str):
        async with semaphore:
            result = await probe_http(sub)
            results.append(result)
            if result["alive"] and not quiet:
                status_color = Colors.GREEN if result["status"] == 200 else Colors.YELLOW
                tech_str = f" [{', '.join(result['tech'][:3])}]" if result["tech"] else ""
                ip_str = f" ({result['ip']})" if result['ip'] else ""
                print(f"  {Colors.GREEN}●{Colors.RESET} [{status_color}{result['status']}{Colors.RESET}] {result['url']}{Colors.DIM}{ip_str}{tech_str}{Colors.RESET}")
    
    tasks = [probe(sub) for sub in subdomains]
    await asyncio.gather(*tasks, return_exceptions=True)
    return results
