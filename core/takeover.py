
import aiodns
from typing import List, Dict, Set
from utils.display import Colors

# Fingerprints for common services
# Format: 'cname_substring': ['response_fingerprint']
TAKEOVER_SIGNATURES = {
    "github.io": ["There isn't a GitHub Pages site here", "404 There isn't a GitHub Pages site here"],
    "herokuapp.com": ["No such app", "There's nothing here, yet"],
    "amazonaws.com": ["NoSuchBucket", "The specified bucket does not exist"],
    "azurewebsites.net": ["404 Web Site not found"],
    "cloudapp.net": ["404 Web Site not found"],
    "visualstudio.com": ["404 Web Site not found"],
    "myshopify.com": ["Sorry, this shop is currently unavailable"],
    "wordpress.com": ["Do you want to register", "doesn't exist"],
    "tumblr.com": ["There's nothing here", "Whatever you were looking for doesn't currently exist at this address"],
    "cargo.site": ["404 Not Found"],
    "helprace.com": ["Alias not configured"],
    "desk.com": ["Please try again or try Desk.com"],
    "teamwork.com": ["Oops - We didn't find your site"],
    "helpscoutdocs.com": ["No settings were found for this company"],
    "ghost.io": ["The thing you were looking for is no longer here"],
    "surge.sh": ["project not found"],
    "pantheon.io": ["404 error unknown site"],
    "readme.io": ["Project doesnt exist... yet!"],
    "fastly.net": ["Fastly error: unknown domain"],
    "smartjobboard.com": ["This job board website is either expired or its domain name is invalid"],
    "uservoice.com": ["This UserVoice subdomain is currently available"],
    "zendesk.com": ["Help Center Closed"],
}

async def check_takeover(domain: str, subdomains: List[str], resolver: aiodns.DNSResolver, quiet: bool = False) -> List[Dict]:
    """
    Check for subdomain takeover vulnerabilities.
    Returns a list of vulnerable subdomains with details.
    """
    results = []
    
    if not quiet:
        print(f"\n{Colors.CYAN}[*] Phase 6: Checking for Subdomain Takeovers{Colors.RESET}")
    
    # Filter potential cnames first to avoid httpx spam if not needed
    # (Actually we can't easily filter by DNS without resolving again, 
    # but since main loop already resolved, maybe we could reuse `dns_results`?
    # For now, let's just re-resolve CNAMEs for the candidates or check checks)
    
    # We'll batch CNAME checks
    # Optimization: We check all alive subdomains
    
    tasks = []
    # Implementation detail: 'subdomains' here assumes we want to check all of them.
    # We'll query CNAME records.
    
    for sub in subdomains:
        try:
            # Resolving CNAME
            # Note: A pure A record implies no CNAME, but valid takeover vectors often mean
            # a CNAME points to a resource that was deleted.
            result = await resolver.query(sub, 'CNAME')
            cname_target = result.cname
            
            # Check signatures
            for sig, fingerprints in TAKEOVER_SIGNATURES.items():
                if sig in cname_target:
                    # Potential takeover! Now verify with HTTP request
                    # We return this candidate to be verified by a probe check
                    results.append({
                        "subdomain": sub,
                        "cname": cname_target,
                        "service": sig,
                        "fingerprints": fingerprints
                    })
                    break
                    
        except Exception:
            # No CNAME or resolution failed
            continue
            
    # Now verify candidates with HTTP
    # We need to make requests to see if the content matches signature
    if results and not quiet:
        print(f"  {Colors.YELLOW}⚠{Colors.RESET}  Found {len(results)} potential CNAME targets. Verifying...")
        
    verified = []
    
    import httpx
    async with httpx.AsyncClient(verify=False, timeout=5) as client:
        for candidate in results:
            try:
                url = f"http://{candidate['subdomain']}"
                response = await client.get(url)
                content = response.text
                
                # Check fingerprints
                is_vulnerable = False
                for fp in candidate['fingerprints']:
                    if fp in content:
                        is_vulnerable = True
                        break
                
                if is_vulnerable:
                    candidate['verified'] = True
                    verified.append(candidate)
                    if not quiet:
                         print(f"  {Colors.RED}[!] VULNERABLE: {candidate['subdomain']} -> {candidate['service']}{Colors.RESET}")
            except:
                pass

    return verified
