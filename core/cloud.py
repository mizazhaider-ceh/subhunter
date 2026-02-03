"""
Cloud Provider Detection Module - SubHunter v4.0

Identifies which cloud provider hosts a subdomain based on:
- CNAME records (e.g., *.amazonaws.com, *.azure.com)
- IP address ranges
- Response headers (already detected in probe.py)
"""
import re
from dataclasses import dataclass
from typing import Optional, List, Dict
from enum import Enum


class CloudProvider(Enum):
    """Supported cloud providers."""
    AWS = "AWS"
    AZURE = "Azure"
    GCP = "GCP"
    CLOUDFLARE = "Cloudflare"
    DIGITALOCEAN = "DigitalOcean"
    HEROKU = "Heroku"
    NETLIFY = "Netlify"
    VERCEL = "Vercel"
    FASTLY = "Fastly"
    AKAMAI = "Akamai"
    GITHUB = "GitHub"
    UNKNOWN = None


@dataclass
class CloudSignature:
    """Signature patterns for cloud provider detection."""
    cname_patterns: List[str]
    ip_prefixes: List[str]
    header_signatures: List[str]


# Cloud provider detection signatures
CLOUD_SIGNATURES: Dict[CloudProvider, CloudSignature] = {
    CloudProvider.AWS: CloudSignature(
        cname_patterns=[
            r"\.amazonaws\.com$",
            r"\.aws\.amazon\.com$",
            r"\.elb\.amazonaws\.com$",
            r"\.s3\.amazonaws\.com$",
            r"\.s3-[a-z0-9-]+\.amazonaws\.com$",
            r"\.cloudfront\.net$",
            r"\.elasticbeanstalk\.com$",
            r"\.awsglobalaccelerator\.com$",
        ],
        ip_prefixes=["3.", "13.", "18.", "35.", "52.", "54.", "99.", "100."],
        header_signatures=["x-amz", "aws", "amazon"]
    ),
    CloudProvider.AZURE: CloudSignature(
        cname_patterns=[
            r"\.azure\.com$",
            r"\.azurewebsites\.net$",
            r"\.blob\.core\.windows\.net$",
            r"\.cloudapp\.azure\.com$",
            r"\.azureedge\.net$",
            r"\.azure-api\.net$",
            r"\.trafficmanager\.net$",
            r"\.windows\.net$",
        ],
        ip_prefixes=["13.", "20.", "23.", "40.", "51.", "52.", "65.", "104."],
        header_signatures=["azure", "microsoft"]
    ),
    CloudProvider.GCP: CloudSignature(
        cname_patterns=[
            r"\.googleapis\.com$",
            r"\.run\.app$",
            r"\.appspot\.com$",
            r"\.cloudfunctions\.net$",
            r"\.googleusercontent\.com$",
            r"\.storage\.googleapis\.com$",
            r"\.web\.app$",
            r"\.firebaseapp\.com$",
        ],
        ip_prefixes=["34.", "35.", "104.", "108.", "130.", "142."],
        header_signatures=["gcp", "google", "gfe"]
    ),
    CloudProvider.CLOUDFLARE: CloudSignature(
        cname_patterns=[
            r"\.cdn\.cloudflare\.net$",
            r"\.cloudflare\.com$",
            r"\.cloudflaressl\.com$",
        ],
        ip_prefixes=["104.16.", "104.17.", "104.18.", "104.19.", "104.20.", 
                     "104.21.", "104.22.", "104.23.", "104.24.", "104.25.",
                     "172.67.", "173.245.", "103.21.", "103.22.", "103.31.",
                     "141.101.", "108.162.", "190.93.", "188.114.", "197.234.",
                     "198.41.", "162.158.", "162.159."],
        header_signatures=["cloudflare", "cf-ray", "cf-cache-status"]
    ),
    CloudProvider.DIGITALOCEAN: CloudSignature(
        cname_patterns=[
            r"\.digitaloceanspaces\.com$",
            r"\.ondigitalocean\.app$",
        ],
        ip_prefixes=["134.209.", "138.68.", "139.59.", "142.93.", "157.230.",
                     "159.65.", "161.35.", "164.90.", "165.22.", "167.172.",
                     "167.99.", "174.138.", "178.128.", "178.62.", "188.166.",
                     "192.241.", "198.199.", "206.189.", "209.97.", "45.55.",
                     "46.101.", "64.225.", "68.183."],
        header_signatures=["digitalocean"]
    ),
    CloudProvider.HEROKU: CloudSignature(
        cname_patterns=[
            r"\.herokuapp\.com$",
            r"\.herokussl\.com$",
            r"\.herokudns\.com$",
        ],
        ip_prefixes=[],
        header_signatures=["heroku"]
    ),
    CloudProvider.NETLIFY: CloudSignature(
        cname_patterns=[
            r"\.netlify\.app$",
            r"\.netlify\.com$",
            r"\.bitballoon\.com$",
        ],
        ip_prefixes=["75.2.", "99.83.", "104."],
        header_signatures=["netlify"]
    ),
    CloudProvider.VERCEL: CloudSignature(
        cname_patterns=[
            r"\.vercel\.app$",
            r"\.now\.sh$",
            r"\.vercel\.com$",
        ],
        ip_prefixes=["76.76."],
        header_signatures=["vercel", "x-vercel"]
    ),
    CloudProvider.FASTLY: CloudSignature(
        cname_patterns=[
            r"\.fastly\.net$",
            r"\.fastlylb\.net$",
        ],
        ip_prefixes=["151.101.", "199.232."],
        header_signatures=["fastly", "x-served-by", "x-cache"]
    ),
    CloudProvider.AKAMAI: CloudSignature(
        cname_patterns=[
            r"\.akamai\.net$",
            r"\.akamaitechnologies\.com$",
            r"\.akamaiedge\.net$",
            r"\.akamaized\.net$",
        ],
        ip_prefixes=["23.", "104."],
        header_signatures=["akamai"]
    ),
    CloudProvider.GITHUB: CloudSignature(
        cname_patterns=[
            r"\.github\.io$",
            r"\.githubusercontent\.com$",
        ],
        ip_prefixes=["185.199."],
        header_signatures=["github"]
    ),
}


def detect_cloud_from_cname(cname: str) -> Optional[str]:
    """
    Detect cloud provider from CNAME record.
    
    Args:
        cname: The CNAME value (e.g., "example.s3.amazonaws.com")
        
    Returns:
        Cloud provider name or None
    """
    if not cname:
        return None
        
    cname_lower = cname.lower()
    
    for provider, signature in CLOUD_SIGNATURES.items():
        for pattern in signature.cname_patterns:
            if re.search(pattern, cname_lower):
                return provider.value
    
    return None


def detect_cloud_from_ip(ip: str) -> Optional[str]:
    """
    Detect cloud provider from IP address prefix.
    
    Note: This is a best-effort detection based on common IP ranges.
    For accurate detection, use CNAME or headers.
    
    Args:
        ip: The IP address
        
    Returns:
        Cloud provider name or None
    """
    if not ip:
        return None
    
    # Cloudflare first (more specific prefixes)
    for prefix in CLOUD_SIGNATURES[CloudProvider.CLOUDFLARE].ip_prefixes:
        if ip.startswith(prefix):
            return CloudProvider.CLOUDFLARE.value
    
    # Then check others
    for provider, signature in CLOUD_SIGNATURES.items():
        if provider == CloudProvider.CLOUDFLARE:
            continue
        for prefix in signature.ip_prefixes:
            if ip.startswith(prefix):
                return provider.value
    
    return None


def detect_cloud_from_headers(headers: dict) -> Optional[str]:
    """
    Detect cloud provider from HTTP response headers.
    
    Args:
        headers: Dict of HTTP response headers
        
    Returns:
        Cloud provider name or None
    """
    if not headers:
        return None
    
    headers_str = str(headers).lower()
    
    for provider, signature in CLOUD_SIGNATURES.items():
        for sig in signature.header_signatures:
            if sig in headers_str:
                return provider.value
    
    return None


def detect_cloud_provider(
    ip: str = None,
    cname: str = None,
    headers: dict = None
) -> Optional[str]:
    """
    Detect cloud provider using all available signals.
    
    Priority: CNAME > Headers > IP
    
    Args:
        ip: IP address of the subdomain
        cname: CNAME record if available
        headers: HTTP response headers
        
    Returns:
        Cloud provider name or None
    """
    # CNAME is most reliable
    if cname:
        provider = detect_cloud_from_cname(cname)
        if provider:
            return provider
    
    # Headers are next most reliable
    if headers:
        provider = detect_cloud_from_headers(headers)
        if provider:
            return provider
    
    # IP is least reliable (many false positives possible)
    if ip:
        provider = detect_cloud_from_ip(ip)
        if provider:
            return provider
    
    return None


# Cloud provider colors for display
CLOUD_COLORS = {
    "AWS": "\033[38;5;208m",       # Orange
    "Azure": "\033[38;5;33m",       # Blue
    "GCP": "\033[38;5;196m",        # Red
    "Cloudflare": "\033[38;5;214m", # Orange-yellow
    "DigitalOcean": "\033[38;5;33m",# Blue
    "Heroku": "\033[38;5;93m",      # Purple
    "Netlify": "\033[38;5;45m",     # Cyan
    "Vercel": "\033[38;5;255m",     # White
    "Fastly": "\033[38;5;196m",     # Red
    "Akamai": "\033[38;5;33m",      # Blue
    "GitHub": "\033[38;5;255m",     # White
}


def get_cloud_color(provider: str) -> str:
    """Get ANSI color code for a cloud provider."""
    return CLOUD_COLORS.get(provider, "\033[0m")
