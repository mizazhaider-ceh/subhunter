"""
Configuration and constants for SubHunter
"""

# Technology signatures for detection
TECH_SIGNATURES = {
    "WordPress": [r"wp-content", r"wp-includes", r"wordpress"],
    "Nginx": [r"nginx", r"server: nginx"],
    "Apache": [r"apache", r"server: apache"],
    "Cloudflare": [r"cloudflare", r"cf-ray"],
    "AWS": [r"amazonaws", r"aws", r"x-amz"],
    "Azure": [r"azure", r"microsoft"],
    "React": [r"react", r"__NEXT_DATA__", r"_next"],
    "Vue.js": [r"vue", r"v-app"],
    "Angular": [r"ng-version", r"angular"],
    "Laravel": [r"laravel", r"x-powered-by: laravel"],
    "Django": [r"django", r"csrfmiddlewaretoken"],
    "Node.js": [r"express", r"x-powered-by: express"],
    "PHP": [r"x-powered-by: php", r"\.php"],
    "ASP.NET": [r"asp\.net", r"x-aspnet-version"],
    "jQuery": [r"jquery"],
    "Bootstrap": [r"bootstrap"],
    "Shopify": [r"shopify", r"cdn\.shopify"],
    "Wix": [r"wix\.com", r"wixsite"],
    "Squarespace": [r"squarespace"],
}

# Default subdomain wordlist
DEFAULT_WORDLIST = [
    "www", "mail", "ftp", "admin", "blog", "shop", "dev", "staging", "test",
    "api", "app", "m", "mobile", "beta", "portal", "secure", "vpn", "remote",
    "webmail", "email", "smtp", "pop", "imap", "ns1", "ns2", "ns3", "dns",
    "mx", "mx1", "mx2", "cdn", "static", "assets", "img", "images", "media",
    "video", "download", "upload", "files", "backup", "old", "new", "legacy",
    "demo", "stage", "uat", "qa", "prod", "production", "internal", "intranet",
    "extranet", "gateway", "proxy", "firewall", "auth", "login", "sso", "oauth",
    "dashboard", "panel", "control", "cpanel", "whm", "plesk", "admin2",
    "administrator", "manage", "manager", "cms", "wordpress", "wp", "joomla",
    "drupal", "magento", "store", "cart", "checkout", "pay", "payment", "billing",
]

# Common ports for scanning
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 8080, 8443]

# State file for resume
STATE_FILE = ".subhunter_state.json"
