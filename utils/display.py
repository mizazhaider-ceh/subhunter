"""
Colors and display utilities for SubHunter v4.0
"""

class Colors:
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'


VERSION = "4.0"


def print_banner():
    """Print the SubHunter banner."""
    print(f"""
{Colors.CYAN}
    ╔═╗╦ ╦╔╗ ╦ ╦╦ ╦╔╗╔╔╦╗╔═╗╦═╗
    ╚═╗║ ║╠╩╗╠═╣║ ║║║║ ║ ║╣ ╠╦╝
    ╚═╝╚═╝╚═╝╩ ╩╚═╝╝╚╝ ╩ ╚═╝╩╚═  {Colors.YELLOW}v{VERSION} PRO{Colors.CYAN}
{Colors.RESET}
    {Colors.GREEN}▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓{Colors.RESET}
    {Colors.GREEN}▓{Colors.RESET}  {Colors.BOLD}Fast Subdomain Enumeration Tool - Pro Edition{Colors.RESET}       {Colors.GREEN}▓{Colors.RESET}
    {Colors.GREEN}▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓{Colors.RESET}
    {Colors.GREEN}▓{Colors.RESET}                                                    {Colors.GREEN}▓{Colors.RESET}
    {Colors.GREEN}▓{Colors.RESET}   {Colors.MAGENTA}◆ Built By  :{Colors.RESET} {Colors.BOLD}MIHx0{Colors.RESET} (Mizaz Haider)              {Colors.GREEN}▓{Colors.RESET}
    {Colors.GREEN}▓{Colors.RESET}   {Colors.MAGENTA}◆ Powered By:{Colors.RESET} {Colors.BOLD}The PenTrix{Colors.RESET}                       {Colors.GREEN}▓{Colors.RESET}
    {Colors.GREEN}▓{Colors.RESET}                                                    {Colors.GREEN}▓{Colors.RESET}
    {Colors.GREEN}▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓{Colors.RESET}
    
    {Colors.DIM}[ 🧠 Wildcard • 🔄 Recursive • ☁️ Cloud • 📡 Probe • 🔐 Ports • 📸 Screenshots ]{Colors.RESET}
""")

