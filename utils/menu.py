
import sys
import os
from typing import Dict, List, Any
from .display import Colors, print_banner

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def get_input(prompt: str, default: str = None) -> str:
    """Get input with color and optional default value."""
    if default:
        p = f"{Colors.BOLD}{prompt} {Colors.DIM}[{default}]{Colors.RESET}: "
    else:
        p = f"{Colors.BOLD}{prompt}{Colors.RESET}: "
    
    try:
        val = input(p).strip()
        return val if val else default
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Cancelled{Colors.RESET}")
        sys.exit(0)

def print_checkbox_options(options: List[Dict], selected: List[bool], pointer: int):
    """Print the checkbox menu options."""
    print(f"\n{Colors.CYAN}Select features (Space to toggle, Enter to confirm, Up/Down to move):{Colors.RESET}\n")
    
    for i, option in enumerate(options):
        # Cursor
        cursor = f"{Colors.CYAN}➜{Colors.RESET}" if i == pointer else " "
        
        # Checkbox
        box = f"{Colors.GREEN}[✓]{Colors.RESET}" if selected[i] else f"{Colors.DIM}[ ]{Colors.RESET}"
        
        # Text style
        if i == pointer:
            name_style = f"{Colors.BOLD}{option['name']}{Colors.RESET}"
            desc_style = f"{Colors.CYAN}{option['desc']}{Colors.RESET}"
        else:
            name_style = option['name']
            desc_style = f"{Colors.DIM}{option['desc']}{Colors.RESET}"
            
        print(f"  {cursor} {box} {option['icon']} {name_style:<25} {desc_style}")

def interactive_menu() -> Dict[str, Any]:
    """
    Run the interactive TUI menu.
    Returns a dictionary of configuration options compatible with argparse args.
    """
    clear_screen()
    print_banner()
    
    print(f"\n{Colors.BG_BLUE}{Colors.BOLD} 🎯 INTERACTIVE MODE {Colors.RESET}\n")
    
    # Get Target Domain
    while True:
        domain = get_input("Enter target domain")
        if domain:
            break
        print(f"{Colors.RED}[!] Domain is required{Colors.RESET}")
    
    # Options setup
    options = [
        {"id": "brute", "name": "DNS Brute-force", "icon": "🔍", "desc": "Dictionary-based enumeration", "default": True},
        {"id": "probe", "name": "HTTP Probing", "icon": "📡", "desc": "Check for alive hosts & tech", "default": True},
        {"id": "ports", "name": "Port Scanning", "icon": "🔐", "desc": "Scan common ports (top 100)", "default": False},
        {"id": "screens", "name": "Screenshots", "icon": "📸", "desc": "Capture screenshots of pages", "default": False},
        {"id": "recurse", "name": "Recursive Scan", "icon": "🔄", "desc": "Find sub-subdomains (depth 2)", "default": False},
        {"id": "cloud", "name": "Cloud Detection", "icon": "☁️", "desc": "Identify cloud providers", "default": True},
        {"id": "takeover", "name": "Takeover Check", "icon": "🎯", "desc": "Check for vulnerable CNAMEs", "default": False},
        {"id": "vhost", "name": "VHost Discovery", "icon": "🌐", "desc": "Find hidden virtual hosts", "default": False},
        {"id": "jsparse", "name": "JS File Parsing", "icon": "📜", "desc": "Extract API endpoints from JS", "default": False},
    ]
    
    selected = [opt["default"] for opt in options]
    pointer = 0
    
    # Simple input loop for menu
    # Note: On Windows without generic cues, ‘msvcrt’ is standard for keypresses.
    # We will try to use a cross-platform approach if possible, but fallback to simple input if needed.
    # For robust interaction without heavy deps like curses/prompt_toolkit, we can use a simpler approach:
    # prompt the user to type Y/N or use a simple list selection if full TUI is hard.
    # However, let's try a simpler numbered list approach instead of full raw buffer control to avoid compatibility hell 
    # if `msvcrt` or `termios` behaves oddly in the user's specific shell environment.
    
    # ACTUALLY, sticking to a non-blocking key read is tricky cross-platform without deps.
    # Let's use a simpler prompt-based selection for maximum stability:
    
    print(f"{Colors.CYAN}Configure Scan Features:{Colors.RESET}")
    for i, opt in enumerate(options):
        status = "ON" if selected[i] else "OFF"
        color = Colors.GREEN if selected[i] else Colors.DIM
        print(f"  {i+1}. {opt['icon']} {opt['name']:<20} {color}[{status}]{Colors.RESET}")
    
    print(f"\n{Colors.DIM}Enter numbers to toggle (e.g. '3,4,7'). Press Enter to start.{Colors.RESET}")
    
    while True:
        choice = get_input("Toggle options", default="").strip()
        if not choice:
            break
        
        parts = choice.replace(',', ' ').split()
        for p in parts:
            if p.isdigit():
                idx = int(p) - 1
                if 0 <= idx < len(options):
                    selected[idx] = not selected[idx]
                    # Reprint state
                    status = "ON" if selected[idx] else "OFF"
                    color = Colors.GREEN if selected[idx] else Colors.RED
                    print(f"     {options[idx]['name']} -> {color}{status}{Colors.RESET}")
    
    # Other settings
    output_file = get_input("Output file (optional)", default=None)
    
    # Confirm
    print(f"\n{Colors.GREEN}{Colors.BOLD}🚀 Starting SubHunter on {domain}...{Colors.RESET}")
    
    # Construct args-like object
    config = {
        "domain": domain,
        "wordlist": None,
        "output": output_file,
        "html": None,
        "no_brute": not selected[0],
        "no_probe": not selected[1],
        "ports": selected[2],
        "screenshots": selected[3],
        "concurrency": 100,
        "quiet": False,
        "resume": False,
        "recursive": selected[4],
        "recursive_depth": 2,
        "no_wildcard_filter": False,
        # New v5.0 features
        "takeover": selected[6],
        "vhost": selected[7],
        "js_parse": selected[8]
    }
    
    return config
