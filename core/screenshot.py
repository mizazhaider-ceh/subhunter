"""
Screenshot module - Robust implementation
"""
import asyncio
import base64
from pathlib import Path
from typing import Set, List, Dict, Optional
from utils.display import Colors

# Try multiple screenshot methods
SCREENSHOT_AVAILABLE = False
SCREENSHOT_METHOD = None

# Try playwright first
try:
    from playwright.async_api import async_playwright
    SCREENSHOT_AVAILABLE = True
    SCREENSHOT_METHOD = "playwright"
except ImportError:
    pass

# Fallback to selenium
if not SCREENSHOT_AVAILABLE:
    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        SCREENSHOT_AVAILABLE = True
        SCREENSHOT_METHOD = "selenium"
    except ImportError:
        pass


async def take_screenshot_playwright(url: str, output_path: Path, timeout: int = 15000) -> Optional[str]:
    """Take screenshot using Playwright."""
    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=['--no-sandbox', '--disable-dev-shm-usage']
            )
            context = await browser.new_context(
                viewport={"width": 1920, "height": 1080},
                ignore_https_errors=True
            )
            page = await context.new_page()
            
            try:
                await page.goto(url, wait_until="domcontentloaded", timeout=timeout)
                await asyncio.sleep(1)  # Wait for page to settle
                await page.screenshot(path=str(output_path), full_page=False)
                await browser.close()
                return str(output_path)
            except Exception:
                await browser.close()
                return None
    except Exception:
        return None


def take_screenshot_selenium(url: str, output_path: Path) -> Optional[str]:
    """Take screenshot using Selenium (fallback)."""
    try:
        options = Options()
        options.add_argument('--headless')
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        options.add_argument('--window-size=1920,1080')
        options.add_argument('--ignore-certificate-errors')
        
        driver = webdriver.Chrome(options=options)
        driver.set_page_load_timeout(15)
        
        try:
            driver.get(url)
            driver.save_screenshot(str(output_path))
            driver.quit()
            return str(output_path)
        except:
            driver.quit()
            return None
    except:
        return None


async def take_screenshot(url: str, output_dir: Path, timeout: int = 15000) -> Optional[Dict]:
    """Take a screenshot of a URL."""
    if not SCREENSHOT_AVAILABLE:
        return None
    
    # Clean filename
    filename = url.replace("https://", "").replace("http://", "").replace("/", "_").replace(":", "_").replace("?", "_")[:100]
    filepath = output_dir / f"{filename}.png"
    
    result = None
    
    if SCREENSHOT_METHOD == "playwright":
        result = await take_screenshot_playwright(url, filepath, timeout)
    elif SCREENSHOT_METHOD == "selenium":
        # Run in executor since selenium is sync
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, take_screenshot_selenium, url, filepath)
    
    if result:
        # Also create base64 for embedding in HTML
        try:
            with open(result, "rb") as f:
                b64 = base64.b64encode(f.read()).decode('utf-8')
            return {
                "url": url,
                "path": result,
                "base64": b64
            }
        except:
            return {"url": url, "path": result, "base64": None}
    
    return None


async def take_all_screenshots(
    probe_results: List[Dict],
    output_dir: Path,
    concurrency: int = 3,
    quiet: bool = False
) -> List[Dict]:
    """Take screenshots of all alive subdomains."""
    
    if not SCREENSHOT_AVAILABLE:
        if not quiet:
            if SCREENSHOT_METHOD is None:
                print(f"  {Colors.YELLOW}[!]{Colors.RESET} Screenshots unavailable. Install: pip install playwright && playwright install chromium")
            return []
        return []
    
    output_dir.mkdir(parents=True, exist_ok=True)
    results = []
    semaphore = asyncio.Semaphore(concurrency)
    
    # Get alive hosts with URLs
    alive = [r for r in probe_results if r.get("alive") and r.get("url")]
    
    if not quiet:
        print(f"{Colors.DIM}    Taking screenshots of {min(len(alive), 30)} hosts (concurrency: {concurrency})...{Colors.RESET}\n")
    
    async def capture(result: Dict):
        async with semaphore:
            url = result["url"]
            screenshot = await take_screenshot(url, output_dir)
            if screenshot:
                results.append(screenshot)
                if not quiet:
                    print(f"  {Colors.GREEN}📸{Colors.RESET} {result['subdomain']}")
    
    # Limit to first 30 to avoid too many
    tasks = [capture(r) for r in alive[:30]]
    await asyncio.gather(*tasks, return_exceptions=True)
    
    return results


# Export availability info
PLAYWRIGHT_AVAILABLE = SCREENSHOT_AVAILABLE and SCREENSHOT_METHOD == "playwright"
