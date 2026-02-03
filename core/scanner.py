"""
Port scanning module
"""
import asyncio
import socket
from typing import Set, List, Dict
from utils.display import Colors
from utils.config import COMMON_PORTS


async def port_scan(host: str, port: int, timeout: float = 1.0) -> bool:
    """Check if a port is open."""
    try:
        conn = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return True
    except:
        return False


async def scan_host_ports(host: str, ports: List[int] = None, timeout: float = 1.0) -> Dict:
    """Scan multiple ports on a host."""
    if ports is None:
        ports = COMMON_PORTS
    
    result = {
        "host": host,
        "open_ports": []
    }
    
    tasks = []
    for port in ports:
        tasks.append(port_scan(host, port, timeout))
    
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    for i, is_open in enumerate(results):
        if is_open is True:
            result["open_ports"].append(ports[i])
    
    return result


async def scan_all_ports(
    subdomains: Set[str],
    ports: List[int] = None,
    concurrency: int = 100,
    timeout: float = 1.0,
    quiet: bool = False
) -> List[Dict]:
    """Scan ports on all subdomains."""
    if ports is None:
        ports = COMMON_PORTS
    
    results = []
    semaphore = asyncio.Semaphore(concurrency)
    
    async def scan(sub: str):
        async with semaphore:
            result = await scan_host_ports(sub, ports, timeout)
            results.append(result)
            if result["open_ports"] and not quiet:
                ports_str = ", ".join(map(str, result["open_ports"]))
                print(f"  {Colors.GREEN}●{Colors.RESET} {sub}: {Colors.CYAN}{ports_str}{Colors.RESET}")
    
    tasks = [scan(sub) for sub in subdomains]
    await asyncio.gather(*tasks, return_exceptions=True)
    return results
