"""
HTML Report Generator - Premium Dark Theme with Full Details
"""
from datetime import datetime
from pathlib import Path
from typing import List, Dict
from utils.display import VERSION


def generate_html_report(
    domain: str,
    probe_results: List[Dict],
    port_results: List[Dict] = None,
    screenshot_results: List[Dict] = None,
    output_path: str = None
) -> str:
    """Generate a premium HTML report with all discovered details."""
    
    alive = [r for r in probe_results if r.get("alive")]
    dead = [r for r in probe_results if not r.get("alive")]
    
    # Count technologies
    tech_counts = {}
    for r in alive:
        for tech in r.get("tech", []):
            tech_counts[tech] = tech_counts.get(tech, 0) + 1
    
    # Status code distribution
    status_counts = {}
    for r in alive:
        status = r.get("status", 0)
        status_counts[status] = status_counts.get(status, 0) + 1
    
    # Port stats
    ports_found = 0
    hosts_with_ports = []
    port_distribution = {}
    if port_results:
        hosts_with_ports = [r for r in port_results if r.get("open_ports")]
        for r in port_results:
            for p in r.get("open_ports", []):
                ports_found += 1
                port_distribution[p] = port_distribution.get(p, 0) + 1
    
    # Average response time
    response_times = [r.get("response_time", 0) for r in alive if r.get("response_time")]
    avg_response_time = round(sum(response_times) / len(response_times)) if response_times else 0
    
    # Server distribution
    server_counts = {}
    for r in alive:
        server = r.get("server", "Unknown") or "Unknown"
        server = server.split("/")[0]  # Just the server name
        server_counts[server] = server_counts.get(server, 0) + 1
    
    # Protocol distribution
    https_count = len([r for r in alive if r.get("protocol") == "HTTPS"])
    http_count = len([r for r in alive if r.get("protocol") == "HTTP"])
    
    # Unique IPs
    unique_ips = set(r.get("ip") for r in alive if r.get("ip"))
    
    # Generate status code chart data
    status_chart = ""
    if status_counts:
        max_count = max(status_counts.values())
        for status, count in sorted(status_counts.items()):
            width = int((count / max_count) * 100)
            color = "#00ff88" if status == 200 else "#ffc107" if status in [301, 302, 307] else "#ff5252"
            status_chart += f'<div class="bar-row"><span class="bar-label">{status}</span><div class="bar" style="width: {width}%; background: {color};"></div><span class="bar-value">{count}</span></div>'
    
    # Format content size
    def format_size(size):
        if size > 1024*1024:
            return f"{size/(1024*1024):.1f} MB"
        elif size > 1024:
            return f"{size/1024:.1f} KB"
        return f"{size} B"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SubHunter Report - {domain}</title>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {{
            --primary: #00ff88;
            --primary-dim: rgba(0, 255, 136, 0.1);
            --secondary: #8b5cf6;
            --danger: #ff5252;
            --warning: #ffc107;
            --info: #3b82f6;
            --bg-dark: #0a0a1a;
            --bg-card: rgba(255, 255, 255, 0.03);
            --border: rgba(255, 255, 255, 0.08);
            --text: #e0e0e0;
            --text-dim: #666;
        }}
        
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        
        body {{
            font-family: 'Inter', system-ui, sans-serif;
            background: var(--bg-dark);
            color: var(--text);
            min-height: 100vh;
            line-height: 1.6;
        }}
        
        .bg-gradient {{
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: 
                radial-gradient(circle at 20% 80%, rgba(0, 255, 136, 0.08) 0%, transparent 50%),
                radial-gradient(circle at 80% 20%, rgba(139, 92, 246, 0.08) 0%, transparent 50%),
                radial-gradient(circle at 40% 40%, rgba(255, 82, 82, 0.05) 0%, transparent 50%);
            z-index: -1;
            animation: pulse 10s ease-in-out infinite;
        }}
        
        @keyframes pulse {{
            0%, 100% {{ opacity: 1; }}
            50% {{ opacity: 0.7; }}
        }}
        
        .container {{ max-width: 1600px; margin: 0 auto; padding: 30px; }}
        
        .header {{
            text-align: center;
            padding: 50px 30px;
            margin-bottom: 40px;
            background: rgba(255, 255, 255, 0.02);
            backdrop-filter: blur(10px);
            border-radius: 24px;
            border: 1px solid var(--border);
            position: relative;
            overflow: hidden;
        }}
        
        .header::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 3px;
            background: linear-gradient(90deg, var(--primary), var(--secondary), var(--primary));
            background-size: 200% 100%;
            animation: shimmer 3s linear infinite;
        }}
        
        @keyframes shimmer {{
            0% {{ background-position: -200% 0; }}
            100% {{ background-position: 200% 0; }}
        }}
        
        .header .logo {{
            font-size: 3.5em;
            font-weight: 700;
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }}
        
        .header .domain {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 1.4em;
            color: var(--primary);
            padding: 8px 20px;
            background: var(--primary-dim);
            border-radius: 30px;
            display: inline-block;
            margin-top: 15px;
        }}
        
        .header .meta {{ margin-top: 20px; color: var(--text-dim); font-size: 0.9em; }}
        .header .branding {{ margin-top: 20px; font-size: 0.85em; color: var(--text-dim); }}
        .header .branding span {{ color: var(--primary); font-weight: 600; }}
        
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin-bottom: 40px;
        }}
        
        .stat-card {{
            background: var(--bg-card);
            backdrop-filter: blur(10px);
            border-radius: 16px;
            padding: 20px;
            text-align: center;
            border: 1px solid var(--border);
            transition: all 0.3s ease;
        }}
        
        .stat-card:hover {{
            transform: translateY(-3px);
            border-color: var(--primary);
        }}
        
        .stat-card .icon {{ font-size: 1.5em; margin-bottom: 8px; }}
        .stat-card .number {{
            font-size: 2em;
            font-weight: 700;
            background: linear-gradient(135deg, #fff, var(--primary));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }}
        .stat-card .label {{
            color: var(--text-dim);
            text-transform: uppercase;
            letter-spacing: 1px;
            font-size: 0.7em;
            margin-top: 5px;
        }}
        
        .section {{
            background: var(--bg-card);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 25px;
            margin-bottom: 25px;
            border: 1px solid var(--border);
        }}
        
        .section h2 {{
            color: var(--primary);
            margin-bottom: 20px;
            font-size: 1.2em;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        
        .grid-2 {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }}
        .grid-3 {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px; }}
        
        .mini-card {{
            background: rgba(0,0,0,0.2);
            border-radius: 12px;
            padding: 15px;
            border: 1px solid var(--border);
        }}
        .mini-card h3 {{ color: var(--primary); font-size: 0.9em; margin-bottom: 10px; }}
        .mini-card .list {{ font-size: 0.85em; }}
        .mini-card .list-item {{ padding: 5px 0; border-bottom: 1px solid rgba(255,255,255,0.05); display: flex; justify-content: space-between; }}
        .mini-card .list-item:last-child {{ border-bottom: none; }}
        
        .tech-grid {{ display: flex; flex-wrap: wrap; gap: 8px; }}
        .tech-tag {{
            padding: 8px 15px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 500;
            background: linear-gradient(135deg, rgba(139, 92, 246, 0.2), rgba(0, 255, 136, 0.1));
            border: 1px solid rgba(139, 92, 246, 0.3);
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        .tech-tag .count {{ background: var(--secondary); color: #000; padding: 2px 8px; border-radius: 10px; font-size: 0.75em; font-weight: 700; }}
        
        .bar-chart {{ display: flex; flex-direction: column; gap: 10px; }}
        .bar-row {{ display: flex; align-items: center; gap: 12px; }}
        .bar-label {{ width: 50px; font-family: 'JetBrains Mono', monospace; font-weight: 600; font-size: 0.9em; }}
        .bar {{ height: 25px; border-radius: 12px; min-width: 15px; }}
        .bar-value {{ font-weight: 600; color: var(--text-dim); font-size: 0.85em; }}
        
        .table-container {{ overflow-x: auto; border-radius: 12px; }}
        table {{ width: 100%; border-collapse: collapse; font-size: 0.85em; }}
        th, td {{ padding: 12px 15px; text-align: left; border-bottom: 1px solid var(--border); }}
        th {{ background: rgba(0, 255, 136, 0.05); color: var(--primary); font-weight: 600; text-transform: uppercase; font-size: 0.75em; letter-spacing: 1px; position: sticky; top: 0; }}
        tr:hover {{ background: rgba(255, 255, 255, 0.02); }}
        
        .status {{ padding: 4px 12px; border-radius: 15px; font-size: 0.8em; font-weight: 600; font-family: 'JetBrains Mono', monospace; }}
        .status-200 {{ background: rgba(0, 255, 136, 0.15); color: var(--primary); }}
        .status-301, .status-302, .status-307, .status-308 {{ background: rgba(255, 193, 7, 0.15); color: var(--warning); }}
        .status-400, .status-401, .status-403, .status-404, .status-500, .status-502, .status-503 {{ background: rgba(255, 82, 82, 0.15); color: var(--danger); }}
        
        .badge {{ display: inline-block; padding: 3px 10px; margin: 2px; border-radius: 12px; font-size: 0.7em; font-weight: 500; }}
        .tech-badge {{ background: rgba(139, 92, 246, 0.15); color: #a78bfa; }}
        .port-badge {{ background: rgba(255, 82, 82, 0.15); color: #ff8888; font-family: 'JetBrains Mono', monospace; }}
        .ip-badge {{ background: rgba(59, 130, 246, 0.15); color: #60a5fa; font-family: 'JetBrains Mono', monospace; }}
        .time-badge {{ background: rgba(0, 255, 136, 0.1); color: var(--primary); }}
        .size-badge {{ background: rgba(255, 193, 7, 0.1); color: var(--warning); }}
        
        a {{ color: var(--primary); text-decoration: none; }}
        a:hover {{ color: #fff; text-shadow: 0 0 10px var(--primary); }}
        
        .expandable {{ cursor: pointer; }}
        .expandable-content {{ display: none; margin-top: 10px; padding: 10px; background: rgba(0,0,0,0.2); border-radius: 8px; font-size: 0.85em; }}
        .expandable.open .expandable-content {{ display: block; }}
        
        .header-row {{ display: flex; gap: 5px; flex-wrap: wrap; }}
        .header-badge {{ background: rgba(59, 130, 246, 0.1); color: #60a5fa; padding: 2px 8px; border-radius: 8px; font-size: 0.7em; }}
        
        .screenshot-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(350px, 1fr)); gap: 20px; }}
        .screenshot-card {{ background: rgba(0, 0, 0, 0.3); border-radius: 15px; overflow: hidden; border: 1px solid var(--border); transition: all 0.3s ease; }}
        .screenshot-card:hover {{ transform: scale(1.02); border-color: var(--primary); box-shadow: 0 10px 30px rgba(0, 255, 136, 0.2); }}
        .screenshot-card img {{ width: 100%; height: auto; display: block; }}
        .screenshot-card .caption {{ padding: 12px; font-size: 0.8em; color: var(--text-dim); font-family: 'JetBrains Mono', monospace; word-break: break-all; }}
        
        .dead-list {{ max-height: 200px; overflow-y: auto; font-family: 'JetBrains Mono', monospace; font-size: 0.8em; color: var(--text-dim); }}
        .dead-item {{ padding: 3px 0; }}
        
        .footer {{ text-align: center; padding: 40px; color: var(--text-dim); border-top: 1px solid var(--border); margin-top: 40px; }}
        .footer .brand {{ font-size: 1.2em; color: var(--primary); font-weight: 600; margin-bottom: 10px; }}
        
        @media (max-width: 768px) {{
            .container {{ padding: 15px; }}
            .header .logo {{ font-size: 2em; }}
            .stat-card .number {{ font-size: 1.5em; }}
            th, td {{ padding: 8px; font-size: 0.75em; }}
        }}
    </style>
</head>
<body>
    <div class="bg-gradient"></div>
    <div class="container">
        <div class="header">
            <div class="logo">🎯 SubHunter Report</div>
            <div class="domain">{domain}</div>
            <div class="meta">
                Generated: {datetime.now().strftime('%B %d, %Y at %H:%M:%S')} | Version {VERSION}
            </div>
            <div class="branding">
                Built by <span>MIHx0</span> (Mizaz Haider) • Powered by <span>The PenTrix</span>
            </div>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <div class="icon">🔍</div>
                <div class="number">{len(probe_results)}</div>
                <div class="label">Total Found</div>
            </div>
            <div class="stat-card">
                <div class="icon">✅</div>
                <div class="number">{len(alive)}</div>
                <div class="label">Alive</div>
            </div>
            <div class="stat-card">
                <div class="icon">❌</div>
                <div class="number">{len(dead)}</div>
                <div class="label">Dead</div>
            </div>
            <div class="stat-card">
                <div class="icon">🌐</div>
                <div class="number">{len(unique_ips)}</div>
                <div class="label">Unique IPs</div>
            </div>
            <div class="stat-card">
                <div class="icon">🔧</div>
                <div class="number">{len(tech_counts)}</div>
                <div class="label">Technologies</div>
            </div>
            <div class="stat-card">
                <div class="icon">🔐</div>
                <div class="number">{https_count}</div>
                <div class="label">HTTPS</div>
            </div>
            <div class="stat-card">
                <div class="icon">⚡</div>
                <div class="number">{avg_response_time}</div>
                <div class="label">Avg ms</div>
            </div>
            <div class="stat-card">
                <div class="icon">🔓</div>
                <div class="number">{ports_found}</div>
                <div class="label">Open Ports</div>
            </div>
        </div>
        
        <div class="grid-2">
            <div class="section">
                <h2>📊 Status Codes</h2>
                <div class="bar-chart">
                    {status_chart if status_chart else '<div class="text-dim">No data</div>'}
                </div>
            </div>
            
            <div class="section">
                <h2>🖥️ Server Distribution</h2>
                <div class="tech-grid">
                    {"".join(f'<div class="tech-tag">{server}<span class="count">{count}</span></div>' for server, count in sorted(server_counts.items(), key=lambda x: -x[1])[:10])}
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2>🔧 Technologies Detected ({len(tech_counts)})</h2>
            <div class="tech-grid">
                {"".join(f'<div class="tech-tag">{tech}<span class="count">{count}</span></div>' for tech, count in sorted(tech_counts.items(), key=lambda x: -x[1]))}
            </div>
        </div>
        
        <div class="section">
            <h2>🌐 Live Subdomains ({len(alive)})</h2>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>Subdomain</th>
                            <th>IP</th>
                            <th>Status</th>
                            <th>Title</th>
                            <th>Size</th>
                            <th>Time</th>
                            <th>Technologies</th>
                            <th>Server</th>
                        </tr>
                    </thead>
                    <tbody>
                        {"".join(f'''<tr>
                            <td><a href="{r.get('url', '#')}" target="_blank">{r['subdomain']}</a></td>
                            <td><span class="badge ip-badge">{r.get('ip', '-') or '-'}</span></td>
                            <td><span class="status status-{r.get('status', 0)}">{r.get('status', '-')}</span></td>
                            <td>{(r.get('title') or '-')[:40]}</td>
                            <td><span class="badge size-badge">{format_size(r.get('content_length', 0))}</span></td>
                            <td><span class="badge time-badge">{r.get('response_time', 0)}ms</span></td>
                            <td>{"".join(f'<span class="badge tech-badge">{t}</span>' for t in r.get('tech', [])[:4])}</td>
                            <td>{(r.get('server', '-') or '-')[:20]}</td>
                        </tr>''' for r in sorted(alive, key=lambda x: x['subdomain']))}
                    </tbody>
                </table>
            </div>
        </div>
"""
    
    # Security headers section
    security_headers_data = []
    for r in alive:
        headers = r.get("headers", {})
        if headers:
            security_headers_data.append({
                "subdomain": r["subdomain"],
                "headers": headers
            })
    
    if security_headers_data:
        html += f"""
        <div class="section">
            <h2>🛡️ Security Headers ({len(security_headers_data)} hosts with headers)</h2>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>Subdomain</th>
                            <th>Security Headers Found</th>
                        </tr>
                    </thead>
                    <tbody>
                        {"".join(f'''<tr>
                            <td>{h['subdomain']}</td>
                            <td><div class="header-row">{"".join(f'<span class="header-badge">{k}</span>' for k in h['headers'].keys())}</div></td>
                        </tr>''' for h in security_headers_data[:50])}
                    </tbody>
                </table>
            </div>
        </div>
"""
    
    # Redirects section
    redirects = [r for r in alive if r.get("redirect_chain")]
    if redirects:
        html += f"""
        <div class="section">
            <h2>🔀 Redirects ({len(redirects)} hosts)</h2>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>Original</th>
                            <th>Final URL</th>
                            <th>Chain</th>
                        </tr>
                    </thead>
                    <tbody>
                        {"".join(f'''<tr>
                            <td>{r['subdomain']}</td>
                            <td><a href="{r.get('final_url', '#')}" target="_blank">{(r.get('final_url') or '-')[:50]}</a></td>
                            <td>{len(r.get('redirect_chain', []))} redirect(s)</td>
                        </tr>''' for r in redirects[:30])}
                    </tbody>
                </table>
            </div>
        </div>
"""
    
    # Port results section
    if hosts_with_ports:
        port_dist_html = "".join(f'<div class="list-item"><span>Port {p}</span><span>{c}</span></div>' for p, c in sorted(port_distribution.items(), key=lambda x: -x[1])[:10])
        
        hosts_html = ""
        for r in hosts_with_ports[:10]:
            port_badges = "".join(f'<span class="badge port-badge">{p}</span>' for p in r["open_ports"][:5])
            hosts_html += f'<div class="list-item"><span>{r["host"]}</span><span>{port_badges}</span></div>'
        
        html += f"""
        <div class="section">
            <h2>🔐 Open Ports ({len(hosts_with_ports)} hosts, {ports_found} total ports)</h2>
            <div class="grid-2">
                <div class="mini-card">
                    <h3>Port Distribution</h3>
                    <div class="list">
                        {port_dist_html}
                    </div>
                </div>
                <div class="mini-card">
                    <h3>Hosts</h3>
                    <div class="list">
                        {hosts_html}
                    </div>
                </div>
            </div>
        </div>
"""
    
    # Screenshots section
    if screenshot_results:
        screenshots_with_b64 = [s for s in screenshot_results if s.get("base64")]
        if screenshots_with_b64:
            screenshot_cards = ""
            for s in screenshots_with_b64[:20]:
                url = s.get("url", "Unknown")
                b64 = s.get("base64", "")
                screenshot_cards += f'''
                <div class="screenshot-card">
                    <img src="data:image/png;base64,{b64}" alt="{url}" loading="lazy">
                    <div class="caption">{url}</div>
                </div>'''
            
            html += f"""
        <div class="section">
            <h2>📸 Screenshots ({len(screenshots_with_b64)})</h2>
            <div class="screenshot-grid">
                {screenshot_cards}
            </div>
        </div>
"""
    
    # Dead subdomains section
    if dead:
        html += f"""
        <div class="section">
            <h2>❌ Dead Subdomains ({len(dead)})</h2>
            <div class="dead-list">
                {"".join(f'<div class="dead-item">{r["subdomain"]}</div>' for r in dead[:100])}
                {f'<div class="dead-item">...and {len(dead) - 100} more</div>' if len(dead) > 100 else ''}
            </div>
        </div>
"""
    
    html += f"""
        <div class="footer">
            <div class="brand">SubHunter v{VERSION}</div>
            <p>Built by MIHx0 (Mizaz Haider) • Powered by The PenTrix</p>
            <p style="margin-top: 10px; font-size: 0.85em;">For authorized security testing only</p>
        </div>
    </div>
    
    <script>
        // Toggle expandable sections
        document.querySelectorAll('.expandable').forEach(el => {{
            el.addEventListener('click', () => el.classList.toggle('open'));
        }});
    </script>
</body>
</html>"""
    
    if output_path:
        Path(output_path).write_text(html, encoding="utf-8")
    
    return html
