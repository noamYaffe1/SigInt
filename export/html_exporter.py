"""HTML exporter for verification results with interactive filtering."""
import json
from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime
from verify.models import VerificationReport


def export_html(
    report: VerificationReport,
    output_path: Path,
    include_all: bool = True
) -> None:
    """Export verification results to interactive HTML.
    
    Args:
        report: The verification report
        output_path: Path to output HTML file
        include_all: Include all results (even score 0)
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Filter and sort results
    results = report.results
    if not include_all:
        results = [r for r in results if r.score > 0]
    results = sorted(results, key=lambda r: r.score, reverse=True)
    
    # Prepare data for JavaScript
    results_data = []
    for r in results:
        results_data.append({
            "url": r.url,  # Full URL with correct scheme (http/https)
            "ip": r.ip,
            "port": r.port,
            "scheme": r.scheme,
            "hostname": r.hostname or "",
            "score": r.score,
            "classification": r.classification,
            "matched_probes": r.matched_probes,
            "total_probes": r.total_probes,
            "country": r.location.get("country", "") if r.location else "",
            "city": r.location.get("city", "") if r.location else "",
            "hosting_provider": r.hosting_provider or "",
            "is_cloud_hosted": r.is_cloud_hosted,
            "organization": r.organization or "",
            "asn": r.asn or "",
            # TLS certificate info (for attribution)
            "tls_common_name": r.tls_common_name or "",
            "tls_subject_org": r.tls_subject_org or "",
            "tls_issuer": r.tls_issuer or "",
            "tls_issuer_org": r.tls_issuer_org or "",
            "tls_valid": r.tls_valid,
            "tls_self_signed": r.tls_self_signed,
            "tls_san": r.tls_san or [],
            "tls_emails": r.tls_emails or [],
            "tls_fingerprint": r.tls_fingerprint or "",
            "sources": r.sources,
            "verified_at": r.verified_at or "",
            "alternate_scheme_tried": r.alternate_scheme_tried
        })
    
    # Calculate stats
    stats = {
        "total": len(results),
        "verified": sum(1 for r in results if r.classification == "verified"),
        "likely": sum(1 for r in results if r.classification == "likely"),
        "partial": sum(1 for r in results if r.classification == "partial"),
        "unlikely": sum(1 for r in results if r.classification == "unlikely"),
        "no_match": sum(1 for r in results if r.classification == "no_match"),
    }
    
    # Get unique values for filters
    countries = sorted(set(r["country"] for r in results_data if r["country"]))
    providers = sorted(set(r["hosting_provider"] for r in results_data if r["hosting_provider"]))
    
    html = _generate_html(
        app_name=report.app_name,
        run_id=report.fingerprint_run_id,
        results_data=results_data,
        stats=stats,
        countries=countries,
        providers=providers,
        verification_time=report.verification_completed or datetime.now().isoformat()
    )
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html)
    
    print(f"[Export] HTML report saved to: {output_path}")
    print(f"         Total results: {len(results_data)}")


def _generate_html(
    app_name: str,
    run_id: str,
    results_data: List[Dict[str, Any]],
    stats: Dict[str, int],
    countries: List[str],
    providers: List[str],
    verification_time: str
) -> str:
    """Generate the HTML content."""
    
    return f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SigInt Report - {app_name}</title>
    <style>
        :root {{
            --bg-primary: #0d1117;
            --bg-secondary: #161b22;
            --bg-tertiary: #21262d;
            --border-color: #30363d;
            --text-primary: #e6edf3;
            --text-secondary: #8b949e;
            --accent-green: #3fb950;
            --accent-blue: #58a6ff;
            --accent-yellow: #d29922;
            --accent-orange: #db6d28;
            --accent-red: #f85149;
            --accent-purple: #a371f7;
        }}
        
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'SF Mono', 'Cascadia Code', 'Fira Code', monospace;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            min-height: 100vh;
        }}
        
        .container {{
            max-width: 1600px;
            margin: 0 auto;
            padding: 24px;
        }}
        
        header {{
            background: linear-gradient(135deg, var(--bg-secondary) 0%, var(--bg-tertiary) 100%);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 24px 32px;
            margin-bottom: 24px;
        }}
        
        h1 {{
            font-size: 28px;
            font-weight: 600;
            color: var(--accent-blue);
            margin-bottom: 8px;
            display: flex;
            align-items: center;
            gap: 12px;
        }}
        
        h1::before {{
            content: "◉";
            color: var(--accent-green);
        }}
        
        .meta {{
            color: var(--text-secondary);
            font-size: 13px;
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }}
        
        .stat-card {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 16px 20px;
            text-align: center;
            transition: transform 0.2s, border-color 0.2s;
        }}
        
        .stat-card:hover {{
            transform: translateY(-2px);
            border-color: var(--accent-blue);
        }}
        
        .stat-card.verified {{ border-left: 3px solid var(--accent-green); }}
        .stat-card.likely {{ border-left: 3px solid var(--accent-blue); }}
        .stat-card.partial {{ border-left: 3px solid var(--accent-yellow); }}
        .stat-card.unlikely {{ border-left: 3px solid var(--accent-orange); }}
        .stat-card.no_match {{ border-left: 3px solid var(--accent-red); }}
        
        .stat-value {{
            font-size: 32px;
            font-weight: 700;
            color: var(--text-primary);
        }}
        
        .stat-label {{
            font-size: 12px;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        
        .filters {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 16px 20px;
            margin-bottom: 24px;
            display: flex;
            flex-wrap: wrap;
            gap: 16px;
            align-items: center;
        }}
        
        .filter-group {{
            display: flex;
            flex-direction: column;
            gap: 4px;
        }}
        
        .filter-group label {{
            font-size: 11px;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        
        input, select {{
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 8px 12px;
            color: var(--text-primary);
            font-family: inherit;
            font-size: 13px;
            outline: none;
            transition: border-color 0.2s;
        }}
        
        input:focus, select:focus {{
            border-color: var(--accent-blue);
        }}
        
        input[type="text"] {{
            width: 200px;
        }}
        
        .results-count {{
            margin-left: auto;
            color: var(--text-secondary);
            font-size: 13px;
        }}
        
        .results-count span {{
            color: var(--accent-blue);
            font-weight: 600;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            overflow: hidden;
        }}
        
        th {{
            background: var(--bg-tertiary);
            padding: 12px 16px;
            text-align: left;
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: var(--text-secondary);
            border-bottom: 1px solid var(--border-color);
            cursor: pointer;
            user-select: none;
            white-space: nowrap;
        }}
        
        th:hover {{
            color: var(--accent-blue);
        }}
        
        th.sorted-asc::after {{ content: " ▲"; color: var(--accent-blue); }}
        th.sorted-desc::after {{ content: " ▼"; color: var(--accent-blue); }}
        
        td {{
            padding: 12px 16px;
            border-bottom: 1px solid var(--border-color);
            font-size: 13px;
        }}
        
        tr:hover {{
            background: var(--bg-tertiary);
        }}
        
        tr:last-child td {{
            border-bottom: none;
        }}
        
        .score {{
            font-weight: 700;
            padding: 4px 8px;
            border-radius: 4px;
            display: inline-block;
            min-width: 50px;
            text-align: center;
        }}
        
        .score.high {{ background: rgba(63, 185, 80, 0.2); color: var(--accent-green); }}
        .score.medium {{ background: rgba(88, 166, 255, 0.2); color: var(--accent-blue); }}
        .score.low {{ background: rgba(210, 153, 34, 0.2); color: var(--accent-yellow); }}
        .score.none {{ background: rgba(248, 81, 73, 0.2); color: var(--accent-red); }}
        
        .badge {{
            display: inline-block;
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: 500;
        }}
        
        .badge.verified {{ background: rgba(63, 185, 80, 0.2); color: var(--accent-green); }}
        .badge.likely {{ background: rgba(88, 166, 255, 0.2); color: var(--accent-blue); }}
        .badge.partial {{ background: rgba(210, 153, 34, 0.2); color: var(--accent-yellow); }}
        .badge.unlikely {{ background: rgba(219, 109, 40, 0.2); color: var(--accent-orange); }}
        .badge.no_match {{ background: rgba(248, 81, 73, 0.2); color: var(--accent-red); }}
        
        .badge.cloud {{ background: rgba(163, 113, 247, 0.2); color: var(--accent-purple); }}
        
        .ip-link {{
            color: var(--accent-blue);
            text-decoration: none;
        }}
        
        .ip-link:hover {{
            text-decoration: underline;
        }}
        
        .tls-info {{
            font-size: 11px;
            color: var(--text-secondary);
        }}
        
        .tls-info.valid {{ color: var(--accent-green); }}
        .tls-info.invalid {{ color: var(--accent-red); }}
        
        .empty-state {{
            text-align: center;
            padding: 48px;
            color: var(--text-secondary);
        }}
        
        footer {{
            text-align: center;
            padding: 24px;
            color: var(--text-secondary);
            font-size: 12px;
        }}
        
        @media (max-width: 1200px) {{
            .container {{ padding: 16px; }}
            .filters {{ flex-direction: column; align-items: stretch; }}
            .results-count {{ margin-left: 0; margin-top: 8px; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>{app_name}</h1>
            <div class="meta">
                Run ID: {run_id} | Verified: {verification_time[:19].replace('T', ' ')} UTC
            </div>
        </header>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value">{stats['total']}</div>
                <div class="stat-label">Total</div>
            </div>
            <div class="stat-card verified">
                <div class="stat-value">{stats['verified']}</div>
                <div class="stat-label">Verified</div>
            </div>
            <div class="stat-card likely">
                <div class="stat-value">{stats['likely']}</div>
                <div class="stat-label">Likely</div>
            </div>
            <div class="stat-card partial">
                <div class="stat-value">{stats['partial']}</div>
                <div class="stat-label">Partial</div>
            </div>
            <div class="stat-card unlikely">
                <div class="stat-value">{stats['unlikely']}</div>
                <div class="stat-label">Unlikely</div>
            </div>
            <div class="stat-card no_match">
                <div class="stat-value">{stats['no_match']}</div>
                <div class="stat-label">No Match</div>
            </div>
        </div>
        
        <div class="filters">
            <div class="filter-group">
                <label>Search</label>
                <input type="text" id="search" placeholder="IP, hostname, org...">
            </div>
            <div class="filter-group">
                <label>Classification</label>
                <select id="filter-class">
                    <option value="">All</option>
                    <option value="verified">Verified (≥80%)</option>
                    <option value="likely">Likely (≥60%)</option>
                    <option value="partial">Partial (≥40%)</option>
                    <option value="unlikely">Unlikely (>0%)</option>
                    <option value="no_match">No Match (0%)</option>
                </select>
            </div>
            <div class="filter-group">
                <label>Country</label>
                <select id="filter-country">
                    <option value="">All Countries</option>
                    {_generate_options(countries)}
                </select>
            </div>
            <div class="filter-group">
                <label>Provider</label>
                <select id="filter-provider">
                    <option value="">All Providers</option>
                    {_generate_options(providers)}
                </select>
            </div>
            <div class="filter-group">
                <label>Cloud Only</label>
                <select id="filter-cloud">
                    <option value="">Any</option>
                    <option value="true">Cloud Hosted</option>
                    <option value="false">Not Cloud</option>
                </select>
            </div>
            <div class="filter-group">
                <label>Min Score</label>
                <input type="number" id="filter-score" min="0" max="100" value="0" style="width: 80px;">
            </div>
            <div class="results-count">
                Showing <span id="visible-count">{stats['total']}</span> of <span>{stats['total']}</span>
            </div>
        </div>
        
        <table id="results-table">
            <thead>
                <tr>
                    <th data-sort="ip">IP</th>
                    <th data-sort="port">Port</th>
                    <th data-sort="score">Score</th>
                    <th data-sort="classification">Status</th>
                    <th data-sort="country">Country</th>
                    <th data-sort="hosting_provider">Provider</th>
                    <th data-sort="organization">Organization</th>
                    <th data-sort="tls_common_name">TLS CN</th>
                </tr>
            </thead>
            <tbody id="results-body">
            </tbody>
        </table>
        
        <footer>
            Generated by SigInt | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} UTC
        </footer>
    </div>
    
    <script>
        const DATA = {json.dumps(results_data)};
        
        let sortColumn = 'score';
        let sortDirection = 'desc';
        
        function getScoreClass(score) {{
            if (score >= 80) return 'high';
            if (score >= 60) return 'medium';
            if (score > 0) return 'low';
            return 'none';
        }}
        
        function renderTable(data) {{
            const tbody = document.getElementById('results-body');
            
            if (data.length === 0) {{
                tbody.innerHTML = '<tr><td colspan="8" class="empty-state">No results match your filters</td></tr>';
                return;
            }}
            
            tbody.innerHTML = data.map(r => `
                <tr>
                    <td>
                        <a href="${{r.url}}" target="_blank" class="ip-link">${{r.ip}}</a>
                        ${{r.hostname ? `<br><span style="color: var(--text-secondary); font-size: 11px;">${{r.hostname}}</span>` : ''}}
                    </td>
                    <td>${{r.port}}</td>
                    <td><span class="score ${{getScoreClass(r.score)}}">${{r.score}}%</span></td>
                    <td><span class="badge ${{r.classification}}">${{r.classification}}</span></td>
                    <td>${{r.country}}${{r.city ? `, ${{r.city}}` : ''}}</td>
                    <td>
                        ${{r.hosting_provider ? `<span class="badge cloud">${{r.hosting_provider}}</span>` : r.is_cloud_hosted ? '<span class="badge cloud">Cloud</span>' : '-'}}
                    </td>
                    <td style="max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${{r.organization}}">${{r.organization || '-'}}</td>
                    <td>
                        ${{r.tls_common_name ? `<span class="tls-info ${{r.tls_valid ? 'valid' : 'invalid'}}">${{r.tls_common_name}}</span>` : '-'}}
                    </td>
                </tr>
            `).join('');
        }}
        
        function filterData() {{
            const search = document.getElementById('search').value.toLowerCase();
            const classFilter = document.getElementById('filter-class').value;
            const countryFilter = document.getElementById('filter-country').value;
            const providerFilter = document.getElementById('filter-provider').value;
            const cloudFilter = document.getElementById('filter-cloud').value;
            const minScore = parseFloat(document.getElementById('filter-score').value) || 0;
            
            let filtered = DATA.filter(r => {{
                if (search && !r.ip.includes(search) && !r.hostname.toLowerCase().includes(search) && !r.organization.toLowerCase().includes(search)) return false;
                if (classFilter && r.classification !== classFilter) return false;
                if (countryFilter && r.country !== countryFilter) return false;
                if (providerFilter && r.hosting_provider !== providerFilter) return false;
                if (cloudFilter === 'true' && !r.is_cloud_hosted) return false;
                if (cloudFilter === 'false' && r.is_cloud_hosted) return false;
                if (r.score < minScore) return false;
                return true;
            }});
            
            // Sort
            filtered.sort((a, b) => {{
                let aVal = a[sortColumn];
                let bVal = b[sortColumn];
                
                if (typeof aVal === 'string') aVal = aVal.toLowerCase();
                if (typeof bVal === 'string') bVal = bVal.toLowerCase();
                
                if (aVal < bVal) return sortDirection === 'asc' ? -1 : 1;
                if (aVal > bVal) return sortDirection === 'asc' ? 1 : -1;
                return 0;
            }});
            
            document.getElementById('visible-count').textContent = filtered.length;
            renderTable(filtered);
        }}
        
        // Event listeners
        document.getElementById('search').addEventListener('input', filterData);
        document.getElementById('filter-class').addEventListener('change', filterData);
        document.getElementById('filter-country').addEventListener('change', filterData);
        document.getElementById('filter-provider').addEventListener('change', filterData);
        document.getElementById('filter-cloud').addEventListener('change', filterData);
        document.getElementById('filter-score').addEventListener('input', filterData);
        
        // Sorting
        document.querySelectorAll('th[data-sort]').forEach(th => {{
            th.addEventListener('click', () => {{
                const col = th.dataset.sort;
                if (sortColumn === col) {{
                    sortDirection = sortDirection === 'asc' ? 'desc' : 'asc';
                }} else {{
                    sortColumn = col;
                    sortDirection = col === 'score' ? 'desc' : 'asc';
                }}
                
                document.querySelectorAll('th').forEach(t => t.classList.remove('sorted-asc', 'sorted-desc'));
                th.classList.add(sortDirection === 'asc' ? 'sorted-asc' : 'sorted-desc');
                
                filterData();
            }});
        }});
        
        // Initial render
        document.querySelector('th[data-sort="score"]').classList.add('sorted-desc');
        filterData();
    </script>
</body>
</html>'''


def _generate_options(items: List[str]) -> str:
    """Generate HTML option tags."""
    return "\n".join(f'<option value="{item}">{item}</option>' for item in items)

