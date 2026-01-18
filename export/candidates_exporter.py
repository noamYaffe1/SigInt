"""Export candidate lists to various formats (CSV, JSON, HTML)."""
import csv
import json
from pathlib import Path
from typing import List, Dict

from discover.models import CandidateHost


def export_candidates(
    candidates: List[CandidateHost],
    formats: List[str],
    output_dir: Path,
    base_name: str,
    geo_distribution: Dict[str, int] = None
) -> List[Path]:
    """Export candidate list to multiple formats.
    
    Args:
        candidates: List of candidate hosts
        formats: List of formats ('csv', 'json', 'html')
        output_dir: Output directory
        base_name: Base name for output files
        geo_distribution: Geographic distribution dict
        
    Returns:
        List of created file paths
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    exported = []
    
    for fmt in formats:
        if fmt == "csv":
            path = output_dir / f"{base_name}.csv"
            _export_csv(candidates, path)
            exported.append(path)
        elif fmt == "json":
            path = output_dir / f"{base_name}.json"
            _export_json(candidates, path, geo_distribution)
            exported.append(path)
        elif fmt == "html":
            path = output_dir / f"{base_name}.html"
            _export_html(candidates, path, geo_distribution)
            exported.append(path)
    
    return exported


def _export_csv(candidates: List[CandidateHost], output_path: Path) -> None:
    """Export candidates to CSV."""
    columns = [
        "ip",
        "port",
        "hostname",
        "country",
        "city",
        "hosting_provider",
        "is_cloud_hosted",
        "organization",
        "asn",
        "sources"
    ]
    
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=columns, extrasaction='ignore')
        writer.writeheader()
        
        for c in candidates:
            row = {
                "ip": c.ip,
                "port": c.port,
                "hostname": c.hostname or "",
                "country": c.location.get("country", "") if c.location else "",
                "city": c.location.get("city", "") if c.location else "",
                "hosting_provider": c.hosting_provider or "",
                "is_cloud_hosted": c.is_cloud_hosted,
                "organization": c.organization or "",
                "asn": c.asn or "",
                "sources": ",".join(c.sources) if c.sources else ""
            }
            writer.writerow(row)
    
    print(f"[Export] CSV saved to: {output_path}")


def _export_json(
    candidates: List[CandidateHost],
    output_path: Path,
    geo_distribution: Dict[str, int] = None
) -> None:
    """Export candidates to JSON."""
    from core.utils import utc_now_iso
    
    data = {
        "export_timestamp": utc_now_iso(),
        "total_candidates": len(candidates),
        "geographic_distribution": geo_distribution or {},
        "candidates": [c.model_dump() for c in candidates]
    }
    
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)
    
    print(f"[Export] JSON saved to: {output_path}")


def _export_html(
    candidates: List[CandidateHost],
    output_path: Path,
    geo_distribution: Dict[str, int] = None
) -> None:
    """Export candidates to HTML."""
    from core.utils import utc_now_iso
    
    # Build HTML
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SigInt Candidates Report</title>
    <style>
        :root {{
            --bg-primary: #0d1117;
            --bg-secondary: #161b22;
            --text-primary: #c9d1d9;
            --text-secondary: #8b949e;
            --accent: #58a6ff;
            --border: #30363d;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            margin: 0;
            padding: 20px;
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
        }}
        h1 {{
            color: var(--accent);
            border-bottom: 1px solid var(--border);
            padding-bottom: 10px;
        }}
        .stats {{
            display: flex;
            gap: 20px;
            margin-bottom: 20px;
        }}
        .stat {{
            background: var(--bg-secondary);
            padding: 15px 25px;
            border-radius: 8px;
            border: 1px solid var(--border);
        }}
        .stat-value {{
            font-size: 24px;
            font-weight: bold;
            color: var(--accent);
        }}
        .stat-label {{
            color: var(--text-secondary);
            font-size: 12px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: var(--bg-secondary);
            border-radius: 8px;
            overflow: hidden;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }}
        th {{
            background: var(--bg-primary);
            color: var(--accent);
            font-weight: 600;
        }}
        tr:hover {{
            background: rgba(88, 166, 255, 0.1);
        }}
        .cloud {{
            color: #3fb950;
        }}
        .sources {{
            font-size: 11px;
            color: var(--text-secondary);
        }}
        .geo-section {{
            margin-top: 30px;
        }}
        .geo-bar {{
            display: flex;
            align-items: center;
            margin: 5px 0;
        }}
        .geo-label {{
            width: 120px;
        }}
        .geo-fill {{
            height: 20px;
            background: var(--accent);
            border-radius: 3px;
            margin-right: 10px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>SigInt Candidates Report</h1>
        <p style="color: var(--text-secondary);">Generated: {utc_now_iso()}</p>
        
        <div class="stats">
            <div class="stat">
                <div class="stat-value">{len(candidates)}</div>
                <div class="stat-label">Total Candidates</div>
            </div>
            <div class="stat">
                <div class="stat-value">{len(geo_distribution) if geo_distribution else 0}</div>
                <div class="stat-label">Countries</div>
            </div>
            <div class="stat">
                <div class="stat-value">{sum(1 for c in candidates if c.is_cloud_hosted)}</div>
                <div class="stat-label">Cloud Hosted</div>
            </div>
        </div>
        
        <table>
            <thead>
                <tr>
                    <th>IP</th>
                    <th>Port</th>
                    <th>Hostname</th>
                    <th>Country</th>
                    <th>Provider</th>
                    <th>Organization</th>
                    <th>Sources</th>
                </tr>
            </thead>
            <tbody>
"""
    
    for c in candidates:
        country = c.location.get("country", "") if c.location else ""
        provider = c.hosting_provider or ""
        cloud_class = "cloud" if c.is_cloud_hosted else ""
        sources = ", ".join(c.sources) if c.sources else ""
        
        html += f"""                <tr>
                    <td>{c.ip}</td>
                    <td>{c.port}</td>
                    <td>{c.hostname or '-'}</td>
                    <td>{country}</td>
                    <td class="{cloud_class}">{provider}</td>
                    <td>{c.organization or '-'}</td>
                    <td class="sources">{sources}</td>
                </tr>
"""
    
    html += """            </tbody>
        </table>
"""
    
    # Add geographic distribution chart
    if geo_distribution:
        max_count = max(geo_distribution.values()) if geo_distribution else 1
        html += """
        <div class="geo-section">
            <h2>Geographic Distribution</h2>
"""
        for country, count in sorted(geo_distribution.items(), key=lambda x: -x[1])[:15]:
            width = int((count / max_count) * 200)
            html += f"""            <div class="geo-bar">
                <span class="geo-label">{country}</span>
                <div class="geo-fill" style="width: {width}px;"></div>
                <span>{count}</span>
            </div>
"""
        html += "        </div>\n"
    
    html += """    </div>
</body>
</html>
"""
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html)
    
    print(f"[Export] HTML saved to: {output_path}")

