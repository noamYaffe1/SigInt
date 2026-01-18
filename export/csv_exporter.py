"""CSV exporter for verification results."""
import csv
from pathlib import Path
from verify.models import VerificationReport


def export_csv(
    report: VerificationReport,
    output_path: Path,
    include_all: bool = True,
    min_score: float = 0.0
) -> None:
    """Export verification results to CSV.
    
    Args:
        report: The verification report
        output_path: Path to output CSV file
        include_all: Include all results (even score 0)
        min_score: Minimum score to include (0-100)
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Filter results
    results = report.results
    if not include_all:
        results = [r for r in results if r.score > 0]
    if min_score > 0:
        results = [r for r in results if r.score >= min_score]
    
    # Sort by score descending
    results = sorted(results, key=lambda r: r.score, reverse=True)
    
    # Define columns - URL first for easy access
    columns = [
        "url",
        "score",
        "classification",
        "ip",
        "port",
        "scheme",
        "hostname",
        "matched_probes",
        "total_probes",
        "country",
        "city",
        "hosting_provider",
        "is_cloud_hosted",
        "organization",
        "asn",
        # TLS certificate info (for attribution)
        "tls_common_name",
        "tls_subject_org",
        "tls_issuer",
        "tls_issuer_org",
        "tls_valid",
        "tls_self_signed",
        "tls_san",
        "tls_emails",
        "sources",
        "verified_at"
    ]
    
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=columns, extrasaction='ignore')
        writer.writeheader()
        
        for result in results:
            row = {
                "url": result.url,  # Full URL with scheme
                "score": result.score,
                "classification": result.classification,
                "ip": result.ip,
                "port": result.port,
                "scheme": result.scheme,
                "hostname": result.hostname or "",
                "matched_probes": result.matched_probes,
                "total_probes": result.total_probes,
                "country": result.location.get("country", "") if result.location else "",
                "city": result.location.get("city", "") if result.location else "",
                "hosting_provider": result.hosting_provider or "",
                "is_cloud_hosted": result.is_cloud_hosted,
                "organization": result.organization or "",
                "asn": result.asn or "",
                # TLS certificate info (for attribution)
                "tls_common_name": result.tls_common_name or "",
                "tls_subject_org": result.tls_subject_org or "",
                "tls_issuer": result.tls_issuer or "",
                "tls_issuer_org": result.tls_issuer_org or "",
                "tls_valid": result.tls_valid if result.tls_valid is not None else "",
                "tls_self_signed": result.tls_self_signed if result.tls_self_signed is not None else "",
                "tls_san": ";".join(result.tls_san) if result.tls_san else "",
                "tls_emails": ";".join(result.tls_emails) if result.tls_emails else "",
                "sources": ",".join(result.sources),
                "verified_at": result.verified_at or ""
            }
            writer.writerow(row)
    
    print(f"[Export] CSV saved to: {output_path}")
    print(f"         Rows: {len(results)}")

