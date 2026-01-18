"""Main export engine."""
import json
from pathlib import Path
from typing import List, Literal, Optional
from verify.models import VerificationReport
from .csv_exporter import export_csv
from .html_exporter import export_html


ExportFormat = Literal["json", "csv", "html"]


class ExportEngine:
    """Engine for exporting verification results in multiple formats."""
    
    def __init__(self, output_dir: Path = Path("output/exports")):
        """Initialize export engine.
        
        Args:
            output_dir: Base directory for exports
        """
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def export(
        self,
        report: VerificationReport,
        formats: List[ExportFormat],
        base_name: Optional[str] = None,
        include_all: bool = True,
        min_score: float = 0.0
    ) -> List[Path]:
        """Export report in specified formats.
        
        Args:
            report: The verification report to export
            formats: List of export formats (json, csv, html)
            base_name: Base filename (without extension)
            include_all: Include all results (even score 0)
            min_score: Minimum score to include (0-100)
            
        Returns:
            List of paths to exported files
        """
        if not base_name:
            # Generate from app name and run ID
            safe_name = "".join(c if c.isalnum() else "_" for c in report.app_name.lower())
            base_name = f"{safe_name}_{report.fingerprint_run_id}"
        
        exported_files: List[Path] = []
        
        print(f"\n[Export] Exporting report in {len(formats)} format(s)...")
        
        for fmt in formats:
            output_path = self.output_dir / f"{base_name}.{fmt}"
            
            if fmt == "json":
                self._export_json(report, output_path, include_all, min_score)
            elif fmt == "csv":
                export_csv(report, output_path, include_all, min_score)
            elif fmt == "html":
                export_html(report, output_path, include_all)
            
            exported_files.append(output_path)
        
        return exported_files
    
    def _export_json(
        self,
        report: VerificationReport,
        output_path: Path,
        include_all: bool,
        min_score: float
    ) -> None:
        """Export to JSON format."""
        # Filter results
        results = report.results
        if not include_all:
            results = [r for r in results if r.score > 0]
        if min_score > 0:
            results = [r for r in results if r.score >= min_score]
        
        # Sort by score
        results = sorted(results, key=lambda r: r.score, reverse=True)
        
        output_data = {
            "fingerprint_run_id": report.fingerprint_run_id,
            "app_name": report.app_name,
            "verification_started": report.verification_started,
            "verification_completed": report.verification_completed,
            "total_duration_ms": report.total_duration_ms,
            "summary": {
                "total_candidates": len(results),
                "verified": sum(1 for r in results if r.classification == "verified"),
                "likely": sum(1 for r in results if r.classification == "likely"),
                "partial": sum(1 for r in results if r.classification == "partial"),
                "unlikely": sum(1 for r in results if r.classification == "unlikely"),
                "no_match": sum(1 for r in results if r.classification == "no_match"),
            },
            "results": [r.model_dump() for r in results]
        }
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, indent=2)
        
        print(f"[Export] JSON saved to: {output_path}")
        print(f"         Results: {len(results)}")


def export_report(
    report: VerificationReport,
    formats: List[str],
    output_dir: Path = Path("output/exports"),
    base_name: Optional[str] = None,
    include_all: bool = True,
    min_score: float = 0.0
) -> List[Path]:
    """Convenience function to export a report.
    
    Args:
        report: The verification report to export
        formats: List of export formats (json, csv, html)
        output_dir: Output directory
        base_name: Base filename (without extension)
        include_all: Include all results (even score 0)
        min_score: Minimum score to include (0-100)
        
    Returns:
        List of paths to exported files
    """
    engine = ExportEngine(output_dir)
    return engine.export(
        report=report,
        formats=[f for f in formats if f in ("json", "csv", "html")],
        base_name=base_name,
        include_all=include_all,
        min_score=min_score
    )

