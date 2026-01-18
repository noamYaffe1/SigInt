"""Pipeline runner - orchestrates all phases."""
import json
import traceback
from dataclasses import dataclass, field
from typing import List, Optional
from pathlib import Path
from core.utils import utc_now_iso

from cli.args import SigIntConfig
from core.models import FingerprintOutput
from core.formatting import get_app_slug, print_fingerprint_summary, print_section_header
from discover.models import CandidateHost
from verify.models import VerificationReport


@dataclass
class PipelineResult:
    """Result from pipeline execution."""
    success: bool = True
    
    # Phase outputs
    fingerprint: Optional[FingerprintOutput] = None
    candidates: List[CandidateHost] = field(default_factory=list)
    verification_report: Optional[VerificationReport] = None
    
    # Output paths
    fingerprint_path: Optional[Path] = None
    candidates_path: Optional[Path] = None
    verification_path: Optional[Path] = None
    export_paths: List[Path] = field(default_factory=list)
    
    # Errors
    errors: List[str] = field(default_factory=list)


class PipelineRunner:
    """Orchestrates the SigInt pipeline."""
    
    def __init__(self, config: SigIntConfig):
        """Initialize pipeline runner.
        
        Args:
            config: Pipeline configuration
        """
        self.config = config
    
    def _prompt_continue(self, phase_name: str, next_phase: str) -> bool:
        """Prompt user whether to continue to next phase.
        
        Args:
            phase_name: Name of the completed phase
            next_phase: Name of the next phase
            
        Returns:
            True if user wants to continue, False to exit
        """
        if not self.config.interactive:
            return True
        
        try:
            print(f"\n{'='*70}")
            print(f"[INTERACTIVE] {phase_name} complete.")
            print(f"[INTERACTIVE] Next: {next_phase}")
            response = input("[?] Continue to next phase? [Y/n]: ").strip().lower()
            if response in ('n', 'no'):
                print("[!] Pipeline stopped by user")
                return False
            return True
        except (EOFError, KeyboardInterrupt):
            print("\n[!] Pipeline stopped by user")
            return False
    
    def run(self) -> PipelineResult:
        """Run the complete pipeline.
        
        Returns:
            PipelineResult with outputs and status
        """
        result = PipelineResult()
        
        try:
            # Phase 1: Fingerprinting (or load existing)
            if self.config.phase1.skip_phase1:
                # Load existing fingerprint file
                self._print_header("SigInt - Loading Existing Fingerprint")
                fingerprint = self._load_fingerprint(self.config.phase1.fingerprint_file)
                result.fingerprint = fingerprint
                result.fingerprint_path = self.config.phase1.fingerprint_file
                print(f"[✓] Loaded fingerprint: {self.config.phase1.fingerprint_file}")
                self._print_phase1_summary(fingerprint)
            else:
                # Generate new fingerprint
                if self.config.phase1.github_repo:
                    self._print_header("SigInt Phase 1 - GitHub Repository Fingerprinting")
                else:
                    self._print_header("SigInt Phase 1 - LLM-Driven Recursive Fingerprinting")
                fingerprint = self._run_phase1()
                result.fingerprint = fingerprint
                result.fingerprint_path = self._save_fingerprint(fingerprint)
                self._print_phase1_summary(fingerprint)
            
            # Interactive: Prompt after Phase 1
            if self.config.phase2.enabled:
                if not self._prompt_continue("Phase 1: Fingerprinting", "Phase 2: Passive Discovery"):
                    return result
            
            # Phase 2: Discovery (if enabled)
            if self.config.phase2.enabled:
                self._print_header("SigInt Phase 2 - Passive Discovery (Shodan/Censys)")
                candidates = self._run_phase2(fingerprint)
                result.candidates = candidates
                result.candidates_path = self._save_candidates(fingerprint, candidates)
                
                # Interactive: Prompt after Phase 2
                if self.config.phase3.enabled and candidates:
                    if not self._prompt_continue("Phase 2: Discovery", "Phase 3: Verification"):
                        return result
                
                # Phase 3: Verification (if enabled)
                if self.config.phase3.enabled and candidates:
                    verification = self._run_phase3(fingerprint, candidates)
                    result.verification_report = verification
                    result.verification_path = self._save_verification(fingerprint, verification)
                    
                    # Interactive: Prompt before Export
                    if self.config.export.formats:
                        if not self._prompt_continue("Phase 3: Verification", "Export"):
                            return result
                        result.export_paths = self._run_export(verification)
                    
                elif not self.config.phase3.enabled:
                    print("\n[INFO] Phase 3 skipped (--skip-phase-3 flag)")
                    print("=" * 70)
                elif not candidates:
                    print("\n[INFO] Phase 3 skipped (no candidates to verify)")
                    print("=" * 70)
            else:
                print("\n[INFO] Phase 2 skipped (--skip-phase-2 flag)")
                print("=" * 70)
                
        except Exception as e:
            result.success = False
            result.errors.append(str(e))
            print(f"\n[ERROR] Pipeline failed: {e}")
            if self.config.verbose:
                traceback.print_exc()
        
        return result
    
    def _run_phase1(self) -> FingerprintOutput:
        """Run Phase 1: Fingerprinting (live site or GitHub repo)."""
        mode = self.config.phase1.mode
        include_version = self.config.phase1.include_version
        
        if self.config.phase1.github_repo:
            # GitHub repo fingerprinting
            from fingerprint.github_analyzer import GitHubAnalyzer
            
            analyzer = GitHubAnalyzer()
            output = analyzer.analyze_repo(
                self.config.phase1.github_repo,
                mode=mode,
                include_version=include_version
            )
        else:
            # Live site fingerprinting (LLM-driven)
            from fingerprint.engine import LLMFingerprintEngine
            
            engine = LLMFingerprintEngine()
            output = engine.fingerprint_live_site(
                url=self.config.phase1.live_site,
                max_iterations=self.config.phase1.max_iterations,
                mode=mode,
                include_version=include_version
            )
        return output
    
    def _run_phase2(self, fingerprint: FingerprintOutput) -> List[CandidateHost]:
        """Run Phase 2: Passive Discovery."""
        from discover.engine import PassiveDiscovery
        
        config = self.config.phase2
        
        print(f"\nSearching for similar instances...")
        print(f"  Max candidates: {config.max_candidates or 'unlimited'}")
        print(f"  Cache strategy: {config.cache_strategy}")
        print(f"  Cache TTL: {config.cache_ttl_days} days" if config.cache_ttl_days > 0 else "  Cache TTL: disabled")
        if config.plugins:
            print(f"  Plugins: {', '.join(config.plugins)}")
        
        discovery = PassiveDiscovery(
            cache_dir="output/cache",
            cache_ttl_days=config.cache_ttl_days
        )
        
        candidates = discovery.discover(
            fingerprint=fingerprint.fingerprint_spec,
            max_results=config.max_candidates,
            max_queries=config.max_queries,
            cache_strategy=config.cache_strategy,
            enrich=config.enrich,
            enrich_workers=config.enrich_workers,
            plugins=config.plugins,
            interactive=self.config.interactive  # Pass interactive mode for query review
        )
        
        return candidates
    
    def _run_phase3(
        self,
        fingerprint: FingerprintOutput,
        candidates: List[CandidateHost]
    ) -> VerificationReport:
        """Run Phase 3: Active Verification."""
        from verify.engine import VerificationEngine
        from core.weights import parse_weights_string, apply_weights_to_plan, interactive_weight_editor, print_probe_weights
        
        config = self.config.phase3
        
        # Apply custom weights if specified
        if config.interactive_weights:
            fingerprint.probe_plan = interactive_weight_editor(fingerprint.probe_plan)
        elif config.weights:
            weights = parse_weights_string(config.weights)
            apply_weights_to_plan(fingerprint.probe_plan, weights)
            print_probe_weights(fingerprint.probe_plan)
        
        verifier = VerificationEngine(
            timeout=config.timeout,
            max_workers=config.workers,
            fetch_tls=config.fetch_tls,
            tcp_check=config.tcp_check
        )
        
        report = verifier.verify_candidates(
            fingerprint=fingerprint,
            candidates=candidates,
            show_progress=True
        )
        
        print("=" * 70)
        print("[✓] Phase 3 Complete!")
        print("=" * 70)
        
        return report
    
    def _run_export(self, report: VerificationReport) -> List[Path]:
        """Run export phase."""
        from export.engine import export_report
        
        config = self.config.export
        app_slug = get_app_slug(report.app_name)
        
        return export_report(
            report=report,
            formats=config.formats,
            output_dir=config.output_dir,
            base_name=f"{app_slug}_{report.fingerprint_run_id}",
            include_all=config.include_all,
            min_score=config.min_score
        )
    
    def _load_fingerprint(self, fingerprint_path: Path) -> FingerprintOutput:
        """Load fingerprint from disk.
        
        Args:
            fingerprint_path: Path to fingerprint JSON file
            
        Returns:
            Loaded FingerprintOutput
        """
        with open(fingerprint_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return FingerprintOutput(**data)
    
    def _save_fingerprint(self, fingerprint: FingerprintOutput) -> Path:
        """Save fingerprint to disk."""
        if self.config.phase1.output_path:
            output_path = self.config.phase1.output_path
        else:
            app_slug = get_app_slug(fingerprint.fingerprint_spec.app_name)
            run_id = fingerprint.fingerprint_spec.run_id
            output_path = Path("output") / "fingerprints" / f"{app_slug}_{run_id}.json"
        
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(fingerprint.model_dump(), f, indent=2)
        
        print(f"\n[✓] Fingerprint saved to: {output_path}")
        return output_path
    
    def _save_candidates(
        self,
        fingerprint: FingerprintOutput,
        candidates: List[CandidateHost]
    ) -> Path:
        """Save candidates to disk."""
        app_slug = get_app_slug(fingerprint.fingerprint_spec.app_name)
        run_id = fingerprint.fingerprint_spec.run_id
        
        candidates_dir = Path("output") / "candidates"
        candidates_dir.mkdir(parents=True, exist_ok=True)
        output_path = candidates_dir / f"{app_slug}_{run_id}_candidates.json"
        
        # Calculate geographic distribution
        geo_dist = {}
        for candidate in candidates:
            country = candidate.location.get("country", "Unknown") if candidate.location else "Unknown"
            geo_dist[country] = geo_dist.get(country, 0) + 1
        
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump({
                "fingerprint_run_id": run_id,
                "discovery_timestamp": utc_now_iso(),
                "total_candidates": len(candidates),
                "geographic_distribution": dict(sorted(geo_dist.items(), key=lambda x: -x[1])),
                "candidates": [c.model_dump() for c in candidates]
            }, f, indent=2)
        
        print(f"\n[✓] Found {len(candidates)} candidates")
        print(f"[✓] Saved to: {output_path}")
        
        # Print top countries
        if geo_dist:
            print(f"\nGeographic distribution:")
            for country, count in sorted(geo_dist.items(), key=lambda x: -x[1])[:10]:
                print(f"  {country}: {count}")
        
        print("=" * 70)
        print("[✓] Phase 2 Complete!")
        print("=" * 70)
        
        return output_path
    
    def _save_verification(
        self,
        fingerprint: FingerprintOutput,
        report: VerificationReport
    ) -> Path:
        """Save verification report to exports directory."""
        from verify.engine import VerificationEngine
        
        app_slug = get_app_slug(fingerprint.fingerprint_spec.app_name)
        run_id = fingerprint.fingerprint_spec.run_id
        
        # Verified results go to exports (they are reports, not raw candidates)
        exports_dir = Path("output") / "exports"
        exports_dir.mkdir(parents=True, exist_ok=True)
        output_path = exports_dir / f"{app_slug}_{run_id}_verified.json"
        
        # Use verification engine's save method
        verifier = VerificationEngine()
        verifier.save_report(
            report=report,
            output_path=output_path,
            include_all=True
        )
        
        return output_path
    
    def _print_header(self, title: str) -> None:
        """Print section header."""
        print_section_header(title)
    
    def _print_phase1_summary(self, fingerprint: FingerprintOutput) -> None:
        """Print Phase 1 summary using shared formatter."""
        spec = fingerprint.fingerprint_spec
        plan = fingerprint.probe_plan
        
        print_fingerprint_summary(
            run_id=spec.run_id,
            created_at=spec.created_at,
            app_name=spec.app_name,
            source=spec.source_location,
            confidence=spec.confidence_level,
            favicon=bool(spec.favicon),
            key_images_count=len(spec.key_images),
            page_signatures_count=len(spec.page_signatures),
            probe_steps_count=len(plan.probe_steps),
            min_matches=plan.minimum_matches_required,
            distinctive_features=spec.distinctive_features,
            notes=spec.notes,
            fingerprint_mode=spec.fingerprint_mode
        )

