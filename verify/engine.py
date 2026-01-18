"""Main verification engine for Phase 3."""
import time
import json
import socket
import re
from typing import List, Optional, Dict
from pathlib import Path
from core.utils import utc_now_iso
from core.debug import debug_print
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

from core.models import FingerprintOutput, ProbePlan, ProbeStep
from discover.models import CandidateHost
from .models import ProbeResult, VerificationResult, VerificationReport
from .probes import ProbeExecutor


def _generate_app_prefix(app_name: str) -> str:
    """Generate a URL-friendly prefix from app name.
    
    Examples:
        "Damn Vulnerable Web Application" -> "dvwa"
        "OWASP Juice Shop" -> "juice-shop"
        "Jenkins" -> "jenkins"
        "Grafana" -> "grafana"
    """
    if not app_name:
        return ""
    
    # Common abbreviation mappings
    abbreviations = {
        "damn vulnerable web application": "dvwa",
        "owasp juice shop": "juice-shop",
    }
    
    app_lower = app_name.lower().strip()
    
    # Check for known abbreviations
    if app_lower in abbreviations:
        return abbreviations[app_lower]
    
    # Remove common prefixes
    for prefix in ["owasp ", "apache ", "the "]:
        if app_lower.startswith(prefix):
            app_lower = app_lower[len(prefix):]
    
    # Convert to URL-friendly format
    # Replace spaces and special chars with dashes
    prefix = re.sub(r'[^a-z0-9]+', '-', app_lower)
    prefix = prefix.strip('-')
    
    # If too long, try to shorten (use first word or first letters)
    if len(prefix) > 20:
        words = app_name.split()
        if len(words) > 1:
            # Try acronym (first letters)
            acronym = ''.join(w[0].lower() for w in words if w)
            if len(acronym) >= 2:
                prefix = acronym
        else:
            prefix = prefix[:20]
    
    return prefix


def _clean_location(location: Optional[Dict]) -> Optional[Dict[str, Optional[str]]]:
    """Filter None values from location dict.
    
    Pydantic requires Dict[str, str] so we need to filter out None values.
    """
    if not location:
        return None
    cleaned = {k: v for k, v in location.items() if v is not None}
    return cleaned if cleaned else None


class VerificationEngine:
    """Engine for verifying candidates against fingerprints."""
    
    def __init__(
        self,
        timeout: int = 10,
        max_workers: int = 10,
        user_agent: str = None,
        fetch_tls: bool = True,
        tls_timeout: int = 5,
        tcp_check: bool = True,
        tcp_timeout: float = 2.0,
        tcp_retries: int = 2
    ):
        """Initialize verification engine.
        
        Args:
            timeout: Request timeout in seconds
            max_workers: Max concurrent verification threads
            user_agent: Custom user agent string
            fetch_tls: Whether to fetch TLS certificates for verified hosts
            tls_timeout: TLS connection timeout in seconds
            tcp_check: Whether to do a quick TCP liveness check before probing (default True)
            tcp_timeout: TCP check timeout in seconds (default 2.0)
            tcp_retries: Number of TCP check retries (default 2)
        """
        self.timeout = timeout
        self.max_workers = max_workers
        self.user_agent = user_agent
        self.fetch_tls = fetch_tls
        self.tls_timeout = tls_timeout
        self.tcp_check = tcp_check
        self.tcp_timeout = tcp_timeout
        self.tcp_retries = tcp_retries
        self.probe_executor = None  # Created during verify_candidates with fingerprint_mode
        self.app_prefix = None  # Set during verify_candidates based on fingerprint mode
    
    def verify_candidates(
        self,
        fingerprint: FingerprintOutput,
        candidates: List[CandidateHost],
        show_progress: bool = True
    ) -> VerificationReport:
        """Verify all candidates against fingerprint.
        
        Args:
            fingerprint: The fingerprint with probe plan
            candidates: List of candidates to verify
            show_progress: Show progress bar
            
        Returns:
            VerificationReport with all results (including score 0)
        """
        report = VerificationReport(
            fingerprint_run_id=fingerprint.fingerprint_spec.run_id or "unknown",
            app_name=fingerprint.fingerprint_spec.app_name
        )
        
        start_time = time.time()
        probe_plan = fingerprint.probe_plan
        
        # Compute app prefix for fallback (only in application mode)
        fingerprint_mode = getattr(fingerprint.fingerprint_spec, 'fingerprint_mode', 'application')
        app_name = fingerprint.fingerprint_spec.app_name
        
        if fingerprint_mode == 'application':
            self.app_prefix = _generate_app_prefix(app_name)
        else:
            self.app_prefix = None  # No prefix fallback for organization mode
        
        # Create probe executor with fingerprint mode for favicon discovery behavior
        self.probe_executor = ProbeExecutor(
            timeout=self.timeout,
            user_agent=self.user_agent,
            fingerprint_mode=fingerprint_mode
        )
        
        print(f"\n{'='*70}")
        print(f"[PHASE 3] Active Verification")
        print(f"{'='*70}")
        target_label = "Organization" if fingerprint_mode == 'organization' else "Application"
        print(f"{target_label}: {app_name}")
        print(f"Candidates to verify: {len(candidates)}")
        print(f"Probe steps per candidate: {len(probe_plan.probe_steps)}")
        print(f"Concurrent workers: {self.max_workers}")
        print(f"Timeout per request: {self.timeout}s")
        if self.tcp_check:
            print(f"TCP liveness check: enabled ({self.tcp_timeout}s timeout, {self.tcp_retries} retries)")
        else:
            print(f"TCP liveness check: disabled")
        if self.app_prefix:
            print(f"App prefix fallback: enabled (/{self.app_prefix}/)")
        
        # Verify candidates (with optional parallelization)
        results = []
        
        if self.max_workers > 1:
            # Parallel verification
            results = self._verify_parallel(candidates, probe_plan, show_progress)
        else:
            # Sequential verification
            results = self._verify_sequential(candidates, probe_plan, show_progress)
        
        # Add all results to report (including score 0)
        report.results = results
        report.calculate_summary()
        
        # Fetch TLS certificates for verified/likely matches
        if self.fetch_tls:
            self._fetch_tls_certificates(report)
        
        # Finalize timing
        total_duration = int((time.time() - start_time) * 1000)
        report.verification_completed = utc_now_iso()
        report.total_duration_ms = total_duration
        
        # Print summary
        self._print_summary(report)
        
        return report
    
    def _determine_scheme(self, port: int) -> str:
        """Determine initial scheme based on port.
        
        Args:
            port: The port number
            
        Returns:
            'https' for port 443/8443, 'http' otherwise
        """
        https_ports = {443, 8443}
        return "https" if port in https_ports else "http"
    
    def _get_alternate_scheme(self, scheme: str) -> str:
        """Get the alternate scheme."""
        return "https" if scheme == "http" else "http"
    
    def _check_tcp_alive(
        self,
        ip: str,
        port: int,
        timeout: float = 2.0,
        retries: int = 2
    ) -> bool:
        """Quick TCP liveness check before probing.
        
        Args:
            ip: Target IP address
            port: Target port
            timeout: Connection timeout in seconds (default 2s)
            retries: Number of retry attempts (default 2)
            
        Returns:
            True if host is reachable via TCP, False otherwise
        """
        for attempt in range(retries):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((ip, port))
                sock.close()
                
                if result == 0:
                    debug_print(f"[TCP] {ip}:{port} is alive (attempt {attempt + 1})")
                    return True
                    
            except socket.error as e:
                debug_print(f"[TCP] {ip}:{port} socket error: {e} (attempt {attempt + 1})")
            except Exception as e:
                debug_print(f"[TCP] {ip}:{port} unexpected error: {e} (attempt {attempt + 1})")
        
        debug_print(f"[TCP] {ip}:{port} is NOT alive after {retries} attempts")
        return False
    
    def _verify_single_candidate(
        self,
        candidate: CandidateHost,
        probe_plan: ProbePlan,
        score_threshold: int = 100,
        retry_threshold: int = 50
    ) -> VerificationResult:
        """Verify a single candidate against probe plan.
        
        Flow:
        1. Quick TCP liveness check (2s timeout, 2 retries)
        2. If dead, return score=0 immediately (saves probe time)
        3. If alive, proceed with HTTP probes
        
        Uses additive scoring with early termination:
        - Each matched probe adds points to the score
        - If score reaches threshold (default 100), remaining probes are skipped
        - If score < retry_threshold (default 50), tries alternate scheme (http/https)
        
        Args:
            candidate: The candidate to verify
            probe_plan: Probe plan with steps and points
            score_threshold: Stop probing when score reaches this (default 100)
            retry_threshold: If score < this, try alternate scheme (default 50)
        """
        # Quick TCP liveness check first (if enabled)
        if self.tcp_check and not self._check_tcp_alive(
            candidate.ip, candidate.port, 
            timeout=self.tcp_timeout, 
            retries=self.tcp_retries
        ):
            # Host is not reachable - return immediately with score 0
            return VerificationResult(
                ip=candidate.ip,
                port=candidate.port,
                hostname=candidate.hostname,
                sources=candidate.sources,
                location=_clean_location(candidate.location),
                asn=candidate.asn,
                organization=candidate.organization,
                hosting_provider=candidate.hosting_provider,
                is_cloud_hosted=candidate.is_cloud_hosted,
                score=0.0,
                classification="no_match",
                verified_at=utc_now_iso(),
                scheme="unknown"
            )
        
        # Host is alive - proceed with HTTP probes
        # Determine initial scheme based on port
        initial_scheme = self._determine_scheme(candidate.port)
        
        # Try initial scheme at root
        result = self._probe_with_scheme(candidate, probe_plan, initial_scheme, score_threshold)
        
        # If score is low, try alternate scheme
        if result.score < retry_threshold:
            alternate_scheme = self._get_alternate_scheme(initial_scheme)
            alternate_result = self._probe_with_scheme(candidate, probe_plan, alternate_scheme, score_threshold)
            alternate_result.alternate_scheme_tried = True
            
            # Keep the better result
            if alternate_result.score > result.score:
                result = alternate_result
            else:
                result.alternate_scheme_tried = True
        
        # If score is still low AND we have an app prefix, try with prefix
        # This catches apps deployed under a context path (e.g., /dvwa/, /juice-shop/)
        if result.score < retry_threshold and self.app_prefix:
            prefix = f"/{self.app_prefix}"
            
            # Create a modified probe plan with prefixed paths
            prefixed_plan = self._create_prefixed_probe_plan(probe_plan, prefix)
            
            # Try with prefix on both schemes
            for scheme in [initial_scheme, self._get_alternate_scheme(initial_scheme)]:
                prefixed_result = self._probe_with_scheme(
                    candidate, prefixed_plan, scheme, score_threshold
                )
                prefixed_result.prefix_used = prefix
                
                if prefixed_result.score > result.score:
                    result = prefixed_result
                    # If we found a good match with prefix, stop trying
                    if result.score >= retry_threshold:
                        break
        
        return result
    
    def _create_prefixed_probe_plan(self, probe_plan: ProbePlan, prefix: str) -> ProbePlan:
        """Create a copy of probe plan with prefixed URL paths.
        
        Args:
            probe_plan: Original probe plan
            prefix: Prefix to add (e.g., "/dvwa")
            
        Returns:
            New ProbePlan with prefixed paths
        """
        prefixed_steps = []
        for step in probe_plan.probe_steps:
            # Create a copy of the step with prefixed path
            prefixed_step = ProbeStep(
                order=step.order,
                url_path=f"{prefix}{step.url_path}",
                method=step.method,
                description=f"{step.description} (prefixed: {prefix})",
                check_type=step.check_type,
                expected_hash=step.expected_hash,
                expected_status=step.expected_status,
                expected_title_pattern=step.expected_title_pattern,
                expected_body_patterns=step.expected_body_patterns,
                fingerprint_index=step.fingerprint_index,
                weight=step.weight
            )
            prefixed_steps.append(prefixed_step)
        
        return ProbePlan(
            probe_steps=prefixed_steps,
            minimum_matches_required=probe_plan.minimum_matches_required,
            default_weights=probe_plan.default_weights,
            timeout_seconds=probe_plan.timeout_seconds,
            follow_redirects=probe_plan.follow_redirects
        )
    
    def _probe_with_scheme(
        self,
        candidate: CandidateHost,
        probe_plan: ProbePlan,
        scheme: str,
        score_threshold: int
    ) -> VerificationResult:
        """Probe a candidate with a specific scheme.
        
        Args:
            candidate: The candidate to verify
            probe_plan: Probe plan with steps and points
            scheme: 'http' or 'https'
            score_threshold: Stop probing when score reaches this
            
        Returns:
            VerificationResult with probe results
        """
        from verify.models import DEFAULT_PROBE_POINTS
        
        start_time = time.time()
        
        result = VerificationResult(
            ip=candidate.ip,
            port=candidate.port,
            hostname=candidate.hostname,
            sources=candidate.sources,
            location=_clean_location(candidate.location),
            asn=candidate.asn,
            organization=candidate.organization,
            # Carry over enrichment data
            hosting_provider=candidate.hosting_provider,
            is_cloud_hosted=candidate.is_cloud_hosted,
            scheme=scheme
        )
        
        base_url = f"{scheme}://{candidate.ip}:{candidate.port}"
        current_score = 0
        max_score = DEFAULT_PROBE_POINTS.get("max_score", 100)
        
        # Execute probes with early termination
        for probe in probe_plan.probe_steps:
            # Check for early termination (reached max score)
            if current_score >= max_score:
                # Skip remaining probes - already at max score
                skipped_result = ProbeResult(
                    probe_order=probe.order,
                    probe_type=probe.check_type,
                    url_path=probe.url_path,
                    skipped=True,
                    max_points=probe.weight or 0
                )
                result.probe_results.append(skipped_result)
                continue
            
            # Execute probe
            probe_result = self.probe_executor.execute_probe(base_url, probe)
            result.probe_results.append(probe_result)
            
            # Update running score with points_earned (supports partial scoring)
            current_score += probe_result.points_earned
        
        # Calculate final score
        result.calculate_score()
        result.verified_at = utc_now_iso()
        result.verification_duration_ms = int((time.time() - start_time) * 1000)
        
        return result
    
    def _verify_sequential(
        self,
        candidates: List[CandidateHost],
        probe_plan: ProbePlan,
        show_progress: bool
    ) -> List[VerificationResult]:
        """Verify candidates sequentially."""
        results = []
        
        iterator = tqdm(candidates, desc="Verifying", unit="host") if show_progress else candidates
        
        for candidate in iterator:
            result = self._verify_single_candidate(candidate, probe_plan)
            results.append(result)
        
        return results
    
    def _verify_parallel(
        self,
        candidates: List[CandidateHost],
        probe_plan: ProbePlan,
        show_progress: bool
    ) -> List[VerificationResult]:
        """Verify candidates in parallel using thread pool."""
        results = []
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all tasks
            future_to_candidate = {
                executor.submit(self._verify_single_candidate, candidate, probe_plan): candidate
                for candidate in candidates
            }
            
            # Collect results with progress bar
            if show_progress:
                pbar = tqdm(total=len(candidates), desc="Verifying", unit="host")
            
            for future in as_completed(future_to_candidate):
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    candidate = future_to_candidate[future]
                    # Create error result
                    result = VerificationResult(
                        ip=candidate.ip,
                        port=candidate.port,
                        hostname=candidate.hostname,
                        sources=candidate.sources,
                        location=_clean_location(candidate.location),
                        asn=candidate.asn,
                        organization=candidate.organization,
                        score=0.0,
                        classification="no_match"
                    )
                    result.probe_results.append(ProbeResult(
                        probe_order=0,
                        probe_type="favicon_hash",
                        url_path="/",
                        error=f"Verification failed: {str(e)[:100]}"
                    ))
                    results.append(result)
                
                if show_progress:
                    pbar.update(1)
            
            if show_progress:
                pbar.close()
        
        return results
    
    def _fetch_tls_certificates(self, report: VerificationReport) -> None:
        """Fetch TLS certificates for verified and likely matches.
        
        Only fetches for hosts with classification 'verified' or 'likely'.
        """
        from enrich.tls_client import TLSClient
        
        # Get verified/likely results
        tls_targets = [
            r for r in report.results
            if r.classification in ("verified", "likely")
        ]
        
        if not tls_targets:
            return
        
        print(f"\n[TLS] Fetching certificates for {len(tls_targets)} verified/likely hosts...")
        
        # Build target list - use port 443 or the original port
        targets = []
        result_map = {}  # Map (ip, port) to result
        
        for r in tls_targets:
            # Try HTTPS ports: 443 first, then original port if different
            if r.port == 443:
                targets.append((r.ip, 443))
                result_map[(r.ip, 443)] = r
            elif r.port == 80:
                # For port 80, try 443
                targets.append((r.ip, 443))
                result_map[(r.ip, 443)] = r
            else:
                # For other ports, try the port itself (might be HTTPS on non-standard port)
                targets.append((r.ip, r.port))
                result_map[(r.ip, r.port)] = r
        
        # Fetch TLS certificates
        tls_client = TLSClient(timeout=self.tls_timeout)
        tls_results = tls_client.bulk_fetch(
            targets=targets,
            workers=self.max_workers,
            show_progress=True
        )
        
        # Apply TLS info to results
        # All cert data is captured even for invalid/self-signed certs (for attribution)
        for key, tls_info in tls_results.items():
            ip, port = key.rsplit(":", 1)
            port = int(port)
            
            result = result_map.get((ip, port))
            if result:
                result.tls_common_name = tls_info.common_name
                result.tls_subject_org = tls_info.subject_org
                result.tls_issuer = tls_info.issuer
                result.tls_issuer_org = tls_info.issuer_org
                result.tls_valid = tls_info.is_valid
                result.tls_self_signed = tls_info.is_self_signed
                result.tls_san = tls_info.san
                result.tls_emails = tls_info.email_addresses
                result.tls_fingerprint = tls_info.fingerprint_sha256
                result.tls_error = tls_info.error
    
    def _print_summary(self, report: VerificationReport) -> None:
        """Print verification summary."""
        print(f"\n{'='*70}")
        print(f"[VERIFICATION SUMMARY]")
        print(f"{'='*70}")
        print(f"Total candidates: {report.total_candidates}")
        print(f"Duration: {report.total_duration_ms / 1000:.1f}s" if report.total_duration_ms else "")
        print(f"\nResults by classification:")
        print(f"  ✓ Verified (≥100):  {report.verified_count}")
        print(f"  ◉ Likely (≥70):     {report.likely_count}")
        print(f"  ◐ Partial (≥40):    {report.partial_count}")
        print(f"  ○ Unlikely (>0):    {report.unlikely_count}")
        print(f"  ✗ No match (0):     {report.no_match_count}")
        if report.error_count > 0:
            print(f"  ⚠ With errors:      {report.error_count}")
        
        # Scheme stats
        http_count = sum(1 for r in report.results if r.scheme == "http")
        https_count = sum(1 for r in report.results if r.scheme == "https")
        retry_count = sum(1 for r in report.results if r.alternate_scheme_tried)
        
        print(f"\nScheme used:")
        print(f"  HTTP:  {http_count}")
        print(f"  HTTPS: {https_count}")
        if retry_count > 0:
            print(f"  Alternate scheme tried: {retry_count}")
        
        # TLS summary
        tls_success = sum(1 for r in report.results if r.tls_common_name)
        if tls_success > 0:
            print(f"\nTLS certificates fetched: {tls_success}")
        
        print(f"{'='*70}")
    
    def save_report(
        self,
        report: VerificationReport,
        output_path: Path,
        include_all: bool = True
    ) -> None:
        """Save verification report to JSON.
        
        Args:
            report: The verification report
            output_path: Path to save JSON file
            include_all: Include all candidates (even score 0) - default True
        """
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Prepare output data
        output_data = {
            "fingerprint_run_id": report.fingerprint_run_id,
            "app_name": report.app_name,
            "verification_started": report.verification_started,
            "verification_completed": report.verification_completed,
            "total_duration_ms": report.total_duration_ms,
            "summary": {
                "total_candidates": report.total_candidates,
                "verified": report.verified_count,
                "likely": report.likely_count,
                "partial": report.partial_count,
                "unlikely": report.unlikely_count,
                "no_match": report.no_match_count,
                "errors": report.error_count
            },
            "results": []
        }
        
        # Sort by score (highest first)
        sorted_results = sorted(report.results, key=lambda r: r.score, reverse=True)
        
        for result in sorted_results:
            if include_all or result.score > 0:
                output_data["results"].append(result.model_dump())
        
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(output_data, f, indent=2)
        
        print(f"\n[✓] Verification report saved to: {output_path}")
        print(f"    Total results: {len(output_data['results'])} (including all scores)")

