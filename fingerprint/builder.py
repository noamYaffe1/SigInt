"""Probe plan builder for fingerprints."""
from typing import Dict, List

from core.models import FingerprintSpec, ProbePlan, ProbeStep


# Generic patterns to filter out
GENERIC_PATTERNS = [
    # HTML
    "<!doctype", "<html", "<head", "<body", "<meta", "<link", "<script",
    "viewport", "charset", "utf-8", "text/html", "text/css", "text/javascript",
    # Common
    "content-type", "cache-control", "expires", "pragma",
    "x-powered-by", "x-frame-options", "x-content-type",
    # Generic text
    "home", "index", "welcome", "loading", "please wait",
    "copyright", "all rights reserved", "privacy policy", "terms of service",
]

GENERIC_PATHS = [
    "/", "/index", "/home", "/admin", "/login", "/api", "/config",
    "/wp-admin", "/wp-login", "/xmlrpc.php", "/administrator",
    "/robots.txt", "/sitemap.xml", "/.well-known",
]


class ProbePlanBuilder:
    """Builds probe plans from fingerprint specifications."""
    
    def build_probe_plan(self, spec: FingerprintSpec) -> ProbePlan:
        """Build a probe plan from fingerprint spec.
        
        Args:
            spec: The fingerprint specification
            
        Returns:
            ProbePlan with ordered probe steps
        """
        steps: List[ProbeStep] = []
        order = 0
        
        # Priority 1: Favicon hash (most reliable)
        if spec.favicon and spec.favicon.hashes and spec.favicon.hashes.mmh3:
            order += 1
            # Include alternative MMH3 hashes if present
            expected_hash = {"hash_type": "mmh3", "value": str(spec.favicon.hashes.mmh3)}
            if spec.favicon.hashes.mmh3_alt:
                expected_hash["alt_values"] = spec.favicon.hashes.mmh3_alt
            
            # Use the actual favicon URL from the spec (LLM-discovered or fallback)
            favicon_url = spec.favicon.url or "/favicon.ico"
            steps.append(ProbeStep(
                order=order,
                check_type="favicon_hash",
                url_path=favicon_url,
                description=f"Verify favicon hash (MMH3) at {favicon_url}",
                expected_hash=expected_hash,
                weight=3  # High weight - very reliable
            ))
        
        # Priority 2: Page signatures
        for idx, sig in enumerate(spec.page_signatures):
            order += 1
            steps.append(ProbeStep(
                order=order,
                check_type="page_signature",
                url_path=sig.url,
                description=f"Verify page signature: {sig.url}",
                fingerprint_index=idx,
                expected_status=200,  # Default expected status
                expected_title_pattern=sig.title_pattern,
                expected_body_patterns=sig.body_patterns,
                weight=1  # Lower weight - can have false positives
            ))
        
        # Priority 3: Key image hashes
        for idx, img in enumerate(spec.key_images):
            if img.hashes and img.hashes.mmh3:
                order += 1
                steps.append(ProbeStep(
                    order=order,
                    check_type="image_hash",
                    url_path=img.url,
                    description=f"Verify image hash: {img.url}",
                    fingerprint_index=idx,
                    expected_hash={"hash_type": "mmh3", "value": str(img.hashes.mmh3)},
                    weight=2  # Medium weight
                ))
        
        # Calculate minimum matches
        # At least 2 matches, or 50% of probes, whichever is higher
        min_matches = max(2, len(steps) // 2)
        
        plan = ProbePlan(
            probe_steps=steps,
            minimum_matches_required=min_matches
        )
        
        # Apply default weights based on probe type
        plan.apply_default_weights()
        
        return plan
    
    def filter_generic_patterns(self, analysis: Dict) -> Dict:
        """Filter out generic patterns from LLM analysis.
        
        Args:
            analysis: Raw LLM analysis dictionary
            
        Returns:
            Filtered analysis with generic patterns removed
        """
        filtered = analysis.copy()
        
        # Filter body patterns
        if "page_signatures" in filtered:
            for sig in filtered["page_signatures"]:
                if "body_patterns" in sig and sig["body_patterns"]:
                    sig["body_patterns"] = [
                        p for p in sig["body_patterns"]
                        if not self._is_generic(p)
                    ]
        
        return filtered
    
    def _is_generic(self, pattern: str) -> bool:
        """Check if a pattern is too generic."""
        if not pattern:
            return True
        
        pattern_lower = pattern.lower()
        
        # Check against generic patterns
        for generic in GENERIC_PATTERNS:
            if generic in pattern_lower:
                return True
        
        # Too short patterns are likely generic
        if len(pattern) < 5:
            return True
        
        # Pure HTML tags
        if pattern.startswith("<") and pattern.endswith(">"):
            return True
        
        return False
    
    def _is_generic_path(self, path: str) -> bool:
        """Check if a path is too generic."""
        if not path:
            return True
        
        path_lower = path.lower()
        
        for generic in GENERIC_PATHS:
            if path_lower == generic or path_lower.startswith(generic + "/"):
                return True
        
        return False

