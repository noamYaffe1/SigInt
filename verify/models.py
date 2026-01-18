"""Verification module data models."""
from typing import List, Dict, Optional, Literal
from pydantic import BaseModel, Field
from core.utils import utc_now_iso


class ProbeResult(BaseModel):
    """Result of a single probe step execution."""
    probe_order: int
    probe_type: Literal["favicon_hash", "page_signature", "image_hash"]
    url_path: str
    
    # Execution status
    success: bool = False  # Did the probe execute without errors?
    matched: bool = False  # Did the probe match (or partially match) the fingerprint?
    skipped: bool = False  # Was this probe skipped (early termination)?
    
    # Details
    expected: Optional[str] = None  # What we expected to find
    actual: Optional[str] = None    # What we actually found
    error: Optional[str] = None     # Error message if probe failed
    
    # Timing
    response_time_ms: Optional[int] = None
    http_status: Optional[int] = None
    
    # Points (additive scoring)
    points_earned: int = 0   # Actual points earned from this probe
    max_points: int = 0      # Maximum possible points for this probe type
    
    # Legacy compatibility
    @property
    def points(self) -> int:
        """Legacy property for backwards compatibility."""
        return self.points_earned
    
    def model_dump(self, **kwargs) -> dict:
        """Override to exclude None values and include earned points."""
        kwargs.setdefault('exclude_none', True)
        data = super().model_dump(**kwargs)
        # Remove zero values for cleaner output
        if data.get('points_earned') == 0:
            data.pop('points_earned', None)
        if data.get('max_points') == 0:
            data.pop('max_points', None)
        return data


# Import defaults from config - single source of truth
from config import Defaults

# Get probe points from config defaults
DEFAULT_PROBE_POINTS = Defaults.get_probe_points()


class VerificationResult(BaseModel):
    """Verification result for a single candidate."""
    # Candidate identity
    ip: str
    port: int
    hostname: Optional[str] = None
    
    # Scoring
    total_probes: int = 0
    matched_probes: int = 0
    score: float = 0.0  # 0.0 to 100.0 percentage (weighted)
    
    # Classification based on score
    classification: Literal["verified", "likely", "partial", "unlikely", "no_match"] = "no_match"
    
    # Detailed results
    probe_results: List[ProbeResult] = Field(default_factory=list)
    
    # Metadata from discovery
    sources: List[str] = Field(default_factory=list)
    location: Optional[Dict[str, Optional[str]]] = None
    asn: Optional[str] = None
    organization: Optional[str] = None
    
    # Enrichment data
    hosting_provider: Optional[str] = None  # AWS, GCP, Azure, etc.
    is_cloud_hosted: bool = False
    
    # TLS certificate info (for verified/likely matches)
    # Extracted even for invalid/self-signed certs for attribution
    tls_common_name: Optional[str] = None      # Subject CN (e.g., "*.example.com")
    tls_subject_org: Optional[str] = None      # Subject organization (useful for attribution)
    tls_issuer: Optional[str] = None           # Issuer CN
    tls_issuer_org: Optional[str] = None       # Issuer organization
    tls_valid: Optional[bool] = None           # Is cert currently valid?
    tls_self_signed: Optional[bool] = None     # Is cert self-signed?
    tls_san: List[str] = Field(default_factory=list)  # Subject Alternative Names
    tls_emails: List[str] = Field(default_factory=list)  # Email addresses from cert
    tls_fingerprint: Optional[str] = None      # SHA256 fingerprint
    tls_error: Optional[str] = None            # Error if fetch failed
    
    # Verification metadata
    verified_at: Optional[str] = None
    verification_duration_ms: Optional[int] = None
    scheme: str = "http"  # http or https - which scheme was used for verification
    alternate_scheme_tried: bool = False  # Was the alternate scheme tried?
    prefix_used: Optional[str] = None  # App prefix if used (e.g., "/dvwa")
    
    @property
    def url(self) -> str:
        """Construct base URL for this candidate (scheme://ip:port[/prefix])."""
        base = f"{self.scheme}://{self.ip}:{self.port}"
        if self.prefix_used:
            return f"{base}{self.prefix_used}"
        return base
    
    def model_dump(self, **kwargs) -> Dict:
        """Override to include computed url field and exclude None/empty values."""
        kwargs.setdefault('exclude_none', True)
        data = super().model_dump(**kwargs)
        data['url'] = self.url  # Add computed URL to output
        # Remove empty collections and default booleans
        if not data.get('probe_results'):
            data.pop('probe_results', None)
        if not data.get('tls_san'):
            data.pop('tls_san', None)
        if not data.get('tls_emails'):
            data.pop('tls_emails', None)
        if not data.get('sources'):
            data.pop('sources', None)
        if not data.get('is_cloud_hosted'):
            data.pop('is_cloud_hosted', None)
        if not data.get('alternate_scheme_tried'):
            data.pop('alternate_scheme_tried', None)
        return data
    
    def calculate_score(self) -> None:
        """Calculate additive score and classification from probe results.
        
        Additive scoring: score = sum of points_earned from each probe (capped at max_score)
        
        Scoring breakdown:
        - favicon_hash: 80 points
        - image_hash: 50 points each
        - title_match: 15 points
        - body_match: 15 points each
        - max_score: 100 (cap)
        """
        # Count probes (excluding skipped)
        executed_probes = [p for p in self.probe_results if not p.skipped]
        self.total_probes = len(executed_probes)
        self.matched_probes = sum(1 for p in executed_probes if p.points_earned > 0)
        
        # Calculate additive score from points_earned
        total_points = sum(p.points_earned for p in self.probe_results if not p.skipped)
        
        # Cap score at max_score (default 100)
        max_score = DEFAULT_PROBE_POINTS.get("max_score", 100)
        self.score = min(float(max_score), float(total_points))
        
        # Classification thresholds
        self._classify_score()
    
    def _classify_score(self) -> None:
        """Classify score based on thresholds from config defaults."""
        # Use thresholds from Defaults
        verified_threshold = Defaults.SCORE_VERIFIED  # 80
        likely_threshold = Defaults.SCORE_LIKELY      # 50
        partial_threshold = Defaults.SCORE_PARTIAL    # 30
        
        if self.score >= verified_threshold:
            self.classification = "verified"
        elif self.score >= likely_threshold:
            self.classification = "likely"
        elif self.score >= partial_threshold:
            self.classification = "partial"
        elif self.score > 0:
            self.classification = "unlikely"
        else:
            self.classification = "no_match"


class VerificationReport(BaseModel):
    """Complete verification report for all candidates."""
    # Fingerprint reference
    fingerprint_run_id: str
    app_name: str
    
    # Summary stats
    total_candidates: int = 0
    verified_count: int = 0      # score >= 80
    likely_count: int = 0        # score >= 60
    partial_count: int = 0       # score >= 40
    unlikely_count: int = 0      # score > 0
    no_match_count: int = 0      # score == 0
    error_count: int = 0         # probes that errored
    
    # All results (including score 0)
    results: List[VerificationResult] = Field(default_factory=list)
    
    # Metadata
    verification_started: str = Field(
        default_factory=utc_now_iso
    )
    verification_completed: Optional[str] = None
    total_duration_ms: Optional[int] = None
    
    def calculate_summary(self) -> None:
        """Calculate summary statistics from results."""
        self.total_candidates = len(self.results)
        self.verified_count = sum(1 for r in self.results if r.classification == "verified")
        self.likely_count = sum(1 for r in self.results if r.classification == "likely")
        self.partial_count = sum(1 for r in self.results if r.classification == "partial")
        self.unlikely_count = sum(1 for r in self.results if r.classification == "unlikely")
        self.no_match_count = sum(1 for r in self.results if r.classification == "no_match")
        self.error_count = sum(
            1 for r in self.results 
            if any(p.error for p in r.probe_results)
        )

