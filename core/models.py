"""Data models for fingerprinting specifications and probe plans."""
from typing import Optional, Dict, List, Literal, Union
from pydantic import BaseModel, Field

# Import defaults from config - single source of truth
from config import Defaults


class HashSet(BaseModel):
    """Multiple hash types for a single asset."""
    sha256: Optional[str] = None
    md5: Optional[str] = None
    phash: Optional[str] = None  # Perceptual hash for images
    mmh3: Optional[str] = None  # MurmurHash3 (used by Shodan)
    mmh3_alt: List[str] = Field(default_factory=list)  # Alternative MMH3 hashes
    
    def __bool__(self) -> bool:
        """Return True if any hash is present."""
        return any([self.sha256, self.md5, self.phash, self.mmh3])
    
    def get_all_mmh3(self) -> List[str]:
        """Get all MMH3 hashes (primary + alternatives)."""
        hashes = []
        if self.mmh3:
            hashes.append(self.mmh3)
        hashes.extend(self.mmh3_alt)
        return hashes


class FaviconFingerprint(BaseModel):
    """Favicon fingerprinting data."""
    url: str
    hashes: HashSet
    content_type: Optional[str] = None


class ImageFingerprint(BaseModel):
    """Image/logo fingerprinting data."""
    url: str
    hashes: HashSet
    description: Optional[str] = None  # What this image represents (e.g., "main logo")


class PageSignature(BaseModel):
    """Signature for a page's content."""
    url: str
    title_pattern: Optional[str] = Field(
        default=None,
        description="Regex pattern for title (use OR | for alternatives, e.g., 'Term1|Term2|Term3')"
    )
    body_patterns: List[str] = Field(
        default_factory=list,
        description="Regex patterns for distinctive text (simple keywords or OR patterns, matched case-insensitive)"
    )
    meta_tags: Optional[Dict[str, str]] = None  # Important meta tags
    
    def model_dump(self, **kwargs) -> dict:
        """Override to exclude None values and empty lists."""
        kwargs.setdefault('exclude_none', True)
        data = super().model_dump(**kwargs)
        if not data.get('body_patterns'):
            data.pop('body_patterns', None)
        return data


class FingerprintSpec(BaseModel):
    """Complete fingerprint specification for an application."""
    app_name: str
    source_type: Literal["local_repo", "github_repo", "live_site"]
    source_location: str
    
    # Core fingerprinting signals
    favicon: Optional[FaviconFingerprint] = None
    key_images: List[ImageFingerprint] = Field(default_factory=list)
    page_signatures: List[PageSignature] = Field(default_factory=list)
    
    # Headers that might be present (supporting evidence)
    common_headers: Optional[Dict[str, str]] = None
    
    # LLM-generated insights (for analyst context only, not used in verification)
    distinctive_features: List[str] = Field(
        default_factory=list,
        description="Human-readable list of distinctive features identified by LLM. For analyst context only."
    )
    
    # Metadata
    confidence_level: Literal["high", "medium", "low"] = "medium"
    notes: Optional[str] = None
    run_id: Optional[str] = Field(
        default=None,
        description="Unique run ID with timestamp (e.g., '20251109_183045_abc123')"
    )
    created_at: Optional[str] = Field(
        default=None,
        description="ISO timestamp when fingerprint was created"
    )
    
    # Mode configuration
    fingerprint_mode: Literal["application", "organization"] = Field(
        default="application",
        description="Fingerprint mode: 'application' (software deployments) or 'organization' (company assets)"
    )
    include_version: bool = Field(
        default=False,
        description="Whether version/year was included in fingerprint patterns"
    )
    
    def model_dump(self, **kwargs) -> dict:
        """Override to exclude None values and empty lists."""
        kwargs.setdefault('exclude_none', True)
        data = super().model_dump(**kwargs)
        # Remove empty lists
        if not data.get('key_images'):
            data.pop('key_images', None)
        if not data.get('page_signatures'):
            data.pop('page_signatures', None)
        if not data.get('distinctive_features'):
            data.pop('distinctive_features', None)
        return data


class ProbeStep(BaseModel):
    """A single probe step in the verification plan.
    
    Contains ALL necessary information to execute the check without lookups.
    Phase 3 verification can use this standalone without referencing fingerprint_spec.
    
    Uses relative paths so it works with dynamic IPs/domains from Shodan/Censys.
    """
    order: int
    url_path: str  # Relative path like "/favicon.ico" or "/dvwa/images/logo.png"
    method: str = "GET"
    description: str
    check_type: Literal[
        "favicon_hash",      # Hash-based favicon matching
        "page_signature",    # Page title/body pattern matching + status check
        "image_hash"         # Hash-based image matching
    ]
    
    # For hash-based checks (favicon_hash, image_hash)
    expected_hash: Optional[Dict[str, Union[str, List[str]]]] = Field(
        default=None,
        description="For hash checks: {'hash_type': 'mmh3|sha256|md5|phash', 'value': 'hash_value', 'alt_values': ['alt1', 'alt2']}"
    )
    
    # For page_signature checks
    expected_title_pattern: Optional[str] = Field(
        default=None,
        description="Regex pattern to match page title (use OR | for alternatives)"
    )
    expected_body_patterns: Optional[List[str]] = Field(
        default=None,
        description="List of regex patterns that must ALL match in response body"
    )
    expected_status: Optional[int] = Field(
        default=None,
        description="Expected HTTP status code (typically 200 for page_signature)"
    )
    
    # Optional: reference to source element (for debugging/tracing only)
    fingerprint_index: Optional[int] = Field(
        default=None,
        description="Source index in fingerprint_spec arrays (for reference only, not needed for verification)"
    )
    
    # Points for additive scoring (user-customizable)
    weight: int = Field(
        default=1,
        ge=0,
        description="Points awarded if this probe matches. Score = sum of matched points (capped at 100). Default: favicon=80, image=50, title=15, body=15"
    )
    
    def model_dump(self, **kwargs) -> dict:
        """Override to exclude None values for cleaner output."""
        kwargs.setdefault('exclude_none', True)
        return super().model_dump(**kwargs)


class ProbePlan(BaseModel):
    """Plan for actively verifying a candidate host.
    
    Uses ADDITIVE scoring with early termination:
    - Score = sum of matched probe points (capped at 100)
    - If score reaches 100, remaining probes are SKIPPED (early termination)
    
    Default points: favicon=80, image=50, title=15, body=15
    
    Example: Set favicon to guarantee instant verification:
        plan.set_probe_weight("favicon_hash", 80)
    """
    probe_steps: List[ProbeStep] = Field(default_factory=list)
    minimum_matches_required: int = 2  # Minimum signals that must match
    
    # Default points by probe type (additive scoring) - uses config defaults
    default_weights: Dict[str, int] = Field(
        default_factory=Defaults.get_probe_points
    )
    
    def apply_default_weights(self, custom_defaults: Dict[str, int] = None, force: bool = True) -> None:
        """Apply default weights to all probe steps based on their type.
        
        Args:
            custom_defaults: Optional custom defaults from config file
            force: If True, always apply defaults (overwrite existing). Default True.
        """
        defaults = custom_defaults or self.default_weights
        for step in self.probe_steps:
            if force or step.weight == 1:  # Apply if forced or not yet customized
                step.weight = defaults.get(step.check_type, 10)
    
    def set_probe_weight(self, probe_type: str, weight: int) -> None:
        """Set weight for all probes of a given type.
        
        Args:
            probe_type: One of "favicon_hash", "image_hash", "page_signature"
            weight: Weight value (0-100)
        """
        for step in self.probe_steps:
            if step.check_type == probe_type:
                step.weight = weight
    
    def set_weight_by_order(self, order: int, weight: int) -> None:
        """Set weight for a specific probe by its order number.
        
        Args:
            order: The probe's order number (1-based)
            weight: Weight value (0-100)
        """
        for step in self.probe_steps:
            if step.order == order:
                step.weight = weight
                break
    
    def get_weights_summary(self) -> Dict[str, int]:
        """Get a summary of weights by probe order."""
        return {
            f"{step.order}:{step.check_type}:{step.url_path}": step.weight
            for step in self.probe_steps
        }
    timeout_seconds: int = 10
    follow_redirects: bool = True


class FingerprintOutput(BaseModel):
    """Complete output combining spec and probe plan."""
    fingerprint_spec: FingerprintSpec
    probe_plan: ProbePlan
    
    def model_dump(self, **kwargs) -> dict:
        """Override to exclude None values by default."""
        kwargs.setdefault('exclude_none', True)
        return super().model_dump(**kwargs)
