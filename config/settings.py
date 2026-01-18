"""Settings and configuration management for SigInt.

Configuration is loaded from (in order of precedence):
1. CLI arguments (highest priority)
2. Environment variables (SIGINT_*)
3. Config file (~/.sigint/config.yaml or ./sigint.yaml)
4. Built-in defaults (lowest priority)

IMPORTANT: All default values should be defined HERE only.
Other modules should import from config to avoid duplication.
"""
import os
from pathlib import Path
from typing import Optional, Dict, List, Any
from pydantic import BaseModel, Field
from functools import lru_cache
import yaml


# =============================================================================
# SINGLE SOURCE OF TRUTH: Default Values
# =============================================================================
# All default values are defined here. Do NOT duplicate in other files.

class Defaults:
    """Central location for all default values."""
    
    # Probe Points (Additive Scoring)
    # Max score is 100 (capped)
    PROBE_POINTS_FAVICON = 80      # Favicon hash match
    PROBE_POINTS_IMAGE = 50        # Each image hash match
    PROBE_POINTS_TITLE = 15        # Title pattern match
    PROBE_POINTS_BODY = 15         # Each body pattern match
    MAX_SCORE = 100                # Maximum possible score (cap)
    
    # Legacy: page_signature is now split into title + body
    PROBE_POINTS_PAGE = 30  # Kept for backwards compatibility
    
    # Score Thresholds
    SCORE_VERIFIED = 80   # Was 100, now 80 for more realistic matching
    SCORE_LIKELY = 50
    SCORE_PARTIAL = 30
    
    # Verification
    VERIFY_TIMEOUT = 10
    VERIFY_WORKERS = 10
    TLS_TIMEOUT = 5
    SCHEME_RETRY_THRESHOLD = 50  # Retry with alternate scheme if score < this
    
    # Discovery
    CACHE_TTL_DAYS = 7
    ENRICH_WORKERS = 20
    MAX_QUERIES = 10  # Max discovery queries per fingerprint (to save API tokens)
    
    # Fingerprint
    MAX_ITERATIONS = 3
    LLM_MODEL = "gpt-4o"
    LLM_TEMPERATURE = 0.2
    MAX_BODY_LENGTH = 50000
    REQUEST_TIMEOUT = 10
    USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
    
    # Fingerprint Modes
    # application: Find all deployments of a software (DVWA, WordPress) - version agnostic
    # organization: Find all assets of a company/brand (Monday.com, BSidesTLV) - brand focused
    FINGERPRINT_MODE = "application"
    INCLUDE_VERSION = False  # Whether to include version/year in fingerprints
    
    @classmethod
    def get_probe_points(cls) -> Dict[str, int]:
        """Get default probe points as dictionary."""
        return {
            "favicon_hash": cls.PROBE_POINTS_FAVICON,
            "image_hash": cls.PROBE_POINTS_IMAGE,
            "page_signature": cls.PROBE_POINTS_PAGE,  # Legacy
            "title_match": cls.PROBE_POINTS_TITLE,
            "body_match": cls.PROBE_POINTS_BODY,
            "max_score": cls.MAX_SCORE,
        }


# =============================================================================
# Configuration Models
# =============================================================================

class ProbePointsConfig(BaseModel):
    """Default probe points for additive scoring.
    
    Points are additive up to max_score (default 100).
    Example: favicon(80) + title(15) + 1 body pattern(15) = 110 → capped at 100
    """
    favicon_hash: int = Field(default=Defaults.PROBE_POINTS_FAVICON, description="Points for favicon hash match")
    image_hash: int = Field(default=Defaults.PROBE_POINTS_IMAGE, description="Points for each image hash match")
    title_match: int = Field(default=Defaults.PROBE_POINTS_TITLE, description="Points for title pattern match")
    body_match: int = Field(default=Defaults.PROBE_POINTS_BODY, description="Points for each body pattern match")
    max_score: int = Field(default=Defaults.MAX_SCORE, description="Maximum score cap")
    
    # Legacy (kept for backwards compatibility with existing fingerprints)
    page_signature: int = Field(default=Defaults.PROBE_POINTS_PAGE, description="[Legacy] Points for page signature match")


class ScoreThresholdsConfig(BaseModel):
    """Score thresholds for classification."""
    verified: int = Field(default=Defaults.SCORE_VERIFIED, description="Minimum score for 'verified' classification")
    likely: int = Field(default=Defaults.SCORE_LIKELY, description="Minimum score for 'likely' classification")
    partial: int = Field(default=Defaults.SCORE_PARTIAL, description="Minimum score for 'partial' classification")


class VerificationConfig(BaseModel):
    """Phase 3 verification settings."""
    timeout: int = Field(default=Defaults.VERIFY_TIMEOUT, description="Request timeout in seconds")
    workers: int = Field(default=Defaults.VERIFY_WORKERS, description="Concurrent verification workers")
    fetch_tls: bool = Field(default=True, description="Fetch TLS certificates for verified hosts")
    tls_timeout: int = Field(default=Defaults.TLS_TIMEOUT, description="TLS connection timeout in seconds")
    probe_points: ProbePointsConfig = Field(default_factory=ProbePointsConfig)
    score_thresholds: ScoreThresholdsConfig = Field(default_factory=ScoreThresholdsConfig)


class DiscoveryConfig(BaseModel):
    """Phase 2 discovery settings."""
    max_queries: int = Field(default=Defaults.MAX_QUERIES, description="Max queries to generate from fingerprint")
    max_candidates: Optional[int] = Field(default=None, description="Max candidates (None = no limit)")
    cache_ttl_days: int = Field(default=Defaults.CACHE_TTL_DAYS, description="Cache TTL in days")
    cache_strategy: str = Field(default="cache_and_new", description="cache_only, new_only, or cache_and_new")
    enrich_workers: int = Field(default=Defaults.ENRICH_WORKERS, description="Concurrent enrichment workers")
    skip_enrichment: bool = Field(default=False, description="Skip IPInfo enrichment")
    enabled_plugins: List[str] = Field(default_factory=lambda: ["shodan", "censys"], description="Enabled discovery plugins")


class FingerprintConfig(BaseModel):
    """Phase 1 fingerprinting settings."""
    max_iterations: int = Field(default=Defaults.MAX_ITERATIONS, description="Max LLM iterations")
    model: str = Field(default=Defaults.LLM_MODEL, description="OpenAI model to use")
    temperature: float = Field(default=Defaults.LLM_TEMPERATURE, description="LLM temperature")
    max_body_length: int = Field(default=Defaults.MAX_BODY_LENGTH, description="Max body length for LLM context")
    user_agent: str = Field(default=Defaults.USER_AGENT, description="User agent for HTTP requests")
    request_timeout: int = Field(default=Defaults.REQUEST_TIMEOUT, description="HTTP request timeout")
    mode: str = Field(default=Defaults.FINGERPRINT_MODE, description="Fingerprint mode: application or organization")
    include_version: bool = Field(default=Defaults.INCLUDE_VERSION, description="Include version/year in fingerprints")


class ExportConfig(BaseModel):
    """Export settings."""
    default_formats: List[str] = Field(default_factory=lambda: ["json"], description="Default export formats")
    output_dir: str = Field(default="output/exports", description="Default export directory")
    min_score: int = Field(default=0, description="Minimum score to include in export")
    include_no_match: bool = Field(default=True, description="Include no-match results in export")


class APIConfig(BaseModel):
    """API keys and endpoints (loaded from environment)."""
    openai_api_key: Optional[str] = Field(default=None, description="OpenAI API key")
    shodan_api_key: Optional[str] = Field(default=None, description="Shodan API key")
    censys_personal_access_token: Optional[str] = Field(default=None, description="Censys Personal Access Token")
    censys_org_id: Optional[str] = Field(default=None, description="Censys Organization ID")
    ipinfo_token: Optional[str] = Field(default=None, description="IPInfo API token")


class OutputConfig(BaseModel):
    """Output paths and naming."""
    base_dir: str = Field(default="output", description="Base output directory")
    fingerprints_dir: str = Field(default="output/fingerprints", description="Fingerprints output directory")
    candidates_dir: str = Field(default="output/candidates", description="Candidates output directory")
    exports_dir: str = Field(default="output/exports", description="Exports output directory")
    cache_dir: str = Field(default="output/cache", description="Cache directory")


class Settings(BaseModel):
    """Main settings container."""
    fingerprint: FingerprintConfig = Field(default_factory=FingerprintConfig)
    discovery: DiscoveryConfig = Field(default_factory=DiscoveryConfig)
    verification: VerificationConfig = Field(default_factory=VerificationConfig)
    export: ExportConfig = Field(default_factory=ExportConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)
    api: APIConfig = Field(default_factory=APIConfig)
    
    def load_api_keys_from_env(self) -> None:
        """Load API keys from environment variables."""
        self.api.openai_api_key = os.getenv("OPENAI_API_KEY")
        self.api.shodan_api_key = os.getenv("SHODAN_API_KEY")
        self.api.censys_personal_access_token = os.getenv("CENSYS_PERSONAL_ACCESS_TOKEN")
        self.api.censys_org_id = os.getenv("CENSYS_ORG_ID")
        self.api.ipinfo_token = os.getenv("IPINFO_TOKEN")
    
    def get_probe_points_dict(self) -> Dict[str, int]:
        """Get probe points as a dictionary for apply_default_weights()."""
        return {
            "favicon_hash": self.verification.probe_points.favicon_hash,
            "image_hash": self.verification.probe_points.image_hash,
            "page_signature": self.verification.probe_points.page_signature,
        }


# =============================================================================
# Config File Loading
# =============================================================================

def find_config_file() -> Optional[Path]:
    """Find config file in standard locations.
    
    Search order:
    1. ./sigint.yaml (current directory)
    2. ~/.sigint/config.yaml (user home)
    3. ~/.config/sigint/config.yaml (XDG config)
    """
    locations = [
        Path("./sigint.yaml"),
        Path("./sigint.yml"),
        Path.home() / ".sigint" / "config.yaml",
        Path.home() / ".sigint" / "config.yml",
        Path.home() / ".config" / "sigint" / "config.yaml",
    ]
    
    for path in locations:
        if path.exists():
            return path
    
    return None


def load_config_file(path: Optional[Path] = None) -> Dict[str, Any]:
    """Load configuration from YAML file.
    
    Args:
        path: Optional explicit path, otherwise searches standard locations
        
    Returns:
        Dictionary of config values (empty if no file found)
    """
    if path is None:
        path = find_config_file()
    
    if path is None or not path.exists():
        return {}
    
    try:
        with open(path, "r") as f:
            config = yaml.safe_load(f) or {}
        return config
    except Exception as e:
        print(f"[WARNING] Failed to load config file {path}: {e}")
        return {}


def merge_config(base: Dict, override: Dict) -> Dict:
    """Deep merge two config dictionaries."""
    result = base.copy()
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = merge_config(result[key], value)
        else:
            result[key] = value
    return result


@lru_cache()
def get_settings(config_file: Optional[str] = None) -> Settings:
    """Get settings instance (cached).
    
    Loads from config file and environment variables.
    
    Args:
        config_file: Optional explicit config file path
        
    Returns:
        Settings instance with merged configuration
    """
    # Load from file
    file_config = load_config_file(Path(config_file) if config_file else None)
    
    # Create settings with file config
    if file_config:
        settings = Settings.model_validate(file_config)
    else:
        settings = Settings()
    
    # Load API keys from environment
    settings.load_api_keys_from_env()
    
    return settings


def create_default_config_file(path: Path = None) -> Path:
    """Create a default config file with all options documented.
    
    Args:
        path: Where to create the file (default: ./sigint.yaml)
        
    Returns:
        Path to created file
    """
    if path is None:
        path = Path("./sigint.yaml")
    
    default_config = """\
# SigInt Configuration File
# ========================
# Place this file in:
#   - ./sigint.yaml (current directory)
#   - ~/.sigint/config.yaml (user home)
#   - ~/.config/sigint/config.yaml (XDG config)

# Phase 1: Fingerprinting
fingerprint:
  max_iterations: 3        # Max LLM exploration iterations
  model: "gpt-4o"          # OpenAI model to use
  temperature: 0.2         # LLM temperature (lower = more deterministic)
  
  # Fingerprint Mode:
  # - application: Find all deployments of software (DVWA, WordPress) - version agnostic
  # - organization: Find all assets of company/brand (Monday.com, BSidesTLV) - brand focused
  mode: "application"
  include_version: false   # Include version/year in fingerprints (default: false)

# Phase 2: Discovery
discovery:
  max_queries: 10          # Max queries from fingerprint (saves API tokens)
  max_candidates: null     # Max candidates after deduplication (null = no limit)
  cache_ttl_days: 7        # Cache expiration in days
  cache_strategy: "cache_and_new"  # cache_only, new_only, or cache_and_new
  enrich_workers: 20       # Concurrent IPInfo enrichment workers
  skip_enrichment: false   # Skip IPInfo enrichment
  enabled_plugins:         # Discovery sources to use
    - shodan
    - censys

# Phase 3: Verification
verification:
  timeout: 10              # Request timeout in seconds
  workers: 10              # Concurrent verification workers
  fetch_tls: true          # Fetch TLS certs for verified hosts
  tls_timeout: 5           # TLS connection timeout
  
  # Additive scoring - points awarded per probe match
  # Score = sum of matched points (capped at 100)
  # If score reaches 100, remaining probes are skipped (early termination)
  probe_points:
    favicon_hash: 80       # Favicon hash match
    image_hash: 50         # Strong - content-based hash
    title_match: 15        # HTML title pattern match
    body_match: 15         # Per body pattern match
    max_score: 100         # Score cap
  
  # Classification thresholds (based on max_score of 100)
  score_thresholds:
    verified: 80           # Minimum score for "verified"
    likely: 50             # Minimum score for "likely"
    partial: 30            # Minimum score for "partial"

# Export settings
export:
  default_formats:         # Default export formats
    - json
    # - csv
    # - html
  output_dir: "output/exports"
  min_score: 0             # Minimum score to include
  include_no_match: true   # Include 0-score results

# Output directories
output:
  base_dir: "output"
  fingerprints_dir: "output/fingerprints"
  candidates_dir: "output/candidates"
  exports_dir: "output/exports"
  cache_dir: "output/cache"

# API Keys (prefer environment variables for security)
# Set these in your shell: export SHODAN_API_KEY="your-key"
# api:
#   shodan_api_key: "your-shodan-key"
#   censys_personal_access_token: "your-censys-pat"
#   ipinfo_token: "your-ipinfo-token"
#   openai_api_key: "your-openai-key"
"""
    
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        f.write(default_config)
    
    return path

