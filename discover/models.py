"""Discovery module data models."""
import hashlib
from typing import List, Dict, Optional, Literal
from pydantic import BaseModel, Field


class CandidateHost(BaseModel):
    """A candidate host discovered via passive intelligence."""
    ip: str
    port: int
    hostname: Optional[str] = None
    
    # Metadata
    sources: List[Literal["shodan", "censys"]] = Field(default_factory=list)
    last_seen: Optional[str] = None  # ISO timestamp
    location: Optional[Dict[str, Optional[str]]] = None  # country, city, etc.
    asn: Optional[str] = None
    organization: Optional[str] = None
    
    # Enrichment data (from IPInfo)
    hosting_provider: Optional[str] = None  # AWS, GCP, Azure, DigitalOcean, etc.
    is_cloud_hosted: bool = False
    enriched_at: Optional[str] = None  # ISO timestamp when enriched
    
    def model_dump(self, **kwargs) -> dict:
        """Override to exclude None values and empty collections."""
        kwargs.setdefault('exclude_none', True)
        data = super().model_dump(**kwargs)
        # Remove empty collections and default booleans
        if not data.get('sources'):
            data.pop('sources', None)
        if not data.get('is_cloud_hosted'):
            data.pop('is_cloud_hosted', None)
        return data
    
    # For deduplication
    @property
    def key(self) -> str:
        """Unique key for deduplication."""
        return f"{self.ip}:{self.port}"
    
    @property
    def url(self) -> str:
        """HTTP URL for this candidate."""
        return f"http://{self.ip}:{self.port}"
    
    def merge_with(self, other: 'CandidateHost') -> 'CandidateHost':
        """Merge data from another candidate (same IP:port)."""
        # Combine sources
        all_sources = list(set(self.sources + other.sources))
        
        # Prefer newer last_seen
        last_seen = self.last_seen
        if other.last_seen:
            if not last_seen or other.last_seen > last_seen:
                last_seen = other.last_seen
        
        # Prefer non-empty values
        return CandidateHost(
            ip=self.ip,
            port=self.port,
            hostname=self.hostname or other.hostname,
            sources=all_sources,
            last_seen=last_seen,
            location=self.location or other.location,
            asn=self.asn or other.asn,
            organization=self.organization or other.organization,
            hosting_provider=self.hosting_provider or other.hosting_provider,
            is_cloud_hosted=self.is_cloud_hosted or other.is_cloud_hosted,
            enriched_at=self.enriched_at or other.enriched_at
        )


class QueryCache(BaseModel):
    """Cache for a single search query result.
    
    Each unique query (platform + query string) gets its own cache entry.
    This allows:
    - Reusing cached results across different fingerprints (same query = same results)
    - Only re-running queries that have changed
    - Efficient API credit usage
    """
    query_hash: str  # Hash of platform + query string
    platform: Literal["shodan", "censys"]
    query_type: str  # e.g., "favicon", "title", "body"
    query_string: str  # The actual query sent to the API
    query_timestamp: str  # ISO timestamp when query was executed
    result_count: int  # Number of results returned
    candidates: List[CandidateHost] = Field(default_factory=list)
    
    @staticmethod
    def hash_query(platform: str, query_string: str) -> str:
        """Generate unique hash for a platform + query combination."""
        content = f"{platform}:{query_string}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]
