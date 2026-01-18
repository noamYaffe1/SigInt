"""Base class for discovery plugins.

All discovery plugins must inherit from DiscoveryPlugin and implement
the required abstract methods. This ensures all discovery sources
produce normalized output that can be aggregated and deduplicated.
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum


class QueryType(str, Enum):
    """Type of discovery query."""
    FAVICON_HASH = "favicon"
    IMAGE_HASH = "image"
    TITLE_PATTERN = "title"
    BODY_PATTERN = "body"
    HEADER_PATTERN = "header"
    ENDPOINT = "endpoint"
    CUSTOM = "custom"


@dataclass
class DiscoveryQuery:
    """Normalized query for discovery plugins.
    
    All discovery sources receive queries in this format,
    allowing them to translate to their native query syntax.
    
    Attributes:
        query_type: Type of query (favicon, title, body, etc.)
        value: The search value (hash, pattern, etc.)
        raw_query: Optional raw query string (plugin-specific syntax)
        metadata: Additional query metadata
    """
    query_type: QueryType
    value: str
    raw_query: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __str__(self) -> str:
        return f"{self.query_type.value}:{self.value[:50]}"


@dataclass
class NormalizedHost:
    """Normalized host result from any discovery source.
    
    This is the standard output format that ALL discovery plugins
    must produce. It maps directly to CandidateHost but is defined
    here to avoid circular imports and make the plugin interface clear.
    
    Attributes:
        ip: IP address of the discovered host
        port: Port number
        protocol: Protocol (http, https)
        hostname: Optional hostname/domain
        source: Which discovery source found this (shodan, censys, etc.)
        first_seen: When the source first saw this host
        last_seen: When the source last saw this host
        location: Geographic location info
        metadata: Additional source-specific metadata
    """
    ip: str
    port: int
    protocol: str = "http"
    hostname: Optional[str] = None
    source: str = "unknown"
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    location: Dict[str, Optional[str]] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def url(self) -> str:
        """Generate URL for this host."""
        host = self.hostname or self.ip
        if (self.protocol == "http" and self.port == 80) or \
           (self.protocol == "https" and self.port == 443):
            return f"{self.protocol}://{host}"
        return f"{self.protocol}://{host}:{self.port}"
    
    @property
    def unique_key(self) -> str:
        """Unique identifier for deduplication."""
        return f"{self.ip}:{self.port}"


@dataclass
class DiscoveryResult:
    """Result from a discovery query.
    
    Attributes:
        query: The original query
        hosts: List of normalized hosts found
        total_available: Total results available (may be more than returned)
        error: Error message if query failed
        raw_response: Optional raw response for debugging
    """
    query: DiscoveryQuery
    hosts: List[NormalizedHost] = field(default_factory=list)
    total_available: int = 0
    error: Optional[str] = None
    raw_response: Optional[Any] = None
    
    @property
    def success(self) -> bool:
        """Whether the query succeeded."""
        return self.error is None
    
    @property
    def count(self) -> int:
        """Number of hosts returned."""
        return len(self.hosts)


class DiscoveryPlugin(ABC):
    """Abstract base class for discovery plugins.
    
    All discovery plugins must inherit from this class and implement
    the required abstract methods. This ensures consistent behavior
    and normalized output across all discovery sources.
    
    Class Attributes:
        name: Unique identifier for the plugin (e.g., "shodan", "censys")
        description: Human-readable description
        requires_auth: Whether the plugin requires authentication
        supported_query_types: List of QueryType this plugin supports
    
    Example:
        class MyServicePlugin(DiscoveryPlugin):
            name = "myservice"
            description = "My discovery service"
            requires_auth = True
            supported_query_types = [QueryType.FAVICON_HASH, QueryType.TITLE_PATTERN]
            
            def __init__(self, api_key: str = None):
                self.api_key = api_key or os.environ.get("MYSERVICE_API_KEY")
            
            def search(self, query: DiscoveryQuery) -> DiscoveryResult:
                native_query = self.translate_query(query)
                response = self._execute(native_query)
                return self._normalize_response(query, response)
    """
    
    # Class attributes - override in subclasses
    name: str = "base"
    description: str = "Base discovery plugin"
    requires_auth: bool = False
    supported_query_types: List[QueryType] = []
    
    @abstractmethod
    def search(self, query: DiscoveryQuery, max_results: int = 100) -> DiscoveryResult:
        """Execute a discovery query.
        
        Args:
            query: The normalized query to execute
            max_results: Maximum number of results to return
            
        Returns:
            DiscoveryResult with normalized hosts
        """
        pass
    
    @abstractmethod
    def is_configured(self) -> bool:
        """Check if the plugin is properly configured (has API keys, etc.).
        
        Returns:
            True if the plugin can be used
        """
        pass
    
    @abstractmethod
    def translate_query(self, query: DiscoveryQuery) -> str:
        """Translate a normalized query to plugin-native syntax.
        
        This method should convert the DiscoveryQuery into the
        query syntax used by the underlying service.
        
        Args:
            query: The normalized query
            
        Returns:
            Query string in plugin-native format
        """
        pass
    
    def supports_query_type(self, query_type: QueryType) -> bool:
        """Check if this plugin supports a query type.
        
        Args:
            query_type: The query type to check
            
        Returns:
            True if supported
        """
        return query_type in self.supported_query_types
    
    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}(name={self.name})>"

