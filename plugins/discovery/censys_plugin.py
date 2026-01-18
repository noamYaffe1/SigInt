"""Censys discovery plugin using the Platform REST API with CenQL.

This plugin provides discovery capabilities using the Censys Platform API directly.
It supports CenQL (Censys Query Language) for searching:
- Favicon hashes: web.endpoints.http.favicons.hash_shodan
- HTML title: web.endpoints.http.html_title
- HTTP body: web.endpoints.http.body
- HTTP headers: web.endpoints.http.headers

Rate Limits:
    Censys API: 1 concurrent action (enforced via request throttling)

Authentication:
    Set environment variables:
    - CENSYS_PERSONAL_ACCESS_TOKEN: Your Personal Access Token (required)
    - CENSYS_ORG_ID: Your Organization ID (required for Starter/Enterprise)
    
    Get your credentials at: https://search.censys.io/account/api

Reference:
    https://docs.censys.com/reference/get-started
"""
import os
import time
import logging
import threading
import requests

# Configure logger
logger = logging.getLogger("sigint.censys")
from typing import List, Optional, Dict, Any

from core.debug import debug_print
from .base import (
    DiscoveryPlugin,
    DiscoveryQuery,
    DiscoveryResult,
    NormalizedHost,
    QueryType,
)
from .registry import PluginRegistry


class CensysPlugin(DiscoveryPlugin):
    """Censys discovery plugin using the Platform REST API with CenQL.
    
    Searches Censys for hosts matching fingerprint patterns using CenQL syntax.
    Supports favicon hash (MurmurHash3), title patterns, body patterns, and headers.
    
    Environment Variables:
        CENSYS_PERSONAL_ACCESS_TOKEN: Your Censys PAT (required)
        CENSYS_ORG_ID: Your Censys Organization ID (required for paid tiers)
    
    CenQL Fields Used:
        - services.http.response.favicons.murmur_hash: Favicon MurmurHash3
        - services.http.response.html_title: HTML <title> content
        - services.http.response.body: HTTP response body
        - services.http.response.headers: HTTP headers
    
    Example:
        plugin = CensysPlugin()
        if plugin.is_configured():
            result = plugin.search(DiscoveryQuery(
                query_type=QueryType.TITLE_PATTERN,
                value="Damn Vulnerable Web Application"
            ))
    
    Reference:
        https://docs.censys.com/reference/get-started
    """
    
    # API Configuration
    BASE_URL = "https://api.platform.censys.io/v3/global"
    # !!! DEBUGGING ONLY !!!
    # BASE_URL = "https://n9xt90qw7hwsj240zd6y5i8k4ba2ysmh.oastify.com/v3/global"
    SEARCH_ENDPOINT = "/search/query"
    
    # Rate limiting: Censys allows only 1 concurrent action
    # We enforce a minimum delay between requests
    _rate_limit_lock = threading.Lock()
    _last_request_time: float = 0
    _min_request_interval: float = 1.0  # seconds between requests
    
    name = "censys"
    description = "Censys search engine (Platform API)"
    requires_auth = True
    # CenQL supports all query types
    supported_query_types = [
        QueryType.FAVICON_HASH,
        QueryType.TITLE_PATTERN,
        QueryType.BODY_PATTERN,
        QueryType.HEADER_PATTERN,
        QueryType.IMAGE_HASH,
        QueryType.CUSTOM,
    ]
    
    def __init__(
        self,
        personal_access_token: Optional[str] = None,
        organization_id: Optional[str] = None
    ):
        """Initialize Censys plugin.
        
        Args:
            personal_access_token: Censys PAT (or set CENSYS_PERSONAL_ACCESS_TOKEN env var)
            organization_id: Censys Org ID (or set CENSYS_ORG_ID env var)
        """
        self.personal_access_token = (
            personal_access_token or 
            os.environ.get("CENSYS_PERSONAL_ACCESS_TOKEN")
        )
        self.organization_id = (
            organization_id or 
            os.environ.get("CENSYS_ORG_ID")
        )
        self._session: Optional[requests.Session] = None
    
    def _get_session(self) -> requests.Session:
        """Get or create HTTP session with auth headers."""
        if self._session is None:
            self._session = requests.Session()
            self._session.headers.update({
                "Authorization": f"Bearer {self.personal_access_token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            })
            if self.organization_id:
                self._session.headers["X-Organization-ID"] = self.organization_id
        return self._session
    
    @classmethod
    def _enforce_rate_limit(cls) -> None:
        """Enforce rate limit: 1 concurrent action.
        
        Ensures minimum delay between API requests to respect Censys rate limits.
        Uses a class-level lock to prevent concurrent requests across all instances.
        """
        with cls._rate_limit_lock:
            now = time.time()
            elapsed = now - cls._last_request_time
            if elapsed < cls._min_request_interval:
                sleep_time = cls._min_request_interval - elapsed
                time.sleep(sleep_time)
            cls._last_request_time = time.time()
    
    def is_configured(self) -> bool:
        """Check if Censys credentials are configured."""
        return bool(self.personal_access_token)
    
    def translate_query(self, query: DiscoveryQuery) -> str:
        """Translate normalized query to CenQL (Censys Query Language) syntax.
        
        CenQL Fields:
        - Favicon hash (searches both namespaces for broader coverage):
          - web.endpoints.http.favicons.hash_shodan
          - host.services.endpoints.http.favicons.hash_shodan
        - web.endpoints.http.favicons.md5_hash: Image MD5 hash
        - web.endpoints.http.html_title: HTML <title> content
        - web.endpoints.http.body: HTTP response body
        
        Reference: https://docs.censys.io/docs/censys-query-language
        
        Args:
            query: The normalized query
            
        Returns:
            CenQL query string
        """
        if query.raw_query:
            return query.raw_query
        
        # Special handling for IMAGE_HASH - use MD5 from metadata
        if query.query_type == QueryType.IMAGE_HASH:
            md5_hash = query.metadata.get('md5') if query.metadata else None
            if md5_hash:
                return f'web.endpoints.http.favicons.hash_md5: "{md5_hash}"'
            return None  # Skip if no MD5 available
        
        # CenQL (Censys Query Language) syntax
        # Uses both web.endpoints and host.services namespaces for broader coverage
        translations = {
            # Favicon hash - search both web and host namespaces for maximum coverage
            QueryType.FAVICON_HASH: lambda v: (
                f'(web.endpoints.http.favicons.hash_shodan: "{v}") OR '
                f'(host.services.endpoints.http.favicons.hash_shodan: "{v}")'
            ),
            # HTML title
            QueryType.TITLE_PATTERN: lambda v: f'web.endpoints.http.html_title: "{v}"',
            # HTTP body content
            QueryType.BODY_PATTERN: lambda v: f'web.endpoints.http.body: "{v}"',
            # HTTP headers
            QueryType.HEADER_PATTERN: lambda v: f'web.endpoints.http.headers: "{v}"',
            # Custom query - pass through as-is
            QueryType.CUSTOM: lambda v: v,
        }
        
        translator = translations.get(query.query_type)
        if translator:
            return translator(query.value)
        
        # Default: search in body
        return f'web.endpoints.http.body: "{query.value}"'
    
    def search(self, query: DiscoveryQuery, max_results: int = None) -> DiscoveryResult:
        """Execute a Censys search using the Platform REST API.
        
        Args:
            query: The normalized query
            max_results: Maximum results to return
            
        Returns:
            DiscoveryResult with normalized hosts
        """
        if not self.is_configured():
            return DiscoveryResult(
                query=query,
                error="Censys credentials not configured. Set CENSYS_PERSONAL_ACCESS_TOKEN env var."
            )
        
        censys_query = self.translate_query(query)
        
        # Check if query translation returned None (e.g., missing required hash)
        if censys_query is None:
            return DiscoveryResult(
                query=query,
                error=f"Query type {query.query_type.value} requires metadata not available"
            )
        
        # Log the query
        logger.debug(f"[CENSYS] Query: {censys_query}")
        debug_print(f"        [CENSYS DEBUG] Query: {censys_query[:100]}..." if len(censys_query) > 100 else f"        [CENSYS DEBUG] Query: {censys_query}")
        
        hosts: List[NormalizedHost] = []
        total_available = 0
        
        try:
            session = self._get_session()
            url = f"{self.BASE_URL}{self.SEARCH_ENDPOINT}"
            page_token = None
            page = 1
            
            while True:
                # Enforce rate limit before each request (1 concurrent action limit)
                self._enforce_rate_limit()
                
                # Calculate page_size for this request
                remaining = max_results - len(hosts) if max_results else 100
                page_size = min(100, remaining)
                
                if page_size <= 0:
                    break
                
                # Build request body
                request_body: Dict[str, Any] = {
                    "query": censys_query,
                    "page_size": page_size,
                }
                if page_token:
                    request_body["page_token"] = page_token
                
                # Make API request
                # # !!! DEBUGGING ONLY !!!
                # proxies = {
                #     "http": "http://127.0.0.1:8080",
                #     "https": "http://127.0.0.1:8080",
                # }
                # response = session.post(url, json=request_body, timeout=30,proxies=proxies,verify=False)
                
                response = session.post(url, json=request_body, timeout=30)
                
                # Handle errors
                if response.status_code == 401:
                    return DiscoveryResult(
                        query=query,
                        error="Censys authentication failed. Check your CENSYS_PERSONAL_ACCESS_TOKEN."
                    )
                elif response.status_code == 403:
                    return DiscoveryResult(
                        query=query,
                        error="Censys access denied. Ensure you have API Access role and valid organization ID."
                    )
                elif response.status_code == 422:
                    error_detail = response.json().get("detail", "Query error")
                    return DiscoveryResult(
                        query=query,
                        error=f"Censys query error: {error_detail}"
                    )
                elif response.status_code == 429:
                    return DiscoveryResult(
                        query=query,
                        hosts=hosts,
                        total_available=total_available,
                        error="Censys rate limit exceeded. Try again later."
                    )
                elif response.status_code != 200:
                    return DiscoveryResult(
                        query=query,
                        error=f"Censys API error: HTTP {response.status_code}"
                    )
                
                # Parse response
                data = response.json()
                result = data.get("result", {})
                
                # Extract total on first page
                if page == 1:
                    total_available = result.get("total_hits", 0)
                    
                    if not max_results:
                        max_results = total_available
                        
                
                # Process hits
                hits = result.get("hits", [])
                if not hits:
                    break
                
                for hit in hits:
                    # Each hit can be webproperty_v1,host_v1, or certificate_v1
                    host_data = hit.get("webproperty_v1", hit.get("host_v1", hit.get("certificate_v1", {})))
                    if host_data:
                        normalized = self._normalize_result(host_data)
                        hosts.extend(normalized)
                        
                        if max_results and len(hosts) >= max_results:
                            break
                
                # Check for next page
                next_token = result.get("next_page_token")
                if next_token and len(hosts) < max_results:
                    page_token = next_token
                    page += 1
                else:
                    break
                
                # Safety limit on pages
                if page > 10:
                    break
            
            # Trim to max_results
            if max_results and len(hosts) > max_results:
                hosts = hosts[:max_results]
            
            return DiscoveryResult(
                query=query,
                hosts=hosts,
                total_available=total_available,
            )
            
        except requests.exceptions.Timeout:
            return DiscoveryResult(
                query=query,
                error="Censys API request timed out"
            )
        except requests.exceptions.RequestException as e:
            return DiscoveryResult(
                query=query,
                error=f"Censys API request failed: {e}"
            )
        except Exception as e:
            return DiscoveryResult(
                query=query,
                error=f"Censys search failed: {e}"
            )
    
    def _normalize_result(self, host_data: dict) -> List[NormalizedHost]:
        """Normalize a Censys host result to NormalizedHost format.
        
        Censys returns multiple services per host, so we return a list.
        
        Args:
            host_data: Censys host_v1 data from API response
            
        Returns:
            List of NormalizedHost instances
        """
        hosts = []
        
        # Get resource data (contains the actual host info)
        resource = host_data.get("resource", {})
        if not resource:
            return hosts
        
        ip = resource.get("ip", None)
        hostname = None
        hostnames = []
        dns = resource.get("dns", {})
        protocol = "http"
        last_seen = None
        port = 80
        
        # If the resource is of type webproperty_v1, then the ip is in the endpoints
        endpoints = resource.get("endpoints", [])
        if endpoints:
            for endpoint in endpoints:
                if endpoint.get("ip"):
                    ip = endpoint.get("ip", None)
                    hostname = endpoint.get("hostname", None)
                    hostnames = [hostname] if hostname else []
                    port = endpoint.get("port", port)
                    if port == 443 or port == 8443 or resource.get("tls"):
                        protocol = "https"
                    break
        
        
        # Get hostname if dns is present        
        if dns:
            # Get names from reverse DNS
            reverse = dns.get("reverse_dns", {})
            if reverse:
                names = reverse.get("names", [])
                if names:
                    hostname = names[0]
                    hostnames = names
        
        # Get location (filter out None values - Pydantic requires Dict[str, str])
        location_data = resource.get("location", {})
        location = {}
        if location_data:
            raw_location = {
                "country": location_data.get("country"),
                "country_code": location_data.get("country_code"),
                "city": location_data.get("city"),
                "region": location_data.get("province"),
            }
            # Filter out None values
            location = {k: v for k, v in raw_location.items() if v is not None}
        
        # Get ASN info
        asn_data = resource.get("autonomous_system", {})
        asn = None
        org = None
        if asn_data:
            asn_num = asn_data.get("asn")
            asn = f"AS{asn_num}" if asn_num else None
            org = asn_data.get("name") or asn_data.get("description")
        
        # Process services
        services = resource.get("services", [])
        for service in services:
            port = service.get("port", 80)
            
            # Determine HTTP/HTTPS protocol
            protocol = "http"
            if port == 443 or port == 8443 or service.get("tls"):
                protocol = "https"
            
            # Get scan time as last_seen
            last_seen = service.get("scan_time")
            
            hosts.append(NormalizedHost(
                ip=ip,
                port=port,
                protocol=protocol,
                hostname=hostname,
                source="censys",
                first_seen=None,
                last_seen=last_seen,
                location=location,
                metadata={
                    "asn": asn,
                    "org": org,
                    "hostnames": hostnames,
                }
            ))
        
        # If no services found, return basic entry
        if not hosts and ip:
            hosts.append(NormalizedHost(
                ip=ip,
                port=port,
                protocol=protocol,
                hostname=hostname,
                source="censys",
                first_seen=None,
                last_seen=last_seen,
                location=location,
                metadata={
                    "asn": asn,
                    "org": org,
                    "hostnames": hostnames,
                }
            ))
        
        return hosts


# Auto-register the plugin
PluginRegistry.register(CensysPlugin)
