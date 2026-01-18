"""Shodan discovery plugin.

This plugin provides discovery capabilities using the Shodan API.
It supports favicon hash, title, and body pattern searches.
"""
import os
import time
import logging
from typing import List, Optional

# Configure logger
logger = logging.getLogger("sigint.shodan")

from core.debug import debug_print
from .base import (
    DiscoveryPlugin,
    DiscoveryQuery,
    DiscoveryResult,
    NormalizedHost,
    QueryType,
)
from .registry import PluginRegistry


class ShodanPlugin(DiscoveryPlugin):
    """Shodan discovery plugin.
    
    Searches Shodan for hosts matching fingerprint patterns.
    Supports favicon hash (MMH3), title patterns, and body patterns.
    
    Environment Variables:
        SHODAN_API_KEY: Your Shodan API key
    
    Example:
        plugin = ShodanPlugin()
        if plugin.is_configured():
            result = plugin.search(DiscoveryQuery(
                query_type=QueryType.FAVICON_HASH,
                value="-231109625"
            ))
    """
    
    name = "shodan"
    description = "Shodan search engine for Internet-connected devices"
    requires_auth = True
    supported_query_types = [
        QueryType.FAVICON_HASH,
        QueryType.TITLE_PATTERN,
        QueryType.BODY_PATTERN,
        QueryType.HEADER_PATTERN,
        QueryType.CUSTOM,
    ]
    
    def __init__(self, api_key: Optional[str] = None):
        """Initialize Shodan plugin.
        
        Args:
            api_key: Shodan API key (or set SHODAN_API_KEY env var)
        """
        self.api_key = api_key or os.environ.get("SHODAN_API_KEY")
        self._client = None
    
    @property
    def client(self):
        """Lazy-load Shodan client."""
        if self._client is None and self.api_key:
            import shodan
            self._client = shodan.Shodan(self.api_key)
        return self._client
    
    def is_configured(self) -> bool:
        """Check if Shodan API key is configured."""
        return bool(self.api_key)
    
    def translate_query(self, query: DiscoveryQuery) -> str:
        """Translate normalized query to Shodan query syntax.
        
        Args:
            query: The normalized query
            
        Returns:
            Shodan query string
        """
        if query.raw_query:
            return query.raw_query
        
        translations = {
            QueryType.FAVICON_HASH: lambda v: f'http.favicon.hash:{v}',
            QueryType.TITLE_PATTERN: lambda v: f'http.title:"{v}"',
            QueryType.BODY_PATTERN: lambda v: f'http.html:"{v}"',
            QueryType.HEADER_PATTERN: lambda v: f'http.headers:"{v}"',
            QueryType.IMAGE_HASH: lambda v: f'http.favicon.hash:{v}',  # Shodan uses favicon for images
            QueryType.CUSTOM: lambda v: v,
        }
        
        translator = translations.get(query.query_type)
        if translator:
            return translator(query.value)
        
        # Default: search in HTML body
        return f'http.html:"{query.value}"'
    
    def search(self, query: DiscoveryQuery, max_results: int = None) -> DiscoveryResult:
        """Execute a Shodan search.
        
        Args:
            query: The normalized query
            max_results: Maximum results to return (None = all)
            
        Returns:
            DiscoveryResult with normalized hosts
        """
        import shodan
        
        if not self.is_configured():
            return DiscoveryResult(
                query=query,
                error="Shodan API key not configured"
            )
        
        shodan_query = self.translate_query(query)
        
        # Log the query
        logger.debug(f"[SHODAN] Query: {shodan_query}")
        debug_print(f"        [SHODAN DEBUG] Query: {shodan_query[:100]}..." if len(shodan_query) > 100 else f"        [SHODAN DEBUG] Query: {shodan_query}")
        
        hosts: List[NormalizedHost] = []
        total_available = 0
        
        try:
            # Get first page
            results = self.client.search(shodan_query)
            total_available = results.get('total', 0)
            
            # Process first page
            for result in results.get('matches', []):
                host = self._normalize_result(result)
                hosts.append(host)
                if max_results and len(hosts) >= max_results:
                    break
            
            # Fetch more pages if needed
            page = 2
            target = total_available if max_results is None else min(max_results, total_available)
            
            while len(hosts) < target:
                try:
                    time.sleep(1)  # Rate limiting
                    page_results = self.client.search(shodan_query, page=page)
                    page_matches = page_results.get('matches', [])
                    
                    if not page_matches:
                        break
                    
                    for result in page_matches:
                        host = self._normalize_result(result)
                        hosts.append(host)
                        if max_results and len(hosts) >= max_results:
                            break
                    
                    page += 1
                    
                    if max_results and len(hosts) >= max_results:
                        break
                        
                except shodan.APIError as e:
                    if 'rate limit' in str(e).lower():
                        break
                    raise
                except Exception:
                    break
            
            return DiscoveryResult(
                query=query,
                hosts=hosts,
                total_available=total_available,
            )
            
        except shodan.APIError as e:
            return DiscoveryResult(
                query=query,
                hosts=hosts,
                total_available=total_available,
                error=f"Shodan API error: {e}"
            )
        except Exception as e:
            return DiscoveryResult(
                query=query,
                error=f"Shodan search failed: {e}"
            )
    
    def _normalize_result(self, result: dict) -> NormalizedHost:
        """Normalize a Shodan result to NormalizedHost format.
        
        Args:
            result: Raw Shodan result dict
            
        Returns:
            NormalizedHost instance
        """
        # Determine protocol
        port = result.get('port', 80)
        ssl = result.get('ssl') or result.get('http', {}).get('redirects', [{}])
        protocol = "https" if ssl or port == 443 else "http"
        
        # Extract location (filter out None values - Pydantic requires Dict[str, str])
        location = {}
        if result.get('location'):
            raw_location = {
                'country': result['location'].get('country_name'),
                'country_code': result['location'].get('country_code'),
                'city': result['location'].get('city'),
                'region': result['location'].get('region_code'),
            }
            # Filter out None values
            location = {k: v for k, v in raw_location.items() if v is not None}
        
        # Extract hostnames
        hostnames = result.get('hostnames', [])
        hostname = hostnames[0] if hostnames else None
        
        return NormalizedHost(
            ip=result.get('ip_str', ''),
            port=port,
            protocol=protocol,
            hostname=hostname,
            source="shodan",
            first_seen=None,  # Shodan doesn't provide this
            last_seen=result.get('timestamp'),
            location=location,
            metadata={
                'asn': result.get('asn'),
                'org': result.get('org'),
                'hostnames': hostnames,
            }
        )


# Auto-register the plugin
PluginRegistry.register(ShodanPlugin)

