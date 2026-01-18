"""Template for creating custom discovery plugins.

Copy this file and modify it to create your own discovery plugin.

Steps:
1. Copy this file to plugins/discovery/your_plugin.py
2. Rename the class (e.g., YourServicePlugin)  
3. Update the class attributes (name, description, etc.)
4. Implement the required methods
5. Add your API key to .env file (e.g., YOURSERVICE_API_KEY=xxx)
6. Uncomment the PluginRegistry.register() line at the bottom
7. The plugin will be auto-discovered on startup

Example plugins to reference:
- shodan_plugin.py - Simple API with pagination
- censys_plugin.py - Platform API with cursor-based pagination

See plugins/discovery/README.md for detailed documentation.
"""
import os
from typing import List, Optional

# Required imports for all plugins
from .base import (
    DiscoveryPlugin,
    DiscoveryQuery,
    DiscoveryResult,
    NormalizedHost,
    QueryType,
)
from .registry import PluginRegistry


class TemplatePlugin(DiscoveryPlugin):
    """Template discovery plugin - copy and customize this.
    
    Replace this docstring with a description of your plugin.
    Include:
    - What service it connects to
    - Required API keys/credentials
    - Any special features or limitations
    
    Environment Variables:
        YOUR_SERVICE_API_KEY: API key for your service
        YOUR_SERVICE_API_SECRET: (Optional) API secret
    """
    
    # === REQUIRED: Update these class attributes ===
    
    name = "template"  # Unique plugin identifier (lowercase, no spaces)
    description = "Template plugin - replace with your description"
    requires_auth = True  # Set to False if no API key needed
    
    # List of query types your plugin supports
    # Remove any types your service doesn't support
    supported_query_types = [
        QueryType.FAVICON_HASH,    # Search by favicon hash (MMH3 or MD5)
        QueryType.IMAGE_HASH,      # Search by image hash
        QueryType.TITLE_PATTERN,   # Search by page title
        QueryType.BODY_PATTERN,    # Search by HTML body content
        QueryType.HEADER_PATTERN,  # Search by HTTP headers
        QueryType.CUSTOM,          # Raw query in service's native syntax
    ]
    
    # === REQUIRED: Implement __init__ ===
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        # Add any other credentials your service needs
    ):
        """Initialize the plugin.
        
        Credentials can be passed directly or loaded from environment variables.
        
        Args:
            api_key: API key (or set YOUR_SERVICE_API_KEY env var)
        """
        self.api_key = api_key or os.environ.get("YOUR_SERVICE_API_KEY")
        # Add any other initialization here
    
    # === REQUIRED: Implement is_configured ===
    
    def is_configured(self) -> bool:
        """Check if the plugin has required credentials.
        
        Returns:
            True if the plugin can make API calls
        """
        return bool(self.api_key)
        # For multiple credentials:
        # return bool(self.api_key and self.api_secret)
    
    # === REQUIRED: Implement translate_query ===
    
    def translate_query(self, query: DiscoveryQuery) -> str:
        """Translate normalized query to your service's query syntax.
        
        This is where you convert the generic DiscoveryQuery into
        the specific query format your service expects.
        
        Args:
            query: The normalized query with query_type and value
            
        Returns:
            Query string in your service's format
        """
        # If a raw query was provided, use it directly
        if query.raw_query:
            return query.raw_query
        
        # Map query types to your service's syntax
        # Example translations (modify for your service):
        translations = {
            QueryType.FAVICON_HASH: lambda v: f'favicon_hash:{v}',
            QueryType.TITLE_PATTERN: lambda v: f'title:"{v}"',
            QueryType.BODY_PATTERN: lambda v: f'body:"{v}"',
            QueryType.HEADER_PATTERN: lambda v: f'header:"{v}"',
            QueryType.CUSTOM: lambda v: v,  # Pass through as-is
        }
        
        translator = translations.get(query.query_type)
        if translator:
            return translator(query.value)
        
        # Default fallback
        return query.value
    
    # === REQUIRED: Implement search ===
    
    def search(self, query: DiscoveryQuery, max_results: int = 100) -> DiscoveryResult:
        """Execute a search query against your service.
        
        This is the main method that:
        1. Translates the query
        2. Makes API calls
        3. Normalizes results to NormalizedHost format
        
        Args:
            query: The normalized query
            max_results: Maximum number of results to return
            
        Returns:
            DiscoveryResult containing normalized hosts
        """
        # Check configuration
        if not self.is_configured():
            return DiscoveryResult(
                query=query,
                error="Plugin not configured (missing API key)"
            )
        
        # Translate the query
        native_query = self.translate_query(query)
        
        # Initialize result containers
        hosts: List[NormalizedHost] = []
        total_available = 0
        
        try:
            # === YOUR API CALL HERE ===
            # 
            # Example using requests:
            # 
            # import requests
            # response = requests.get(
            #     "https://api.yourservice.com/search",
            #     params={"query": native_query, "limit": max_results},
            #     headers={"Authorization": f"Bearer {self.api_key}"},
            #     timeout=30
            # )
            # response.raise_for_status()
            # data = response.json()
            # 
            # total_available = data.get('total', 0)
            # for result in data.get('results', []):
            #     host = self._normalize_result(result)
            #     if host:
            #         hosts.append(host)
            
            # For now, return empty result (replace with your implementation)
            return DiscoveryResult(
                query=query,
                hosts=hosts,
                total_available=total_available,
            )
            
        except Exception as e:
            return DiscoveryResult(
                query=query,
                hosts=hosts,  # Return any hosts we got before the error
                total_available=total_available,
                error=f"Search failed: {e}"
            )
    
    # === HELPER: Normalize results ===
    
    def _normalize_result(self, result: dict) -> Optional[NormalizedHost]:
        """Convert a raw API result to NormalizedHost format.
        
        This ensures all discovery plugins produce consistent output.
        
        Args:
            result: Raw result from your API
            
        Returns:
            NormalizedHost or None if result is invalid
        """
        try:
            # Extract fields from your API response format
            # Modify these based on your service's response structure
            
            ip = result.get('ip', '')
            port = result.get('port', 80)
            
            # Skip invalid results
            if not ip:
                return None
            
            # Determine protocol
            protocol = "http"
            if port == 443 or result.get('ssl'):
                protocol = "https"
            
            # Build location info
            location = {}
            if result.get('country'):
                location['country'] = result['country']
            if result.get('city'):
                location['city'] = result['city']
            
            return NormalizedHost(
                ip=ip,
                port=port,
                protocol=protocol,
                hostname=result.get('hostname'),
                source=self.name,  # Use plugin name as source
                first_seen=result.get('first_seen'),
                last_seen=result.get('last_seen'),
                location=location,
                metadata={
                    # Add any extra fields specific to your service
                    'org': result.get('organization'),
                }
            )
            
        except Exception:
            return None


# === IMPORTANT: Register the plugin ===
# This line makes the plugin auto-discoverable
# Comment it out during development if needed

# PluginRegistry.register(TemplatePlugin)

