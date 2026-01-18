"""Discovery Plugin System.

This module provides a plugin architecture for discovery sources.
All discovery plugins must inherit from DiscoveryPlugin and implement
the required methods.

Example usage:
    from plugins.discovery import DiscoveryPlugin, PluginRegistry
    
    class MyCustomPlugin(DiscoveryPlugin):
        name = "mycustom"
        description = "My custom discovery source"
        
        def search(self, query: DiscoveryQuery) -> DiscoveryResult:
            # Your implementation here
            pass
    
    # Register the plugin
    PluginRegistry.register(MyCustomPlugin)
"""
from .base import DiscoveryPlugin, DiscoveryQuery, DiscoveryResult, NormalizedHost, QueryType
from .registry import PluginRegistry, discover_plugins

__all__ = [
    "DiscoveryPlugin",
    "DiscoveryQuery", 
    "DiscoveryResult",
    "NormalizedHost",
    "QueryType",
    "PluginRegistry",
    "discover_plugins",
]

