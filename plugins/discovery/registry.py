"""Plugin registry and discovery system.

This module provides the PluginRegistry class for managing discovery plugins,
and the discover_plugins function for auto-discovering plugins from the
plugins/discovery directory.
"""
import importlib
import importlib.util
from pathlib import Path
from typing import Dict, List, Optional, Type

from .base import DiscoveryPlugin


class PluginRegistry:
    """Registry for discovery plugins.
    
    This singleton class manages the registration and retrieval of
    discovery plugins. Plugins can be registered manually or
    auto-discovered from the plugins directory.
    
    Example:
        # Register a plugin
        PluginRegistry.register(ShodanPlugin)
        
        # Get a plugin by name
        shodan = PluginRegistry.get("shodan")
        
        # List all plugins
        for plugin in PluginRegistry.all():
            print(plugin.name)
    """
    
    _plugins: Dict[str, Type[DiscoveryPlugin]] = {}
    _instances: Dict[str, DiscoveryPlugin] = {}
    
    @classmethod
    def register(cls, plugin_class: Type[DiscoveryPlugin]) -> None:
        """Register a discovery plugin class.
        
        Args:
            plugin_class: The plugin class to register
            
        Raises:
            ValueError: If plugin with same name already registered
        """
        name = plugin_class.name
        if name in cls._plugins and cls._plugins[name] != plugin_class:
            raise ValueError(f"Plugin '{name}' already registered")
        cls._plugins[name] = plugin_class
    
    @classmethod
    def unregister(cls, name: str) -> None:
        """Unregister a plugin by name.
        
        Args:
            name: The plugin name to unregister
        """
        cls._plugins.pop(name, None)
        cls._instances.pop(name, None)
    
    @classmethod
    def get(cls, name: str, **kwargs) -> Optional[DiscoveryPlugin]:
        """Get a plugin instance by name.
        
        Creates and caches plugin instances. Additional kwargs are
        passed to the plugin constructor on first instantiation.
        
        Args:
            name: The plugin name
            **kwargs: Arguments for plugin constructor
            
        Returns:
            Plugin instance or None if not found
        """
        if name not in cls._plugins:
            return None
        
        # Create instance if not cached or if kwargs provided
        if name not in cls._instances or kwargs:
            try:
                cls._instances[name] = cls._plugins[name](**kwargs)
            except Exception as e:
                print(f"[Plugin] Error instantiating {name}: {e}")
                return None
        
        return cls._instances[name]
    
    @classmethod
    def get_class(cls, name: str) -> Optional[Type[DiscoveryPlugin]]:
        """Get a plugin class by name (without instantiation).
        
        Args:
            name: The plugin name
            
        Returns:
            Plugin class or None if not found
        """
        return cls._plugins.get(name)
    
    @classmethod
    def all(cls) -> List[Type[DiscoveryPlugin]]:
        """Get all registered plugin classes.
        
        Returns:
            List of plugin classes
        """
        return list(cls._plugins.values())
    
    @classmethod
    def all_instances(cls, **kwargs) -> List[DiscoveryPlugin]:
        """Get instances of all registered plugins.
        
        Creates instances for any plugins not yet instantiated.
        
        Args:
            **kwargs: Arguments passed to plugin constructors
            
        Returns:
            List of plugin instances
        """
        instances = []
        for name in cls._plugins:
            instance = cls.get(name, **kwargs)
            if instance:
                instances.append(instance)
        return instances
    
    @classmethod
    def configured_plugins(cls, **kwargs) -> List[DiscoveryPlugin]:
        """Get only plugins that are properly configured.
        
        Args:
            **kwargs: Arguments passed to plugin constructors
            
        Returns:
            List of configured plugin instances
        """
        return [p for p in cls.all_instances(**kwargs) if p.is_configured()]
    
    @classmethod
    def names(cls) -> List[str]:
        """Get names of all registered plugins.
        
        Returns:
            List of plugin names
        """
        return list(cls._plugins.keys())
    
    @classmethod
    def clear(cls) -> None:
        """Clear all registered plugins and instances."""
        cls._plugins.clear()
        cls._instances.clear()
    
    @classmethod
    def info(cls) -> Dict[str, Dict]:
        """Get information about all registered plugins.
        
        Returns:
            Dict mapping plugin name to info dict
        """
        return {
            name: {
                "description": plugin.description,
                "requires_auth": plugin.requires_auth,
                "supported_query_types": [qt.value for qt in plugin.supported_query_types],
            }
            for name, plugin in cls._plugins.items()
        }


def discover_plugins(plugins_dir: Optional[Path] = None) -> int:
    """Auto-discover and register plugins from the plugins directory.
    
    Scans the plugins/discovery directory for Python files and attempts
    to import them. Any DiscoveryPlugin subclasses found are automatically
    registered.
    
    Args:
        plugins_dir: Optional path to plugins directory.
                    Defaults to plugins/discovery relative to this file.
    
    Returns:
        Number of plugins discovered
    """
    if plugins_dir is None:
        plugins_dir = Path(__file__).parent
    
    discovered = 0
    
    # Look for Python files in the plugins directory
    for filepath in plugins_dir.glob("*.py"):
        # Skip __init__.py and base files
        if filepath.name.startswith("_") or filepath.name in ("base.py", "registry.py"):
            continue
        
        module_name = filepath.stem
        
        try:
            # Import the module
            spec = importlib.util.spec_from_file_location(
                f"plugins.discovery.{module_name}",
                filepath
            )
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                
                # Find DiscoveryPlugin subclasses
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    if (isinstance(attr, type) and 
                        issubclass(attr, DiscoveryPlugin) and 
                        attr is not DiscoveryPlugin and
                        attr.name != "base"):
                        PluginRegistry.register(attr)
                        discovered += 1
                        
        except Exception as e:
            print(f"[Plugin] Error loading {filepath.name}: {e}")
    
    return discovered


def load_external_plugins(directory: Path) -> int:
    """Load plugins from an external directory.
    
    This allows users to add custom plugins without modifying
    the SigInt codebase.
    
    Args:
        directory: Path to directory containing plugin files
        
    Returns:
        Number of plugins loaded
    """
    if not directory.exists():
        return 0
    
    return discover_plugins(directory)

