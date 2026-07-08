# Copyright (c) 2026 waymap developers
# See the file 'LICENSE' for copying permission.

"""Plugin registry for managing scan plugins."""

from typing import Dict, List, Optional
from lib.core.logger import get_logger
from lib.plugins.base import ScanPlugin, PluginMetadata

logger = get_logger(__name__)


class PluginRegistry:
    """Registry for managing scan plugins."""
    
    def __init__(self):
        self._plugins: Dict[str, ScanPlugin] = {}
        self._metadata: Dict[str, PluginMetadata] = {}
    
    def register(self, plugin: ScanPlugin) -> None:
        """
        Register a scan plugin.
        
        Args:
            plugin: ScanPlugin instance to register
        """
        metadata = plugin.metadata()
        
        # Check for conflicts
        if metadata.name in self._plugins:
            logger.warning(f"Plugin '{metadata.name}' already registered, overwriting")
        
        self._plugins[metadata.name] = plugin
        self._metadata[metadata.name] = metadata
        
        logger.info(f"Registered plugin: {metadata.name} v{metadata.version}")
    
    def get_plugin(self, name: str) -> Optional[ScanPlugin]:
        """
        Get a registered plugin by name.
        
        Args:
            name: Plugin name
            
        Returns:
            ScanPlugin instance or None if not found
        """
        return self._plugins.get(name)
    
    def get_plugin_metadata(self, name: str) -> Optional[PluginMetadata]:
        """
        Get metadata for a registered plugin.
        
        Args:
            name: Plugin name
            
        Returns:
            PluginMetadata or None if not found
        """
        return self._metadata.get(name)
    
    def list_plugins(self) -> List[PluginMetadata]:
        """
        List all registered plugins.
        
        Returns:
            List of PluginMetadata
        """
        return list(self._metadata.values())
    
    def get_plugins_for_scan_type(self, scan_type: str) -> List[ScanPlugin]:
        """
        Get all plugins that support a specific scan type.
        
        Args:
            scan_type: Scan type (e.g., 'sqli', 'xss')
            
        Returns:
            List of ScanPlugin instances
        """
        matching_plugins = []
        
        for name, metadata in self._metadata.items():
            if scan_type in metadata.scan_types:
                matching_plugins.append(self._plugins[name])
        
        return matching_plugins
    
    def resolve_dependencies(self, plugin: ScanPlugin) -> List[ScanPlugin]:
        """
        Resolve plugin dependencies.
        
        Args:
            plugin: Plugin to resolve dependencies for
            
        Returns:
            List of plugins in dependency order
        """
        resolved = []
        visited = set()
        
        def _resolve(plugin_name: str):
            if plugin_name in visited:
                return
            
            if plugin_name not in self._plugins:
                logger.warning(f"Dependency '{plugin_name}' not found")
                return
            
            visited.add(plugin_name)
            dep_plugin = self._plugins[plugin_name]
            
            # Resolve dependencies first
            for dep in dep_plugin.dependencies():
                _resolve(dep)
            
            resolved.append(dep_plugin)
        
        # Resolve dependencies for the requested plugin
        metadata = plugin.metadata()
        for dep in metadata.dependencies:
            _resolve(dep)
        
        # Add the plugin itself
        resolved.append(plugin)
        
        return resolved
    
    def unregister(self, name: str) -> bool:
        """
        Unregister a plugin.
        
        Args:
            name: Plugin name
            
        Returns:
            True if unregistered, False if not found
        """
        if name in self._plugins:
            del self._plugins[name]
            del self._metadata[name]
            logger.info(f"Unregistered plugin: {name}")
            return True
        return False
    
    def clear(self) -> None:
        """Clear all registered plugins."""
        self._plugins.clear()
        self._metadata.clear()
        logger.info("Cleared all plugins")


# Global plugin registry instance
_global_registry: Optional[PluginRegistry] = None


def get_plugin_registry() -> PluginRegistry:
    """
    Get the global plugin registry instance.
    
    Returns:
        PluginRegistry instance
    """
    global _global_registry
    if _global_registry is None:
        _global_registry = PluginRegistry()
    return _global_registry
