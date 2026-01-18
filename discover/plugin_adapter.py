"""Adapter to use discovery plugins with the existing discovery engine.

This module bridges the plugin system with the existing discovery engine,
allowing plugins to be used as additional or replacement discovery sources.
"""
import re
from typing import List, Dict, Optional, Tuple, Set
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.models import FingerprintSpec
from fingerprint.filters import is_query_blacklisted
from .models import CandidateHost
from plugins.discovery import (
    DiscoveryPlugin,
    DiscoveryQuery,
    NormalizedHost,
    QueryType,
    PluginRegistry,
    discover_plugins,
)

# Maximum queries to generate per fingerprint (to save API tokens)
MAX_QUERIES_DEFAULT = 10

# Priority order for query types (higher = more valuable)
QUERY_TYPE_PRIORITY = {
    QueryType.FAVICON_HASH: 100,   # Most reliable
    QueryType.IMAGE_HASH: 80,      # Also very reliable
    QueryType.TITLE_PATTERN: 60,   # Good signal
    QueryType.BODY_PATTERN: 40,    # Can be noisy
    QueryType.HEADER_PATTERN: 20,  # Least reliable
}


# Patterns that indicate non-distinctive title parts (versions, years, generic terms)
VERSION_PATTERNS = [
    r'^v?\d+(\.\d+)*$',              # v1.0, 1.0.0, etc.
    r'^v?\d+(\.\d+)*\s*[\*\-].*$',   # v1.0 *Development*, 1.0-beta
    r'^\d{4}$',                       # Years: 2024, 2025
    r'^version\s*\d+',                # "Version 1", "Version 2.0"
    r'^\*.*\*$',                      # *Development*, *Beta*
    r'^(alpha|beta|dev|rc|release)\s*\d*$',  # alpha, beta1, rc2
]

# Minimum length for a title part to be considered distinctive
MIN_TITLE_PART_LENGTH = 3


def _split_title_pattern(title_pattern: str) -> List[str]:
    """Split a title pattern into distinctive parts for querying.
    
    Takes patterns like "Damn Vulnerable Web Application|DVWA|Version 1.0"
    and returns distinctive parts like ["Damn Vulnerable Web Application", "DVWA"],
    filtering out version numbers, years, and non-distinctive fragments.
    
    Args:
        title_pattern: Title pattern (may contain | for OR alternatives)
        
    Returns:
        List of distinctive title parts suitable for individual queries
    """
    if not title_pattern:
        return []
    
    # Split on | (regex OR operator used in verification)
    parts = [p.strip() for p in title_pattern.split('|')]
    
    # Filter out non-distinctive parts
    distinctive = []
    for part in parts:
        # Skip empty or too short
        if not part or len(part) < MIN_TITLE_PART_LENGTH:
            continue
        
        # Skip if matches version/year patterns
        is_version = False
        for pattern in VERSION_PATTERNS:
            if re.match(pattern, part, re.IGNORECASE):
                is_version = True
                break
        
        if is_version:
            continue
        
        # Skip common generic terms
        if part.lower() in ['home', 'index', 'welcome', 'login', 'dashboard', 'admin']:
            continue
        
        distinctive.append(part)
    
    return distinctive


def init_plugins() -> None:
    """Initialize and discover all plugins."""
    # Auto-discover built-in plugins
    discover_plugins()


def get_configured_plugins() -> List[DiscoveryPlugin]:
    """Get all properly configured plugins.
    
    Returns:
        List of plugin instances that have valid credentials
    """
    return PluginRegistry.configured_plugins()


def list_plugins() -> Dict[str, dict]:
    """List all available plugins with their info.
    
    Returns:
        Dict mapping plugin name to info
    """
    return PluginRegistry.info()


def normalized_host_to_candidate(host: NormalizedHost) -> CandidateHost:
    """Convert a NormalizedHost (from plugin) to CandidateHost (for engine).
    
    This ensures all plugins produce output compatible with the rest of SigInt.
    
    Args:
        host: NormalizedHost from a discovery plugin
        
    Returns:
        CandidateHost compatible with existing engine
    """
    return CandidateHost(
        ip=host.ip,
        port=host.port,
        hostname=host.hostname,
        sources=[host.source],
        last_seen=host.last_seen,
        location=host.location if host.location else None,
        asn=host.metadata.get('asn'),
        organization=host.metadata.get('org'),
        hosting_provider=host.metadata.get('hosting_provider'),
        is_cloud_hosted=host.metadata.get('is_cloud_hosted', False),
    )


def fingerprint_to_queries(
    fingerprint: FingerprintSpec, 
    max_queries: int = MAX_QUERIES_DEFAULT
) -> List[DiscoveryQuery]:
    """Convert a FingerprintSpec into normalized DiscoveryQuery objects.
    
    This creates queries that any plugin can understand, regardless of
    the underlying search service's native syntax.
    
    Queries are:
    - Filtered to remove generic/blacklisted terms
    - Deduplicated by value
    - Limited to max_queries (prioritized by type)
    
    Args:
        fingerprint: The fingerprint specification
        max_queries: Maximum number of queries to generate (default: 10)
        
    Returns:
        List of DiscoveryQuery objects
    """
    raw_queries = []
    seen_values: Set[str] = set()
    
    def add_query(query: DiscoveryQuery) -> None:
        """Add query if not duplicate and not blacklisted."""
        value_key = f"{query.query_type.value}:{query.value.lower()}"
        
        # Skip duplicates
        if value_key in seen_values:
            return
        
        # Skip blacklisted/generic values (except for hashes)
        if query.query_type not in (QueryType.FAVICON_HASH, QueryType.IMAGE_HASH):
            if is_query_blacklisted(query.value):
                return
        
        seen_values.add(value_key)
        raw_queries.append(query)
    
    # Favicon hash queries (highest priority - always include)
    if fingerprint.favicon and fingerprint.favicon.hashes:
        all_mmh3 = fingerprint.favicon.hashes.get_all_mmh3()
        for i, mmh3_hash in enumerate(all_mmh3):
            source = 'favicon' if i == 0 else f'favicon_alt_{i}'
            add_query(DiscoveryQuery(
                query_type=QueryType.FAVICON_HASH,
                value=str(mmh3_hash),
                metadata={'source': source}
            ))
    
    # Image hash queries (high priority)
    for i, img in enumerate(fingerprint.key_images):
        if img.hashes.mmh3 or img.hashes.md5:
            add_query(DiscoveryQuery(
                query_type=QueryType.IMAGE_HASH,
                value=str(img.hashes.mmh3) if img.hashes.mmh3 else "",
                metadata={
                    'source': f'image_{i}',
                    'url': img.url,
                    'md5': img.hashes.md5,  # Censys uses MD5
                    'mmh3': img.hashes.mmh3,  # Shodan uses MMH3
                }
            ))
    
    # Title queries - only from first page signature (usually the most important)
    # Limit to 2 distinctive title parts max
    title_count = 0
    for sig in fingerprint.page_signatures[:2]:  # Max 2 page signatures
        if sig.title_pattern and title_count < 2:
            title_parts = _split_title_pattern(sig.title_pattern)
            for part in title_parts[:2]:  # Max 2 parts per title
                if title_count >= 2:
                    break
                add_query(DiscoveryQuery(
                    query_type=QueryType.TITLE_PATTERN,
                    value=part,
                    metadata={'source': 'title', 'url': sig.url, 'original': sig.title_pattern}
                ))
                title_count += 1
    
    # Body pattern queries - only the app name or most distinctive patterns
    # Limit to 2 body patterns max (prefer app name if present)
    body_count = 0
    app_name = fingerprint.app_name.lower() if fingerprint.app_name else ""
    
    for sig in fingerprint.page_signatures[:2]:  # Max 2 page signatures
        for pattern in (sig.body_patterns or []):
            if body_count >= 2:
                break
            # Prioritize patterns containing app name
            if app_name and app_name in pattern.lower():
                add_query(DiscoveryQuery(
                    query_type=QueryType.BODY_PATTERN,
                    value=pattern,
                    metadata={'source': 'body', 'url': sig.url}
                ))
                body_count += 1
    
    # If no body patterns with app name, add first distinctive pattern
    if body_count == 0:
        for sig in fingerprint.page_signatures[:1]:
            for pattern in (sig.body_patterns or [])[:1]:
                add_query(DiscoveryQuery(
                    query_type=QueryType.BODY_PATTERN,
                    value=pattern,
                    metadata={'source': 'body', 'url': sig.url}
                ))
    
    # Sort by priority and limit
    raw_queries.sort(
        key=lambda q: QUERY_TYPE_PRIORITY.get(q.query_type, 0),
        reverse=True
    )
    
    return raw_queries[:max_queries]


def search_with_plugin(
    plugin: DiscoveryPlugin,
    query: DiscoveryQuery,
    max_results: int = 100
) -> Tuple[List[CandidateHost], Optional[str]]:
    """Execute a search with a specific plugin.
    
    Args:
        plugin: The discovery plugin to use
        query: The normalized query
        max_results: Maximum results to return
        
    Returns:
        Tuple of (candidates list, error message or None)
    """
    # Check if plugin supports this query type
    if not plugin.supports_query_type(query.query_type):
        return [], f"Plugin {plugin.name} doesn't support {query.query_type}"
    
    # Execute search
    result = plugin.search(query, max_results)
    
    if not result.success:
        return [], result.error
    
    # Convert to CandidateHost format
    candidates = [normalized_host_to_candidate(h) for h in result.hosts]
    return candidates, None


def search_all_plugins(
    queries: List[DiscoveryQuery],
    plugins: Optional[List[str]] = None,
    max_results_per_query: int = 100,
    max_workers: int = 5
) -> Tuple[List[CandidateHost], Dict[str, int]]:
    """Execute queries across all configured plugins.
    
    Args:
        queries: List of normalized queries
        plugins: Optional list of plugin names to use (None = all configured)
        max_results_per_query: Max results per query
        max_workers: Number of concurrent workers
        
    Returns:
        Tuple of (all candidates, stats dict)
    """
    # Get plugins to use
    if plugins:
        plugin_instances = [
            PluginRegistry.get(name) 
            for name in plugins 
            if PluginRegistry.get(name)
        ]
    else:
        plugin_instances = get_configured_plugins()
    
    if not plugin_instances:
        print("[Plugins] No configured plugins found!")
        return [], {}
    
    print(f"\n[Plugins] Using {len(plugin_instances)} plugins: {[p.name for p in plugin_instances]}")
    
    all_candidates: List[CandidateHost] = []
    stats = {p.name: 0 for p in plugin_instances}
    
    # Create work items: (plugin, query) pairs
    work_items = []
    for plugin in plugin_instances:
        for query in queries:
            if plugin.supports_query_type(query.query_type):
                work_items.append((plugin, query))
    
    print(f"[Plugins] Executing {len(work_items)} query/plugin combinations...")
    
    # Execute in parallel
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(
                search_with_plugin, plugin, query, max_results_per_query
            ): (plugin, query)
            for plugin, query in work_items
        }
        
        for future in as_completed(futures):
            plugin, query = futures[future]
            try:
                candidates, error = future.result()
                if error:
                    print(f"    [{plugin.name.upper()}] ({query.query_type.value}) ERROR: {error}")
                else:
                    print(f"    [{plugin.name.upper()}] ({query.query_type.value}) Found: {len(candidates)}")
                    all_candidates.extend(candidates)
                    stats[plugin.name] += len(candidates)
            except Exception as e:
                print(f"    [{plugin.name.upper()}] ({query.query_type.value}) EXCEPTION: {e}")
    
    print(f"\n[Plugins] Total candidates from plugins: {len(all_candidates)}")
    return all_candidates, stats


def discover_with_plugins(
    fingerprint: FingerprintSpec,
    plugins: Optional[List[str]] = None,
    max_results_per_query: int = 100,
    max_workers: int = 5
) -> List[CandidateHost]:
    """Complete discovery workflow using plugins.
    
    This is a high-level function that:
    1. Converts fingerprint to normalized queries
    2. Executes queries across all configured plugins
    3. Returns aggregated candidates (deduplication should be done by caller)
    
    Args:
        fingerprint: The fingerprint to search for
        plugins: Optional list of plugin names (None = all configured)
        max_results_per_query: Max results per query
        max_workers: Concurrent workers
        
    Returns:
        List of candidate hosts (not deduplicated)
    """
    # Initialize plugins if not done
    init_plugins()
    
    # Convert fingerprint to queries
    queries = fingerprint_to_queries(fingerprint)
    print(f"[Plugins] Generated {len(queries)} queries from fingerprint")
    
    # Search all plugins
    candidates, stats = search_all_plugins(
        queries=queries,
        plugins=plugins,
        max_results_per_query=max_results_per_query,
        max_workers=max_workers
    )
    
    return candidates

