"""Main passive discovery engine with query-level caching and plugin support."""
import json
from typing import List, Optional, Literal, Tuple
from pathlib import Path
from datetime import datetime, timezone, timedelta
from core.utils import utc_now_iso

from core.models import FingerprintSpec
from .models import CandidateHost, QueryCache
from .deduplication import deduplicate_candidates

# Import defaults from config - single source of truth
from config import Defaults


def _init_plugins():
    """Initialize the plugin system (lazy load to avoid circular imports)."""
    from .plugin_adapter import init_plugins
    init_plugins()


class PassiveDiscovery:
    """Passive discovery engine using the plugin system.
    
    Uses plugins (Shodan, Censys, etc.) for discovery.
    Plugins are auto-discovered and configured via environment variables.
    
    Example:
        discovery = PassiveDiscovery()
        candidates = discovery.discover(fingerprint)
    """
    
    def __init__(
        self,
        cache_dir: str = "output/cache",
        cache_ttl_days: int = Defaults.CACHE_TTL_DAYS,
        plugin_names: Optional[List[str]] = None
    ):
        """Initialize discovery engine.
        
        Args:
            cache_dir: Directory for caching query results
            cache_ttl_days: Cache time-to-live in days (0 = no expiration)
            plugin_names: List of plugin names to use (None = all configured)
        """
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True, parents=True)
        self.cache_ttl_days = cache_ttl_days
        self.plugin_names = plugin_names
        
        # Always initialize plugins
        _init_plugins()
    
    def discover(
        self,
        fingerprint: FingerprintSpec,
        cache_strategy: Literal["cache_only", "new_only", "cache_and_new"] = "cache_and_new",
        max_results: Optional[int] = None,
        max_queries: int = 10,
        enrich: bool = True,
        enrich_workers: int = 20,
        plugins: Optional[List[str]] = None,
        interactive: bool = False
    ) -> List[CandidateHost]:
        """Discover candidate hosts for a fingerprint.
        
        Uses plugins to search multiple discovery sources simultaneously.
        Results are deduplicated and optionally enriched with IPInfo data.
        
        Args:
            fingerprint: The fingerprint spec to search for
            cache_strategy: How to use cached data
                - cache_only: Only return cached results (no API calls)
                - new_only: Ignore cache, fetch fresh data
                - cache_and_new: Use cached where available, fetch new queries
            max_results: Maximum candidates to return (None = no limit)
            enrich: Whether to enrich candidates with IPInfo data
            enrich_workers: Number of concurrent workers for enrichment
            plugins: List of plugin names to use (None = all configured)
            interactive: If True, prompt user to approve/deny/modify each query
        
        Returns:
            Deduplicated list of candidate hosts
        """
        from .plugin_adapter import (
            fingerprint_to_queries,
            get_configured_plugins,
        )
        from plugins.discovery import PluginRegistry
        
        plugin_names = plugins or self.plugin_names
        
        print(f"\n{'='*70}")
        print(f"[PHASE 2] Passive Discovery")
        print(f"{'='*70}")
        target_label = "Organization" if getattr(fingerprint, 'fingerprint_mode', 'application') == 'organization' else "Application"
        print(f"{target_label}: {fingerprint.app_name}")
        print(f"Strategy: {cache_strategy}")
        print(f"Cache TTL: {self.cache_ttl_days} days" if self.cache_ttl_days > 0 else "Cache TTL: disabled")
        
        # Get configured plugins
        if plugin_names:
            plugin_instances = [
                PluginRegistry.get(name) 
                for name in plugin_names 
                if PluginRegistry.get(name) and PluginRegistry.get(name).is_configured()
            ]
            print(f"Plugins: {', '.join(plugin_names)}")
        else:
            plugin_instances = get_configured_plugins()
            print(f"Plugins: {', '.join(p.name for p in plugin_instances)} (all configured)")
        
        if not plugin_instances:
            print("\n[WARNING] No configured plugins found!")
            print("  Set SHODAN_API_KEY or CENSYS_PERSONAL_ACCESS_TOKEN")
            return []
        
        # Convert fingerprint to normalized queries (limited to max_queries)
        queries = fingerprint_to_queries(fingerprint, max_queries=max_queries)
        print(f"\n[Query Translation] Generated {len(queries)} queries (max: {max_queries})")
        
        # Interactive mode: let user approve/deny/modify each query
        if interactive and queries:
            queries = self._interactive_query_review(queries)
            if not queries:
                print("\n[!] All queries denied by user")
                return []
            print(f"\n[Interactive] {len(queries)} queries approved for execution")
        
        all_candidates: List[CandidateHost] = []
        cached_count = 0
        fresh_count = 0
        
        # Execute queries for each plugin
        abort_discovery = False
        for plugin in plugin_instances:
            if abort_discovery:
                break
                
            plugin_queries = [q for q in queries if plugin.supports_query_type(q.query_type)]
            if not plugin_queries:
                continue
                
            print(f"\n[{plugin.name.upper()}] Processing {len(plugin_queries)} queries...")
            
            for query in plugin_queries:
                candidates, from_cache, error = self._execute_query_with_cache(
                    plugin=plugin,
                    query=query,
                    cache_strategy=cache_strategy,
                    max_results_per_query=None  # Get all results per query, limit total after dedupe
                )
                all_candidates.extend(candidates)
                if from_cache:
                    cached_count += 1
                else:
                    fresh_count += 1
                
                # If error occurred, ask user if they want to continue
                if error:
                    try:
                        response = input("\n[?] Query error occurred. Continue with remaining queries? [y/N]: ").strip().lower()
                        if response not in ('y', 'yes'):
                            print("[!] Discovery aborted by user")
                            abort_discovery = True
                            break
                    except (EOFError, KeyboardInterrupt):
                        print("\n[!] Discovery aborted")
                        abort_discovery = True
                        break
        
        print(f"\n[Cache Summary] {cached_count} queries from cache, {fresh_count} fresh API calls")
        
        # Deduplicate by IP:PORT across all sources
        print(f"\n[Dedupe] Aggregating {len(all_candidates):,} total candidates from all queries...")
        deduplicated = deduplicate_candidates(all_candidates)
        print(f"[Dedupe] {len(deduplicated):,} unique IP:PORT combinations after deduplication")
        
        # Count sources
        source_counts = {}
        for c in deduplicated:
            for src in c.sources:
                source_counts[src] = source_counts.get(src, 0) + 1
        if source_counts:
            print(f"[Dedupe] By source: {' | '.join(f'{s}: {n}' for s, n in source_counts.items())}")
        
        result = deduplicated[:max_results] if max_results else deduplicated
        
        # Enrich with IPInfo data
        if enrich and result:
            result = self._enrich_candidates(result, workers=enrich_workers)
        
        print(f"\n[✓] Found {len(result):,} candidates")
        
        return result
    
    def _interactive_query_review(self, queries: List) -> List:
        """Interactively review and approve/deny/modify each discovery query.
        
        Provides human-in-the-loop control over which queries to execute.
        
        Options for each query:
        - [A]pprove: Run this query as-is
        - [D]eny: Skip this query
        - [M]odify: Edit the query value before running
        - [R]un all: Approve all remaining queries without prompting
        - [S]kip all: Skip all remaining queries
        
        Args:
            queries: List of DiscoveryQuery objects to review
            
        Returns:
            List of approved (possibly modified) queries
        """
        from plugins.discovery import DiscoveryQuery
        
        approved = []
        run_all = False
        skip_all = False
        
        print(f"\n{'='*70}")
        print("[INTERACTIVE] Query Review Mode")
        print("="*70)
        print("For each query, choose:")
        print("  [A]pprove  - Run this query as-is")
        print("  [D]eny    - Skip this query")
        print("  [M]odify  - Edit the query value")
        print("  [R]un all - Approve all remaining queries")
        print("  [S]kip all - Skip all remaining queries")
        print("="*70)
        
        for i, query in enumerate(queries, 1):
            if skip_all:
                break
            
            if run_all:
                approved.append(query)
                continue
            
            # Show query details
            query_label = query.metadata.get('source', 'unknown')
            print(f"\n[Query {i}/{len(queries)}]")
            print(f"  Type:   {query.query_type.value}")
            print(f"  Source: {query_label}")
            print(f"  Value:  {query.value}")
            
            while True:
                try:
                    response = input("\n  [A]pprove / [D]eny / [M]odify / [R]un all / [S]kip all: ").strip().lower()
                    
                    if response == 'a':
                        approved.append(query)
                        print("  → Approved")
                        break
                    
                    elif response == 'd':
                        print("  → Denied")
                        break
                    
                    elif response == 'm':
                        print(f"\n  Current value: {query.value}")
                        new_value = input("  Enter new value (or press Enter to keep current): ").strip()
                        if new_value:
                            # Create a new query with modified value
                            modified_query = DiscoveryQuery(
                                query_type=query.query_type,
                                value=new_value,
                                raw_query=None,  # Clear raw query since value changed
                                metadata={**query.metadata, 'modified': True, 'original_value': query.value}
                            )
                            approved.append(modified_query)
                            print(f"  → Modified and approved: {new_value}")
                        else:
                            approved.append(query)
                            print("  → Approved (unchanged)")
                        break
                    
                    elif response == 'r':
                        run_all = True
                        approved.append(query)
                        print("  → Approved (and all remaining)")
                        break
                    
                    elif response == 's':
                        skip_all = True
                        print("  → Skipped (and all remaining)")
                        break
                    
                    else:
                        print("  Invalid option. Please enter A, D, M, R, or S.")
                        
                except (EOFError, KeyboardInterrupt):
                    print("\n[!] Query review cancelled")
                    skip_all = True
                    break
        
        print(f"\n{'='*70}")
        print(f"[Interactive] Summary: {len(approved)} approved, {len(queries) - len(approved)} denied")
        print("="*70)
        
        return approved
    
    def _execute_query_with_cache(
        self,
        plugin,
        query,
        cache_strategy: Literal["cache_only", "new_only", "cache_and_new"],
        max_results_per_query: Optional[int] = None
    ) -> Tuple[List[CandidateHost], bool, Optional[str]]:
        """Execute a single query with caching support.
        
        Args:
            plugin: The discovery plugin to use
            query: The normalized DiscoveryQuery
            cache_strategy: Caching strategy to use
            max_results_per_query: Max results per query (None = unlimited)
            
        Returns:
            Tuple of (candidates list, was_from_cache boolean, error message or None)
        """
        from .plugin_adapter import normalized_host_to_candidate
        
        # Create cache key from plugin name + query
        cache_key = f"{plugin.name}_{query.query_type.value}_{hash(query.value)}"
        query_hash = QueryCache.hash_query(plugin.name, f"{query.query_type.value}:{query.value}")
        cache_file = self.cache_dir / f"query_{query_hash}.json"
        
        query_label = query.metadata.get('source', query.query_type.value)
        platform_tag = f"[{plugin.name.upper()}]"
        
        # Truncate query value for display (show first 60 chars)
        display_value = query.value[:60] + "..." if len(query.value) > 60 else query.value
        
        # Try to load from cache
        if cache_strategy in ["cache_only", "cache_and_new"]:
            cached = self._load_query_cache(cache_file)
            if cached:
                # Calculate age for display
                cache_time = datetime.fromisoformat(cached.query_timestamp.replace("Z", "+00:00"))
                age_days = (datetime.now(timezone.utc) - cache_time).days
                print(f"    {platform_tag} ({query_label}) {display_value} → {cached.result_count} results (cached, {age_days}d old)")
                return cached.candidates, True, None
            elif cache_strategy == "cache_only":
                if cache_file.exists():
                    print(f"    {platform_tag} ({query_label}) {display_value} → EXPIRED")
                else:
                    print(f"    {platform_tag} ({query_label}) {display_value} → NO CACHE")
                return [], True, None
        
        # Execute fresh query
        if cache_strategy == "cache_only":
            return [], True, None
        
        candidates: List[CandidateHost] = []
        error_msg: Optional[str] = None
        
        try:
            result = plugin.search(query, max_results=max_results_per_query)
            
            if result.success:
                # Convert NormalizedHost to CandidateHost
                candidates = [normalized_host_to_candidate(h) for h in result.hosts]
                print(f"    {platform_tag} ({query_label}) {display_value} → {len(candidates)} results")
                
                # Save to cache
                self._save_query_cache(
                    cache_file, 
                    plugin.name, 
                    query_label,
                    f"{query.query_type.value}:{query.value}",
                    candidates
                )
            else:
                error_msg = result.error
                full_query = plugin.translate_query(query)
                print(f"    {platform_tag} ({query_label}) {display_value} → ERROR:")
                print(f"          Query: {full_query}")
                print(f"          Reason: {result.error}")
                
        except Exception as e:
            error_msg = str(e)
            try:
                full_query = plugin.translate_query(query)
            except:
                full_query = f"{query.query_type.value}:{query.value}"
            print(f"    {platform_tag} ({query_label}) {display_value} → ERROR:")
            print(f"          Query: {full_query}")
            print(f"          Reason: {e}")
        
        return candidates, False, error_msg
    
    def _load_query_cache(self, cache_file: Path) -> Optional[QueryCache]:
        """Load a cached query result if valid and not expired."""
        if not cache_file.exists():
            return None
        
        try:
            with open(cache_file, 'r') as f:
                data = json.load(f)
            cache = QueryCache(**data)
            
            # Check TTL expiration (0 = no expiration)
            if self.cache_ttl_days > 0:
                cache_time = datetime.fromisoformat(cache.query_timestamp.replace("Z", "+00:00"))
                age = datetime.now(timezone.utc) - cache_time
                if age > timedelta(days=self.cache_ttl_days):
                    return None  # Cache expired
            
            return cache
        except Exception:
            return None
    
    def _save_query_cache(
        self,
        cache_file: Path,
        platform: str,
        query_type: str,
        query_string: str,
        candidates: List[CandidateHost]
    ):
        """Save query results to cache."""
        cache = QueryCache(
            query_hash=QueryCache.hash_query(platform, query_string),
            platform=platform,
            query_type=query_type,
            query_string=query_string,
            query_timestamp=utc_now_iso(),
            result_count=len(candidates),
            candidates=candidates
        )
        
        with open(cache_file, 'w') as f:
            json.dump(cache.model_dump(), f, indent=2)
    
    def clear_cache(self, expired_only: bool = False):
        """Clear cached query results.
        
        Args:
            expired_only: If True, only clear expired entries. If False, clear all.
        """
        cleared = 0
        kept = 0
        
        for cache_file in self.cache_dir.glob("query_*.json"):
            try:
                if expired_only:
                    with open(cache_file, 'r') as f:
                        data = json.load(f)
                    cache = QueryCache(**data)
                    cache_time = datetime.fromisoformat(cache.query_timestamp.replace("Z", "+00:00"))
                    age = datetime.now(timezone.utc) - cache_time
                    
                    if self.cache_ttl_days > 0 and age > timedelta(days=self.cache_ttl_days):
                        cache_file.unlink()
                        cleared += 1
                    else:
                        kept += 1
                else:
                    cache_file.unlink()
                    cleared += 1
            except Exception:
                cache_file.unlink()
                cleared += 1
        
        if expired_only:
            print(f"[Cache] Cleared {cleared} expired queries, kept {kept} valid")
        else:
            print(f"[Cache] Cleared {cleared} cached queries")
    
    def cache_stats(self) -> dict:
        """Get cache statistics."""
        now = datetime.now(timezone.utc)
        stats = {
            "total_queries": 0,
            "total_candidates": 0,
            "valid_queries": 0,
            "expired_queries": 0,
            "by_platform": {},
            "oldest_cache": None,
            "newest_cache": None
        }
        
        for cache_file in self.cache_dir.glob("query_*.json"):
            try:
                with open(cache_file, 'r') as f:
                    data = json.load(f)
                cache = QueryCache(**data)
                
                stats["total_queries"] += 1
                stats["total_candidates"] += cache.result_count
                stats["by_platform"][cache.platform] = stats["by_platform"].get(cache.platform, 0) + 1
                
                cache_time = datetime.fromisoformat(cache.query_timestamp.replace("Z", "+00:00"))
                age = now - cache_time
                
                if self.cache_ttl_days > 0 and age > timedelta(days=self.cache_ttl_days):
                    stats["expired_queries"] += 1
                else:
                    stats["valid_queries"] += 1
                
                if stats["oldest_cache"] is None or cache_time < stats["oldest_cache"]:
                    stats["oldest_cache"] = cache_time
                if stats["newest_cache"] is None or cache_time > stats["newest_cache"]:
                    stats["newest_cache"] = cache_time
            except Exception:
                continue
        
        return stats
    
    def _enrich_candidates(
        self,
        candidates: List[CandidateHost],
        workers: int = 20
    ) -> List[CandidateHost]:
        """Enrich candidates with IPInfo data (cloud provider, geo, etc.).
        
        Args:
            candidates: List of candidates to enrich
            workers: Number of concurrent workers
            
        Returns:
            Enriched candidates list
        """
        import os
        from enrich.ipinfo_client import IPInfoClient
        
        ipinfo_token = os.environ.get("IPINFO_TOKEN")
        if not ipinfo_token:
            print(f"\n[Enrich] Skipped - IPINFO_TOKEN not set")
            return candidates
        
        print(f"\n[Enrich] Enriching {len(candidates):,} candidates with IPInfo...")
        
        # Initialize IPInfo client with cache
        client = IPInfoClient(
            token=ipinfo_token,
            cache_dir=str(self.cache_dir / "ipinfo"),
            cache_ttl_days=30  # IPInfo data is stable, cache for 30 days
        )
        
        # Get unique IPs
        unique_ips = list(set(c.ip for c in candidates))
        
        # Bulk lookup
        ip_results = client.bulk_lookup(
            ips=unique_ips,
            workers=workers,
            use_cache=True,
            show_progress=True
        )
        
        # Apply enrichment to candidates
        enriched_at = utc_now_iso()
        cloud_count = 0
        
        for candidate in candidates:
            ip_info = ip_results.get(candidate.ip)
            if ip_info:
                candidate.hosting_provider = ip_info.hosting_provider
                candidate.is_cloud_hosted = ip_info.is_hosting
                candidate.enriched_at = enriched_at
                
                # Update location if not already set
                if not candidate.location and (ip_info.country or ip_info.city):
                    candidate.location = {
                        "country": ip_info.country,
                        "country_name": ip_info.country_name,
                        "city": ip_info.city,
                        "region": ip_info.region
                    }
                
                # Update hostname if not set
                if not candidate.hostname and ip_info.hostname:
                    candidate.hostname = ip_info.hostname
                
                # Update org/asn if not set
                if not candidate.organization and ip_info.company:
                    candidate.organization = ip_info.company
                if not candidate.asn and ip_info.asn:
                    candidate.asn = ip_info.asn
                
                if ip_info.is_hosting:
                    cloud_count += 1
        
        # Summary
        providers = {}
        for c in candidates:
            if c.hosting_provider:
                providers[c.hosting_provider] = providers.get(c.hosting_provider, 0) + 1
        
        print(f"[Enrich] Cloud-hosted: {cloud_count:,} ({cloud_count*100//len(candidates)}%)")
        if providers:
            top_providers = sorted(providers.items(), key=lambda x: -x[1])[:5]
            print(f"[Enrich] Top providers: {', '.join(f'{p}:{n}' for p, n in top_providers)}")
        
        return candidates
