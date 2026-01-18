"""IPInfo API client with caching and cloud provider detection."""
import os
import json
import logging
import requests
from typing import Optional, List, Dict
from pathlib import Path
from datetime import datetime, timezone, timedelta
from core.utils import utc_now_iso
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

from core.debug import debug_print
from .models import IPInfoResult, IPInfoCache

# Configure logger
logger = logging.getLogger("sigint.ipinfo")


# Cloud/Hosting provider detection patterns
# Maps ASN numbers and org name patterns to provider names
PROVIDER_PATTERNS: Dict[str, List[str]] = {
    "AWS": ["amazon", "aws", "as16509", "as14618"],
    "GCP": ["google cloud", "google llc", "as15169", "as396982"],
    "Azure": ["microsoft", "azure", "as8075"],
    "DigitalOcean": ["digitalocean", "as14061"],
    "Linode": ["linode", "akamai connected cloud", "as63949"],
    "Vultr": ["vultr", "as20473", "the constant company"],
    "OVH": ["ovh", "as16276"],
    "Hetzner": ["hetzner", "as24940"],
    "Cloudflare": ["cloudflare", "as13335"],
    "Alibaba": ["alibaba", "aliyun", "as45102", "as37963"],
    "Oracle Cloud": ["oracle", "as31898"],
    "IBM Cloud": ["ibm", "softlayer", "as36351"],
    "Tencent": ["tencent", "as45090", "as132203"],
    "Scaleway": ["scaleway", "online s.a.s", "as12876"],
    "UpCloud": ["upcloud", "as202053"],
    "Kamatera": ["kamatera", "as36007"],
    "Contabo": ["contabo", "as51167"],
    "Hostinger": ["hostinger", "as47583"],
}

# ASNs commonly associated with hosting providers
HOSTING_ASNS = {
    "AS16509", "AS14618",  # Amazon
    "AS15169", "AS396982",  # Google
    "AS8075",  # Microsoft
    "AS14061",  # DigitalOcean
    "AS63949",  # Linode
    "AS20473",  # Vultr
    "AS16276",  # OVH
    "AS24940",  # Hetzner
    "AS13335",  # Cloudflare
    "AS45102", "AS37963",  # Alibaba
    "AS31898",  # Oracle
    "AS36351",  # IBM
    "AS45090", "AS132203",  # Tencent
    "AS12876",  # Scaleway
}


class IPInfoClient:
    """Client for IPInfo.io API with caching and connection pooling."""
    
    BASE_URL = "https://ipinfo.io"
    
    # Thread-local storage for sessions
    _thread_local = None
    
    def __init__(
        self,
        token: Optional[str] = None,
        cache_dir: str = "output/cache/ipinfo",
        cache_ttl_days: int = 30,
        timeout: int = 10
    ):
        """Initialize IPInfo client.
        
        Args:
            token: IPInfo API token (or use IPINFO_TOKEN env var)
            cache_dir: Directory for caching results
            cache_ttl_days: Cache TTL in days (0 = no expiration)
            timeout: Request timeout in seconds
        """
        import threading
        
        self.token = token or os.environ.get("IPINFO_TOKEN")
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_ttl_days = cache_ttl_days
        self.timeout = timeout
        self._thread_local = threading.local()
        
        if not self.token:
            print("[IPInfo] Warning: No IPINFO_TOKEN found. Using free tier (limited).")
    
    def _get_session(self) -> requests.Session:
        """Get or create a thread-local session with connection pooling."""
        from requests.adapters import HTTPAdapter
        
        if not hasattr(self._thread_local, 'session'):
            session = requests.Session()
            if self.token:
                session.headers["Authorization"] = f"Bearer {self.token}"
            
            # Mount adapter with connection pooling
            adapter = HTTPAdapter(pool_connections=50, pool_maxsize=50)
            session.mount("https://", adapter)
            
            self._thread_local.session = session
        
        return self._thread_local.session
    
    def _get_cache_path(self, ip: str) -> Path:
        """Get cache file path for an IP."""
        # Use IP as filename (replace dots with underscores)
        safe_ip = ip.replace(".", "_").replace(":", "_")
        return self.cache_dir / f"{safe_ip}.json"
    
    def _load_cache(self, ip: str) -> Optional[IPInfoResult]:
        """Load cached result for an IP if valid."""
        cache_path = self._get_cache_path(ip)
        if not cache_path.exists():
            return None
        
        try:
            with open(cache_path, 'r') as f:
                data = json.load(f)
            cache = IPInfoCache(**data)
            
            # Check TTL
            if self.cache_ttl_days > 0:
                cache_time = datetime.fromisoformat(cache.cached_at.replace("Z", "+00:00"))
                age = datetime.now(timezone.utc) - cache_time
                if age > timedelta(days=self.cache_ttl_days):
                    return None
            
            return cache.result
        except Exception:
            return None
    
    def _save_cache(self, ip: str, result: IPInfoResult):
        """Save result to cache."""
        cache = IPInfoCache(
            ip=ip,
            result=result,
            cached_at=utc_now_iso()
        )
        cache_path = self._get_cache_path(ip)
        with open(cache_path, 'w') as f:
            json.dump(cache.model_dump(), f, indent=2)
    
    def _detect_provider(self, org: Optional[str], asn: Optional[str]) -> tuple[bool, Optional[str]]:
        """Detect if IP belongs to a hosting provider and which one.
        
        Returns:
            Tuple of (is_hosting, provider_name)
        """
        if not org and not asn:
            return False, None
        
        # Normalize for matching
        org_lower = (org or "").lower()
        asn_upper = (asn or "").upper()
        
        # Check each provider pattern
        for provider, patterns in PROVIDER_PATTERNS.items():
            for pattern in patterns:
                if pattern.lower() in org_lower or pattern.upper() == asn_upper:
                    return True, provider
        
        # Check if ASN is in known hosting ASNs
        if asn_upper in HOSTING_ASNS:
            return True, None  # Known hosting but unidentified provider
        
        return False, None
    
    def _parse_asn(self, org: Optional[str]) -> Optional[str]:
        """Extract ASN from org string like 'AS16509 Amazon.com, Inc.'"""
        if not org:
            return None
        parts = org.split()
        if parts and parts[0].upper().startswith("AS"):
            return parts[0].upper()
        return None
    
    def lookup(self, ip: str, use_cache: bool = True) -> IPInfoResult:
        """Look up IP information.
        
        Args:
            ip: IP address to look up
            use_cache: Whether to use cached results
            
        Returns:
            IPInfoResult with enrichment data
        """
        # Check cache first
        if use_cache:
            cached = self._load_cache(ip)
            if cached:
                return cached
        
        # Make API request using pooled session
        try:
            session = self._get_session()
            url = f"{self.BASE_URL}/{ip}/json"
            logger.debug(f"[IPINFO] GET {url}")
            debug_print(f"        [IPINFO DEBUG] GET {url}")
            response = session.get(url, timeout=self.timeout)
            
            if response.status_code == 429:
                # Rate limited
                return IPInfoResult(ip=ip, company="Rate Limited")
            
            response.raise_for_status()
            data = response.json()
            
            # Parse response
            org = data.get("org")
            asn = self._parse_asn(org)
            is_hosting, provider = self._detect_provider(org, asn)
            
            # Extract company name (org without ASN prefix)
            company = None
            if org:
                parts = org.split(maxsplit=1)
                if len(parts) > 1 and parts[0].upper().startswith("AS"):
                    company = parts[1]
                else:
                    company = org
            
            result = IPInfoResult(
                ip=ip,
                hostname=data.get("hostname"),
                city=data.get("city"),
                region=data.get("region"),
                country=data.get("country"),
                org=org,
                asn=asn,
                company=company,
                is_hosting=is_hosting,
                hosting_provider=provider,
                loc=data.get("loc"),
                postal=data.get("postal"),
                timezone=data.get("timezone")
            )
            
            # Cache the result
            self._save_cache(ip, result)
            
            return result
            
        except requests.RequestException as e:
            return IPInfoResult(ip=ip, company=f"Error: {str(e)[:50]}")
    
    def bulk_lookup(
        self,
        ips: List[str],
        workers: int = 20,
        use_cache: bool = True,
        show_progress: bool = True
    ) -> Dict[str, IPInfoResult]:
        """Look up multiple IPs concurrently.
        
        Args:
            ips: List of IP addresses
            workers: Number of concurrent workers
            use_cache: Whether to use cached results
            show_progress: Show progress bar
            
        Returns:
            Dictionary mapping IP to IPInfoResult
        """
        # Deduplicate IPs
        unique_ips = list(set(ips))
        results: Dict[str, IPInfoResult] = {}
        
        # Check cache first
        to_fetch = []
        cached_count = 0
        for ip in unique_ips:
            if use_cache:
                cached = self._load_cache(ip)
                if cached:
                    results[ip] = cached
                    cached_count += 1
                    continue
            to_fetch.append(ip)
        
        if cached_count > 0:
            print(f"    [IPInfo] {cached_count} IPs from cache")
        
        if not to_fetch:
            return results
        
        print(f"    [IPInfo] Fetching {len(to_fetch)} IPs...")
        
        # Fetch remaining IPs concurrently
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(self.lookup, ip, False): ip for ip in to_fetch}
            
            iterator = as_completed(futures)
            if show_progress:
                iterator = tqdm(iterator, total=len(futures), desc="    Enriching", unit="ip")
            
            for future in iterator:
                ip = futures[future]
                try:
                    results[ip] = future.result()
                except Exception as e:
                    results[ip] = IPInfoResult(ip=ip, company=f"Error: {str(e)[:30]}")
        
        return results

