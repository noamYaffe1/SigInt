"""Probe execution logic for verification."""
import re
import time
import logging
import hashlib
import mmh3
import base64
from io import BytesIO
import requests
from PIL import Image
import imagehash

from core.models import ProbeStep
from core.debug import debug_print
from config import Defaults
from .models import ProbeResult

# Configure logger
logger = logging.getLogger("sigint.probes")


class ProbeExecutor:
    """Executes individual probe steps against a target.
    
    Uses thread-local sessions with connection pooling for efficient
    concurrent HTTP requests.
    """
    
    # Thread-local storage for per-thread sessions
    _thread_local = None
    
    def __init__(self, timeout: int = 10, user_agent: str = None, verify_ssl: bool = False, 
                 pool_connections: int = 100, pool_maxsize: int = 100,
                 fingerprint_mode: str = "application"):
        """Initialize probe executor.
        
        Args:
            timeout: Request timeout in seconds
            user_agent: Custom user agent string
            verify_ssl: Whether to verify SSL certificates (default: False for recon)
            pool_connections: Number of connection pools to cache (default: 100)
            pool_maxsize: Max connections per pool (default: 100)
            fingerprint_mode: 'application' or 'organization' - affects favicon discovery
        """
        import threading
        from requests.adapters import HTTPAdapter
        from urllib3.util.retry import Retry
        
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.user_agent = user_agent or "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
        self.pool_connections = pool_connections
        self.pool_maxsize = pool_maxsize
        self.fingerprint_mode = fingerprint_mode
        
        # Thread-local storage for sessions
        self._thread_local = threading.local()
        
        # Disable SSL warnings when not verifying (cleaner output)
        if not verify_ssl:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    def _get_session(self) -> requests.Session:
        """Get or create a thread-local session with connection pooling.
        
        Each thread gets its own session to avoid thread-safety issues.
        Sessions are configured with larger connection pools for better reuse.
        """
        from requests.adapters import HTTPAdapter
        from urllib3.util.retry import Retry
        
        if not hasattr(self._thread_local, 'session'):
            # Create new session for this thread
            session = requests.Session()
            session.headers.update({"User-Agent": self.user_agent})
            
            # Configure retry strategy
            retry_strategy = Retry(
                total=2,  # Max 2 retries
                backoff_factor=0.5,  # Wait 0.5s, 1s between retries
                status_forcelist=[500, 502, 503, 504],  # Retry on server errors
            )
            
            # Mount adapters with larger connection pools
            adapter = HTTPAdapter(
                pool_connections=self.pool_connections,
                pool_maxsize=self.pool_maxsize,
                max_retries=retry_strategy
            )
            session.mount("http://", adapter)
            session.mount("https://", adapter)
            
            self._thread_local.session = session
        
        return self._thread_local.session
    
    def _discover_favicon_path(self, base_url: str) -> str:
        """Dynamically discover favicon path by parsing HTML for link tags.
        
        Used in organization mode where different sites may have favicons
        in different locations but share the same hash (brand).
        
        Args:
            base_url: Base URL to fetch homepage from
            
        Returns:
            Discovered favicon path (e.g., "/assets/favicon.ico") or "/favicon.ico" as fallback
        """
        try:
            session = self._get_session()
            response = session.get(
                base_url,
                timeout=self.timeout,
                allow_redirects=True,
                verify=self.verify_ssl
            )
            
            if response.status_code != 200:
                return "/favicon.ico"
            
            html = response.text
            
            # Look for <link rel="icon" href="..."> or <link rel="shortcut icon" href="...">
            # Patterns to match various favicon link formats
            patterns = [
                r'<link[^>]*rel=["\'](?:shortcut )?icon["\'][^>]*href=["\']([^"\']+)["\']',
                r'<link[^>]*href=["\']([^"\']+)["\'][^>]*rel=["\'](?:shortcut )?icon["\']',
                r'<link[^>]*rel=["\']apple-touch-icon["\'][^>]*href=["\']([^"\']+)["\']',
            ]
            
            for pattern in patterns:
                match = re.search(pattern, html, re.IGNORECASE)
                if match:
                    favicon_href = match.group(1)
                    
                    # Handle relative vs absolute paths
                    if favicon_href.startswith('http://') or favicon_href.startswith('https://'):
                        # Absolute URL - extract path
                        from urllib.parse import urlparse
                        parsed = urlparse(favicon_href)
                        favicon_path = parsed.path
                    elif favicon_href.startswith('//'):
                        # Protocol-relative URL
                        from urllib.parse import urlparse
                        parsed = urlparse('https:' + favicon_href)
                        favicon_path = parsed.path
                    elif favicon_href.startswith('/'):
                        # Absolute path
                        favicon_path = favicon_href
                    else:
                        # Relative path - prepend /
                        favicon_path = '/' + favicon_href
                    
                    logger.debug(f"[FAVICON] Discovered favicon at: {favicon_path}")
                    debug_print(f"        [FAVICON] Discovered at: {favicon_path}")
                    return favicon_path
            
            # No link tag found - use default
            logger.debug("[FAVICON] No link tag found, using /favicon.ico")
            debug_print("        [FAVICON] No link tag found, using /favicon.ico")
            return "/favicon.ico"
            
        except Exception as e:
            logger.debug(f"[FAVICON] Discovery failed: {e}, using /favicon.ico")
            debug_print(f"        [FAVICON] Discovery failed: {e}")
            return "/favicon.ico"
    
    def _probe_favicon_organization_mode(
        self, 
        base_url: str, 
        probe: ProbeStep, 
        session: requests.Session,
        start_time: float
    ) -> ProbeResult:
        """Handle favicon probing for organization mode.
        
        For organization mode, we discover the favicon path dynamically by parsing
        the homepage HTML for <link rel="icon"> tags. Different sites under the
        same organization may have favicons in different locations.
        
        Flow:
        1. Discover favicon path by parsing homepage HTML
        2. Fetch favicon from discovered path
        3. If no link tag found or fetch fails, try /favicon.ico
        
        Args:
            base_url: Base URL of target
            probe: The favicon probe step
            session: HTTP session to use
            start_time: Start time for timing
            
        Returns:
            ProbeResult with match status
        """
        from config import Defaults
        
        result = ProbeResult(
            probe_order=probe.order,
            probe_type=probe.check_type,
            url_path=probe.url_path,
            points_earned=0,
            max_points=probe.weight or 0
        )
        
        # Step 1: Discover favicon path by parsing homepage
        logger.debug(f"[FAVICON] Organization mode: discovering favicon path for {base_url}")
        debug_print(f"        [FAVICON] Organization mode: discovering favicon path...")
        
        discovered_path = self._discover_favicon_path(base_url)
        
        # Step 2: Fetch favicon from discovered path
        favicon_url = f"{base_url.rstrip('/')}{discovered_path}"
        logger.debug(f"[PROBE] GET {favicon_url} (type: favicon_hash, discovered: {discovered_path})")
        debug_print(f"        [PROBE DEBUG] GET {favicon_url} (discovered)")
        
        try:
            response = session.get(
                favicon_url,
                timeout=self.timeout,
                allow_redirects=True,
                verify=self.verify_ssl
            )
            
            result.http_status = response.status_code
            result.response_time_ms = int((time.time() - start_time) * 1000)
            result.success = True
            result.url_path = discovered_path
            
            if response.status_code == 200:
                result = self._check_favicon_hash(response, probe, result)
                if result.matched:
                    result.url_path = f"{discovered_path} (discovered)"
                    return result
                    
        except Exception as e:
            logger.debug(f"[PROBE] Discovered path failed: {e}")
            debug_print(f"        [PROBE DEBUG] Discovered path failed: {e}")
        
        # Step 3: Try /favicon.ico as fallback if discovered path failed
        if discovered_path != "/favicon.ico":
            fallback_url = f"{base_url.rstrip('/')}/favicon.ico"
            logger.debug(f"[PROBE] Favicon fallback: trying {fallback_url}")
            debug_print(f"        [PROBE DEBUG] Favicon fallback: {fallback_url}")
            
            try:
                fallback_response = session.get(
                    fallback_url,
                    timeout=self.timeout,
                    allow_redirects=True,
                    verify=self.verify_ssl
                )
                
                if fallback_response.status_code == 200:
                    result.url_path = "/favicon.ico"
                    result.http_status = fallback_response.status_code
                    result = self._check_favicon_hash(fallback_response, probe, result)
                    if result.matched:
                        result.url_path = f"{discovered_path} → /favicon.ico (fallback)"
                        
            except Exception:
                pass  # Fallback failed too
        
        return result
    
    def execute_probe(self, base_url: str, probe: ProbeStep) -> ProbeResult:
        """Execute a single probe step.
        
        Args:
            base_url: Base URL of target (e.g., "http://1.2.3.4:80")
            probe: The probe step to execute
            
        Returns:
            ProbeResult with match status, points_earned and details
        """
        result = ProbeResult(
            probe_order=probe.order,
            probe_type=probe.check_type,
            url_path=probe.url_path,
            points_earned=0,
            max_points=probe.weight or 0
        )
        
        start_time = time.time()
        
        try:
            # Get thread-local session
            session = self._get_session()
            
            # Organization mode + favicon: discover path FIRST before making request
            if probe.check_type == "favicon_hash" and self.fingerprint_mode == "organization":
                return self._probe_favicon_organization_mode(base_url, probe, session, start_time)
            
            # Default behavior: use exact path from probe
            url = f"{base_url.rstrip('/')}{probe.url_path}"
            
            # Log the request
            logger.debug(f"[PROBE] GET {url} (type: {probe.check_type})")
            debug_print(f"        [PROBE DEBUG] GET {url}")
            
            response = session.get(
                url,
                timeout=self.timeout,
                allow_redirects=True,
                verify=self.verify_ssl  # False by default for self-signed certs
            )
            
            result.http_status = response.status_code
            result.response_time_ms = int((time.time() - start_time) * 1000)
            result.success = True
            
            # Execute appropriate check based on probe type
            if probe.check_type == "favicon_hash":
                # Application mode: use exact path from fingerprint with fallback
                result = self._check_favicon_hash(response, probe, result)
                
                # Favicon fallback: if designated path failed, try /favicon.ico
                # (browsers do this implicitly when no <link rel="icon"> is present)
                if not result.matched and probe.url_path != "/favicon.ico":
                    fallback_url = f"{base_url.rstrip('/')}/favicon.ico"
                    logger.debug(f"[PROBE] Favicon fallback: trying {fallback_url}")
                    debug_print(f"        [PROBE DEBUG] Favicon fallback: {fallback_url}")
                    try:
                        fallback_response = session.get(
                            fallback_url,
                            timeout=self.timeout,
                            allow_redirects=True,
                            verify=self.verify_ssl
                        )
                        if fallback_response.status_code == 200:
                            fallback_result = ProbeResult(
                                probe_order=probe.order,
                                probe_type=probe.check_type,
                                url_path="/favicon.ico (fallback)",
                                points_earned=0,
                                max_points=probe.weight or 0
                            )
                            fallback_result.http_status = fallback_response.status_code
                            fallback_result.success = True
                            fallback_result = self._check_favicon_hash(fallback_response, probe, fallback_result)
                            if fallback_result.matched:
                                result = fallback_result
                                result.url_path = f"{probe.url_path} → /favicon.ico (fallback)"
                    except Exception:
                        pass  # Fallback failed, keep original result
                        
            elif probe.check_type == "image_hash":
                result = self._check_image_hash(response, probe, result)
            elif probe.check_type == "page_signature":
                result = self._check_page_signature(response, probe, result)
            else:
                result.error = f"Unknown probe type: {probe.check_type}"
                
        except requests.exceptions.Timeout:
            result.error = "Request timed out"
            result.response_time_ms = int((time.time() - start_time) * 1000)
        except requests.exceptions.ConnectionError as e:
            result.error = f"Connection error: {str(e)[:100]}"
        except Exception as e:
            result.error = f"Probe failed: {str(e)[:100]}"
        
        return result
    
    def _check_favicon_hash(
        self, 
        response: requests.Response, 
        probe: ProbeStep, 
        result: ProbeResult
    ) -> ProbeResult:
        """Check favicon hash match.
        
        Points: Defaults.PROBE_POINTS_FAVICON (80) if matched.
        """
        result.max_points = Defaults.PROBE_POINTS_FAVICON
        
        if response.status_code != 200:
            result.error = f"HTTP {response.status_code}"
            return result
        
        if not probe.expected_hash:
            result.error = "No expected hash in probe"
            return result
        
        hash_type = probe.expected_hash.get("hash_type", "mmh3")
        expected_value = probe.expected_hash.get("value")
        expected_alt = probe.expected_hash.get("alt_values", [])  # Alternative hash values
        
        # Combine primary and alternative values
        all_expected = [expected_value] + expected_alt if expected_value else expected_alt
        result.expected = f"{hash_type}:{expected_value}" + (f" (+{len(expected_alt)} alt)" if expected_alt else "")
        
        # Calculate actual hash
        content = response.content
        if hash_type == "mmh3":
            # Shodan-style: base64 encode then MMH3
            b64_content = base64.encodebytes(content)
            actual_hash = str(mmh3.hash(b64_content))
        elif hash_type == "sha256":
            actual_hash = hashlib.sha256(content).hexdigest()
        elif hash_type == "md5":
            actual_hash = hashlib.md5(content).hexdigest()
        else:
            result.error = f"Unknown hash type: {hash_type}"
            return result
        
        result.actual = f"{hash_type}:{actual_hash}"
        result.matched = bool(actual_hash in all_expected)  # Check against all expected values
        
        # Award points if matched
        if result.matched:
            result.points_earned = Defaults.PROBE_POINTS_FAVICON
        
        return result
    
    def _check_image_hash(
        self, 
        response: requests.Response, 
        probe: ProbeStep, 
        result: ProbeResult
    ) -> ProbeResult:
        """Check image hash match (supports perceptual hashing).
        
        Points: Defaults.PROBE_POINTS_IMAGE (50) per image matched.
        """
        result.max_points = Defaults.PROBE_POINTS_IMAGE
        
        if response.status_code != 200:
            result.error = f"HTTP {response.status_code}"
            return result
        
        if not probe.expected_hash:
            result.error = "No expected hash in probe"
            return result
        
        hash_type = probe.expected_hash.get("hash_type", "phash")
        expected_value = probe.expected_hash.get("value")
        result.expected = f"{hash_type}:{expected_value}"
        
        content = response.content
        
        try:
            if hash_type == "phash":
                # Perceptual hash - allows for minor image variations
                img = Image.open(BytesIO(content))
                actual_hash = str(imagehash.phash(img))
                result.actual = f"phash:{actual_hash}"
                
                # For perceptual hash, check hamming distance (allow small differences)
                if actual_hash == expected_value:
                    result.matched = True
                else:
                    # Calculate hamming distance for near-matches
                    try:
                        expected_phash = imagehash.hex_to_hash(expected_value)
                        actual_phash = imagehash.hex_to_hash(actual_hash)
                        distance = int(expected_phash - actual_phash)  # Convert numpy int
                        # Allow up to 10 bits difference (out of 64)
                        result.matched = bool(distance <= 10)
                        if result.matched and distance > 0:
                            result.actual += f" (distance: {distance})"
                    except:
                        result.matched = False
                        
            elif hash_type == "sha256":
                actual_hash = hashlib.sha256(content).hexdigest()
                result.actual = f"sha256:{actual_hash}"
                result.matched = bool(actual_hash == expected_value)
            elif hash_type == "md5":
                actual_hash = hashlib.md5(content).hexdigest()
                result.actual = f"md5:{actual_hash}"
                result.matched = bool(actual_hash == expected_value)
            elif hash_type == "mmh3":
                # MurmurHash3 (Shodan-compatible)
                encoded = base64.b64encode(content).decode()
                actual_hash = str(mmh3.hash(encoded))
                result.actual = f"mmh3:{actual_hash}"
                result.matched = bool(actual_hash == expected_value)
            else:
                result.error = f"Unknown hash type: {hash_type}"
                
        except Exception as e:
            result.error = f"Image hash failed: {str(e)[:100]}"
        
        # Award points if matched
        if result.matched:
            result.points_earned = Defaults.PROBE_POINTS_IMAGE
        
        return result
    
    def _check_page_signature(
        self, 
        response: requests.Response, 
        probe: ProbeStep, 
        result: ProbeResult
    ) -> ProbeResult:
        """Check page signature with partial scoring.
        
        Scoring:
        - Title match: Defaults.PROBE_POINTS_TITLE (15) if title pattern matches
        - Body match: Defaults.PROBE_POINTS_BODY (15) per body pattern matched
        
        matched=True if ANY points were earned (partial matching allowed).
        """
        # Calculate max possible points for this probe
        max_points = 0
        if probe.expected_title_pattern:
            max_points += Defaults.PROBE_POINTS_TITLE
        if probe.expected_body_patterns:
            max_points += len(probe.expected_body_patterns) * Defaults.PROBE_POINTS_BODY
        result.max_points = max_points
        
        # Check status code first
        if probe.expected_status and response.status_code != probe.expected_status:
            result.expected = f"HTTP {probe.expected_status}"
            result.actual = f"HTTP {response.status_code}"
            result.matched = False
            return result
        
        content = response.text
        matches_found = []
        matches_expected = []
        points_earned = 0
        
        # Check title pattern
        if probe.expected_title_pattern:
            matches_expected.append(f"title:/{probe.expected_title_pattern}/")
            title_match = re.search(
                r"<title[^>]*>([^<]*)</title>",
                content,
                re.IGNORECASE
            )
            if title_match:
                actual_title = title_match.group(1)
                if re.search(probe.expected_title_pattern, actual_title, re.IGNORECASE):
                    matches_found.append(f"title:{actual_title[:50]}")
                    points_earned += Defaults.PROBE_POINTS_TITLE
        
        # Check body patterns - each pattern match earns points independently
        if probe.expected_body_patterns:
            for pattern in probe.expected_body_patterns:
                matches_expected.append(f"body:/{pattern[:30]}/")
                if re.search(re.escape(pattern), content, re.IGNORECASE):
                    matches_found.append(f"body:/{pattern[:30]}/")
                    points_earned += Defaults.PROBE_POINTS_BODY
        
        result.expected = " AND ".join(matches_expected) if matches_expected else "HTTP 200"
        result.actual = " AND ".join(matches_found) if matches_found else "no patterns matched"
        
        # Partial matching: matched=True if ANY points earned
        result.points_earned = points_earned
        result.matched = bool(points_earned > 0)
        
        return result

