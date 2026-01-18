"""HTTP fetching and content extraction for fingerprinting."""
import logging
from typing import Dict, List, Optional
from urllib.parse import urljoin
import requests
from bs4 import BeautifulSoup

from config import get_settings
from core.debug import debug_print
from core.utils import calculate_hashes, calculate_image_hashes, calculate_favicon_mmh3
from core.models import HashSet

# Configure logger
logger = logging.getLogger("sigint.fetcher")


class ContentFetcher:
    """Fetches and extracts content from web pages."""
    
    def __init__(self, session: Optional[requests.Session] = None):
        """Initialize fetcher.
        
        Args:
            session: Optional requests session to reuse
        """
        self.settings = get_settings()
        self.session = session or requests.Session()
        self.session.headers.update({"User-Agent": self.settings.fingerprint.user_agent})
    
    def fetch_path(self, base_url: str, path: str) -> Optional[Dict]:
        """Fetch a path and return structured content.
        
        Args:
            base_url: Base URL of the site
            path: Path to fetch
            
        Returns:
            Dictionary with response content and metadata, or None on error
        """
        try:
            full_url = urljoin(base_url, path)
            logger.debug(f"[FETCH] GET {full_url}")
            debug_print(f"        [FETCH DEBUG] GET {full_url}")
            response = self.session.get(
                full_url,
                timeout=self.settings.fingerprint.request_timeout,
                allow_redirects=True
            )
            
            # Store response details
            content = {
                "path": path,
                "url": response.url,
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "content": response.text[:self.settings.fingerprint.max_body_length],
                "content_length": len(response.content)
            }
            
            # Parse HTML if applicable
            if "text/html" in response.headers.get("Content-Type", ""):
                soup = BeautifulSoup(response.text, "html.parser")
                content["title"] = soup.title.string if soup.title else None
                content["links"] = [a.get("href") for a in soup.find_all("a", href=True)][:20]
                content["forms"] = [{"action": f.get("action"), "method": f.get("method")} 
                                   for f in soup.find_all("form")]
                content["scripts"] = [s.get("src") for s in soup.find_all("script", src=True)][:10]
                content["images"] = [img.get("src") for img in soup.find_all("img", src=True)][:10]
                
                # Extract favicon links from <link> tags
                favicon_links = []
                for link in soup.find_all("link", rel=True):
                    rel = link.get("rel", [])
                    # rel can be a list or string
                    rel_values = rel if isinstance(rel, list) else [rel]
                    if any(r.lower() in ("icon", "shortcut icon", "apple-touch-icon", "apple-touch-icon-precomposed") for r in rel_values):
                        href = link.get("href")
                        if href:
                            favicon_links.append({
                                "href": href,
                                "rel": " ".join(rel_values) if isinstance(rel, list) else rel,
                                "type": link.get("type"),
                                "sizes": link.get("sizes")
                            })
                content["favicon_links"] = favicon_links
            
            print(f"        ✓ HTTP {response.status_code} - {len(response.content)} bytes")
            
            return content
            
        except Exception as e:
            print(f"        ✗ Error: {e}")
            return None
    
    def fetch_and_hash_assets(
        self,
        base_url: str,
        discovered_assets: List[Dict],
        page_contents: Optional[List[Dict]] = None
    ) -> Dict:
        """Fetch and hash all discovered assets (favicon, images).
        
        Args:
            base_url: Base URL of the site
            discovered_assets: List of discovered asset dictionaries
            page_contents: Optional list of page content dictionaries with extracted favicon_links
            
        Returns:
            Dictionary with hashed assets
        """
        assets = {
            "favicon": None,
            "key_images": []
        }
        
        # Collect favicon paths to try, in order of preference
        favicon_paths_to_try = []
        
        # 1. First, check for favicon links extracted from HTML <link> tags
        if page_contents:
            for content in page_contents:
                for fav_link in content.get("favicon_links", []):
                    href = fav_link.get("href")
                    if href:
                        # Normalize path
                        if href.startswith(("http://", "https://")):
                            # Full URL - extract path or use as-is
                            from urllib.parse import urlparse
                            parsed = urlparse(href)
                            # If same domain, use path; otherwise skip external favicons
                            if parsed.netloc == "" or parsed.netloc in base_url:
                                href = parsed.path
                            else:
                                continue
                        if not href.startswith("/"):
                            href = f"/{href}"
                        if href not in favicon_paths_to_try:
                            favicon_paths_to_try.append(href)
                            print(f"        [*] Found favicon in HTML: {href}")
        
        # 2. Check for LLM-discovered favicon assets
        for asset in discovered_assets:
            asset_type = asset.get("type", "").lower()
            if asset_type == "favicon":
                discovered_path = asset.get("path") or asset.get("url")
                if discovered_path:
                    # Ensure path starts with /
                    favicon_path = discovered_path if discovered_path.startswith("/") else f"/{discovered_path}"
                    if favicon_path not in favicon_paths_to_try:
                        favicon_paths_to_try.append(favicon_path)
                        print(f"        [*] Found LLM-discovered favicon: {favicon_path}")
        
        # 3. Fallback to /favicon.ico
        if "/favicon.ico" not in favicon_paths_to_try:
            favicon_paths_to_try.append("/favicon.ico")
        
        # Fetch favicon - try each path in order until one works
        for favicon_path in favicon_paths_to_try:
            favicon_url = urljoin(base_url, favicon_path)
            logger.debug(f"[FETCH] GET {favicon_url}")
            debug_print(f"        [FETCH DEBUG] GET {favicon_url}")
            try:
                response = self.session.get(favicon_url, timeout=10)
                if response.status_code == 200 and len(response.content) > 0:
                    # Calculate multiple hash types
                    hashes = calculate_hashes(response.content)
                    mmh3_hash = calculate_favicon_mmh3(response.content)
                    
                    assets["favicon"] = {
                        "url": favicon_path,
                        "hashes": HashSet(
                            sha256=hashes.get("sha256"),
                            md5=hashes.get("md5"),
                            mmh3=mmh3_hash
                        ),
                        "size": len(response.content)
                    }
                    print(f"        ✓ Favicon hashed from {favicon_path} (MMH3: {mmh3_hash})")
                    break  # Stop once we successfully hash a favicon
                else:
                    print(f"        [*] {favicon_path} returned {response.status_code}, trying next...")
            except Exception as e:
                print(f"        [*] {favicon_path} error: {e}, trying next...")
        
        if not assets["favicon"]:
            print(f"        ✗ No favicon found after trying {len(favicon_paths_to_try)} paths")
        
        # Fetch key images from discovered assets
        for asset in discovered_assets:
            asset_type = asset.get("type", "")
            # Support both old format (type/path) and new format (purpose/url)
            is_logo = (
                asset_type == "logo" or 
                asset_type == "image" or
                "logo" in asset.get("purpose", "").lower()
            )
            if is_logo:
                # Support both "url" and "path" keys
                asset_url = asset.get("url") or asset.get("path", "")
                if not asset_url:
                    continue
                    
                full_url = urljoin(base_url, asset_url)
                logger.debug(f"[FETCH] GET {full_url}")
                debug_print(f"        [FETCH DEBUG] GET {full_url}")
                try:
                    response = self.session.get(full_url, timeout=10)
                    if response.status_code == 200 and len(response.content) > 0:
                        hashes = calculate_hashes(response.content)
                        img_hashes = calculate_image_hashes(response.content)
                        mmh3_hash = calculate_favicon_mmh3(response.content)
                        
                        assets["key_images"].append({
                            "url": asset_url,
                            "purpose": asset.get("purpose") or asset.get("reason", "logo"),
                            "hashes": HashSet(
                                sha256=hashes.get("sha256"),
                                md5=hashes.get("md5"),
                                mmh3=mmh3_hash,
                                phash=img_hashes.get("phash")
                            ),
                            "size": len(response.content)
                        })
                        print(f"        ✓ Logo hashed")
                except Exception as e:
                    print(f"        ✗ Logo error: {e}")
        
        return assets

