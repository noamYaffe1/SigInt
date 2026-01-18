"""GitHub repository analyzer for fingerprint extraction.

Analyzes a GitHub repository using LLM-driven analysis to extract fingerprint signals:
- Static assets (favicon, images, logos) with hashes
- Unique file paths and directory structure
- HTML/template patterns analyzed by LLM
- Route patterns from source code
- Application identification from code and config
"""
import os
import re
import json
import logging
import tempfile
import zipfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import requests
import openai
import secrets

# Configure logger
logger = logging.getLogger("sigint.github")

from config import get_settings
from core.debug import debug_print
from core.models import (
    FingerprintSpec, FingerprintOutput,
    FaviconFingerprint, ImageFingerprint, PageSignature, HashSet
)
from core.utils import calculate_hashes, calculate_image_hashes, calculate_favicon_mmh3, utc_now_iso
from .builder import ProbePlanBuilder
from .filters import filter_generic_patterns
from .prompts import get_github_analysis_prompt


# File patterns to look for
STATIC_ASSET_PATTERNS = [
    "favicon.ico",
    "*.png", "*.jpg", "*.jpeg", "*.gif", "*.svg", "*.webp",
    "*.css", "*.js",
]

# Directories commonly containing static assets
STATIC_DIRS = [
    "static", "public", "assets", "images", "img", "css", "js",
    "dist", "build", "web", "www", "htdocs",
]

# Template file extensions
TEMPLATE_EXTENSIONS = {
    ".html", ".htm", ".php", ".twig", ".blade.php", ".ejs", 
    ".hbs", ".mustache", ".pug", ".jade", ".erb", ".jinja", ".jinja2",
    ".vue", ".svelte", ".jsx", ".tsx",
}

# Route definition files to analyze
ROUTE_FILES = [
    "routes.py", "urls.py", "router.py",  # Python
    "routes.php", "web.php", "api.php",    # PHP/Laravel
    "routes.rb", "config/routes.rb",       # Ruby
    "routes.js", "router.js", "app.js", "server.js", "index.js",  # Node
    "main.go", "routes.go",                # Go
]

# Config files for app identification
CONFIG_FILES = [
    "package.json", "composer.json", "Gemfile", "requirements.txt",
    "setup.py", "pyproject.toml", "Cargo.toml", "pom.xml", "build.gradle",
    "README.md", "README.rst", "README.txt", "readme.md",
    "config.php", "config.py", "config.js", "settings.py", ".env.example",
]

# Files that indicate web roots
WEB_ROOT_INDICATORS = [
    "index.html", "index.php", "index.htm",
    "default.html", "default.php",
    ".htaccess", "web.config",
]

# Image files to prioritize for fingerprinting
PRIORITY_IMAGE_NAMES = [
    "logo", "brand", "header", "banner", "icon", "favicon",
]


class GitHubAnalyzer:
    """Analyzes GitHub repositories using LLM-driven fingerprinting."""
    
    def __init__(self, github_token: Optional[str] = None):
        """Initialize analyzer.
        
        Args:
            github_token: Optional GitHub token for private repos/higher rate limits
        """
        self.settings = get_settings()
        self.github_token = github_token or os.environ.get("GITHUB_TOKEN")
        self.session = requests.Session()
        if self.github_token:
            self.session.headers["Authorization"] = f"token {self.github_token}"
        self.session.headers["Accept"] = "application/vnd.github.v3+json"
        
        # OpenAI client for LLM analysis
        self.client = openai.OpenAI(api_key=self.settings.api.openai_api_key)
        
        # Builder for probe plan
        self.builder = ProbePlanBuilder()
    
    def analyze_repo(
        self, 
        repo_url: str,
        mode: str = "application",
        include_version: bool = False
    ) -> FingerprintOutput:
        """Analyze a GitHub repository and generate fingerprint using LLM.
        
        Args:
            repo_url: GitHub repository URL (e.g., https://github.com/user/repo)
            mode: Fingerprint mode - 'application' (software) or 'organization' (brand)
            include_version: Whether to include version/year in fingerprints
            
        Returns:
            FingerprintOutput compatible with existing pipeline
        """
        self.mode = mode
        self.include_version = include_version
        
        print("\n" + "=" * 70)
        print("[GITHUB FINGERPRINTING] LLM-Driven Repository Analysis")
        print("=" * 70)
        print(f"[*] Repository: {repo_url}")
        print(f"[*] Mode: {mode} {'(include version)' if include_version else '(version-agnostic)'}")
        print(f"[*] Model: {self.settings.fingerprint.model}")
        
        # Parse repo URL
        owner, repo = self._parse_github_url(repo_url)
        print(f"[*] Owner: {owner}, Repo: {repo}")
        
        # Get repo info
        repo_info = self._get_repo_info(owner, repo)
        app_name = repo_info.get("name", repo).replace("-", " ").replace("_", " ").title()
        description = repo_info.get("description", "")
        
        print(f"[*] App Name: {app_name}")
        if description:
            print(f"[*] Description: {description[:80]}")
        
        # Download and analyze repo
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_path = self._download_repo(owner, repo, temp_dir)
            
            # Phase 1: Extract files for LLM analysis
            print("\n" + "=" * 70)
            print("[PHASE 1] Extracting Key Files for Analysis")
            print("=" * 70)
            
            extracted_content = self._extract_key_files(repo_path)
            
            # Phase 2: Find and hash static assets
            print("\n" + "=" * 70)
            print("[PHASE 2] Finding and Hashing Static Assets")
            print("=" * 70)
            
            assets = self._find_static_assets(repo_path)
            web_root, paths = self._find_web_paths(repo_path)
            hashed_assets = self._hash_assets(repo_path, assets, web_root)
            
            # Phase 3: LLM Analysis
            print("\n" + "=" * 70)
            print("[PHASE 3] LLM-Driven Analysis")
            print("=" * 70)
            
            llm_analysis = self._llm_analyze_repo(
                repo_url=repo_url,
                app_name=app_name,
                description=description,
                extracted_content=extracted_content,
                paths=paths,
                hashed_assets=hashed_assets
            )
        
        # Phase 4: Build fingerprint
        print("\n" + "=" * 70)
        print("[PHASE 4] Building Fingerprint Specification")
        print("=" * 70)
        
        fingerprint = self._build_fingerprint_from_llm(
            app_name=llm_analysis.get("app_name", app_name),
            repo_url=repo_url,
            llm_analysis=llm_analysis,
            hashed_assets=hashed_assets
        )
        
        # Build probe plan using the builder
        probe_plan = self.builder.build_probe_plan(fingerprint)
        
        output = FingerprintOutput(
            fingerprint_spec=fingerprint,
            probe_plan=probe_plan
        )
        
        self._print_summary(output, hashed_assets, paths)
        
        return output
    
    def _parse_github_url(self, url: str) -> Tuple[str, str]:
        """Parse GitHub URL to extract owner and repo name."""
        url = url.rstrip("/")
        
        if url.endswith(".git"):
            url = url[:-4]
        
        if "github.com" in url:
            parts = url.split("github.com/")[-1].split("/")
            if len(parts) >= 2:
                return parts[0], parts[1]
        
        raise ValueError(f"Invalid GitHub URL: {url}")
    
    def _get_repo_info(self, owner: str, repo: str) -> Dict:
        """Get repository information from GitHub API."""
        url = f"https://api.github.com/repos/{owner}/{repo}"
        logger.debug(f"[GITHUB] GET {url}")
        debug_print(f"        [GITHUB DEBUG] GET {url}")
        try:
            response = self.session.get(url)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"    [!] Warning: Could not fetch repo info: {e}")
            return {"name": repo}
    
    def _download_repo(self, owner: str, repo: str, temp_dir: str) -> Path:
        """Download repository as ZIP and extract."""
        print(f"\n[*] Downloading repository...")
        
        zip_url = f"https://github.com/{owner}/{repo}/archive/refs/heads/main.zip"
        logger.debug(f"[GITHUB] GET {zip_url}")
        debug_print(f"        [GITHUB DEBUG] GET {zip_url}")
        
        try:
            response = self.session.get(zip_url, stream=True)
            if response.status_code == 404:
                zip_url = f"https://github.com/{owner}/{repo}/archive/refs/heads/master.zip"
                logger.debug(f"[GITHUB] GET {zip_url} (fallback to master)")
                debug_print(f"        [GITHUB DEBUG] GET {zip_url} (fallback to master)")
                response = self.session.get(zip_url, stream=True)
            response.raise_for_status()
        except Exception as e:
            raise RuntimeError(f"Failed to download repository: {e}")
        
        zip_path = Path(temp_dir) / "repo.zip"
        with open(zip_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        
        print(f"    ✓ Downloaded ({zip_path.stat().st_size / 1024:.1f} KB)")
        
        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.extractall(temp_dir)
        
        for item in Path(temp_dir).iterdir():
            if item.is_dir() and item.name != "__MACOSX":
                print(f"    ✓ Extracted to {item.name}")
                return item
        
        raise RuntimeError("Failed to find extracted repository")
    
    def _extract_key_files(self, repo_path: Path) -> Dict[str, str]:
        """Extract key files for LLM analysis."""
        extracted = {
            "config_files": [],
            "route_files": [],
            "template_files": [],
            "readme": None,
        }
        
        # Find and read config files
        print("    [1/4] Extracting config files...")
        for config_name in CONFIG_FILES:
            for config_path in repo_path.rglob(config_name):
                if self._should_skip_path(config_path):
                    continue
                try:
                    content = config_path.read_text(encoding="utf-8", errors="ignore")
                    rel_path = str(config_path.relative_to(repo_path))
                    
                    if config_name.lower().startswith("readme"):
                        extracted["readme"] = {"path": rel_path, "content": content[:3000]}
                    else:
                        extracted["config_files"].append({
                            "path": rel_path,
                            "content": content[:2000]
                        })
                except Exception:
                    continue
        print(f"        Found: {len(extracted['config_files'])} config files")
        
        # Find and read route files
        print("    [2/4] Extracting route definitions...")
        for route_name in ROUTE_FILES:
            for route_path in repo_path.rglob(route_name):
                if self._should_skip_path(route_path):
                    continue
                try:
                    content = route_path.read_text(encoding="utf-8", errors="ignore")
                    rel_path = str(route_path.relative_to(repo_path))
                    extracted["route_files"].append({
                        "path": rel_path,
                        "content": content[:3000]
                    })
                except Exception:
                    continue
        print(f"        Found: {len(extracted['route_files'])} route files")
        
        # Find and read template files (first 10)
        print("    [3/4] Extracting template files...")
        template_count = 0
        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if not self._should_skip_dir(d)]
            
            for file in files:
                ext = Path(file).suffix.lower()
                if ext in TEMPLATE_EXTENSIONS:
                    file_path = Path(root) / file
                    try:
                        content = file_path.read_text(encoding="utf-8", errors="ignore")
                        rel_path = str(file_path.relative_to(repo_path))
                        extracted["template_files"].append({
                            "path": rel_path,
                            "content": content[:2000]
                        })
                        template_count += 1
                        if template_count >= 10:
                            break
                    except Exception:
                        continue
            if template_count >= 10:
                break
        print(f"        Found: {len(extracted['template_files'])} template files")
        
        # Extract title patterns from templates
        print("    [4/4] Extracting title patterns...")
        extracted["title_patterns"] = self._extract_title_patterns(repo_path)
        print(f"        Found: {len(extracted['title_patterns'])} title patterns")
        
        # Summary
        print("    [5/5] Extraction complete")
        if extracted["readme"]:
            print(f"        README: ✓")
        
        return extracted
    
    def _extract_title_patterns(self, repo_path: Path) -> List[Dict[str, str]]:
        """Extract <title> patterns from template and HTML files.
        
        Returns actual title content found in the source code.
        """
        import re
        
        title_patterns = []
        title_regex = re.compile(r'<title[^>]*>(.*?)</title>', re.IGNORECASE | re.DOTALL)
        
        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if not self._should_skip_dir(d)]
            
            for file in files:
                ext = Path(file).suffix.lower()
                if ext in TEMPLATE_EXTENSIONS or ext in {'.html', '.htm', '.php'}:
                    file_path = Path(root) / file
                    try:
                        content = file_path.read_text(encoding="utf-8", errors="ignore")
                        matches = title_regex.findall(content)
                        for match in matches:
                            title_content = match.strip()
                            if title_content and len(title_content) < 500:  # Sanity check
                                rel_path = str(file_path.relative_to(repo_path))
                                title_patterns.append({
                                    "file": rel_path,
                                    "title": title_content
                                })
                    except Exception:
                        continue
        
        return title_patterns
    
    def _should_skip_path(self, path: Path) -> bool:
        """Check if path should be skipped."""
        skip_dirs = {"node_modules", "vendor", "__pycache__", "venv", ".git", "dist", "build"}
        return any(part in skip_dirs for part in path.parts)
    
    def _should_skip_dir(self, dirname: str) -> bool:
        """Check if directory should be skipped."""
        return dirname.startswith(".") or dirname in {
            "node_modules", "vendor", "__pycache__", "venv", "dist", "build", "test", "tests"
        }
    
    def _find_static_assets(self, repo_path: Path) -> Dict[str, List[Path]]:
        """Find static assets in the repository."""
        assets = {
            "favicon": [],
            "images": [],
            "css": [],
            "js": [],
        }
        
        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if not self._should_skip_dir(d)]
            
            for file in files:
                file_lower = file.lower()
                file_path = Path(root) / file
                
                if "favicon" in file_lower and file_lower.endswith((".ico", ".png", ".svg")):
                    assets["favicon"].append(file_path)
                elif file_lower.endswith((".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp")):
                    assets["images"].append(file_path)
                elif file_lower.endswith(".css"):
                    assets["css"].append(file_path)
                elif file_lower.endswith(".js") and not file_lower.endswith(".min.js"):
                    assets["js"].append(file_path)
        
        print(f"        Found: {len(assets['favicon'])} favicons, {len(assets['images'])} images")
        
        return assets
    
    def _find_web_paths(self, repo_path: Path) -> Tuple[Optional[Path], List[Dict]]:
        """Find web root and extract unique paths."""
        web_root = None
        paths = []
        
        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if not self._should_skip_dir(d)]
            
            for indicator in WEB_ROOT_INDICATORS:
                if indicator in files:
                    web_root = Path(root)
                    break
            
            if web_root:
                break
        
        if not web_root:
            for static_dir in STATIC_DIRS:
                candidate = repo_path / static_dir
                if candidate.exists():
                    web_root = candidate
                    break
        
        if not web_root:
            web_root = repo_path
        
        print(f"        Web root: {web_root.relative_to(repo_path)}")
        
        seen_paths = set()
        for root, dirs, files in os.walk(web_root):
            dirs[:] = [d for d in dirs if not d.startswith(".")]
            
            rel_root = Path(root).relative_to(web_root)
            
            for file in files:
                if file.startswith("."):
                    continue
                
                rel_path = rel_root / file
                path_str = "/" + str(rel_path).replace("\\", "/")
                
                if path_str not in seen_paths:
                    seen_paths.add(path_str)
                    paths.append({
                        "path": path_str,
                        "file": file,
                        "extension": Path(file).suffix.lower(),
                    })
        
        def path_priority(p):
            if "index" in p["file"].lower():
                return 0
            if p["extension"] in [".html", ".php"]:
                return 1
            if p["extension"] in [".ico", ".png", ".jpg"]:
                return 2
            return 3
        
        paths.sort(key=path_priority)
        
        print(f"        Found {len(paths)} unique paths")
        
        return web_root, paths[:50]
    
    def _hash_assets(self, repo_path: Path, assets: Dict, web_root: Optional[Path]) -> Dict:
        """Hash static assets for fingerprinting."""
        hashed = {
            "favicon": None,
            "key_images": [],
        }
        
        # Hash favicon
        for favicon_path in assets.get("favicon", []):
            try:
                content = favicon_path.read_bytes()
                hashes = calculate_hashes(content)
                mmh3_hash = calculate_favicon_mmh3(content)
                
                try:
                    rel_path = "/" + str(favicon_path.relative_to(web_root)).replace("\\", "/")
                except ValueError:
                    rel_path = "/" + favicon_path.name
                
                hashed["favicon"] = {
                    "url": rel_path,
                    "hashes": HashSet(
                        sha256=hashes.get("sha256"),
                        md5=hashes.get("md5"),
                        mmh3=mmh3_hash
                    ),
                    "size": len(content),
                }
                print(f"        ✓ Favicon: {rel_path} (MMH3: {mmh3_hash})")
                break
            except Exception:
                continue
        
        # Hash priority images (logos, etc.)
        for img_path in assets.get("images", []):
            is_priority = any(name in img_path.name.lower() for name in PRIORITY_IMAGE_NAMES)
            
            if is_priority or len(hashed["key_images"]) < 3:
                try:
                    content = img_path.read_bytes()
                    hashes = calculate_hashes(content)
                    img_hashes = calculate_image_hashes(content)
                    mmh3_hash = calculate_favicon_mmh3(content)
                    
                    try:
                        rel_path = "/" + str(img_path.relative_to(web_root)).replace("\\", "/")
                    except ValueError:
                        rel_path = "/" + img_path.name
                    
                    hashed["key_images"].append({
                        "url": rel_path,
                        "name": img_path.name,
                        "hashes": HashSet(
                            sha256=hashes.get("sha256"),
                            md5=hashes.get("md5"),
                            mmh3=mmh3_hash,
                            phash=img_hashes.get("phash"),
                        ),
                        "size": len(content),
                        "description": "logo" if is_priority else "image",
                    })
                    
                    if is_priority:
                        print(f"        ✓ Logo: {rel_path}")
                except Exception:
                    continue
            
            if len(hashed["key_images"]) >= 5:
                break
        
        return hashed
    
    def _llm_analyze_repo(
        self,
        repo_url: str,
        app_name: str,
        description: str,
        extracted_content: Dict,
        paths: List[Dict],
        hashed_assets: Dict
    ) -> Dict:
        """Use LLM to analyze the repository and generate fingerprint signals."""
        
        # Build context for LLM
        context_parts = []
        
        context_parts.append(f"Repository: {repo_url}")
        context_parts.append(f"App Name (from repo): {app_name}")
        context_parts.append(f"Mode: {self.mode} ({'include version' if self.include_version else 'version-agnostic'})")
        if description:
            context_parts.append(f"Description: {description}")
        
        # Add README
        if extracted_content.get("readme"):
            readme = extracted_content["readme"]
            context_parts.append(f"\n--- README ({readme['path']}) ---")
            context_parts.append(readme["content"][:2000])
        
        # Add config files
        if extracted_content.get("config_files"):
            context_parts.append(f"\n--- CONFIG FILES ({len(extracted_content['config_files'])} files) ---")
            for cfg in extracted_content["config_files"][:5]:
                context_parts.append(f"\n[{cfg['path']}]")
                context_parts.append(cfg["content"][:1000])
        
        # Add route files
        if extracted_content.get("route_files"):
            context_parts.append(f"\n--- ROUTE FILES ({len(extracted_content['route_files'])} files) ---")
            for route in extracted_content["route_files"][:3]:
                context_parts.append(f"\n[{route['path']}]")
                context_parts.append(route["content"][:1500])
        
        # Add template files
        if extracted_content.get("template_files"):
            context_parts.append(f"\n--- TEMPLATE FILES ({len(extracted_content['template_files'])} files) ---")
            for tmpl in extracted_content["template_files"][:5]:
                context_parts.append(f"\n[{tmpl['path']}]")
                context_parts.append(tmpl["content"][:1000])
        
        # Add discovered paths
        context_parts.append(f"\n--- WEB PATHS ({len(paths)} unique paths) ---")
        for p in paths[:20]:
            context_parts.append(f"  {p['path']}")
        
        # Add asset info
        context_parts.append(f"\n--- STATIC ASSETS ---")
        if hashed_assets.get("favicon"):
            context_parts.append(f"  Favicon: {hashed_assets['favicon']['url']}")
        for img in hashed_assets.get("key_images", []):
            context_parts.append(f"  Image: {img['url']} ({img.get('description', 'image')})")
        
        # Add extracted title patterns - THIS IS CRITICAL for accurate title fingerprinting
        if extracted_content.get("title_patterns"):
            context_parts.append(f"\n--- ACTUAL <title> TAGS FOUND IN SOURCE CODE ---")
            context_parts.append("USE ONLY THESE for title_pattern (do NOT invent titles):")
            for tp in extracted_content["title_patterns"]:
                context_parts.append(f"  File: {tp['file']}")
                context_parts.append(f"  Title: {tp['title']}")
                context_parts.append("")
        else:
            context_parts.append(f"\n--- NO <title> TAGS FOUND ---")
            context_parts.append("No static title tags found. Set title_pattern to null and rely on body_patterns.")
        
        context = "\n".join(context_parts)
        
        # Get mode-aware prompt
        prompt = get_github_analysis_prompt(
            mode=self.mode,
            include_version=self.include_version,
            context=context
        )

        try:
            print(f"[LLM] Analyzing repository with {self.settings.fingerprint.model}...")
            
            response = self.client.chat.completions.create(
                model=self.settings.fingerprint.model,
                messages=[
                    {"role": "system", "content": "You are a web application fingerprinting expert. Analyze source code repositories to identify unique fingerprint signals. Respond only with valid JSON."},
                    {"role": "user", "content": prompt}
                ],
                response_format={"type": "json_object"},
                temperature=0.3
            )
            
            print(f"[LLM] ✓ Analysis complete (tokens: {response.usage.prompt_tokens}+{response.usage.completion_tokens})")
            
            analysis = json.loads(response.choices[0].message.content)
            
            # Post-process: Filter out generic patterns
            analysis = filter_generic_patterns(analysis)
            
            # Display LLM findings
            print(f"\n{'='*70}")
            print(f"[LLM ANALYSIS RESULTS]")
            print(f"{'='*70}")
            target_label = "Organization" if self.mode == "organization" else "Application"
            print(f"{target_label}: {analysis.get('app_name', 'Unknown')}")
            print(f"Confidence: {analysis.get('confidence_level', 'unknown').upper()}")
            print(f"Reasoning: {analysis.get('confidence_reasoning', '')[:100]}")
            
            print(f"\nDistinctive Features:")
            for feat in analysis.get("distinctive_features", [])[:5]:
                print(f"  • {feat}")
            
            print(f"\nPage Signatures: {len(analysis.get('page_signatures', []))}")
            for sig in analysis.get("page_signatures", [])[:3]:
                print(f"  - {sig.get('url')}: {sig.get('title_pattern', '')[:50]}")
            
            if analysis.get("notes"):
                print(f"\nNotes: {analysis.get('notes')[:100]}...")
            
            print(f"{'='*70}\n")
            
            return analysis
            
        except Exception as e:
            print(f"[!] LLM analysis failed: {e}")
            # Return minimal analysis
            return {
                "app_name": app_name,
                "confidence_level": "low",
                "distinctive_features": [],
                "page_signatures": [],
                "notes": f"LLM analysis failed: {e}"
            }
    
    def _build_fingerprint_from_llm(
        self,
        app_name: str,
        repo_url: str,
        llm_analysis: Dict,
        hashed_assets: Dict
    ) -> FingerprintSpec:
        """Build FingerprintSpec from LLM analysis and hashed assets."""
        
        # Build favicon fingerprint
        favicon = None
        if hashed_assets.get("favicon"):
            fav = hashed_assets["favicon"]
            favicon = FaviconFingerprint(
                url=fav["url"],
                hashes=fav["hashes"]
            )
        
        # Build image fingerprints
        key_images = []
        for img in hashed_assets.get("key_images", []):
            key_images.append(ImageFingerprint(
                url=img["url"],
                hashes=img["hashes"],
                description=img.get("description", "image")
            ))
        
        # Build page signatures from LLM analysis
        page_signatures = []
        for sig in llm_analysis.get("page_signatures", []):
            page_signatures.append(PageSignature(
                url=sig.get("url", "/"),
                title_pattern=sig.get("title_pattern"),
                body_patterns=sig.get("body_patterns", []),
            ))
        
        # Generate run_id
        run_id = f"{utc_now_iso().replace(':', '').replace('-', '').replace('T', '_')[:15]}_{secrets.token_hex(3)}"
        
        return FingerprintSpec(
            app_name=llm_analysis.get("app_name", app_name),
            source_type="github_repo",
            source_location=repo_url,
            run_id=run_id,
            created_at=utc_now_iso(),
            favicon=favicon,
            key_images=key_images,
            page_signatures=page_signatures,
            distinctive_features=llm_analysis.get("distinctive_features", []),
            confidence_level=llm_analysis.get("confidence_level", "medium"),
            notes=llm_analysis.get("notes"),
            fingerprint_mode=self.mode,
            include_version=self.include_version,
        )
    
    def _print_summary(self, output: FingerprintOutput, assets: Dict, paths: List[Dict]) -> None:
        """Print fingerprint summary."""
        spec = output.fingerprint_spec
        plan = output.probe_plan
        
        print("\n" + "=" * 70)
        print("[GITHUB FINGERPRINT SUMMARY]")
        print("=" * 70)
        target_label = "Organization" if spec.fingerprint_mode == "organization" else "Application"
        print(f"{target_label}: {spec.app_name}")
        print(f"Source: {spec.source_location}")
        print(f"Run ID: {spec.run_id}")
        print(f"Confidence: {spec.confidence_level.upper()}")
        
        print(f"\nAssets:")
        print(f"  Favicon: {'✓' if spec.favicon else '✗'}")
        print(f"  Key Images: {len(spec.key_images)}")
        
        print(f"\nSignatures:")
        print(f"  Page Signatures: {len(spec.page_signatures)}")
        
        print(f"\nDistinctive Features:")
        for feat in spec.distinctive_features[:3]:
            print(f"  • {feat}")
        
        print(f"\nProbe Plan: {len(plan.probe_steps)} steps")
        for step in plan.probe_steps[:5]:
            print(f"  #{step.order} {step.check_type}: {step.url_path} ({step.weight} pts)")
        
        if spec.notes:
            print(f"\nNotes: {spec.notes[:100]}...")
        
        print("=" * 70)
