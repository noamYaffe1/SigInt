"""LLM-driven recursive fingerprinting engine.

This module orchestrates the fingerprinting process:
1. Recursive discovery guided by LLM analysis
2. Asset fetching and hashing
3. LLM-based fingerprint normalization
4. Probe plan building

The actual implementations are delegated to helper modules:
- fetcher.py: HTTP fetching and content extraction
- builder.py: Probe plan construction
"""
import json
from typing import Dict, List, Set
from datetime import datetime, timezone
import secrets
import requests
import openai
from core.utils import utc_now_iso

from config import get_settings, Defaults
from core.models import (
    FingerprintSpec, FingerprintOutput,
    FaviconFingerprint, ImageFingerprint, PageSignature
)
from .fetcher import ContentFetcher
from .builder import ProbePlanBuilder
from .filters import filter_generic_patterns
from .prompts import get_iteration_analysis_prompt, get_normalization_prompt


class LLMFingerprintEngine:
    """LLM-driven recursive fingerprinting engine.
    
    Orchestrates the complete fingerprinting workflow:
    1. Iterative discovery with LLM guidance
    2. Asset collection and hashing
    3. Fingerprint normalization
    4. Probe plan generation
    """
    
    def __init__(self):
        self.settings = get_settings()
        self.client = openai.OpenAI(api_key=self.settings.api.openai_api_key)
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": self.settings.fingerprint.user_agent})
        
        # Helper modules
        self.fetcher = ContentFetcher(session=self.session)
        self.builder = ProbePlanBuilder()
        
        # Track what we've discovered
        self.visited_paths: Set[str] = set()
        self.discovered_endpoints: List[Dict] = []
        self.discovered_assets: List[Dict] = []
        self.page_contents: List[Dict] = []
        self.discovered_page_signatures: List[Dict] = []  # page_signatures from iteration analysis
        
    def fingerprint_live_site(
        self, 
        url: str, 
        max_iterations: int = Defaults.MAX_ITERATIONS,
        mode: str = "application",
        include_version: bool = False
    ) -> FingerprintOutput:
        """Recursively fingerprint a live site using LLM guidance.
        
        Args:
            url: Base URL of the site
            max_iterations: Maximum discovery iterations (default from config)
            mode: Fingerprint mode - 'application' (software) or 'organization' (brand)
            include_version: Whether to include version/year in fingerprints
            
        Returns:
            FingerprintOutput with complete fingerprint
        """
        self.mode = mode
        self.include_version = include_version
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"
        
        base_url = url
        
        print("\n" + "="*70)
        print("[LLM-DRIVEN FINGERPRINTING] Starting Recursive Discovery")
        print("="*70)
        print(f"[*] Target: {base_url}")
        print(f"[*] Mode: {mode} {'(include version)' if include_version else '(version-agnostic)'}")
        print(f"[*] Max iterations: {max_iterations}")
        print(f"[*] Model: {self.settings.fingerprint.model}")
        
        # Phase 1: Recursive Discovery
        print("\n" + "="*70)
        print("[PHASE 1] LLM-Guided Recursive Discovery")
        print("="*70)
        
        iteration = 0
        paths_to_probe = ["/"]
        high_confidence_count = 0  # Track consecutive high confidence results
        
        while iteration < max_iterations and paths_to_probe:
            iteration += 1
            print(f"\n[ITERATION {iteration}/{max_iterations}]")
            print(f"[*] Paths to probe: {paths_to_probe}")
            
            # Fetch all new paths
            new_content = []
            for path in paths_to_probe:
                if path in self.visited_paths:
                    continue
                
                print(f"    [Fetcher] GET {path}")
                content = self.fetcher.fetch_path(base_url, path)
                if content:
                    new_content.append(content)
                    self.page_contents.append(content)
                    self.visited_paths.add(path)
            
            if not new_content:
                print("[!] No new content fetched, stopping discovery")
                break
            
            # Let LLM analyze and decide next steps
            print(f"\n[LLM] Analyzing {len(new_content)} responses...")
            analysis = self._llm_analyze_iteration(base_url, new_content, iteration, max_iterations)
            
            # Display LLM's findings with reasoning
            print(f"\n{'='*70}")
            print(f"[LLM ANALYSIS - Iteration {iteration}]")
            print(f"{'='*70}")
            
            # Application identification
            app_name = analysis.get('app_name', 'Unknown')
            app_version = analysis.get('app_version', 'Unknown')
            print(f"\n[Application Identification]")
            print(f"  Name: {app_name}")
            if app_version and app_version != "Unknown":
                print(f"  Version: {app_version}")
            
            # Confidence with reasoning
            confidence = analysis.get('confidence_level', 'unknown').lower()
            confidence_reasoning = analysis.get('confidence_reasoning', 'No reasoning provided')
            print(f"\n[Confidence Assessment]")
            print(f"  Level: {confidence.upper()}")
            print(f"  Reasoning: {confidence_reasoning}")
            
            # Discovered endpoints with reasons
            if analysis.get('discovered_endpoints'):
                print(f"\n[Discovered Endpoints] ({len(analysis['discovered_endpoints'])} total)")
                for ep in analysis['discovered_endpoints'][:5]:
                    priority = ep.get('priority', 'medium')
                    priority_icon = '🔴' if priority == 'high' else '🟡' if priority == 'medium' else '🟢'
                    print(f"  {priority_icon} {ep.get('path')}")
                    print(f"     → {ep.get('reason', 'no reason provided')}")
            
            # Page signatures (CRITICAL for robust fingerprinting)
            if analysis.get('page_signatures'):
                print(f"\n[Page Signatures] ({len(analysis['page_signatures'])} total)")
                for sig in analysis['page_signatures'][:3]:
                    print(f"  • Path: {sig.get('path', '/')}")
                    if sig.get('title_pattern'):
                        print(f"    Title: {sig.get('title_pattern')}")
                    if sig.get('body_patterns'):
                        print(f"    Body patterns: {sig.get('body_patterns')[:3]}")
            else:
                print(f"\n[⚠️ WARNING] No page signatures extracted - fingerprint may be weak!")
            
            # Discovered assets with reasons
            if analysis.get('discovered_assets'):
                print(f"\n[Discovered Assets] ({len(analysis['discovered_assets'])} total)")
                for asset in analysis['discovered_assets'][:5]:
                    print(f"  • {asset.get('type')}: {asset.get('path')}")
                    if asset.get('reason'):
                        print(f"     → {asset.get('reason')}")
            
            # Next paths to probe
            next_paths = analysis.get('next_paths_to_probe', [])
            if next_paths:
                print(f"\n[LLM Suggests Next Paths]")
                next_paths_reasoning = analysis.get('next_paths_reasoning', '')
                if next_paths_reasoning:
                    print(f"  Reasoning: {next_paths_reasoning}")
                for path in next_paths[:5]:
                    print(f"  → {path}")
            
            # Track high confidence iterations
            if confidence == 'high':
                high_confidence_count += 1
                print(f"\n[✓] High Confidence Achievement: {high_confidence_count}/2")
            else:
                high_confidence_count = 0  # Reset if not high
            
            print(f"{'='*70}\n")
            
            # Store findings
            self.discovered_endpoints.extend(analysis.get('discovered_endpoints', []))
            self.discovered_assets.extend(analysis.get('discovered_assets', []))
            
            # Capture page_signatures from iteration analysis
            if analysis.get('page_signatures'):
                self.discovered_page_signatures.extend(analysis.get('page_signatures', []))
            
            # Smart early stopping: 2+ high confidence OR LLM says stop
            if high_confidence_count >= 2:
                print(f"\n{'='*70}")
                print(f"[SMART EARLY STOP TRIGGERED]")
                print(f"{'='*70}")
                print(f"✓ 2+ consecutive HIGH confidence iterations achieved")
                print(f"✓ Sufficient distinctive signals collected")
                print(f"✓ Stopping discovery early to save time and API costs")
                print(f"{'='*70}\n")
                break
            
            # Check if LLM says we're done
            should_continue_reasoning = analysis.get('should_continue_reasoning', '')
            if analysis.get('should_continue', True) == False:
                print(f"\n{'='*70}")
                print(f"[LLM-INITIATED STOP]")
                print(f"{'='*70}")
                print(f"✓ LLM determined sufficient confidence reached")
                if should_continue_reasoning:
                    print(f"✓ Reasoning: {should_continue_reasoning}")
                print(f"{'='*70}\n")
                break
            
            # Get next paths to probe
            paths_to_probe = analysis.get('next_paths_to_probe', [])[:5]  # Limit to 5 per iteration
            
            if not paths_to_probe:
                print(f"[!] No more paths suggested by LLM")
                break
        
        print(f"\n[✓] Discovery complete after {iteration} iterations")
        print(f"[*] Visited {len(self.visited_paths)} unique paths")
        print(f"[*] Found {len(self.discovered_endpoints)} unique endpoints")
        print(f"[*] Found {len(self.discovered_assets)} assets")
        print(f"[*] Found {len(self.discovered_page_signatures)} page signatures")
        
        # Phase 2: Fetch and hash assets
        print("\n" + "="*70)
        print("[PHASE 2] Fetching and Hashing Assets")
        print("="*70)
        
        processed_assets = self.fetcher.fetch_and_hash_assets(base_url, self.discovered_assets, self.page_contents)
        
        # Phase 3: Normalize findings
        print("\n" + "="*70)
        print("[PHASE 3] LLM Normalization & Validation")
        print("="*70)
        
        fingerprint_spec = self._llm_normalize_fingerprint(base_url, processed_assets)
        
        # Add run metadata
        run_id = self._generate_run_id()
        fingerprint_spec.run_id = run_id
        fingerprint_spec.created_at = utc_now_iso()
        
        # Phase 4: Build probe plan
        print("\n" + "="*70)
        print("[PHASE 4] Building Probe Plan")
        print("="*70)
        
        probe_plan = self.builder.build_probe_plan(fingerprint_spec)
        
        print(f"\n[✓] Fingerprint generation complete!")
        print(f"    Run ID: {run_id}")
        print(f"    Confidence: {fingerprint_spec.confidence_level.upper()}")
        print(f"    Probe steps: {len(probe_plan.probe_steps)}")
        
        return FingerprintOutput(
            fingerprint_spec=fingerprint_spec,
            probe_plan=probe_plan
        )
    
    def _generate_run_id(self) -> str:
        """Generate unique run ID with timestamp."""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        random_suffix = secrets.token_hex(3)
        return f"{timestamp}_{random_suffix}"
    
    def _llm_analyze_iteration(
        self, 
        base_url: str, 
        new_content: List[Dict], 
        iteration: int,
        max_iterations: int
    ) -> Dict:
        """Let LLM analyze current findings and guide next steps."""
        
        # Build context summary
        summary_parts = []
        for content in new_content:
            summary_parts.append(f"\n--- {content['path']} (HTTP {content['status_code']}) ---")
            if content.get('title'):
                summary_parts.append(f"Title: {content['title']}")
            summary_parts.append(f"Content: {content['content'][:1000]}")
            if content.get('links'):
                summary_parts.append(f"Links found: {len(content['links'])}")
            if content.get('forms'):
                summary_parts.append(f"Forms: {content['forms']}")
            if content.get('favicon_links'):
                summary_parts.append(f"Favicon links found: {content['favicon_links']}")
        
        summary = "\n".join(summary_parts)
        
        # Get mode-aware prompt
        prompt = get_iteration_analysis_prompt(
            mode=self.mode,
            include_version=self.include_version,
            base_url=base_url,
            visited_paths=list(self.visited_paths),
            discovered_endpoints=len(self.discovered_endpoints),
            new_content_summary=summary,
            iteration=iteration,
            max_iterations=max_iterations
        )

        try:
            response = self.client.chat.completions.create(
                model=self.settings.fingerprint.model,
                messages=[
                    {"role": "system", "content": "You are a web application fingerprinting expert. Respond only with valid JSON."},
                    {"role": "user", "content": prompt}
                ],
                response_format={"type": "json_object"},
                temperature=0.3
            )
            
            print(f"[LLM] ✓ Response received (tokens: {response.usage.prompt_tokens}+{response.usage.completion_tokens})")
            
            return json.loads(response.choices[0].message.content)
            
        except Exception as e:
            print(f"[!] LLM analysis failed: {e}")
            return {
                "confidence_level": "low",
                "discovered_endpoints": [],
                "discovered_assets": [],
                "next_paths_to_probe": [],
                "should_continue": False
            }
    
    def _llm_normalize_fingerprint(self, base_url: str, assets: Dict) -> FingerprintSpec:
        """Let LLM normalize all findings into final fingerprint."""
        
        # Build comprehensive summary
        summary_parts = [f"Target: {base_url}"]
        summary_parts.append(f"Mode: {self.mode} ({'include version' if self.include_version else 'version-agnostic'})")
        summary_parts.append(f"\nPaths Visited ({len(self.visited_paths)}):")
        for path in list(self.visited_paths)[:10]:
            summary_parts.append(f"  - {path}")
        
        summary_parts.append(f"\nPage Contents (CRITICAL - Extract title_pattern and body_patterns from this!):")
        for content in self.page_contents[:5]:
            summary_parts.append(f"\n--- {content['path']} ---")
            title = content.get('title')
            if title:
                summary_parts.append(f"TITLE TAG: \"{title}\" (USE THIS in title_pattern!)")
            else:
                summary_parts.append(f"TITLE TAG: (none or dynamic)")
            # Include more content for pattern extraction
            summary_parts.append(f"HTML Content (first 2000 chars):\n{content['content'][:2000]}")
        
        summary_parts.append(f"\nDiscovered Endpoints ({len(self.discovered_endpoints)}):")
        for ep in self.discovered_endpoints[:10]:
            summary_parts.append(f"  - {ep}")
        
        summary_parts.append(f"\nAssets:")
        summary_parts.append(f"  Favicon: {'Yes' if assets['favicon'] else 'No'}")
        summary_parts.append(f"  Key Images: {len(assets.get('key_images', []))}")
        
        # Include already discovered page signatures (from iteration analysis)
        if self.discovered_page_signatures:
            summary_parts.append(f"\n[Page Signatures Already Discovered - USE THESE]:")
            for sig in self.discovered_page_signatures:
                summary_parts.append(f"  Path: {sig.get('path', '/')}")
                if sig.get('title_pattern'):
                    summary_parts.append(f"  Title Pattern: {sig.get('title_pattern')}")
                if sig.get('body_patterns'):
                    summary_parts.append(f"  Body Patterns: {sig.get('body_patterns')}")
        
        summary = "\n".join(summary_parts)
        
        # Get mode-aware prompt
        prompt = get_normalization_prompt(
            mode=self.mode,
            include_version=self.include_version,
            base_url=base_url,
            summary=summary
        )

        try:
            response = self.client.chat.completions.create(
                model=self.settings.fingerprint.model,
                messages=[
                    {"role": "system", "content": "You are a web application fingerprinting expert. Respond only with valid JSON."},
                    {"role": "user", "content": prompt}
                ],
                response_format={"type": "json_object"},
                temperature=0.3
            )
            
            print(f"[LLM] ✓ Normalization complete (tokens: {response.usage.prompt_tokens}+{response.usage.completion_tokens})")
            
            analysis = json.loads(response.choices[0].message.content)
            
            # Post-process: Filter out generic patterns
            analysis = filter_generic_patterns(analysis)
            
            # Display normalization results
            print(f"\n{'='*70}")
            print(f"[LLM NORMALIZATION RESULTS]")
            print(f"{'='*70}")
            target_label = "Organization" if self.mode == "organization" else "Application"
            print(f"{target_label}: {analysis.get('app_name', 'Unknown')}")
            print(f"Confidence: {analysis.get('confidence_level', 'unknown').upper()}")
            print(f"\nDistinctive Features ({len(analysis.get('distinctive_features', []))}):")
            for feat in analysis.get('distinctive_features', [])[:5]:
                print(f"  • {feat}")
            print(f"\nPage Signatures: {len(analysis.get('page_signatures', []))}")
            if analysis.get('notes'):
                print(f"\nLLM Notes: {analysis.get('notes')}")
            print(f"{'='*70}\n")
            
            # Build FingerprintSpec
            favicon_fp = None
            if assets['favicon']:
                favicon_fp = FaviconFingerprint(
                    url=assets['favicon']['url'],
                    hashes=assets['favicon']['hashes'],
                    content_type=assets['favicon'].get('content_type')
                )
            
            key_images = [
                ImageFingerprint(
                    url=img['url'],
                    hashes=img['hashes'],
                    description=img.get('purpose', 'Logo')
                )
                for img in assets.get('key_images', [])
            ]
            
            # Build page signatures from LLM response
            llm_page_sigs = analysis.get('page_signatures', [])
            
            # Fallback: use discovered page_signatures from iteration if LLM returned none
            if not llm_page_sigs and self.discovered_page_signatures:
                print(f"[!] LLM returned no page signatures - using discovered ones")
                llm_page_sigs = self.discovered_page_signatures
            
            page_sigs = [
                PageSignature(
                    url=sig.get('url', sig.get('path', '/')),  # Support both 'url' and 'path'
                    title_pattern=sig.get('title_pattern'),
                    body_patterns=sig.get('body_patterns', []),
                    meta_tags=None
                )
                for sig in llm_page_sigs
            ]
            
            # Warn if still no page signatures
            if not page_sigs:
                print(f"[⚠️ WARNING] No page signatures found - fingerprint will rely solely on favicon/images!")
                print(f"[⚠️ WARNING] This is a weak fingerprint - consider manual review.")
            
            return FingerprintSpec(
                app_name=analysis.get('app_name', 'Unknown'),
                source_type='live_site',
                source_location=base_url,
                favicon=favicon_fp,
                key_images=key_images,
                page_signatures=page_sigs,
                distinctive_features=analysis.get('distinctive_features', []),
                confidence_level=analysis.get('confidence_level', 'medium'),
                notes=analysis.get('notes'),
                fingerprint_mode=self.mode,
                include_version=self.include_version
            )
            
        except Exception as e:
            print(f"[!] Normalization failed: {e}")
            import traceback
            traceback.print_exc()
            
            return FingerprintSpec(
                app_name="Unknown Application",
                source_type='live_site',
                source_location=base_url,
                confidence_level='low',
                notes=f"Normalization failed: {e}",
                fingerprint_mode=self.mode,
                include_version=self.include_version
        )
