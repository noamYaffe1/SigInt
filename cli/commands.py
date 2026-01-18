"""CLI subcommand implementations."""
import json
from pathlib import Path

from core.models import FingerprintOutput
from core.formatting import get_app_slug, print_fingerprint_summary
from core.utils import utc_now_iso
from discover.models import CandidateHost
from verify.models import VerificationReport


def cmd_fingerprint(args) -> int:
    """Run Phase 1: Fingerprinting only.
    
    Args:
        args: Parsed arguments with live_site or github, output, max_iterations
        
    Returns:
        Exit code (0 = success)
    """
    # Check if using GitHub repo fingerprinting
    if getattr(args, 'github', None):
        return _fingerprint_github(args)
    else:
        return _fingerprint_live_site(args)


def _fingerprint_live_site(args) -> int:
    """Fingerprint a live website using LLM-driven analysis."""
    from fingerprint.engine import LLMFingerprintEngine
    
    mode = getattr(args, 'mode', 'application')
    include_version = getattr(args, 'include_version', False)
    
    print("\n" + "=" * 70)
    print("SigInt Phase 1 - LLM-Driven Recursive Fingerprinting")
    print("=" * 70)
    print(f"[*] Mode: {mode} {'(include version)' if include_version else '(version-agnostic)'}")
    
    engine = LLMFingerprintEngine()
    output = engine.fingerprint_live_site(
        url=args.live_site,
        max_iterations=args.max_iterations,
        mode=mode,
        include_version=include_version
    )
    
    # Determine output path
    if args.output:
        output_path = Path(args.output)
    else:
        app_slug = get_app_slug(output.fingerprint_spec.app_name)
        run_id = output.fingerprint_spec.run_id
        output_path = Path("output/fingerprints") / f"{app_slug}_{run_id}.json"
    
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output.model_dump(), f, indent=2)
    
    spec = output.fingerprint_spec
    plan = output.probe_plan
    print_fingerprint_summary(
        run_id=spec.run_id,
        created_at=spec.created_at,
        app_name=spec.app_name,
        source=spec.source_location,
        confidence=spec.confidence_level,
        favicon=bool(spec.favicon),
        key_images_count=len(spec.key_images),
        page_signatures_count=len(spec.page_signatures),
        probe_steps_count=len(plan.probe_steps),
        min_matches=plan.minimum_matches_required,
        distinctive_features=spec.distinctive_features,
        fingerprint_mode=spec.fingerprint_mode,
    )
    print(f"\n[✓] Fingerprint saved to: {output_path}")
    
    return 0


def _fingerprint_github(args) -> int:
    """Fingerprint a GitHub repository by analyzing static assets and structure."""
    from fingerprint.github_analyzer import GitHubAnalyzer
    
    mode = getattr(args, 'mode', 'application')
    include_version = getattr(args, 'include_version', False)
    
    analyzer = GitHubAnalyzer()
    output = analyzer.analyze_repo(
        args.github,
        mode=mode,
        include_version=include_version
    )
    
    # Determine output path
    if args.output:
        output_path = Path(args.output)
    else:
        app_slug = get_app_slug(output.fingerprint_spec.app_name)
        run_id = output.fingerprint_spec.run_id
        output_path = Path("output/fingerprints") / f"{app_slug}_{run_id}.json"
    
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output.model_dump(), f, indent=2)
    
    print(f"\n[✓] Fingerprint saved to: {output_path}")
    print(f"[*] Use this fingerprint with 'sigint discover' to find instances")
    
    return 0


def cmd_discover(args) -> int:
    """Run Phase 2: Discovery from existing fingerprint.
    
    Args:
        args: Parsed arguments with fingerprint_file, options
        
    Returns:
        Exit code (0 = success)
    """
    from discover.engine import PassiveDiscovery
    
    # Handle --list-plugins flag
    if getattr(args, 'list_plugins', False):
        from discover.plugin_adapter import init_plugins, list_plugins, get_configured_plugins
        init_plugins()
        
        print("\n" + "=" * 70)
        print("Available Discovery Plugins")
        print("=" * 70)
        
        configured = [p.name for p in get_configured_plugins()]
        
        for name, info in list_plugins().items():
            status = "✓ configured" if name in configured else "✗ not configured"
            print(f"\n  {name} ({status})")
            print(f"    {info['description']}")
            print(f"    Query types: {', '.join(info['supported_query_types'])}")
        
        print("\n" + "=" * 70)
        print("To configure a plugin, set its environment variables in .env")
        print("=" * 70 + "\n")
        return 0
    
    # Load fingerprint
    fingerprint_path = Path(args.fingerprint_file)
    if not fingerprint_path.exists():
        print(f"[ERROR] Fingerprint file not found: {fingerprint_path}")
        return 1
    
    with open(fingerprint_path) as f:
        data = json.load(f)
    
    fingerprint = FingerprintOutput.model_validate(data)
    
    print("\n" + "=" * 70)
    print("SigInt Phase 2 - Passive Discovery")
    print("=" * 70)
    print(f"[*] Fingerprint: {fingerprint_path}")
    spec = fingerprint.fingerprint_spec
    target_label = "Organization" if getattr(spec, 'fingerprint_mode', 'application') == 'organization' else "Application"
    print(f"[*] {target_label}: {spec.app_name}")
    
    # Parse plugins if specified
    plugin_names = None
    if getattr(args, 'plugins', None):
        plugin_names = [p.strip() for p in args.plugins.split(',')]
    
    print(f"\n[*] Searching for similar instances...")
    print(f"    Max candidates: {args.max_candidates or 'unlimited'}")
    print(f"    Cache strategy: {args.cache_strategy}")
    
    discovery = PassiveDiscovery(
        cache_dir="output/cache",
        cache_ttl_days=args.cache_ttl,
        plugin_names=plugin_names
    )
    
    candidates = discovery.discover(
        fingerprint=fingerprint.fingerprint_spec,
        max_results=args.max_candidates,
        max_queries=args.max_queries,
        cache_strategy=args.cache_strategy,
        plugins=plugin_names,
        enrich=not args.skip_enrichment,
        enrich_workers=args.enrich_workers,
        interactive=getattr(args, 'interactive', False)
    )
    
    # Save candidates
    if args.output:
        output_path = Path(args.output)
    else:
        app_slug = get_app_slug(fingerprint.fingerprint_spec.app_name)
        run_id = fingerprint.fingerprint_spec.run_id
        output_path = Path("output/candidates") / f"{app_slug}_{run_id}_candidates.json"
    
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Calculate geographic distribution
    geo_dist = {}
    for candidate in candidates:
        country = candidate.location.get("country", "Unknown") if candidate.location else "Unknown"
        geo_dist[country] = geo_dist.get(country, 0) + 1
    
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump({
            "fingerprint_run_id": fingerprint.fingerprint_spec.run_id,
            "discovery_timestamp": utc_now_iso(),
            "total_candidates": len(candidates),
            "geographic_distribution": dict(sorted(geo_dist.items(), key=lambda x: -x[1])),
            "candidates": [c.model_dump() for c in candidates]
        }, f, indent=2)
    
    print(f"\n[✓] Found {len(candidates)} candidates")
    print(f"[✓] Saved to: {output_path}")
    
    if geo_dist:
        print(f"\nGeographic distribution:")
        for country, count in sorted(geo_dist.items(), key=lambda x: -x[1])[:10]:
            print(f"  {country}: {count}")
    
    # Export candidates if requested
    export_formats = []
    if getattr(args, 'export', None):
        export_formats = [f.strip().lower() for f in args.export.split(",")]
        export_formats = [f for f in export_formats if f in ("csv", "json", "html")]
    
    if export_formats:
        from export.candidates_exporter import export_candidates
        
        app_slug = get_app_slug(fingerprint.fingerprint_spec.app_name)
        run_id = fingerprint.fingerprint_spec.run_id
        export_dir = Path(getattr(args, 'export_dir', 'output/exports'))
        
        exported = export_candidates(
            candidates=candidates,
            formats=export_formats,
            output_dir=export_dir,
            base_name=f"{app_slug}_{run_id}_candidates",
            geo_distribution=geo_dist
        )
        
        if exported:
            print(f"\n[✓] Exported {len(exported)} file(s):")
            for path in exported:
                print(f"    - {path}")
    
    print("=" * 70)
    print("[✓] Phase 2 Complete!")
    print("=" * 70)
    
    return 0


def cmd_verify(args) -> int:
    """Run Phase 3: Verification from fingerprint + candidates.
    
    Args:
        args: Parsed arguments with fingerprint_file, candidates_file, options
        
    Returns:
        Exit code (0 = success)
    """
    from verify.engine import VerificationEngine
    
    # Load fingerprint
    fingerprint_path = Path(args.fingerprint_file)
    if not fingerprint_path.exists():
        print(f"[ERROR] Fingerprint file not found: {fingerprint_path}")
        return 1
    
    with open(fingerprint_path) as f:
        fingerprint = FingerprintOutput.model_validate(json.load(f))
    
    # Load candidates
    candidates_path = Path(args.candidates_file)
    if not candidates_path.exists():
        print(f"[ERROR] Candidates file not found: {candidates_path}")
        return 1
    
    with open(candidates_path) as f:
        data = json.load(f)
    
    candidates = [CandidateHost.model_validate(c) for c in data.get("candidates", [])]
    
    if not candidates:
        print("[ERROR] No candidates found in file")
        return 1
    
    print("\n" + "=" * 70)
    print("SigInt Phase 3 - Active Verification")
    print("=" * 70)
    print(f"[*] Fingerprint: {fingerprint_path}")
    print(f"[*] Candidates: {candidates_path} ({len(candidates)} hosts)")
    
    # Apply custom weights if specified
    from core.weights import parse_weights_string, apply_weights_to_plan, interactive_weight_editor, print_probe_weights
    from config import get_settings
    
    # Load settings from config file
    settings = get_settings()
    
    # Apply default weights from config (favicon:80, image:50, title:15, body:15)
    config_defaults = settings.get_probe_points_dict()
    fingerprint.probe_plan.apply_default_weights(config_defaults)
    
    if getattr(args, 'interactive_weights', False):
        # Show defaults, then let user customize
        fingerprint.probe_plan = interactive_weight_editor(fingerprint.probe_plan)
    elif getattr(args, 'weights', None):
        # Override with user-specified weights
        weights = parse_weights_string(args.weights)
        apply_weights_to_plan(fingerprint.probe_plan, weights)
        print_probe_weights(fingerprint.probe_plan)
    
    verifier = VerificationEngine(
        timeout=args.timeout,
        max_workers=args.workers,
        fetch_tls=not args.skip_tls,
        tcp_check=not getattr(args, 'skip_tcp_check', False)
    )
    
    report = verifier.verify_candidates(
        fingerprint=fingerprint,
        candidates=candidates,
        show_progress=True
    )
    
    # Determine export formats: CLI arg > config file > none
    export_formats = []
    if getattr(args, 'export', None):
        export_formats = [f.strip().lower() for f in args.export.split(",")]
    elif settings.export.default_formats:
        export_formats = settings.export.default_formats
    
    # Export results if formats specified
    if export_formats:
        from export.engine import export_report
        from verify.models import VerificationReport
        
        # Convert to VerificationReport if needed
        app_slug = get_app_slug(fingerprint.fingerprint_spec.app_name)
        run_id = fingerprint.fingerprint_spec.run_id
        
        output_dir = Path(getattr(args, 'export_dir', None) or settings.export.output_dir)
        min_score = getattr(args, 'min_score', settings.export.min_score)
        
        exported = export_report(
            report=report,
            formats=export_formats,
            output_dir=output_dir,
            base_name=f"{app_slug}_{run_id}",
            include_all=True,
            min_score=min_score
        )
        
        print(f"\n[✓] Exported {len(exported)} file(s):")
        for path in exported:
            print(f"    - {path}")
    else:
        print("\n[!] No export formats specified. Use --export or set default_formats in config.")
        print("    Example: --export json,csv,html")
    
    print("\n" + "=" * 70)
    print("[✓] Phase 3 Complete!")
    print("=" * 70)
    
    return 0


def cmd_export(args) -> int:
    """Export verification results to various formats.
    
    Args:
        args: Parsed arguments with report_file, formats, options
        
    Returns:
        Exit code (0 = success)
    """
    from export.engine import export_report
    
    # Load verification report
    report_path = Path(args.report_file)
    if not report_path.exists():
        print(f"[ERROR] Report file not found: {report_path}")
        return 1
    
    with open(report_path) as f:
        data = json.load(f)
    
    report = VerificationReport.model_validate(data)
    
    # Parse formats
    formats = [f.strip().lower() for f in args.formats.split(",")]
    formats = [f for f in formats if f in ("csv", "json", "html")]
    
    if not formats:
        print("[ERROR] No valid formats specified. Use: csv, json, html")
        return 1
    
    print("\n" + "=" * 70)
    print("SigInt Export")
    print("=" * 70)
    print(f"[*] Report: {report_path}")
    print(f"[*] Formats: {', '.join(formats)}")
    
    app_slug = get_app_slug(report.app_name)
    base_name = f"{app_slug}_{report.fingerprint_run_id}"
    
    export_paths = export_report(
        report=report,
        formats=formats,
        output_dir=Path(args.output_dir),
        base_name=base_name,
        include_all=True,
        min_score=args.min_score
    )
    
    print("\n" + "=" * 70)
    print("[✓] Export Complete!")
    print("=" * 70)
    
    return 0


def cmd_run(args) -> int:
    """Run the complete pipeline (legacy mode).
    
    Args:
        args: Parsed arguments
        
    Returns:
        Exit code (0 = success)
    """
    from cli.args import SigIntConfig
    from pipeline.runner import PipelineRunner
    
    config = SigIntConfig.from_args(args)
    runner = PipelineRunner(config)
    result = runner.run()
    
    return 0 if result.success else 1


def cmd_config(args) -> int:
    """Manage configuration.
    
    Args:
        args: Parsed arguments with action (init, show, path)
        
    Returns:
        Exit code (0 = success)
    """
    from pathlib import Path
    from config.settings import (
        get_settings, 
        create_default_config_file, 
        find_config_file
    )
    
    action = getattr(args, 'action', 'show')
    
    if action == "init":
        # Create default config file
        output_path = Path(args.output)
        if output_path.exists():
            print(f"[!] Config file already exists: {output_path}")
            response = input("Overwrite? [y/N]: ").strip().lower()
            if response != 'y':
                print("Cancelled.")
                return 1
        
        created_path = create_default_config_file(output_path)
        print(f"\n[✓] Created config file: {created_path}")
        print("\nEdit this file to customize:")
        print("  - Probe points (favicon=80, image=50, title=15, body=15)")
        print("  - Score thresholds (verified=100, likely=70, partial=40)")
        print("  - Discovery settings (cache TTL, plugins)")
        print("  - Export defaults (formats, output directory)")
        print("\nAPI keys should be set via environment variables:")
        print("  export SHODAN_API_KEY='your-key'")
        print("  export CENSYS_PERSONAL_ACCESS_TOKEN='your-token'")
        print("  export OPENAI_API_KEY='your-key'")
        return 0
    
    elif action == "show":
        # Show current configuration
        settings = get_settings()
        
        print("\n" + "=" * 70)
        print("CURRENT CONFIGURATION")
        print("=" * 70)
        
        config_file = find_config_file()
        if config_file:
            print(f"Config file: {config_file}")
        else:
            print("Config file: None (using defaults)")
        
        print("\n[Probe Points - Additive Scoring]")
        print(f"  favicon_hash:   {settings.verification.probe_points.favicon_hash} pts")
        print(f"  image_hash:     {settings.verification.probe_points.image_hash} pts")
        print(f"  page_signature: {settings.verification.probe_points.page_signature} pts")
        
        print("\n[Score Thresholds]")
        print(f"  Verified: >= {settings.verification.score_thresholds.verified}")
        print(f"  Likely:   >= {settings.verification.score_thresholds.likely}")
        print(f"  Partial:  >= {settings.verification.score_thresholds.partial}")
        
        print("\n[Discovery]")
        print(f"  Cache TTL:     {settings.discovery.cache_ttl_days} days")
        print(f"  Cache strategy: {settings.discovery.cache_strategy}")
        print(f"  Plugins:       {', '.join(settings.discovery.enabled_plugins)}")
        
        print("\n[Verification]")
        print(f"  Workers:  {settings.verification.workers}")
        print(f"  Timeout:  {settings.verification.timeout}s")
        print(f"  Fetch TLS: {settings.verification.fetch_tls}")
        
        print("\n[Export]")
        print(f"  Formats:    {', '.join(settings.export.default_formats)}")
        print(f"  Output dir: {settings.export.output_dir}")
        
        print("\n[API Keys]")
        print(f"  OPENAI_API_KEY:              {'✓ Set' if settings.api.openai_api_key else '✗ Not set'}")
        print(f"  SHODAN_API_KEY:              {'✓ Set' if settings.api.shodan_api_key else '✗ Not set'}")
        print(f"  CENSYS_PERSONAL_ACCESS_TOKEN: {'✓ Set' if settings.api.censys_personal_access_token else '✗ Not set'}")
        print(f"  IPINFO_TOKEN:                {'✓ Set' if settings.api.ipinfo_token else '✗ Not set'}")
        
        print("=" * 70)
        return 0
    
    elif action == "path":
        # Show config file path
        config_file = find_config_file()
        if config_file:
            print(config_file)
        else:
            print("No config file found. Create one with: sigint config init")
        return 0
    
    return 1

