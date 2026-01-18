"""CLI argument parsing and configuration."""
import argparse
from dataclasses import dataclass, field
from typing import List, Optional
from pathlib import Path

# Import defaults from config - single source of truth
from config import Defaults


# =============================================================================
# Shared Argument Helpers (DRY - Don't Repeat Yourself)
# =============================================================================

def _add_phase2_args(parser_or_group) -> None:
    """Add Phase 2 (Discovery) arguments to a parser or argument group.
    
    Shared between 'discover' and 'run' subcommands.
    """
    parser_or_group.add_argument(
        "--max-queries",
        metavar="N",
        type=int,
        default=10,
        help="Maximum discovery queries to generate from fingerprint (default: 10)"
    )
    parser_or_group.add_argument(
        "--max-candidates",
        metavar="N",
        type=int,
        default=None,
        help="Maximum candidates after deduplication (default: no limit)"
    )
    parser_or_group.add_argument(
        "--cache-strategy",
        choices=["cache_only", "new_only", "cache_and_new"],
        default="cache_and_new",
        help="Cache strategy (default: cache_and_new)"
    )
    parser_or_group.add_argument(
        "--cache-ttl",
        metavar="DAYS",
        type=int,
        default=Defaults.CACHE_TTL_DAYS,
        help=f"Cache TTL in days (default: {Defaults.CACHE_TTL_DAYS})"
    )
    parser_or_group.add_argument(
        "--skip-enrichment",
        action="store_true",
        help="Skip IPInfo enrichment"
    )
    parser_or_group.add_argument(
        "--enrich-workers",
        metavar="N",
        type=int,
        default=Defaults.ENRICH_WORKERS,
        help=f"Concurrent enrichment workers (default: {Defaults.ENRICH_WORKERS})"
    )
    parser_or_group.add_argument(
        "--plugins",
        metavar="NAMES",
        type=str,
        default=None,
        help="Discovery plugins to use (comma-separated, e.g. shodan,censys)"
    )


def _add_phase3_args(parser_or_group) -> None:
    """Add Phase 3 (Verification) arguments to a parser or argument group.
    
    Shared between 'verify' and 'run' subcommands.
    """
    parser_or_group.add_argument(
        "--verify-workers", "-w",
        metavar="N",
        type=int,
        default=Defaults.VERIFY_WORKERS,
        dest="verify_workers",
        help=f"Concurrent verification workers (default: {Defaults.VERIFY_WORKERS})"
    )
    parser_or_group.add_argument(
        "--verify-timeout", "-t",
        metavar="SECONDS",
        type=int,
        default=Defaults.VERIFY_TIMEOUT,
        dest="verify_timeout",
        help=f"Timeout per verification request (default: {Defaults.VERIFY_TIMEOUT})"
    )
    parser_or_group.add_argument(
        "--skip-tls",
        action="store_true",
        help="Skip TLS certificate fetching"
    )
    parser_or_group.add_argument(
        "--skip-tcp-check",
        action="store_true",
        help="Skip TCP liveness check before probing (not recommended)"
    )
    parser_or_group.add_argument(
        "--weights",
        metavar="WEIGHTS",
        type=str,
        default=None,
        help="Custom probe weights (e.g., 'favicon:80,image:50,title:15,body:15' or '1:80,2:50' by order)"
    )
    parser_or_group.add_argument(
        "--interactive-weights",
        action="store_true",
        help="Interactively set probe weights before verification"
    )


# =============================================================================
# Configuration Dataclasses
# =============================================================================


@dataclass
class Phase1Config:
    """Phase 1 (Fingerprinting) configuration."""
    live_site: Optional[str] = None
    github_repo: Optional[str] = None
    fingerprint_file: Optional[Path] = None  # Use existing fingerprint (skip Phase 1)
    output_path: Optional[Path] = None
    max_iterations: int = Defaults.MAX_ITERATIONS
    mode: str = "application"  # application or organization
    include_version: bool = False  # Include version/year in fingerprints
    
    @property
    def skip_phase1(self) -> bool:
        """Return True if Phase 1 should be skipped (using existing fingerprint)."""
        return self.fingerprint_file is not None
    
    @property
    def source_type(self) -> str:
        """Return the source type: 'live_site', 'github_repo', or 'fingerprint_file'."""
        if self.fingerprint_file:
            return "fingerprint_file"
        return "github_repo" if self.github_repo else "live_site"
    
    @property
    def source(self) -> str:
        """Return the source URL or file path."""
        if self.fingerprint_file:
            return str(self.fingerprint_file)
        return self.github_repo if self.github_repo else self.live_site


@dataclass
class Phase2Config:
    """Phase 2 (Discovery) configuration."""
    enabled: bool = True
    cache_strategy: str = "cache_and_new"
    cache_ttl_days: int = Defaults.CACHE_TTL_DAYS
    max_queries: int = 10  # Maximum queries to generate from fingerprint
    max_candidates: Optional[int] = None
    enrich: bool = True
    enrich_workers: int = Defaults.ENRICH_WORKERS
    plugins: Optional[List[str]] = None  # List of plugin names to use


@dataclass
class Phase3Config:
    """Phase 3 (Verification) configuration."""
    enabled: bool = True
    workers: int = Defaults.VERIFY_WORKERS
    timeout: int = Defaults.VERIFY_TIMEOUT
    fetch_tls: bool = True
    tcp_check: bool = True  # Quick TCP liveness check before probing
    weights: Optional[str] = None  # Custom weights string
    interactive_weights: bool = False  # Interactive weight editor


@dataclass
class ExportConfig:
    """Export configuration."""
    formats: List[str] = field(default_factory=list)
    output_dir: Path = field(default_factory=lambda: Path("output/exports"))
    min_score: float = 0.0
    include_all: bool = True


@dataclass
class SigIntConfig:
    """Complete SigInt configuration."""
    phase1: Phase1Config
    phase2: Phase2Config = field(default_factory=Phase2Config)
    phase3: Phase3Config = field(default_factory=Phase3Config)
    export: ExportConfig = field(default_factory=ExportConfig)
    verbose: bool = False
    interactive: bool = False  # Prompt user between phases
    
    @classmethod
    def from_args(cls, args: argparse.Namespace) -> "SigIntConfig":
        """Create config from parsed arguments."""
        # Phase 1
        fingerprint_file = getattr(args, 'fingerprint', None)
        phase1 = Phase1Config(
            live_site=getattr(args, 'live_site', None),
            github_repo=getattr(args, 'github', None),
            fingerprint_file=Path(fingerprint_file) if fingerprint_file else None,
            output_path=Path(args.output) if args.output else None,
            max_iterations=args.max_iterations,
            mode=getattr(args, 'mode', 'application'),
            include_version=getattr(args, 'include_version', False)
        )
        
        # Phase 2
        # Parse plugins from comma-separated string
        plugins_list = None
        if getattr(args, 'plugins', None):
            plugins_list = [p.strip() for p in args.plugins.split(',') if p.strip()]
        
        phase2 = Phase2Config(
            enabled=not args.skip_phase_2,
            cache_strategy=args.cache_strategy,
            cache_ttl_days=args.cache_ttl,
            max_queries=args.max_queries,
            max_candidates=args.max_candidates,
            enrich=not args.skip_enrichment,
            enrich_workers=args.enrich_workers,
            plugins=plugins_list
        )
        
        # Phase 3
        phase3 = Phase3Config(
            enabled=not args.skip_phase_3,
            workers=args.verify_workers,
            timeout=args.verify_timeout,
            fetch_tls=not args.skip_tls,
            tcp_check=not getattr(args, 'skip_tcp_check', False),
            weights=getattr(args, 'weights', None),
            interactive_weights=getattr(args, 'interactive_weights', False)
        )
        
        # Export
        export_formats = []
        if args.export:
            export_formats = [f.strip().lower() for f in args.export.split(",")]
            export_formats = [f for f in export_formats if f in ("csv", "json", "html")]
        
        export = ExportConfig(
            formats=export_formats,
            output_dir=Path(args.export_dir),
            min_score=args.export_min_score
        )
        
        return cls(
            phase1=phase1,
            phase2=phase2,
            phase3=phase3,
            export=export,
            verbose=args.verbose,
            interactive=getattr(args, 'interactive', False)
        )


# ============================================================================
# Subcommand Parsers
# ============================================================================

def _add_fingerprint_parser(subparsers) -> None:
    """Add 'fingerprint' subcommand."""
    parser = subparsers.add_parser(
        "fingerprint",
        help="Phase 1: Generate fingerprint from live site or GitHub repo",
        description="Analyze a live website or GitHub repository and generate a unique fingerprint.",
        epilog="""
Examples:
  # Fingerprint a live website
  sigint fingerprint --live-site https://example.com
  sigint fingerprint --live-site https://example.com --mode application
  
  # Fingerprint a GitHub repository  
  sigint fingerprint --github https://github.com/OWASP/juice-shop
  sigint fingerprint --github https://github.com/user/repo --mode application
        """
    )
    
    # Source options (mutually exclusive) - same as 'run' command
    source_group = parser.add_argument_group("source (one required)")
    source_mutex = source_group.add_mutually_exclusive_group(required=True)
    source_mutex.add_argument(
        "--live-site", "-l",
        metavar="URL",
        dest="live_site",
        help="Live website URL to fingerprint"
    )
    source_mutex.add_argument(
        "--github", "-g",
        metavar="REPO_URL",
        help="GitHub repository URL (e.g., https://github.com/user/repo)"
    )
    
    parser.add_argument(
        "-o", "--output",
        metavar="PATH",
        help="Output JSON file path (default: output/fingerprints/<app>_<run_id>.json)"
    )
    parser.add_argument(
        "-i", "--max-iterations",
        metavar="N",
        type=int,
        default=3,
        help="Maximum discovery iterations for live site (default: 3)"
    )
    parser.add_argument(
        "-m", "--mode",
        choices=["application", "organization"],
        default="application",
        help="Fingerprint mode: 'application' (software deployments, version-agnostic) or 'organization' (company assets, brand-focused)"
    )
    parser.add_argument(
        "--include-version",
        action="store_true",
        help="Include version/year in fingerprint patterns (default: exclude)"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    parser.set_defaults(command="fingerprint")


def _add_discover_parser(subparsers) -> None:
    """Add 'discover' subcommand."""
    parser = subparsers.add_parser(
        "discover",
        help="Phase 2: Discover candidates from fingerprint",
        description="Discover candidates from services like Shodan/Censys for hosts matching a fingerprint."
    )
    parser.add_argument(
        "fingerprint_file",
        metavar="FINGERPRINT",
        help="Path to fingerprint JSON file"
    )
    parser.add_argument(
        "-o", "--output",
        metavar="PATH",
        help="Output JSON file path (default: output/candidates/<app>_<run_id>_candidates.json)"
    )
    
    # Add shared Phase 2 arguments
    _add_phase2_args(parser)
    
    parser.add_argument(
        "--list-plugins",
        action="store_true",
        help="List available discovery plugins and exit"
    )
    # Export options
    parser.add_argument(
        "--export",
        metavar="FORMATS",
        type=str,
        default=None,
        help="Export candidate list: json,csv,html (comma-separated)"
    )
    parser.add_argument(
        "--export-dir",
        metavar="PATH",
        type=str,
        default="output/exports",
        help="Export output directory (default: output/exports)"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    parser.add_argument(
        "-i", "--interactive",
        action="store_true",
        help="Interactive mode - review and approve/modify each query before execution"
    )
    parser.set_defaults(command="discover")


def _add_verify_parser(subparsers) -> None:
    """Add 'verify' subcommand."""
    parser = subparsers.add_parser(
        "verify",
        help="Phase 3: Verify candidates against fingerprint",
        description="Actively probe candidates to verify they match the fingerprint."
    )
    parser.add_argument(
        "fingerprint_file",
        metavar="FINGERPRINT",
        help="Path to fingerprint JSON file"
    )
    parser.add_argument(
        "candidates_file",
        metavar="CANDIDATES",
        help="Path to candidates JSON file"
    )
    parser.add_argument(
        "-w", "--workers", "--verify-workers",
        metavar="N",
        type=int,
        default=Defaults.VERIFY_WORKERS,
        dest="workers",
        help=f"Concurrent verification workers (default: {Defaults.VERIFY_WORKERS})"
    )
    parser.add_argument(
        "-t", "--timeout", "--verify-timeout",
        metavar="SECONDS",
        type=int,
        default=Defaults.VERIFY_TIMEOUT,
        dest="timeout",
        help=f"Timeout per request (default: {Defaults.VERIFY_TIMEOUT})"
    )
    parser.add_argument(
        "--skip-tls",
        action="store_true",
        help="Skip TLS certificate fetching"
    )
    parser.add_argument(
        "--skip-tcp-check",
        action="store_true",
        help="Skip TCP liveness check before probing (not recommended)"
    )
    parser.add_argument(
        "--weights",
        metavar="WEIGHTS",
        type=str,
        default=None,
        help="Custom probe weights (e.g., 'favicon:80,image:50,title:15,body:15')"
    )
    parser.add_argument(
        "--interactive-weights",
        action="store_true",
        help="Interactively set probe weights before verification"
    )
    # Export options
    parser.add_argument(
        "--export",
        metavar="FORMATS",
        type=str,
        default=None,
        help="Export formats: json,csv,html (comma-separated). Uses config default if not specified."
    )
    parser.add_argument(
        "--export-dir",
        metavar="PATH",
        type=str,
        default=None,
        help="Export output directory (default: from config)"
    )
    parser.add_argument(
        "--min-score", "--export-min-score",
        metavar="N",
        type=float,
        default=0.0,
        dest="min_score",
        help="Minimum score for export (default: 0)"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    parser.set_defaults(command="verify")


def _add_export_parser(subparsers) -> None:
    """Add 'export' subcommand."""
    parser = subparsers.add_parser(
        "export",
        help="Export verification results",
        description="Export verification results to CSV, JSON, or HTML formats."
    )
    parser.add_argument(
        "report_file",
        metavar="REPORT",
        help="Path to verified results JSON file"
    )
    parser.add_argument(
        "formats",
        metavar="FORMATS",
        help="Export formats: csv,json,html (comma-separated)"
    )
    parser.add_argument(
        "-o", "--output-dir",
        metavar="PATH",
        default="output/exports",
        help="Export output directory (default: output/exports)"
    )
    parser.add_argument(
        "--min-score",
        metavar="N",
        type=float,
        default=0.0,
        help="Minimum score for export (0-100, default: 0)"
    )
    parser.set_defaults(command="export")


def _add_run_parser(subparsers) -> None:
    """Add 'run' subcommand (complete pipeline)."""
    parser = subparsers.add_parser(
        "run",
        help="Run complete pipeline (Phase 1 + 2 + 3)",
        description="Run the complete SigInt pipeline from fingerprinting to verification."
    )
    
    # Phase 1 options
    phase1_group = parser.add_argument_group("Phase 1 - Fingerprinting")
    source_group = phase1_group.add_mutually_exclusive_group(required=True)
    source_group.add_argument(
        "--live-site",
        metavar="URL",
        help="Live website URL to fingerprint"
    )
    source_group.add_argument(
        "--github",
        metavar="REPO_URL",
        help="GitHub repository URL to fingerprint"
    )
    source_group.add_argument(
        "--fingerprint",
        metavar="FILE",
        help="Use existing fingerprint file (skip Phase 1)"
    )
    phase1_group.add_argument(
        "--output",
        metavar="PATH",
        default=None,
        help="Output JSON file path"
    )
    phase1_group.add_argument(
        "--max-iterations",
        metavar="N",
        type=int,
        default=3,
        help="Maximum discovery iterations for live site (default: 3)"
    )
    phase1_group.add_argument(
        "--mode",
        choices=["application", "organization"],
        default="application",
        help="Fingerprint mode: 'application' (software, version-agnostic) or 'organization' (company, brand-focused)"
    )
    phase1_group.add_argument(
        "--include-version",
        action="store_true",
        help="Include version/year in fingerprint patterns"
    )
    
    # Phase 2 options (using shared helper)
    phase2_group = parser.add_argument_group("Phase 2 - Discovery")
    phase2_group.add_argument(
        "--skip-phase-2",
        action="store_true",
        help="Skip Phase 2 discovery"
    )
    _add_phase2_args(phase2_group)  # Shared arguments
    
    # Phase 3 options (using shared helper)
    phase3_group = parser.add_argument_group("Phase 3 - Verification")
    phase3_group.add_argument(
        "--skip-phase-3",
        action="store_true",
        help="Skip Phase 3 verification"
    )
    _add_phase3_args(phase3_group)  # Shared arguments
    
    # Export options
    export_group = parser.add_argument_group("Export")
    export_group.add_argument(
        "--export",
        metavar="FORMATS",
        type=str,
        default=None,
        help="Export formats: csv,json,html (comma-separated)"
    )
    export_group.add_argument(
        "--export-dir",
        metavar="PATH",
        type=str,
        default="output/exports",
        help="Export output directory (default: output/exports)"
    )
    export_group.add_argument(
        "--export-min-score",
        metavar="N",
        type=float,
        default=0.0,
        help="Minimum score for export (default: 0)"
    )
    
    # General options
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    parser.add_argument(
        "-i", "--interactive",
        action="store_true",
        help="Interactive mode - prompt before each phase to continue or exit"
    )
    
    parser.set_defaults(command="run")


# ============================================================================
# Main Parser
# ============================================================================

def _add_config_parser(subparsers) -> None:
    """Add 'config' subcommand for configuration management."""
    parser = subparsers.add_parser(
        "config",
        help="Manage configuration",
        description="Generate or show configuration file."
    )
    parser.add_argument(
        "action",
        choices=["init", "show", "path"],
        nargs="?",
        default="show",
        help="Action: init (create config file), show (display current config), path (show config file location)"
    )
    parser.add_argument(
        "-o", "--output",
        metavar="PATH",
        type=str,
        default="./sigint.yaml",
        help="Output path for config file (default: ./sigint.yaml)"
    )
    parser.set_defaults(command="config")


def create_parser() -> argparse.ArgumentParser:
    """Create the main argument parser with subcommands."""
    parser = argparse.ArgumentParser(
        prog="sigint",
        description="SigInt - LLM-Driven Web Application Intelligence Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Subcommands:
  fingerprint   Phase 1: Generate fingerprint from live site or GitHub repo
  discover      Phase 2: Discover candidates from fingerprint  
  verify        Phase 3: Verify candidates against fingerprint
  export        Export verification results
  run           Run complete pipeline (all phases)
  config        Manage configuration file

Examples:
  # Generate default config file
  sigint config init
  
  # Phase 1: Fingerprint a live site
  sigint fingerprint --live-site https://example.com
  sigint fingerprint -l https://example.com --mode application
  
  # Phase 1: Fingerprint a GitHub repo
  sigint fingerprint --github https://github.com/user/repo
  sigint fingerprint -g https://github.com/OWASP/juice-shop --mode application
  
  # Phase 2: Discover candidates
  sigint discover fingerprint.json --plugins shodan,censys
  sigint discover fingerprint.json --export csv,html
  
  # Phase 3: Verify candidates
  sigint verify fingerprint.json candidates.json -w 30 --export csv,html
  
  # Export to multiple formats
  sigint export verified_results.json csv,html
  
  # Run complete pipeline
  sigint run --live-site https://example.com --export csv,html
  sigint run --github https://github.com/user/repo --plugins shodan,censys
  sigint run --fingerprint fingerprint.json --export csv,html
  sigint run --live-site https://example.com -i  # interactive mode
        """
    )
    
    subparsers = parser.add_subparsers(
        title="commands",
        dest="command",
        metavar="<command>"
    )
    
    _add_fingerprint_parser(subparsers)
    _add_discover_parser(subparsers)
    _add_verify_parser(subparsers)
    _add_export_parser(subparsers)
    _add_run_parser(subparsers)
    _add_config_parser(subparsers)
    
    return parser


def parse_args() -> argparse.Namespace:
    """Parse command line arguments.
    
    Returns:
        Parsed arguments namespace
    """
    parser = create_parser()
    args = parser.parse_args()
    
    # If no command specified, show help
    if not args.command:
        parser.print_help()
        raise SystemExit(0)
    
    return args
