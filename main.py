#!/usr/bin/env python3
"""SigInt - LLM-Driven Web Application Intelligence Pipeline.

This is the main entry point for the SigInt tool.

Usage:
    sigint fingerprint <url>              # Phase 1: Generate fingerprint
    sigint discover <fingerprint.json>    # Phase 2: Discover candidates
    sigint verify <fp.json> <cand.json>   # Phase 3: Verify candidates
    sigint export <verified.json> <fmt>   # Export results
    sigint run --live-site <url>          # Run complete pipeline
    sigint config init                    # Create default config file
    sigint config show                    # Show current configuration
"""
import os
import sys
import logging
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


def configure_logging(verbose: bool = False):
    """Configure logging based on verbosity.
    
    Args:
        verbose: If True, enable debug logging for sigint modules
    """
    # Set log level based on verbose flag or SIGINT_DEBUG env var
    debug_mode = verbose or os.environ.get("SIGINT_DEBUG", "").lower() in ("1", "true", "yes")
    
    # Set SIGINT_DEBUG env var so debug_print utility works
    if debug_mode:
        os.environ["SIGINT_DEBUG"] = "1"
    
    level = logging.DEBUG if debug_mode else logging.WARNING
    
    # Configure sigint loggers
    for logger_name in ["sigint.shodan", "sigint.censys", "sigint.github", 
                        "sigint.fetcher", "sigint.probes", "sigint.ipinfo"]:
        logger = logging.getLogger(logger_name)
        logger.setLevel(level)
        if not logger.handlers:
            handler = logging.StreamHandler()
            handler.setFormatter(logging.Formatter("%(message)s"))
            logger.addHandler(handler)


def main():
    """Main entry point - routes to subcommands."""
    from cli.args import parse_args
    from cli.commands import (
        cmd_fingerprint,
        cmd_discover,
        cmd_verify,
        cmd_export,
        cmd_run,
        cmd_config
    )
    
    # Command router
    commands = {
        "fingerprint": cmd_fingerprint,
        "discover": cmd_discover,
        "verify": cmd_verify,
        "export": cmd_export,
        "run": cmd_run,
        "config": cmd_config,
    }
    
    # Parse arguments
    args = parse_args()
    
    # Configure logging based on verbose flag
    verbose = getattr(args, 'verbose', False)
    configure_logging(verbose)
    
    # Route to appropriate command
    handler = commands.get(args.command)
    if handler:
        exit_code = handler(args)
        sys.exit(exit_code)
    else:
        print(f"Unknown command: {args.command}")
        sys.exit(1)


if __name__ == "__main__":
    main()
