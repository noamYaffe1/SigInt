"""Shared formatting utilities."""
from typing import Optional


def get_app_slug(app_name: str) -> str:
    """Convert app name to filesystem-safe slug.
    
    Args:
        app_name: Application name (e.g., "Damn Vulnerable Web Application")
        
    Returns:
        Slug (e.g., "damn_vulnerable_web_application")
    """
    return "".join(c if c.isalnum() else "_" for c in app_name.lower())


def print_section_header(title: str, char: str = "=", width: int = 70) -> None:
    """Print a section header.
    
    Args:
        title: Title to print
        char: Character for the line (default: "=")
        width: Line width (default: 70)
    """
    print("\n" + char * width)
    print(title)
    print(char * width)


def print_fingerprint_summary(
    run_id: str,
    created_at: str,
    app_name: str,
    source: str,
    confidence: str,
    favicon: bool,
    key_images_count: int,
    page_signatures_count: int,
    probe_steps_count: int,
    min_matches: int,
    distinctive_features: Optional[list] = None,
    notes: Optional[str] = None,
    fingerprint_mode: Optional[str] = None
) -> None:
    """Print a standardized fingerprint summary.
    
    Args:
        All the fingerprint details to display
        fingerprint_mode: Optional mode ('application' or 'organization')
    """
    print("\n" + "=" * 70)
    print("FINGERPRINT SUMMARY")
    print("=" * 70)
    print(f"Run ID: {run_id}")
    print(f"Created: {created_at}")
    target_label = "Organization" if fingerprint_mode == "organization" else "Application"
    print(f"\n{target_label}: {app_name}")
    print(f"Source: {source}")
    print(f"Confidence: {confidence.upper()}")
    print(f"\nSignals collected:")
    print(f"  - Favicon: {'✓' if favicon else '✗'}")
    print(f"  - Key images: {key_images_count}")
    print(f"  - Page signatures: {page_signatures_count}")
    print(f"\nProbe plan: {probe_steps_count} steps")
    print(f"Minimum matches required: {min_matches}")
    
    if distinctive_features:
        print("\nDistinctive features:")
        for feature in distinctive_features[:5]:
            print(f"  • {feature}")
    
    if notes:
        print(f"\nNotes: {notes}")
    
    print("=" * 70)
    print("[✓] Phase 1 Complete!")
    print("=" * 70)

