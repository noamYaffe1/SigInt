"""Debug utilities for SigInt."""
import os


def is_debug_mode() -> bool:
    """Check if debug mode is enabled.
    
    Debug mode is enabled if:
    - SIGINT_DEBUG environment variable is set to "1", "true", or "yes"
    
    Returns:
        True if debug mode is enabled
    """
    return os.environ.get("SIGINT_DEBUG", "").lower() in ("1", "true", "yes")


def debug_print(message: str) -> None:
    """Print message only if debug mode is enabled.
    
    Args:
        message: Message to print
    """
    if is_debug_mode():
        print(message)

