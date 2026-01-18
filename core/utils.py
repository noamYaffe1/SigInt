"""Utility functions for hashing, content processing, and common patterns."""
import hashlib
import mmh3
import base64
from datetime import datetime, timezone
from io import BytesIO
from PIL import Image
import imagehash


def utc_now_iso() -> str:
    """Get current UTC timestamp in ISO 8601 format with Z suffix.
    
    Returns:
        ISO formatted timestamp (e.g., "2025-12-06T12:30:00.123456Z")
    """
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def calculate_hashes(content: bytes) -> dict:
    """Calculate multiple hash types for content.
    
    Args:
        content: Raw bytes to hash
        
    Returns:
        Dictionary with sha256, md5, and mmh3 hashes
    """
    hashes = {
        "sha256": hashlib.sha256(content).hexdigest(),
        "md5": hashlib.md5(content).hexdigest(),
        "mmh3": str(mmh3.hash(content))
    }
    return hashes


def calculate_image_hashes(image_content: bytes) -> dict:
    """Calculate hashes for image content including perceptual hash.
    
    Args:
        image_content: Raw image bytes
        
    Returns:
        Dictionary with sha256, md5, mmh3, and phash
    """
    hashes = calculate_hashes(image_content)
    
    # Add perceptual hash for images
    try:
        img = Image.open(BytesIO(image_content))
        hashes["phash"] = str(imagehash.phash(img))
    except Exception as e:
        print(f"Warning: Could not calculate perceptual hash: {e}")
        hashes["phash"] = None
    
    return hashes


def calculate_favicon_mmh3(content: bytes) -> str:
    """Calculate Shodan-style favicon hash (base64 encoded MMH3).
    
    This matches the format used by Shodan's http.favicon.hash field.
    
    Args:
        content: Raw favicon bytes
        
    Returns:
        Base64-encoded MurmurHash3 hash as string
    """
    # Shodan uses base64 encoding, then calculates MMH3 hash
    b64_content = base64.encodebytes(content)
    favicon_hash = mmh3.hash(b64_content)
    return str(favicon_hash)