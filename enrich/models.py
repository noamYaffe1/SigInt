"""Data models for enrichment results."""
from typing import Optional, List
from pydantic import BaseModel, Field


class IPInfoResult(BaseModel):
    """Result from IPInfo API enrichment."""
    ip: str
    hostname: Optional[str] = None
    city: Optional[str] = None
    region: Optional[str] = None
    country: Optional[str] = None
    country_name: Optional[str] = None
    org: Optional[str] = None  # ASN + Org name (e.g., "AS16509 Amazon.com, Inc.")
    asn: Optional[str] = None  # Just the ASN number
    company: Optional[str] = None  # Company/organization name
    is_hosting: bool = False  # Is this a hosting/cloud provider?
    hosting_provider: Optional[str] = None  # AWS, GCP, Azure, DigitalOcean, etc.
    
    # Raw response fields
    loc: Optional[str] = None  # Lat,Lon
    postal: Optional[str] = None
    timezone: Optional[str] = None


class TLSInfo(BaseModel):
    """TLS/SSL certificate information.
    
    Certificate data is extracted even for invalid/self-signed/expired certs
    for attribution and enrichment purposes.
    """
    # Subject information (the entity the cert is issued TO)
    common_name: Optional[str] = None  # CN from certificate subject
    subject_org: Optional[str] = None  # Organization from subject (useful for attribution)
    
    # Issuer information (the CA that issued the cert)
    issuer: Optional[str] = None  # Certificate issuer CN
    issuer_org: Optional[str] = None  # Issuer organization
    
    # Validity dates
    valid_from: Optional[str] = None  # Not Before date (ISO format)
    valid_to: Optional[str] = None  # Not After date (ISO format)
    
    # Alternative names (domains/IPs the cert covers)
    san: List[str] = Field(default_factory=list)  # Subject Alternative Names
    email_addresses: List[str] = Field(default_factory=list)  # Email addresses from cert
    
    # Certificate identifiers
    serial_number: Optional[str] = None
    fingerprint_sha256: Optional[str] = None
    
    # Validity flags
    is_valid: bool = False  # Is certificate currently valid (not expired)?
    is_self_signed: bool = False  # Is the cert self-signed?
    
    # Error (only if fetch/parse failed)
    error: Optional[str] = None  # Error message if fetch failed


class IPInfoCache(BaseModel):
    """Cache entry for IPInfo results."""
    ip: str
    result: IPInfoResult
    cached_at: str  # ISO timestamp

