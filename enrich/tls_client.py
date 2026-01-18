"""TLS/SSL certificate fetcher.

Fetches TLS certificates even from hosts with invalid/self-signed certs.
Uses the cryptography library to parse binary DER certificates.
"""
import ssl
import socket
import hashlib
from typing import Optional, List, Dict
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

from .models import TLSInfo

# Try to import cryptography for proper cert parsing
try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.x509.oid import NameOID, ExtensionOID
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


class TLSClient:
    """Client for fetching TLS/SSL certificates.
    
    Fetches certificate data regardless of validity (self-signed, expired, etc.)
    for attribution and enrichment purposes.
    """
    
    def __init__(self, timeout: int = 5):
        """Initialize TLS client.
        
        Args:
            timeout: Connection timeout in seconds
        """
        self.timeout = timeout
        if not CRYPTO_AVAILABLE:
            print("[WARNING] cryptography library not installed. TLS parsing may be limited.")
    
    def _extract_name_attribute(self, name: 'x509.Name', oid) -> Optional[str]:
        """Extract an attribute from X.509 Name by OID."""
        try:
            attrs = name.get_attributes_for_oid(oid)
            if attrs:
                return attrs[0].value
        except Exception:
            pass
        return None
    
    def _parse_san(self, cert: 'x509.Certificate') -> tuple:
        """Extract Subject Alternative Names and email addresses from certificate.
        
        Returns:
            Tuple of (san_list, email_list)
        """
        san = []
        emails = []
        try:
            ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            for name in ext.value:
                if isinstance(name, x509.DNSName):
                    san.append(name.value)
                elif isinstance(name, x509.IPAddress):
                    san.append(str(name.value))
                elif isinstance(name, x509.RFC822Name):
                    # Email addresses in SAN
                    emails.append(name.value)
        except x509.ExtensionNotFound:
            pass
        except Exception:
            pass
        
        # Also check subject for email
        try:
            email_attrs = cert.subject.get_attributes_for_oid(NameOID.EMAIL_ADDRESS)
            for attr in email_attrs:
                if attr.value and attr.value not in emails:
                    emails.append(attr.value)
        except Exception:
            pass
        
        return san, emails
    
    def _parse_binary_cert(self, cert_binary: bytes) -> TLSInfo:
        """Parse a binary DER certificate using cryptography library.
        
        This method extracts certificate data regardless of validity,
        which is useful for attribution and enrichment.
        """
        if not CRYPTO_AVAILABLE:
            return TLSInfo(error="cryptography library not installed")
        
        try:
            cert = x509.load_der_x509_certificate(cert_binary, default_backend())
            
            # Extract subject info
            subject = cert.subject
            cn = self._extract_name_attribute(subject, NameOID.COMMON_NAME)
            subject_org = self._extract_name_attribute(subject, NameOID.ORGANIZATION_NAME)
            
            # Extract issuer info
            issuer = cert.issuer
            issuer_cn = self._extract_name_attribute(issuer, NameOID.COMMON_NAME)
            issuer_org = self._extract_name_attribute(issuer, NameOID.ORGANIZATION_NAME)
            
            # Get dates
            not_before = cert.not_valid_before_utc if hasattr(cert, 'not_valid_before_utc') else cert.not_valid_before
            not_after = cert.not_valid_after_utc if hasattr(cert, 'not_valid_after_utc') else cert.not_valid_after
            
            # Check validity
            now = datetime.now(timezone.utc)
            # Make dates timezone-aware if they aren't
            if not_before.tzinfo is None:
                not_before = not_before.replace(tzinfo=timezone.utc)
            if not_after.tzinfo is None:
                not_after = not_after.replace(tzinfo=timezone.utc)
            is_valid = not_before <= now <= not_after
            
            # Check self-signed (subject == issuer)
            is_self_signed = (cert.subject == cert.issuer)
            
            # Get SANs and emails
            san, emails = self._parse_san(cert)
            
            # Calculate fingerprint
            fingerprint = hashlib.sha256(cert_binary).hexdigest()
            
            # Serial number
            serial = format(cert.serial_number, 'x').upper()
            
            return TLSInfo(
                common_name=cn,
                subject_org=subject_org,
                issuer=issuer_cn,
                issuer_org=issuer_org,
                valid_from=not_before.isoformat() if not_before else None,
                valid_to=not_after.isoformat() if not_after else None,
                san=san,
                email_addresses=emails,
                serial_number=serial,
                fingerprint_sha256=fingerprint,
                is_valid=is_valid,
                is_self_signed=is_self_signed
            )
            
        except Exception as e:
            return TLSInfo(error=f"Parse error: {str(e)[:50]}")
    
    def fetch_cert(self, host: str, port: int = 443) -> TLSInfo:
        """Fetch TLS certificate from a host.
        
        Fetches certificate data even for invalid/self-signed/expired certs.
        This is intentional for enrichment purposes (attribution, org discovery).
        
        Args:
            host: Hostname or IP address
            port: Port number (default 443)
            
        Returns:
            TLSInfo with certificate details (even for invalid certs)
        """
        try:
            # Create SSL context that doesn't verify - we want the cert regardless
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    # Get binary DER certificate - this always works
                    cert_binary = ssock.getpeercert(binary_form=True)
                    
                    if not cert_binary:
                        return TLSInfo(error="No certificate returned")
                    
                    # Parse using cryptography library
                    return self._parse_binary_cert(cert_binary)
                    
        except ssl.SSLError as e:
            return TLSInfo(error=f"SSL error: {str(e)[:50]}")
        except socket.timeout:
            return TLSInfo(error="Connection timeout")
        except socket.gaierror as e:
            return TLSInfo(error=f"DNS error: {str(e)[:30]}")
        except ConnectionRefusedError:
            return TLSInfo(error="Connection refused")
        except ConnectionResetError:
            return TLSInfo(error="Connection reset")
        except OSError as e:
            return TLSInfo(error=f"OS error: {str(e)[:30]}")
        except Exception as e:
            return TLSInfo(error=f"Error: {str(e)[:40]}")
    
    def bulk_fetch(
        self,
        targets: List[tuple],  # List of (host, port) tuples
        workers: int = 20,
        show_progress: bool = True
    ) -> Dict[str, TLSInfo]:
        """Fetch certificates from multiple hosts concurrently.
        
        Args:
            targets: List of (host, port) tuples
            workers: Number of concurrent workers
            show_progress: Show progress bar
            
        Returns:
            Dictionary mapping "host:port" to TLSInfo
        """
        results: Dict[str, TLSInfo] = {}
        
        if not targets:
            return results
        
        # Deduplicate targets
        unique_targets = list(set(targets))
        
        print(f"    [TLS] Fetching certificates from {len(unique_targets)} hosts...")
        
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(self.fetch_cert, host, port): (host, port)
                for host, port in unique_targets
            }
            
            iterator = as_completed(futures)
            if show_progress:
                iterator = tqdm(iterator, total=len(futures), desc="    TLS certs", unit="host")
            
            for future in iterator:
                host, port = futures[future]
                key = f"{host}:{port}"
                try:
                    results[key] = future.result()
                except Exception as e:
                    results[key] = TLSInfo(error=f"Error: {str(e)[:30]}")
        
        # Count successes
        success = sum(1 for t in results.values() if t.common_name)
        errors = sum(1 for t in results.values() if t.error)
        print(f"    [TLS] Success: {success}, Errors: {errors}")
        
        return results
