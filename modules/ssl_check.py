"""SSL/TLS certificate analysis module."""

import socket
import ssl
from datetime import datetime
from typing import Dict, List, Optional

from core.dataclasses import SSLInfo


class SSLModule:
    """
    SSL/TLS certificate analysis module.
    Extracts certificate details including expiry and Subject Alternative Names.
    """

    TIMEOUT = 10

    @staticmethod
    def get_certificate(domain: str, port: int = 443) -> Optional[SSLInfo]:
        """
        Retrieve SSL/TLS certificate information for a domain.

        Args:
            domain: Target domain name
            port: SSL/TLS port (default 443)

        Returns:
            SSLInfo object or None if unable to retrieve certificate
        """
        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED

            # Connect and get certificate
            with socket.create_connection((domain, port), timeout=SSLModule.TIMEOUT) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    der_cert = ssock.getpeercert(binary_form=True)

        except ssl.SSLError as e:
            print(f"  [!] SSL Error: {str(e)}")
            return None
        except socket.timeout:
            print(f"  [!] SSL connection timeout")
            return None
        except socket.gaierror:
            print(f"  [!] Could not resolve domain for SSL lookup")
            return None
        except Exception as e:
            print(f"  [!] Error retrieving SSL certificate: {str(e)}")
            return None

        try:
            # Extract certificate information
            subject = SSLModule._extract_subject(cert)
            issuer = SSLModule._extract_issuer(cert)
            valid_from = cert.get('notBefore', 'N/A')
            valid_until = cert.get('notAfter', 'N/A')
            san = SSLModule._extract_san(cert)

            # Check if expired
            is_expired = SSLModule._is_certificate_expired(valid_until)

            return SSLInfo(
                subject=subject,
                issuer=issuer,
                valid_from=valid_from,
                valid_until=valid_until,
                is_expired=is_expired,
                san=san
            )

        except Exception as e:
            print(f"  [!] Error parsing certificate: {str(e)}")
            return None

    @staticmethod
    def _extract_subject(cert: dict) -> str:
        """Extract certificate subject."""
        try:
            subject = cert.get('subject', [])
            if subject:
                cn = next((value for rdn in subject for key, value in rdn if key == 'commonName'), 'N/A')
                return cn
            return 'N/A'
        except:
            return 'N/A'

    @staticmethod
    def _extract_issuer(cert: dict) -> str:
        """Extract certificate issuer."""
        try:
            issuer = cert.get('issuer', [])
            if issuer:
                cn = next((value for rdn in issuer for key, value in rdn if key == 'commonName'), 'N/A')
                return cn
            return 'N/A'
        except:
            return 'N/A'

    @staticmethod
    def _extract_san(cert: dict) -> List[str]:
        """Extract Subject Alternative Names (SANs) from certificate."""
        try:
            san_list = cert.get('subjectAltName', [])
            sans = [value for _, value in san_list]
            return sans
        except:
            return []

    @staticmethod
    def _is_certificate_expired(not_after: str) -> bool:
        """Check if certificate is expired based on notAfter date."""
        try:
            if not_after == 'N/A':
                return False
            # SSL date format: 'Nov 15 23:59:59 2025 GMT'
            cert_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
            return datetime.now() > cert_date
        except:
            return False
