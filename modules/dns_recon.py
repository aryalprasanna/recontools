"""DNS reconnaissance module."""

import sys
from typing import Dict, Optional

try:
    import dns.resolver
    import dns.rdatatype
except ImportError:
    print("Error: dnspython is required. Install it with: pip install dnspython")
    sys.exit(1)

from core.dataclasses import DNSRecord


class DNSModule:
    """
    DNS reconnaissance module for fetching various DNS records.
    Supports A, MX, TXT, and CNAME records.
    """

    COMMON_RECORDS = ['A', 'MX', 'TXT', 'CNAME', 'NS']

    @staticmethod
    def fetch_records(domain: str, record_type: str = 'A') -> Optional[DNSRecord]:
        """
        Fetch specific DNS records for a domain.

        Args:
            domain: Target domain name
            record_type: DNS record type (A, MX, TXT, CNAME, NS)

        Returns:
            DNSRecord object or None if lookup fails
        """
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5

            answers = resolver.resolve(domain, record_type)
            values = [str(rdata) for rdata in answers]

            return DNSRecord(record_type=record_type, values=values)

        except dns.resolver.NXDOMAIN:
            print(f"  [!] Domain {domain} does not exist (NXDOMAIN)")
            return None
        except dns.resolver.NoAnswer:
            return None
        except dns.exception.Timeout:
            print(f"  [!] DNS query timeout for {record_type} record")
            return None
        except Exception as e:
            print(f"  [!] Error fetching {record_type} records: {str(e)}")
            return None

    @staticmethod
    def lookup_all(domain: str) -> Dict[str, Optional[DNSRecord]]:
        """
        Fetch all common DNS records for a domain.

        Args:
            domain: Target domain name

        Returns:
            Dictionary with DNS record types as keys and DNSRecord objects as values
        """
        results = {}
        for record_type in DNSModule.COMMON_RECORDS:
            results[record_type] = DNSModule.fetch_records(domain, record_type)
        return results
