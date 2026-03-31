#!/usr/bin/env python3
"""
Cybersecurity Reconnaissance Tool
A modular tool for IP and website analysis with DNS, IP Intel, Socket Scanning, and SSL capabilities.
For educational and authorized security testing purposes only.
"""

import argparse
import socket
import ssl
import sys
import time
import json
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime
from urllib.request import urlopen
from urllib.error import URLError, HTTPError

try:
    import dns.resolver
    import dns.rdatatype
except ImportError:
    print("Error: dnspython is required. Install it with: pip install dnspython")
    sys.exit(1)


# ============================================================================
# DATA STRUCTURES
# ============================================================================

@dataclass
class DNSRecord:
    """Store DNS record information"""
    record_type: str
    values: List[str]


@dataclass
class IPIntel:
    """Store IP intelligence data"""
    ip: str
    country: str
    region: str
    city: str
    isp: str
    asn: str
    lat: float
    lon: float


@dataclass
class PortStatus:
    """Store port scan results"""
    port: int
    status: str
    service: str
    banner: Optional[str] = None


@dataclass
class SSLInfo:
    """Store SSL certificate information"""
    subject: str
    issuer: str
    valid_from: str
    valid_until: str
    is_expired: bool
    san: List[str]


# ============================================================================
# DNS MODULE
# ============================================================================

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


# ============================================================================
# IP INTELLIGENCE MODULE
# ============================================================================

class IPIntelModule:
    """
    IP intelligence module using ip-api.com for geolocation, ISP, and ASN data.
    Note: Free API has rate limits (~45 requests/minute)
    """

    API_URL = "http://ip-api.com/json/{}"
    TIMEOUT = 10

    @staticmethod
    def get_ip_intel(ip_address: str) -> Optional[IPIntel]:
        """
        Fetch IP intelligence data from ip-api.com.

        Args:
            ip_address: Target IP address

        Returns:
            IPIntel object or None if lookup fails
        """
        try:
            url = IPIntelModule.API_URL.format(ip_address)

            # Fetch data with timeout
            response = urlopen(url, timeout=IPIntelModule.TIMEOUT)
            data = json.loads(response.read().decode('utf-8'))

            if data.get('status') != 'success':
                print(f"  [!] IP lookup failed: {data.get('message', 'Unknown error')}")
                return None

            intel = IPIntel(
                ip=data.get('query', ip_address),
                country=data.get('country', 'N/A'),
                region=data.get('regionName', 'N/A'),
                city=data.get('city', 'N/A'),
                isp=data.get('isp', 'N/A'),
                asn=data.get('as', 'N/A'),
                lat=float(data.get('lat', 0)),
                lon=float(data.get('lon', 0))
            )

            return intel

        except HTTPError as e:
            print(f"  [!] HTTP Error: {e.code}")
            return None
        except URLError as e:
            print(f"  [!] Connection Error: {e.reason}")
            return None
        except json.JSONDecodeError:
            print(f"  [!] Invalid JSON response from IP API")
            return None
        except socket.timeout:
            print(f"  [!] Request timeout for IP lookup")
            return None
        except Exception as e:
            print(f"  [!] Error fetching IP intelligence: {str(e)}")
            return None

    @staticmethod
    def resolve_domain_to_ip(domain: str) -> Optional[str]:
        """
        Resolve a domain name to its primary IP address.

        Args:
            domain: Target domain name

        Returns:
            IP address string or None if resolution fails
        """
        try:
            ip = socket.gethostbyname(domain)
            return ip
        except socket.gaierror as e:
            print(f"  [!] DNS resolution failed: {str(e)}")
            return None
        except socket.timeout:
            print(f"  [!] DNS resolution timeout")
            return None
        except Exception as e:
            print(f"  [!] Error resolving domain: {str(e)}")
            return None


# ============================================================================
# SOCKET SCANNER MODULE
# ============================================================================

class SocketScannerModule:
    """
    Lightweight port scanner using socket library.
    Includes basic banner grabbing capability.
    """

    DEFAULT_PORTS = {
        21: 'FTP',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        443: 'HTTPS',
        8080: 'HTTP-Alt',
        3389: 'RDP'
    }

    TIMEOUT = 3
    BANNER_TIMEOUT = 2

    @staticmethod
    def scan_port(host: str, port: int, service_name: str = '') -> PortStatus:
        """
        Scan a single port and attempt banner grab.

        Args:
            host: Target hostname or IP
            port: Port number to scan
            service_name: Name of the service (optional)

        Returns:
            PortStatus object with scan results
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(SocketScannerModule.TIMEOUT)

        try:
            # Attempt connection
            result = sock.connect_ex((host, port))

            if result == 0:
                # Port is open, attempt banner grab
                banner = SocketScannerModule._grab_banner(sock, host, port)
                return PortStatus(
                    port=port,
                    status='OPEN',
                    service=service_name or f'Port {port}',
                    banner=banner
                )
            else:
                return PortStatus(
                    port=port,
                    status='CLOSED',
                    service=service_name or f'Port {port}'
                )

        except socket.timeout:
            return PortStatus(
                port=port,
                status='FILTERED',
                service=service_name or f'Port {port}'
            )
        except Exception as e:
            return PortStatus(
                port=port,
                status='ERROR',
                service=service_name or f'Port {port}',
                banner=str(e)
            )
        finally:
            sock.close()

    @staticmethod
    def _grab_banner(sock: socket.socket, host: str, port: int) -> Optional[str]:
        """
        Attempt to grab service banner from open port.

        Args:
            sock: Connected socket
            host: Target host
            port: Target port

        Returns:
            Banner string or None if unable to grab
        """
        try:
            sock.settimeout(SocketScannerModule.BANNER_TIMEOUT)
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            return banner if banner else None
        except:
            # Some services require a request before responding
            # For HTTP/HTTPS, try a basic HEAD request
            if port in [80, 443, 8080]:
                try:
                    if port == 443:
                        sock_ssl = ssl.wrap_socket(sock)
                        sock_ssl.send(b"HEAD / HTTP/1.0\r\n\r\n")
                        banner = sock_ssl.recv(1024).decode('utf-8', errors='ignore').strip()
                        return banner[:100] if banner else None
                    else:
                        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                        return banner[:100] if banner else None
                except:
                    return None
            return None

    @staticmethod
    def scan_common_ports(host: str) -> List[PortStatus]:
        """
        Scan all common ports on a target host.

        Args:
            host: Target hostname or IP

        Returns:
            List of PortStatus objects
        """
        results = []
        print(f"\n[*] Scanning {host} for open ports...")

        for port, service in SocketScannerModule.DEFAULT_PORTS.items():
            sys.stdout.write(f"\r    Scanning port {port}... ")
            sys.stdout.flush()

            result = SocketScannerModule.scan_port(host, port, service)
            results.append(result)
            time.sleep(0.1)  # Small delay to avoid overwhelming the network

        print("\r" + " " * 50 + "\r", end="")  # Clear the progress line
        return results


# ============================================================================
# SSL MODULE
# ============================================================================

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


# ============================================================================
# CLI & FORMATTER
# ============================================================================

class ResultFormatter:
    """Format and display reconnaissance results in a clean, organized manner."""

    @staticmethod
    def print_header(title: str):
        """Print a formatted section header."""
        print(f"\n{'='*70}")
        print(f"  {title}")
        print(f"{'='*70}")

    @staticmethod
    def print_subheader(title: str):
        """Print a formatted subsection header."""
        print(f"\n[*] {title}")
        print(f"{'-'*70}")

    @staticmethod
    def print_dns_results(results: Dict[str, Optional[DNSRecord]]):
        """Format and display DNS reconnaissance results."""
        ResultFormatter.print_subheader("DNS Records")

        has_results = False
        for record_type, record in results.items():
            if record:
                print(f"\n  {record_type} Records:")
                for value in record.values:
                    print(f"    → {value}")
                has_results = True

        if not has_results:
            print("  [!] No DNS records found or resolver error occurred")

    @staticmethod
    def print_ip_intel(intel: Optional[IPIntel]):
        """Format and display IP intelligence results."""
        ResultFormatter.print_subheader("IP Intelligence")

        if intel:
            print(f"  IP Address:     {intel.ip}")
            print(f"  Country:        {intel.country}")
            print(f"  Region:         {intel.region}")
            print(f"  City:           {intel.city}")
            print(f"  ISP:            {intel.isp}")
            print(f"  ASN:            {intel.asn}")
            print(f"  Coordinates:    {intel.lat}, {intel.lon}")
        else:
            print("  [!] Unable to retrieve IP intelligence")

    @staticmethod
    def print_port_scan_results(results: List[PortStatus]):
        """Format and display port scan results in a table."""
        ResultFormatter.print_subheader("Port Scan Results")

        # Filter and display only relevant results
        open_ports = [r for r in results if r.status == 'OPEN']

        if open_ports:
            print(f"\n  {'Port':<8} {'Service':<20} {'Status':<10} {'Banner':<30}")
            print(f"  {'-'*68}")
            for port in open_ports:
                banner = port.banner[:27] + "..." if port.banner and len(port.banner) > 30 else (port.banner or "N/A")
                print(f"  {port.port:<8} {port.service:<20} {port.status:<10} {banner:<30}")
        else:
            print("  [!] No open ports detected")

        # Summary
        closed = len([r for r in results if r.status == 'CLOSED'])
        filtered = len([r for r in results if r.status == 'FILTERED'])
        print(f"\n  Summary: {len(open_ports)} open, {closed} closed, {filtered} filtered")

    @staticmethod
    def print_ssl_info(ssl_info: Optional[SSLInfo]):
        """Format and display SSL/TLS certificate information."""
        ResultFormatter.print_subheader("SSL/TLS Certificate")

        if ssl_info:
            expired_status = "[EXPIRED]" if ssl_info.is_expired else "[VALID]"
            print(f"  Subject:        {ssl_info.subject}")
            print(f"  Issuer:         {ssl_info.issuer}")
            print(f"  Valid From:     {ssl_info.valid_from}")
            print(f"  Valid Until:    {ssl_info.valid_until} {expired_status}")

            if ssl_info.san:
                print(f"\n  Subject Alternative Names:")
                for san in ssl_info.san:
                    print(f"    → {san}")
        else:
            print("  [!] Unable to retrieve SSL certificate (may be running on non-standard port)")


# ============================================================================
# MAIN EXECUTION
# ============================================================================

def main():
    """Main function with CLI argument parsing."""

    parser = argparse.ArgumentParser(
        description='Cybersecurity Reconnaissance Tool - IP and Website Analysis',
        epilog='Example: python recon_tool.py example.com',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        'target',
        help='Domain name or IP address to analyze'
    )

    parser.add_argument(
        '-d', '--dns',
        action='store_true',
        help='Perform DNS reconnaissance (default: enabled)'
    )

    parser.add_argument(
        '-i', '--ip-intel',
        action='store_true',
        help='Retrieve IP intelligence (default: enabled)'
    )

    parser.add_argument(
        '-p', '--ports',
        action='store_true',
        help='Perform port scanning (default: enabled)'
    )

    parser.add_argument(
        '-s', '--ssl',
        action='store_true',
        help='Retrieve SSL certificate information (default: enabled)'
    )

    parser.add_argument(
        '--all',
        action='store_true',
        help='Run all reconnaissance modules'
    )

    args = parser.parse_args()

    # Determine which modules to run
    if args.all:
        run_dns = run_ip = run_ports = run_ssl = True
    else:
        # If no flags specified, run all by default
        run_dns = args.dns or (not any([args.dns, args.ip_intel, args.ports, args.ssl]))
        run_ip = args.ip_intel or (not any([args.dns, args.ip_intel, args.ports, args.ssl]))
        run_ports = args.ports or (not any([args.dns, args.ip_intel, args.ports, args.ssl]))
        run_ssl = args.ssl or (not any([args.dns, args.ip_intel, args.ports, args.ssl]))

    target = args.target

    # Display banner
    ResultFormatter.print_header(f"RECONNAISSANCE: {target}")

    # Resolve domain to IP if necessary
    target_ip = None
    if run_ip or run_ports:
        print(f"\n[*] Resolving {target}...")
        target_ip = IPIntelModule.resolve_domain_to_ip(target)
        if target_ip:
            print(f"    Resolved to: {target_ip}")
        else:
            if run_ip or run_ports:
                print(f"    [!] Could not resolve {target}")

    # Run DNS module
    if run_dns:
        dns_results = DNSModule.lookup_all(target)
        ResultFormatter.print_dns_results(dns_results)

    # Run IP Intel module
    if run_ip and target_ip:
        ip_intel = IPIntelModule.get_ip_intel(target_ip)
        ResultFormatter.print_ip_intel(ip_intel)

    # Run Port Scanner
    if run_ports and target_ip:
        port_results = SocketScannerModule.scan_common_ports(target_ip)
        ResultFormatter.print_port_scan_results(port_results)

    # Run SSL module
    if run_ssl:
        ssl_info = SSLModule.get_certificate(target)
        ResultFormatter.print_ssl_info(ssl_info)

    # Footer
    print(f"\n{'='*70}")
    print("[+] Reconnaissance completed")
    print(f"{'='*70}\n")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Reconnaissance interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Fatal error: {str(e)}")
        sys.exit(1)
