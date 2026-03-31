#!/usr/bin/env python3
"""
Cybersecurity Reconnaissance Tool
A comprehensive modular tool for IP and website analysis including DNS, IP Intel, 
Port Scanning, SSL Analysis, WHOIS, Subdomains, Headers, Fingerprinting, and GeoIP mapping.
For educational and authorized security testing purposes only.
"""

import argparse
import socket
import ssl
import sys
import time
import json
import subprocess
import csv
import asyncio
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, asdict
from datetime import datetime
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
from io import StringIO

try:
    import dns.resolver
    import dns.rdatatype
except ImportError:
    print("Error: dnspython is required. Install it with: pip install dnspython")
    sys.exit(1)

try:
    from whois import whois as whois_lookup
except ImportError:
    whois_lookup = None

try:
    import aiohttp
except ImportError:
    aiohttp = None


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


@dataclass
class WHOISInfo:
    """Store WHOIS information"""
    domain: str
    registrar: Optional[str] = None
    created_date: Optional[str] = None
    updated_date: Optional[str] = None
    expires_date: Optional[str] = None
    registrant: Optional[str] = None
    raw_data: Optional[str] = None


@dataclass
class HeaderInfo:
    """Store HTTP header analysis"""
    status_code: Optional[int] = None
    server: Optional[str] = None
    powered_by: Optional[str] = None
    x_powered_by: Optional[str] = None
    content_type: Optional[str] = None
    security_headers: Dict[str, str] = None
    raw_headers: Dict[str, str] = None

    def __post_init__(self):
        if self.security_headers is None:
            self.security_headers = {}
        if self.raw_headers is None:
            self.raw_headers = {}


@dataclass
class Fingerprint:
    """Store web service fingerprinting results"""
    technologies: List[str]
    cms: Optional[str] = None
    web_server: Optional[str] = None
    programming_language: Optional[str] = None
    frameworks: List[str] = None

    def __post_init__(self):
        if self.frameworks is None:
            self.frameworks = []


@dataclass
class GeoIPData:
    """Store GeoIP mapping data"""
    ip: str
    country: str
    region: str
    city: str
    lat: float
    lon: float
    confidence: Optional[str] = None


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

    @staticmethod
    def print_whois(whois_info: Optional[WHOISInfo]):
        """Format and display WHOIS information."""
        ResultFormatter.print_subheader("WHOIS Information")
        if whois_info:
            print(f"  Domain:         {whois_info.domain}")
            if whois_info.registrar:
                print(f"  Registrar:      {whois_info.registrar}")
            if whois_info.created_date:
                print(f"  Created Date:   {whois_info.created_date}")
            if whois_info.updated_date:
                print(f"  Updated Date:   {whois_info.updated_date}")
            if whois_info.expires_date:
                print(f"  Expires Date:   {whois_info.expires_date}")
            if whois_info.registrant:
                print(f"  Registrant:     {whois_info.registrant}")
        else:
            print("  [!] Unable to retrieve WHOIS information")

    @staticmethod
    def print_subdomains(subdomains: List[str]):
        """Format and display discovered subdomains."""
        ResultFormatter.print_subheader("Subdomain Enumeration")
        if subdomains:
            print(f"  Found {len(subdomains)} subdomain(s):")
            for subdomain in sorted(subdomains):
                print(f"    → {subdomain}")
        else:
            print("  [!] No subdomains discovered")

    @staticmethod
    def print_headers(headers_info: Optional[HeaderInfo]):
        """Format and display HTTP header analysis."""
        ResultFormatter.print_subheader("HTTP Header Analysis")
        if headers_info and headers_info.raw_headers:
            if headers_info.status_code:
                print(f"  Status Code:    {headers_info.status_code}")
            if headers_info.server:
                print(f"  Server:         {headers_info.server}")
            if headers_info.powered_by:
                print(f"  Powered By:     {headers_info.powered_by}")
            if headers_info.x_powered_by:
                print(f"  X-Powered-By:   {headers_info.x_powered_by}")
            if headers_info.content_type:
                print(f"  Content-Type:   {headers_info.content_type}")
            
            if headers_info.security_headers:
                print(f"\n  Security Headers:")
                for header, value in headers_info.security_headers.items():
                    print(f"    {header}: {value}")
        else:
            print("  [!] Unable to retrieve HTTP headers")

    @staticmethod
    def print_fingerprint(fingerprint: Optional[Fingerprint]):
        """Format and display fingerprinting results."""
        ResultFormatter.print_subheader("Web Service Fingerprinting")
        if fingerprint:
            if fingerprint.web_server:
                print(f"  Web Server:     {fingerprint.web_server}")
            if fingerprint.cms:
                print(f"  CMS:            {fingerprint.cms}")
            if fingerprint.programming_language:
                print(f"  Language:       {fingerprint.programming_language}")
            if fingerprint.technologies:
                print(f"  Technologies:   {', '.join(fingerprint.technologies)}")
            if fingerprint.frameworks:
                print(f"  Frameworks:     {', '.join(fingerprint.frameworks)}")
        else:
            print("  [!] Unable to fingerprint web service")

    @staticmethod
    def print_geoip(geoip_data: Optional[GeoIPData]):
        """Format and display GeoIP mapping data."""
        ResultFormatter.print_subheader("GeoIP Mapping")
        if geoip_data:
            print(f"  IP Address:     {geoip_data.ip}")
            print(f"  Country:        {geoip_data.country}")
            print(f"  Region:         {geoip_data.region}")
            print(f"  City:           {geoip_data.city}")
            print(f"  Coordinates:    {geoip_data.lat}, {geoip_data.lon}")
            if geoip_data.confidence:
                print(f"  Confidence:     {geoip_data.confidence}")
        else:
            print("  [!] Unable to retrieve GeoIP data")


# ============================================================================
# WHOIS MODULE
# ============================================================================

class WHOISModule:
    """WHOIS lookup module for domain and IP ownership information."""

    @staticmethod
    def lookup(target: str) -> Optional[WHOISInfo]:
        """Lookup WHOIS information for domain or IP."""
        try:
            if whois_lookup:
                result = whois_lookup(target)
                whois_info = WHOISInfo(domain=target)
                
                # Extract common fields
                if hasattr(result, 'registrar'):
                    whois_info.registrar = result.registrar
                if hasattr(result, 'creation_date'):
                    whois_info.created_date = str(result.creation_date)
                if hasattr(result, 'updated_date'):
                    whois_info.updated_date = str(result.updated_date)
                if hasattr(result, 'expiration_date'):
                    whois_info.expires_date = str(result.expiration_date)
                if hasattr(result, 'registrant_name'):
                    whois_info.registrant = result.registrant_name
                
                whois_info.raw_data = str(result)
                return whois_info
            else:
                return WHOISModule._socket_whois_lookup(target)
        except Exception as e:
            return None

    @staticmethod
    def _socket_whois_lookup(target: str) -> Optional[WHOISInfo]:
        """Fallback WHOIS lookup using socket connection."""
        try:
            socket_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket_conn.settimeout(5)
            socket_conn.connect(("whois.iana.org", 43))
            socket_conn.send(f"{target}\r\n".encode())
            
            data = b""
            while True:
                chunk = socket_conn.recv(4096)
                if not chunk:
                    break
                data += chunk
            socket_conn.close()
            
            raw_data = data.decode('utf-8', errors='ignore')
            return WHOISInfo(domain=target, raw_data=raw_data)
        except Exception:
            return None


# ============================================================================
# SUBDOMAIN ENUMERATION MODULE
# ============================================================================

class SubdomainModule:
    """Subdomain enumeration module for discovering subdomains."""
    
    # Common subdomains wordlist
    COMMON_SUBDOMAINS = [
        'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
        'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test',
        'portal', 'admin', 'admin', 'api', 'blog', 'cdn', 'dev', 'dev', 'git',
        'staging', 'stage', 'prod', 'production', 'qa', 'quality', 'search', 'secure',
        'shop', 'support', 'vpn', 'wiki', 'apps', 'assets', 'backup', 'calendar',
        'chat', 'crm', 'dashboard', 'db', 'dns', 'docs', 'download', 'email',
        'erp', 'files', 'gw', 'help', 'home', 'images', 'info', 'internal',
        'intranet', 'it', 'knowledge', 'lab', 'legacy', 'library', 'live', 'logs',
        'manager', 'media', 'mobile', 'monitor', 'mx', 'mysql', 'net', 'network',
        'news', 'ota', 'pay', 'payment', 'people', 'photo', 'photos', 'platform',
        'plesk', 'promo', 'proxy', 'public', 'rep', 'report', 'resource', 'rs',
        'rtc', 's3', 'sandbox', 'sap', 'secure', 'server', 'services', 'share',
        'sms', 'soap', 'social', 'software', 'source', 'sql', 'ssh', 'ssl',
        'status', 'storage', 'store', 'stream', 'sys', 'sysadmin', 'system', 'tech',
        'test', 'testing', 'ticketing', 'tmp', 'tools', 'tracker', 'training',
        'transfer', 'traveler', 'tunnel', 'tv', 'twitter', 'upload', 'uptime',
        'us', 'user', 'users', 'video', 'voip', 'vpn', 'wap', 'ware',
        'warehouse', 'weather', 'webcam', 'webdev', 'webhook', 'webserver', 'website',
        'whois', 'widget', 'windows', 'wireless', 'wpad', 'ww', 'www2', 'www3',
        'www4', 'www5', 'www6', 'www7', 'www8', 'www9', 'wwwdev', 'wwwtest',
        'xs', 'xss', 'yard', 'yardım', 'yara', 'yb', 'yc', 'yellow',
        'yes', 'yld', 'yml', 'you', 'young', 'yours', 'youth', 'yp', 'yr',
        'z', 'zabbix', 'zapier', 'zd', 'zendesk', 'zero', 'zeronet', 'zeus',
        'zip', 'zl', 'zn', 'zo', 'zone', 'zonefile', 'zoo', 'zoom', 'zoneminder'
    ]

    @staticmethod
    def enumerate(domain: str) -> List[str]:
        """Enumerate common subdomains for a domain."""
        discovered = []
        
        for subdomain in SubdomainModule.COMMON_SUBDOMAINS:
            full_domain = f"{subdomain}.{domain}"
            try:
                socket.gethostbyname(full_domain)
                discovered.append(full_domain)
            except (socket.gaierror, socket.timeout):
                pass
            except Exception:
                pass
        
        return discovered


# ============================================================================
# HTTP HEADER ANALYSIS MODULE
# ============================================================================

class HeaderAnalysisModule:
    """HTTP header analysis module for extracting response headers."""
    
    SECURITY_HEADERS = [
        'Strict-Transport-Security',
        'Content-Security-Policy',
        'X-Content-Type-Options',
        'X-Frame-Options',
        'X-XSS-Protection',
        'Referrer-Policy',
        'Permissions-Policy'
    ]

    @staticmethod
    def analyze(target: str) -> Optional[HeaderInfo]:
        """Analyze HTTP headers from target."""
        try:
            # Try both http and https
            for scheme in ['https://', 'http://']:
                try:
                    url = f"{scheme}{target}" if not target.startswith('http') else target
                    headers_info = HeaderAnalysisModule._fetch_headers(url)
                    if headers_info:
                        return headers_info
                except Exception:
                    continue
            return None
        except Exception:
            return None

    @staticmethod
    def _fetch_headers(url: str) -> Optional[HeaderInfo]:
        """Fetch and analyze headers from URL."""
        try:
            req = Request(url, method='HEAD')
            req.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)')
            
            with urlopen(req, timeout=5) as response:
                headers_dict = dict(response.headers)
                headers_info = HeaderInfo(
                    status_code=response.status,
                    raw_headers=headers_dict
                )
                
                # Extract common headers
                headers_info.server = headers_dict.get('Server')
                headers_info.powered_by = headers_dict.get('X-Powered-By') or headers_dict.get('Powered-By')
                headers_info.x_powered_by = headers_dict.get('X-Powered-By')
                headers_info.content_type = headers_dict.get('Content-Type')
                
                # Extract security headers
                security = {}
                for header in HeaderAnalysisModule.SECURITY_HEADERS:
                    if header in headers_dict:
                        security[header] = headers_dict[header]
                
                headers_info.security_headers = security
                return headers_info
        except Exception:
            return None


# ============================================================================
# WEB SERVICE FINGERPRINTING MODULE
# ============================================================================

class FingerprintModule:
    """Web service fingerprinting module for identifying technologies."""
    
    SIGNATURES = {
        'Apache': r'(?i)(apache|httpd)',
        'Nginx': r'(?i)(nginx)',
        'IIS': r'(?i)(Microsoft-IIS|IIS)',
        'Lighttpd': r'(?i)(lighttpd)',
        'Cloudflare': r'(?i)(cloudflare)',
        'WordPress': r'(?i)(wordpress|wp-content|wp-includes)',
        'Joomla': r'(?i)(joomla|/components/|/modules/)',
        'Drupal': r'(?i)(drupal|sites/all)',
        'Magento': r'(?i)(magento|/skin/|/app/)',
        'PHP': r'(?i)(PHP|php-info)',
        'ASP.NET': r'(?i)(ASP\.NET|\.NET|ASPX|X-AspNet)',
        'Python': r'(?i)(Python|Django|Flask)',
        'Node.js': r'(?i)(node|express|nextjs)',
        'Java': r'(?i)(Java|Tomcat|Spring)',
        'Ruby': r'(?i)(Ruby|Rails)',
        'Bootstrap': r'(?i)(bootstrap)',
        'jQuery': r'(?i)(jquery)',
        'React': r'(?i)(react)',
        'Vue': r'(?i)(vue)',
        'Angular': r'(?i)(angular)',
    }

    @staticmethod
    def fingerprint(target: str, headers_info: Optional[HeaderInfo]) -> Optional[Fingerprint]:
        """Fingerprint web service technologies."""
        fp = Fingerprint(technologies=[])
        
        if not headers_info or not headers_info.raw_headers:
            return None
        
        # Check headers for technologies
        headers_str = str(headers_info.raw_headers).lower()
        
        for tech, pattern in FingerprintModule.SIGNATURES.items():
            if re.search(pattern, headers_str):
                fp.technologies.append(tech)
        
        # Extract web server
        if headers_info.server:
            fp.web_server = headers_info.server.split('/')[0]
        
        # Detect CMS
        for cms in ['WordPress', 'Joomla', 'Drupal', 'Magento']:
            if cms in fp.technologies:
                fp.cms = cms
                break
        
        return fp if fp.technologies else None


# ============================================================================
# ASYNC PORT SCANNING MODULE
# ============================================================================

class AsyncPortScannerModule:
    """Async port scanner for concurrent port scanning."""
    
    COMMON_PORTS = {
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

    @staticmethod
    def scan_common_ports(target_ip: str) -> List[PortStatus]:
        """Scan common ports asynchronously."""
        if aiohttp:
            return asyncio.run(AsyncPortScannerModule._async_scan(target_ip))
        else:
            # Fallback to original socket scanner
            return SocketScannerModule.scan_common_ports(target_ip)

    @staticmethod
    async def _async_scan(target_ip: str) -> List[PortStatus]:
        """Async scan implementation."""
        tasks = []
        for port, service in AsyncPortScannerModule.COMMON_PORTS.items():
            task = AsyncPortScannerModule._scan_port(target_ip, port, service)
            tasks.append(task)
        
        results = await asyncio.gather(*tasks)
        return [r for r in results if r]

    @staticmethod
    async def _scan_port(target_ip: str, port: int, service: str) -> Optional[PortStatus]:
        """Scan a single port asynchronously."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target_ip, port),
                timeout=3
            )
            writer.close()
            await writer.wait_closed()
            
            banner = await AsyncPortScannerModule._grab_banner(target_ip, port)
            return PortStatus(port=port, status='OPEN', service=service, banner=banner)
        except asyncio.TimeoutError:
            return PortStatus(port=port, status='FILTERED', service=service)
        except ConnectionRefusedError:
            return PortStatus(port=port, status='CLOSED', service=service)
        except Exception:
            return PortStatus(port=port, status='ERROR', service=service)

    @staticmethod
    async def _grab_banner(target_ip: str, port: int) -> Optional[str]:
        """Grab service banner asynchronously."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target_ip, port),
                timeout=2
            )
            
            # Special handling for HTTP/HTTPS
            if port in [80, 8080, 8443]:
                writer.write(b'HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n')
            else:
                writer.write(b'\r\n')
            
            await writer.drain()
            
            try:
                data = await asyncio.wait_for(reader.read(500), timeout=1)
                banner = data.decode('utf-8', errors='ignore').strip()
                return banner[:100] if banner else None
            except Exception:
                return None
            finally:
                writer.close()
                await writer.wait_closed()
        except Exception:
            return None


# ============================================================================
# EXPORT MODULE
# ============================================================================

class ExportModule:
    """Export reconnaissance results to JSON/CSV formats."""

    @staticmethod
    def export_json(results: Dict, filepath: str) -> bool:
        """Export results to JSON file."""
        try:
            # Convert dataclass objects to dicts
            export_data = {}
            for key, value in results.items():
                if value is None:
                    export_data[key] = None
                elif isinstance(value, dict):
                    # Handle DNS results dict
                    export_data[key] = {}
                    for k, v in value.items():
                        if hasattr(v, '__dataclass_fields__'):
                            export_data[key][k] = asdict(v)
                        else:
                            export_data[key][k] = v
                elif isinstance(value, list):
                    export_data[key] = [
                        asdict(v) if hasattr(v, '__dataclass_fields__') else v
                        for v in value
                    ]
                elif hasattr(value, '__dataclass_fields__'):
                    export_data[key] = asdict(value)
                else:
                    export_data[key] = value
            
            with open(filepath, 'w') as f:
                json.dump(export_data, f, indent=2, default=str)
            return True
        except Exception as e:
            return False

    @staticmethod
    def export_csv(results: Dict, filepath: str) -> bool:
        """Export results to CSV file."""
        try:
            with open(filepath, 'w', newline='') as f:
                writer = csv.writer(f)
                
                # Flatten nested data for CSV
                writer.writerow(['Category', 'Key', 'Value'])
                
                for category, data in results.items():
                    if data is None:
                        writer.writerow([category, 'N/A', 'No data'])
                    elif isinstance(data, list):
                        for item in data:
                            if hasattr(item, '__dataclass_fields__'):
                                for key, value in asdict(item).items():
                                    writer.writerow([category, key, str(value)])
                            else:
                                writer.writerow([category, 'item', str(item)])
                    elif hasattr(data, '__dataclass_fields__'):
                        for key, value in asdict(data).items():
                            writer.writerow([category, key, str(value)])
                    else:
                        writer.writerow([category, 'value', str(data)])
            
            return True
        except Exception:
            return False

    @staticmethod
    def export_geojson(geoip_data: List[GeoIPData], filepath: str) -> bool:
        """Export GeoIP data to GeoJSON format."""
        try:
            features = []
            for data in geoip_data:
                feature = {
                    "type": "Feature",
                    "geometry": {
                        "type": "Point",
                        "coordinates": [data.lon, data.lat]
                    },
                    "properties": {
                        "ip": data.ip,
                        "country": data.country,
                        "region": data.region,
                        "city": data.city
                    }
                }
                features.append(feature)
            
            geojson = {
                "type": "FeatureCollection",
                "features": features
            }
            
            with open(filepath, 'w') as f:
                json.dump(geojson, f, indent=2)
            return True
        except Exception:
            return False


# ============================================================================
# MAIN EXECUTION
# ============================================================================

def main():
    """Main function with CLI argument parsing."""

    parser = argparse.ArgumentParser(
        description='Cybersecurity Reconnaissance Tool - Comprehensive IP and Website Analysis',
        epilog='Example: python recon_tool.py example.com --all',
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
        '-w', '--whois',
        action='store_true',
        help='Perform WHOIS lookup'
    )

    parser.add_argument(
        '--subdomains',
        action='store_true',
        help='Enumerate subdomains'
    )

    parser.add_argument(
        '--headers',
        action='store_true',
        help='Analyze HTTP headers'
    )

    parser.add_argument(
        '--fingerprint',
        action='store_true',
        help='Fingerprint web services'
    )

    parser.add_argument(
        '--async-ports',
        action='store_true',
        help='Use async port scanning (faster)'
    )

    parser.add_argument(
        '--export',
        choices=['json', 'csv', 'geojson'],
        help='Export results to specified format'
    )

    parser.add_argument(
        '--output',
        default='recon_results',
        help='Output filename (default: recon_results)'
    )

    parser.add_argument(
        '--all',
        action='store_true',
        help='Run all reconnaissance modules'
    )

    args = parser.parse_args()

    # Determine which modules to run
    if args.all:
        run_dns = run_ip = run_ports = run_ssl = run_whois = True
        run_subdomains = run_headers = run_fingerprint = True
    else:
        # Check for any enabled flags
        any_flag = any([args.dns, args.ip_intel, args.ports, args.ssl, args.whois, 
                       args.subdomains, args.headers, args.fingerprint])
        
        run_dns = args.dns or (not any_flag)
        run_ip = args.ip_intel or (not any_flag)
        run_ports = args.ports or (not any_flag)
        run_ssl = args.ssl or (not any_flag)
        run_whois = args.whois
        run_subdomains = args.subdomains
        run_headers = args.headers
        run_fingerprint = args.fingerprint

    target = args.target
    results = {}

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
        results['dns'] = dns_results

    # Run IP Intel module
    if run_ip and target_ip:
        ip_intel = IPIntelModule.get_ip_intel(target_ip)
        ResultFormatter.print_ip_intel(ip_intel)
        results['ip_intelligence'] = ip_intel

    # Run Port Scanner (async or sync)
    if run_ports and target_ip:
        if args.async_ports and aiohttp:
            port_results = AsyncPortScannerModule.scan_common_ports(target_ip)
        else:
            port_results = SocketScannerModule.scan_common_ports(target_ip)
        ResultFormatter.print_port_scan_results(port_results)
        results['ports'] = port_results

    # Run SSL module
    if run_ssl:
        ssl_info = SSLModule.get_certificate(target)
        ResultFormatter.print_ssl_info(ssl_info)
        results['ssl'] = ssl_info

    # Run WHOIS module
    if run_whois:
        whois_info = WHOISModule.lookup(target)
        ResultFormatter.print_whois(whois_info)
        results['whois'] = whois_info

    # Run Subdomain Enumeration
    if run_subdomains:
        subdomains = SubdomainModule.enumerate(target)
        ResultFormatter.print_subdomains(subdomains)
        results['subdomains'] = subdomains

    # Run Header Analysis
    if run_headers:
        headers_info = HeaderAnalysisModule.analyze(target)
        ResultFormatter.print_headers(headers_info)
        results['headers'] = headers_info

    # Run Fingerprinting
    if run_fingerprint and target_ip:
        headers_info = results.get('headers') or HeaderAnalysisModule.analyze(target)
        fingerprint = FingerprintModule.fingerprint(target, headers_info)
        ResultFormatter.print_fingerprint(fingerprint)
        results['fingerprint'] = fingerprint

    # Export results if requested
    if args.export:
        export_file = f"{args.output}.{args.export if args.export != 'geojson' else 'json'}"
        if args.export == 'json':
            if ExportModule.export_json(results, export_file):
                print(f"\n[+] Results exported to {export_file}")
            else:
                print(f"\n[!] Failed to export results to {export_file}")
        elif args.export == 'csv':
            if ExportModule.export_csv(results, export_file):
                print(f"\n[+] Results exported to {export_file}")
            else:
                print(f"\n[!] Failed to export results to {export_file}")
        elif args.export == 'geojson':
            # For GeoJSON, we need GeoIP data
            if 'ip_intelligence' in results and results['ip_intelligence']:
                ip_data = results['ip_intelligence']
                geoip = GeoIPData(
                    ip=ip_data.ip,
                    country=ip_data.country,
                    region=ip_data.region,
                    city=ip_data.city,
                    lat=ip_data.lat,
                    lon=ip_data.lon
                )
                if ExportModule.export_geojson([geoip], export_file):
                    print(f"\n[+] GeoJSON exported to {export_file}")
                else:
                    print(f"\n[!] Failed to export GeoJSON to {export_file}")

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
