"""Result formatting module for displaying reconnaissance output."""

from typing import Dict, List, Optional

from core.dataclasses import (
    DNSRecord,
    IPIntel,
    PortStatus,
    SSLInfo,
    WHOISInfo,
    HeaderInfo,
    Fingerprint,
    GeoIPData,
)


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
