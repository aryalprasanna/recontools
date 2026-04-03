#!/usr/bin/env python3
"""
Cybersecurity Reconnaissance Tool
A comprehensive modular tool for IP and website analysis including DNS, IP Intel, 
Port Scanning, SSL Analysis, WHOIS, Subdomains, Headers, Fingerprinting, and GeoIP mapping.
For educational and authorized security testing purposes only.
"""

import argparse
import sys

from core.dataclasses import GeoIPData
from modules.dns_recon import DNSModule
from modules.ip_intel import IPIntelModule
from modules.port_scanner import SocketScannerModule
from modules.ssl_check import SSLModule
from modules.whois_lookup import WHOISModule
from modules.subdomain_enum import SubdomainModule
from modules.header_analysis import HeaderAnalysisModule
from modules.fingerprinting import FingerprintModule
from modules.async_port_scan import AsyncPortScannerModule
from modules.geoip_map import GeoIPModule
from utils.formatter import ResultFormatter
from utils.exporter import ExportModule
from ui.dashboard import ReconDashboard


def main():
    """Main function with CLI argument parsing."""

    parser = argparse.ArgumentParser(
        description='Cybersecurity Reconnaissance Tool - Comprehensive IP and Website Analysis',
        epilog='Example: python main.py example.com --all',
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
        nargs='?',
        const='all',
        default=False,
        help='Perform port scanning. Optionally specify comma-separated list of ports (e.g., -p 80,443)'
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

    parser.add_argument(
        '--console',
        action='store_true',
        help='Run in console CLI mode instead of TUI'
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
        run_ports = bool(args.ports) or (not any_flag)
        run_ssl = args.ssl or (not any_flag)
        run_whois = args.whois
        run_subdomains = args.subdomains
        run_headers = args.headers
        run_fingerprint = args.fingerprint

    target = args.target
    results = {}
    
    # Handle custom port list mapping
    custom_ports = None
    if isinstance(args.ports, str) and args.ports != 'all':
        custom_ports = [int(p.strip()) for p in args.ports.split(',') if p.strip().isdigit()]

    options = {
        "dns": run_dns,
        "ip_intel": run_ip,
        "ports": run_ports,
        "ports_list": custom_ports,
        "async_ports": args.async_ports,
        "ssl": run_ssl,
        "whois": run_whois,
        "subdomains": run_subdomains,
        "headers": run_headers,
        "fingerprint": run_fingerprint,
        "export": args.export,
        "output": args.output
    }

    # If --console is not passed, launch TUI
    if not args.console:
        app = ReconDashboard(target=target, options=options)
        app.run()
        return

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
        if args.async_ports:
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
