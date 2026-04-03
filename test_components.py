import asyncio
import sys
import os

# Add parent dir to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from modules.dns_recon import DNSModule
from modules.whois_lookup import WHOISModule
from modules.subdomain_enum import SubdomainModule
from modules.async_port_scan import AsyncPortScannerModule
from modules.port_scanner import SocketScannerModule
from modules.cve_mapping import CVEModule
from modules.fingerprinting import FingerprintModule
from modules.geoip_map import GeoIPModule
from modules.header_analysis import HeaderAnalysisModule
from modules.intel_aggregator import IntelAggregatorModule
from modules.ip_intel import IPIntelModule
from modules.ssl_check import SSLModule
from modules.web_screenshot import WebScreenshotModule

async def main():
    target = "example.com"
    ip_target = "93.184.216.34"

    print("--- Testing DNSModule ---")
    try:
        res = DNSModule.lookup_all(target)
        print("Success:", res)
    except Exception as e:
        print("Error:", e)

    print("\n--- Testing WHOISModule ---")
    try:
        res = WHOISModule.lookup(target)
        print("Success:", res)
    except Exception as e:
        print("Error:", e)
        
    print("\n--- Testing SubdomainModule ---")
    try:
        res = await SubdomainModule.enumerate(target)
        print("Success:", res)
    except Exception as e:
        # Maybe it's not async?
        try:
            res = SubdomainModule.enumerate(target)
            print("Success (Sync):", res)
        except Exception as e:
            print("Error:", e)

    print("\n--- Testing AsyncPortScannerModule ---")
    try:
        res = await AsyncPortScannerModule.scan(ip_target, ports=[80, 443])
        print("Success:", res)
    except Exception as e:
        print("Error:", e)

    print("\n--- Testing SocketScannerModule ---")
    try:
        res = SocketScannerModule.scan(ip_target, [80, 443])
        print("Success:", res)
    except Exception as e:
        try:
            res = SocketScannerModule().scan(ip_target, [80, 443])
            print("Success:", res)
        except Exception as e:
            print("Error:", e)
            
    print("\n--- Testing CVEModule ---")
    try:
        res = await CVEModule.lookup("OpenSSH 7.9")
        print("Success:", res)
    except Exception as e:
        try:
            res = CVEModule.lookup("OpenSSH 7.9")
            print("Success (Sync):", res)
        except Exception as e:
            print("Error:", e)

    print("\n--- Testing FingerprintModule ---")
    try:
        res = await FingerprintModule.analyze(target, 443)
        print("Success:", res)
    except Exception as e:
        try:
            res = FingerprintModule.fingerprint(target, 443)
            print("Success (Sync):", res)
        except Exception as e:
            print("Error:", e)

    print("\n--- Testing GeoIPModule ---")
    try:
        res = await GeoIPModule.lookup(ip_target)
        print("Success:", res)
    except Exception as e:
        try:
            res = GeoIPModule.lookup(ip_target)
            print("Success (Sync):", res)
        except Exception as e:
            print("Error:", e)

    print("\n--- Testing HeaderAnalysisModule ---")
    try:
        res = await HeaderAnalysisModule.analyze(target)
        print("Success:", res)
    except Exception as e:
        try:
            res = HeaderAnalysisModule.analyze(target)
            print("Success (Sync):", res)
        except Exception as e:
            print("Error:", e)

    print("\n--- Testing IPIntelModule ---")
    try:
        res = await IPIntelModule.lookup(ip_target)
        print("Success:", res)
    except Exception as e:
        try:
            res = IPIntelModule.check(ip_target)
            print("Success (Sync):", res)
        except Exception as e:
            print("Error:", e)

    print("\n--- Testing SSLModule ---")
    try:
        res = await SSLModule.check(target)
        print("Success:", res)
    except Exception as e:
        try:
            res = SSLModule.check(target)
            print("Success (Sync):", res)
        except Exception as e:
            print("Error:", e)

    print("\n--- Testing WebScreenshotModule ---")
    try:
        res = await WebScreenshotModule.capture(target)
        print("Success:", res)
    except Exception as e:
        try:
            res = WebScreenshotModule.capture(target)
            print("Success (Sync):", res)
        except Exception as e:
            print("Error:", e)

if __name__ == "__main__":
    asyncio.run(main())
