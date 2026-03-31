"""IP intelligence module."""

import json
import socket
from typing import Optional
from urllib.error import HTTPError, URLError
from urllib.request import urlopen

from core.dataclasses import IPIntel


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
