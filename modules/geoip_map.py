"""GeoIP mapping module."""

from typing import List, Optional

from core.dataclasses import GeoIPData, IPIntel


class GeoIPModule:
    """GeoIP mapping module for geographic data visualization."""

    @staticmethod
    def create_from_ip_intel(ip_intel: IPIntel) -> Optional[GeoIPData]:
        """
        Create GeoIP data from IP intelligence.

        Args:
            ip_intel: IPIntel object

        Returns:
            GeoIPData object or None
        """
        if not ip_intel:
            return None

        return GeoIPData(
            ip=ip_intel.ip,
            country=ip_intel.country,
            region=ip_intel.region,
            city=ip_intel.city,
            lat=ip_intel.lat,
            lon=ip_intel.lon,
            confidence='high'
        )
