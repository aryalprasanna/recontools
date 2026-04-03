"""Data classes for storing reconnaissance results."""

from dataclasses import dataclass, field
from typing import List, Optional, Dict


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
    security_headers: Dict[str, str] = field(default_factory=dict)
    raw_headers: Dict[str, str] = field(default_factory=dict)


@dataclass
class Fingerprint:
    """Store web service fingerprinting results"""
    technologies: List[str]
    versions: Dict[str, str] = field(default_factory=dict)
    cms: Optional[str] = None
    web_server: Optional[str] = None
    programming_language: Optional[str] = None
    frameworks: List[str] = field(default_factory=list)


@dataclass
class CVEMatch:
    """Store CVE matching information for a discovered technology"""
    cve_id: str
    severity: str
    description: str
    tech: str
    version: str


@dataclass
class ScreenshotData:
    """Store textual web screenshot (title, meta description)"""
    title: Optional[str] = None
    description: Optional[str] = None
    raw_text: Optional[str] = None


@dataclass
class RiskScore:
    """Store the aggregated risk assessment score"""
    score: int
    level: str  # "Low", "Medium", "High", "Critical"
    factors: List[str] = field(default_factory=list)


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
