"""HTTP header analysis module."""

import re
from typing import Optional
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

from core.dataclasses import HeaderInfo


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
