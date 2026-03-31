"""Web service fingerprinting module."""

import re
from typing import Optional

from core.dataclasses import HeaderInfo, Fingerprint


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
