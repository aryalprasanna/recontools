"""Subdomain enumeration module."""

import requests
from typing import List


class SubdomainModule:
    """Subdomain enumeration module for discovering subdomains using crt.sh."""

    @staticmethod
    def enumerate(domain: str) -> List[str]:
        """Enumerate common subdomains for a domain using Certificate Transparency logs via crt.sh."""
        discovered = set()
        
        try:
            # Output=json flag triggers REST friendly format on crt.sh
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = requests.get(url, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name_value = entry.get('name_value', '')
                    # name_value can contain \n with multiple domains bundled
                    for sub in name_value.splitlines():
                        sub = sub.strip().lower()
                        # Filter out wildcard strings (*.example.com)
                        if sub.startswith('*.'):
                            sub = sub[2:]
                        if sub.endswith(domain) and sub != domain:
                            discovered.add(sub)
        except Exception:
            # In case of API timeout, offline status, or JSON parse fault, we return what was found (if any)
            pass
        
        return sorted(list(discovered))
