"""CVE Mapping module to match technologies to known vulnerabilities."""

import logging
from typing import List, Optional

from core.dataclasses import Fingerprint, CVEMatch

# Local mock database for demonstration
MOCK_CVE_DB = {
    'Apache': {
        '2.4.49': [
            {'id': 'CVE-2021-41773', 'severity': 'Critical', 'description': 'Path traversal and file disclosure vulnerability in Apache HTTP Server 2.4.49'}
        ],
        '2.4.50': [
            {'id': 'CVE-2021-42013', 'severity': 'Critical', 'description': 'Path traversal and remote code execution in Apache HTTP Server 2.4.50'}
        ]
    },
    'Nginx': {
        '1.18.0': [
            {'id': 'CVE-2021-23017', 'severity': 'High', 'description': '1-byte memory overwrite in resolver'}
        ]
    },
    'PHP': {
        '8.1.0-dev': [
            {'id': 'CVE-2021-31439', 'severity': 'Critical', 'description': 'PHP 8.1.0-dev Backdoor Remote Code Execution'}
        ]
    },
    'WordPress': {
        '5.8': [
            {'id': 'CVE-2022-21661', 'severity': 'High', 'description': 'SQL injection via WP_Query in WordPress'}
        ]
    }
}


class CVEModule:
    """Module for checking fingerprint technologies against known CVEs."""

    @staticmethod
    def lookup(fingerprint: Optional[Fingerprint]) -> List[CVEMatch]:
        """Perform a lookup for known CVEs based on fingerprinted technologies and versions."""
        matches: List[CVEMatch] = []
        
        if not fingerprint:
            return matches
            
        for tech in fingerprint.technologies:
            version = fingerprint.versions.get(tech)
            
            # Use mock data mapping
            if tech in MOCK_CVE_DB:
                tech_db = MOCK_CVE_DB[tech]
                if version and version in tech_db:
                    for vuln in tech_db[version]:
                        matches.append(CVEMatch(
                            cve_id=vuln['id'],
                            severity=vuln['severity'],
                            description=vuln['description'],
                            tech=tech,
                            version=version
                        ))
                else:
                    # Provide generic "potential risks" if version is unknown or unmatched
                    # Just to show something in the TUI when testing without specific versions
                    matches.append(CVEMatch(
                        cve_id=f"POTENTIAL-{tech.upper()}-RISK",
                        severity="Low",
                        description=f"Ensure {tech} is kept up to date to prevent exploitation.",
                        tech=tech,
                        version=version or "Unknown"
                    ))
        
        return matches
