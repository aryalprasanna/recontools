"""Intel Aggregator module to compute Risk Score."""

from typing import Dict, Any, List
from core.dataclasses import RiskScore, PortStatus, CVEMatch


class IntelAggregatorModule:
    """Aggregate results into a single risk score."""

    @staticmethod
    def calculate_risk(results: Dict[str, Any]) -> RiskScore:
        """Calculate the risk based on the scan results."""
        score = 0
        factors: List[str] = []
        
        # Check Open Ports
        ports: List[PortStatus] = results.get('ports', [])
        open_critical_ports = [p.port for p in ports if p.status == 'open' and p.port in [21, 22, 23, 445, 3389]]
        if open_critical_ports:
            score += 30
            factors.append(f"Critical ports open: {open_critical_ports}")
        elif any(p.status == 'open' for p in ports):
            score += 10
            factors.append(f"Has open ports")
            
        # Check SSL
        ssl = results.get('ssl')
        if ssl:
            if ssl.is_expired:
                score += 40
                factors.append("SSL Certificate is expired")
        else:
            if any(p.port == 443 and p.status == 'open' for p in ports):
                score += 20
                factors.append("Port 443 open but SSL scan failed or missing")
                
        # Check CVEs
        cves: List[CVEMatch] = results.get('cves', [])
        critical_cves = [c for c in cves if c.severity.lower() == 'critical']
        high_cves = [c for c in cves if c.severity.lower() == 'high']
        
        if critical_cves:
            score += 50
            factors.append(f"Found {len(critical_cves)} critical CVEs")
        if high_cves:
            score += 30
            factors.append(f"Found {len(high_cves)} high severity CVEs")
            
        # Headers Risk
        headers = results.get('headers')
        if headers:
            missing_security = []
            expected = ['Strict-Transport-Security', 'X-Content-Type-Options', 'X-Frame-Options']
            for e in expected:
                if e.lower() not in headers.raw_headers:
                    missing_security.append(e)
            if missing_security:
                score += 10
                factors.append(f"Missing security headers: {len(missing_security)}")
                
        # Determine Level
        if score >= 80:
            level = "Critical"
        elif score >= 50:
            level = "High"
        elif score >= 20:
            level = "Medium"
        else:
            level = "Low"
            
        if not factors:
            factors.append("No significant misconfigurations identified")
            
        return RiskScore(score=score, level=level, factors=factors)
