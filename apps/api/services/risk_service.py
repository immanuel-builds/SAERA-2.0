"""
Host-Centric Risk Service
Aggregates risk across services, vulnerabilities, and misconfigurations at the host level.
"""

from typing import List, Dict, Any
from apps.scanner.models import ScanJob, Vulnerability
from apps.scanner.risk_engine import calculate_risk

class RiskService:
    @staticmethod
    def calculate_host_risk(scan: ScanJob) -> Dict[str, Any]:
        """
        Aggregates risk posture for a host based on all discovered vulnerabilities.
        Shift from vulnerability-centric to host-centric.
        """
        vulnerabilities = scan.vulnerabilities.all()
        
        if not vulnerabilities.exists():
            return {
                "score": 0.0,
                "level": "Clear",
                "factors": ["No vulnerabilities detected"],
                "trend": "stable"
            }
            
        # 1. Weighted Aggregation
        # Critical vulns have a much higher weight in host-centric scoring
        total_weight = 0
        weighted_score_sum = 0
        
        severity_weights = {
            'critical': 1.0,
            'high': 0.7,
            'medium': 0.4,
            'low': 0.2,
            'info': 0.05
        }
        
        factors = []
        for vuln in vulnerabilities:
            weight = severity_weights.get(vuln.severity, 0.1)
            weighted_score_sum += (vuln.risk_score * weight)
            total_weight += weight
            
            # Identify key risk factors
            if vuln.severity in ['critical', 'high'] and vuln.title not in factors:
                factors.append(vuln.title)
        
        # Calculate aggregate score (0-10)
        # Using a dampening factor to prevent infinite growth but penalize multiple high vulns
        aggregate_score = min(10.0, weighted_score_sum / max(1, total_weight) * (1 + (vulnerabilities.count() * 0.05)))
        
        # Determine Level
        if aggregate_score >= 9.0:
            level = "Critical"
        elif aggregate_score >= 7.0:
            level = "High"
        elif aggregate_score >= 4.0:
            level = "Medium"
        else:
            level = "Low"
            
        return {
            "score": round(aggregate_score, 1),
            "level": level,
            "factors": factors[:5], # Top 5 factors
            "vulnerability_count": vulnerabilities.count()
        }
