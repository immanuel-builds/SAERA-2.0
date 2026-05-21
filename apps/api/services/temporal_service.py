"""
Temporal Intelligence Service
Tracks risk drift, threat persistence, and recurrence over time.
"""

from typing import Dict, Any
from django.utils import timezone
from apps.scanner.models import ScanJob, Vulnerability

class TemporalService:
    @staticmethod
    def analyze_risk_drift(current_scan: ScanJob) -> Dict[str, Any]:
        """
        Compares current scan risk with the previous scan of the same target.
        """
        previous_scan = ScanJob.objects.filter(
            target=current_scan.target,
            status='completed'
        ).exclude(id=current_scan.id).order_by('-completed_at').first()
        
        if not previous_scan:
            return {
                "drift_percentage": 0,
                "direction": "stable",
                "narrative": "Initial operational baseline established."
            }
            
        # Compare risk scores (assuming avg_risk_score exists or we compute it)
        # Note: We'll use the aggregate risk from our new RiskService soon
        curr_score = getattr(current_scan, 'aggregate_risk_score', 0)
        prev_score = getattr(previous_scan, 'aggregate_risk_score', 0)
        
        if prev_score == 0:
            drift = 100 if curr_score > 0 else 0
        else:
            drift = ((curr_score - prev_score) / prev_score) * 100
            
        direction = "increasing" if drift > 5 else "decreasing" if drift < -5 else "stable"
        
        return {
            "drift_percentage": round(drift, 1),
            "direction": direction,
            "previous_scan_date": previous_scan.completed_at,
            "narrative": TemporalService._generate_drift_narrative(drift, direction)
        }

    @staticmethod
    def track_threat_persistence(current_scan: ScanJob) -> Dict[str, Any]:
        """
        Identifies vulnerabilities that have persisted across multiple scans.
        """
        # This is a complex query: find vulns in current scan that also existed in previous scans
        # Simplified for now: count recurring CVEs or Titles
        current_vulns = set(current_scan.vulnerabilities.values_list('title', flat=True))
        
        previous_scans = ScanJob.objects.filter(
            target=current_scan.target,
            status='completed'
        ).exclude(id=current_scan.id).order_by('-completed_at')[:5]
        
        persistence_map = {}
        for title in current_vulns:
            count = 1
            for scan in previous_scans:
                if scan.vulnerabilities.filter(title=title).exists():
                    count += 1
                else:
                    break # Stop if it wasn't in the immediate previous scan
            persistence_map[title] = count
            
        persistent_threats = {k: v for k, v in persistence_map.items() if v > 1}
        
        return {
            "persistent_count": len(persistent_threats),
            "max_persistence": max(persistent_threats.values()) if persistent_threats else 1,
            "threats": persistent_threats
        }

    @staticmethod
    def _generate_drift_narrative(drift: float, direction: str) -> str:
        if direction == "increasing":
            return f"Risk posture has escalated by {abs(drift):.1f}% since the last observation."
        if direction == "decreasing":
            return f"Risk posture has improved by {abs(drift):.1f}% through remediation efforts."
        return "Risk posture remains stable across operational sweeps."
