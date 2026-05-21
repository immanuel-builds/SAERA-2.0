"""
Analytics Service for SAERA.
Calculates math-based risk drift, chronological risk tides, and exposed service concentrations.
"""
import logging
from django.db.models import Count, Avg
from apps.scanner.models import ScanJob, Vulnerability, PortScanResult

logger = logging.getLogger(__name__)

class AnalyticsService:
    """
    Synthesizes historical scan results into mathematical trend metrics and visual analytics.
    Calculates current vs prior scan changes, risk tides, and concentration metrics.
    """

    @classmethod
    def get_risk_drift(cls, target_id: int) -> dict:
        """
        Calculates difference and percentages between the latest two completed scans.
        """
        scans = ScanJob.objects.filter(
            target_id=target_id,
            status='completed'
        ).order_by('-completed_at')[:2]
        
        if scans.count() < 2:
            # First scan base state
            if scans.count() == 1:
                curr = scans[0]
                return {
                    "score_delta": 0.0,
                    "score_drift_percentage": 0.0,
                    "threats_delta": 0,
                    "status": "baseline",
                    "new_exposures": [],
                    "resolved_exposures": []
                }
            return {
                "score_delta": 0.0,
                "score_drift_percentage": 0.0,
                "threats_delta": 0,
                "status": "insufficient_data",
                "new_exposures": [],
                "resolved_exposures": []
            }
            
        current = scans[0]
        previous = scans[1]
        
        score_t = current.aggregate_risk_score or 0.0
        score_t1 = previous.aggregate_risk_score or 0.0
        
        score_delta = round(score_t - score_t1, 2)
        
        if score_t1 > 0:
            score_drift_percentage = round((score_delta / score_t1) * 100, 1)
        else:
            score_drift_percentage = 100.0 if score_delta > 0 else 0.0
            
        threats_delta = current.vulnerabilities_found - previous.vulnerabilities_found
        
        # Determine status
        if score_delta > 0.1:
            status = "escalating"
        elif score_delta < -0.1:
            status = "improving"
        else:
            status = "stabilized"
            
        # Get active new exposures (flagged in current scan, but not in previous scan)
        prev_active_titles = set(previous.vulnerabilities.values_list('title', flat=True))
        new_findings = current.vulnerabilities.exclude(title__in=prev_active_titles)
        
        new_exposures = [
            {
                "title": f.title,
                "port": f.port,
                "service": f.service,
                "severity": f.severity
            } for f in new_findings
        ]
        
        # Get recently resolved exposures (marked resolved in the current/previous period)
        resolved_findings = Vulnerability.objects.filter(
            scan_job=previous,
            resolved=True
        )
        resolved_exposures = [
            {
                "title": r.title,
                "port": r.port,
                "service": r.service,
                "resolved_at": r.resolved_at.strftime("%Y-%m-%d %H:%M:%S") if r.resolved_at else None
            } for r in resolved_findings
        ]
        
        return {
            "score_delta": score_delta,
            "score_drift_percentage": score_drift_percentage,
            "threats_delta": threats_delta,
            "status": status,
            "new_exposures": new_exposures,
            "resolved_exposures": resolved_exposures
        }

    @classmethod
    def get_risk_tide_series(cls, target_id: int, limit: int = 15) -> list:
        """
        Chronological series of risk scores and threat counts, prepared for line charts.
        """
        scans = ScanJob.objects.filter(
            target_id=target_id,
            status='completed'
        ).only('id', 'completed_at', 'created_at', 'aggregate_risk_score', 'vulnerabilities_found').order_by('completed_at')[:limit]
        
        series = []
        for index, scan in enumerate(scans):
            date_val = scan.completed_at or scan.created_at
            series.append({
                "scan_id": scan.id,
                "date": date_val.strftime("%Y-%m-%d") if date_val else "Unknown",
                "score": scan.aggregate_risk_score or 0.0,
                "threats": scan.vulnerabilities_found,
                "phase": f"Observation {index + 1}" if index > 0 else "Baseline"
            })
        return series

    @classmethod
    def get_service_concentration(cls, target_id: int) -> list:
        """
        Calculates service concentration across a host's active open ports.
        """
        # Fetch latest completed scan
        latest_scan = ScanJob.objects.filter(
            target_id=target_id,
            status='completed'
        ).order_by('-completed_at').first()
        
        if not latest_scan:
            return []
            
        concentration = latest_scan.port_results.filter(
            state='open'
        ).values('service').annotate(count=Count('id')).order_by('-count')
        
        return [
            {
                "service": c['service'].upper() if c['service'] else "UNKNOWN",
                "count": c['count']
            } for c in concentration
        ]
