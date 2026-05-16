from django.db.models import Count, Avg
from django.db.models.functions import TruncDate
from apps.scanner.models import ScanJob, Vulnerability

class AnalyticsService:
    """
    Synthesizes historical scan data into actionable security trends.
    Powers the time-series charts and prediction precursors.
    """

    @staticmethod
    def get_target_risk_trend(target_id, limit=10):
        """
        Retrieves the risk posture trajectory for a specific asset.
        """
        scans = ScanJob.objects.filter(
            target_id=target_id, 
            status='completed'
        ).order_by('-created_at')[:limit]
        
        history = []
        for scan in reversed(scans):
            # Calculate avg risk for this scan
            avg_risk = Vulnerability.objects.filter(scan_job=scan).aggregate(Avg('risk_score'))['risk_score__avg'] or 0
            
            history.append({
                "date": scan.created_at.strftime("%Y-%m-%d"),
                "scan_id": scan.id,
                "risk_score": round(avg_risk, 2),
                "threat_count": scan.vulnerabilities_found
            })
            
        return history

    @staticmethod
    def get_global_threat_distribution():
        """
        Aggregates threat levels across the entire observation grid.
        """
        distribution = Vulnerability.objects.values('severity').annotate(
            count=Count('id')
        ).order_by('-count')
        
        return {item['severity']: item['count'] for item in distribution}

    @staticmethod
    def get_drift_analysis(target_id):
        """
        Performs a differential analysis between the last two scans 
        to identify emergent and resolved threats.
        """
        last_two_scans = ScanJob.objects.filter(
            target_id=target_id, 
            status='completed'
        ).order_by('-created_at')[:2]
        
        if last_two_scans.count() < 2:
            return {"status": "insufficient_data"}
            
        current = last_two_scans[0]
        previous = last_two_scans[1]
        
        curr_titles = set(current.vulnerabilities.values_list('title', flat=True))
        prev_titles = set(previous.vulnerabilities.values_list('title', flat=True))
        
        new_threats = curr_titles - prev_titles
        resolved_threats = prev_titles - curr_titles
        
        return {
            "emergent": list(new_threats),
            "resolved": list(resolved_threats),
            "count_delta": len(new_threats) - len(resolved_threats)
        }
