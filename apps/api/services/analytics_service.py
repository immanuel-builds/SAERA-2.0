from django.db.models import Count, Avg
from apps.scanner.models import ScanJob, Vulnerability
from apps.scanner.services.analytics_service import AnalyticsService as ScannerAnalyticsService

class AnalyticsService:
    """
    Synthesizes historical scan data into actionable security trends.
    Delegates to the authoritative core scanner services.
    """

    @staticmethod
    def get_target_risk_trend(target_id, limit=10):
        """
        Retrieves the risk posture trajectory for a specific asset.
        """
        tide = ScannerAnalyticsService.get_risk_tide_series(target_id, limit=limit)
        return [
            {
                "date": item["date"],
                "scan_id": item["scan_id"],
                "risk_score": item["score"],
                "threat_count": item["threats"]
            } for item in tide
        ]

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
        Performs a differential analysis between the last two scans.
        """
        drift = ScannerAnalyticsService.get_risk_drift(target_id)
        if drift.get("status") == "insufficient_data":
            return {"status": "insufficient_data"}
            
        return {
            "emergent": [e["title"] for e in drift.get("new_exposures", [])],
            "resolved": [r["title"] for r in drift.get("resolved_exposures", [])],
            "count_delta": drift.get("threats_delta", 0)
        }
