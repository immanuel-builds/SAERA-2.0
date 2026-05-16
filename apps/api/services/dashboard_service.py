from django.db.models import Count, Avg, Q
from apps.scanner.models import ScanJob, Vulnerability
from apps.scanner.prediction_engine import predictor
from apps.api.services.analytics_service import AnalyticsService

class DashboardService:
    """
    Service layer for aggregating complex dashboard telemetry.
    Ensures views remain lightweight and logic is centralized.
    """

    @staticmethod
    def get_dashboard_context(user):
        """
        Synthesizes the complete dashboard intelligence context for a user.
        """
        # 1. Base Querysets
        if user.is_admin:
            scans = ScanJob.objects.all()
            vulns = Vulnerability.objects.all()
        else:
            scans = ScanJob.objects.filter(initiated_by=user)
            vulns = Vulnerability.objects.filter(scan_job__initiated_by=user)

        # 2. Key Metrics
        total_scans = scans.count()
        completed_scans = scans.filter(status='completed').count()
        running_scans = scans.filter(status='running').count()
        total_vulnerabilities = vulns.count()
        
        avg_risk_score = vulns.aggregate(avg=Avg('risk_score'))['avg'] or 0
        high_risk_hosts = vulns.filter(risk_score__gte=7.0).values('scan_job__target').distinct().count()
        
        # 3. Recent Activity
        recent_scans = scans.select_related('target')[:5]
        recent_vulns = vulns.filter(severity='critical').select_related('scan_job', 'scan_job__target').order_by('-created_at')[:10]

        # 4. Threat Distribution
        vuln_distribution = vulns.values('severity').annotate(count=Count('id'))
        severity_counts = {s: 0 for s, _ in Vulnerability.SEVERITY_CHOICES}
        for item in vuln_distribution:
            severity_counts[item['severity']] = item['count']

        # 5. Predictive Analytics
        has_critical = vulns.filter(severity='critical').exists()
        prediction_likelihood = predictor.predict_risk_probability(
            num_ports=vulns.filter(vuln_type='port').count(),
            num_services=vulns.filter(vuln_type='service').count(),
            has_critical=has_critical,
            avg_risk=avg_risk_score
        )

        attack_surface_score = round(max(0, 100 - (avg_risk_score * 10)), 1)

        # 6. Trend Data (Flow Rhythm)
        # We'll take the global trend or the user's trend
        if user.is_admin:
            # For simplicity, we aggregate recent scans
            latest_scans = ScanJob.objects.filter(status='completed').order_by('-created_at')[:10]
            risk_trends = []
            for s in reversed(latest_scans):
                risk_trends.append({
                    "date": s.created_at.strftime("%H:%M"),
                    "score": s.vulnerabilities.aggregate(avg=Avg('risk_score'))['avg'] or 0
                })
        else:
            # User specific trends
            latest_scans = scans.filter(status='completed').order_by('-created_at')[:10]
            risk_trends = [{"date": s.created_at.strftime("%H:%M"), "score": s.vulnerabilities.aggregate(avg=Avg('risk_score'))['avg'] or 0} for s in reversed(latest_scans)]

        return {
            'total_scans': total_scans,
            'completed_scans': completed_scans,
            'running_scans': running_scans,
            'total_vulnerabilities': total_vulnerabilities,
            'critical_vulns': severity_counts.get('critical', 0),
            'high_vulns': severity_counts.get('high', 0),
            'recent_scans': recent_scans,
            'recent_vulns': recent_vulns,
            'severity_counts': severity_counts,
            'avg_risk_score': round(avg_risk_score, 1),
            'high_risk_hosts': high_risk_hosts,
            'attack_surface_score': attack_surface_score,
            'threat_likelihood': prediction_likelihood,
            'risk_trends': risk_trends,
        }
