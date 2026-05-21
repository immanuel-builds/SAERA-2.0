from django.db.models import Count, Avg, Q
from django.core.cache import cache
from apps.scanner.models import ScanJob, Vulnerability
from apps.api.services.risk_service import RiskService
from apps.api.services.temporal_service import TemporalService

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
        cache_key = f"dashboard_context_{user.id}"
        cached_data = cache.get(cache_key)
        if cached_data:
            return cached_data

        # 1. Base Querysets
        if user.is_admin:
            scans = ScanJob.objects.all()
            vulns = Vulnerability.objects.all()
        else:
            scans = ScanJob.objects.filter(initiated_by=user)
            vulns = Vulnerability.objects.filter(scan_job__initiated_by=user)

        # 2. Key Metrics (Intelligence-Driven)
        total_scans = scans.count()
        completed_scans = scans.filter(status='completed').count()
        running_scans = scans.filter(status='running').count()

        # 3. Host-Centric Posture
        # Identify top high-risk hosts using aggregated risk
        # Note: In production, we'd have a 'Host' model, here we use 'ScanTarget'
        high_risk_targets = scans.filter(status='completed').select_related('target').prefetch_related('vulnerabilities', 'port_results').order_by('-aggregate_risk_score')[:5]

        avg_risk_score = scans.filter(status='completed').aggregate(avg=Avg('aggregate_risk_score'))['avg'] or 0

        # 4. Temporal Intelligence (Global Drift)
        latest_scan = scans.filter(status='completed').order_by('-completed_at').first()
        drift_data = TemporalService.analyze_risk_drift(latest_scan) if latest_scan else {}

        # 5. Risk Distribution
        severity_counts = vulns.values('severity').annotate(count=Count('id'))
        severity_map = {s: 0 for s, _ in Vulnerability.SEVERITY_CHOICES}
        for item in severity_counts:
            severity_map[item['severity']] = item['count']

        # 6. Trend Data (Temporal Flow)
        recent_history = scans.filter(status='completed', completed_at__isnull=False).order_by('-completed_at')[:12]
        risk_trends = [
            {"date": s.completed_at.strftime("%m.%d"), "score": s.aggregate_risk_score}
            for s in reversed(recent_history)
        ]

        # 7. Recent Critical Intelligence (For UI & Tests)
        recent_vulns = vulns.filter(severity='critical').select_related('scan_job', 'scan_job__target').order_by('-created_at')[:5]

        # 8. Operational Priority Queue (Top 5 Capped, Persistent & Recurring)
        priority_vulns = vulns.filter(resolved=False, is_suppressed=False).select_related('scan_job', 'scan_job__target').order_by('-priority_score')[:5]

        # 9. Lifecycle Analytics (Operational Flow)
        lifecycle_counts = vulns.values('lifecycle_state').annotate(count=Count('id'))
        lifecycle_map = {'active': 0, 'recurring': 0, 'escalated': 0, 'resolved': 0, 'suppressed': 0}
        for item in lifecycle_counts:
            lifecycle_map[item['lifecycle_state']] = item['count']

        context = {
            'total_scans': total_scans,
            'completed_scans': completed_scans,
            'running_scans': running_scans,
            'avg_risk_score': round(avg_risk_score, 1),
            'drift': drift_data,
            'high_risk_targets': high_risk_targets,
            'severity_counts': severity_map,
            'risk_trends': risk_trends,
            'recent_scans': scans.select_related('target')[:8],
            'recent_vulns': recent_vulns,
            'priority_vulns': priority_vulns,
            'total_vulns': vulns.count(),
            'lifecycle_flow': lifecycle_map
        }

        # Cache the operational context dashboard context for 30 seconds to optimize DB loading
        cache.set(cache_key, context, 30)
        return context
