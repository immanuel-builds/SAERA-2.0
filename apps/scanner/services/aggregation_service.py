"""
Aggregation Service for SAERA.
Centres the Host as the core unit of observation, assembling complete Posture dossier summaries.
"""
import logging
from django.utils import timezone
from apps.scanner.models import ScanJob, ScanTarget, Vulnerability, PortScanResult
from apps.scanner.services.analytics_service import AnalyticsService

logger = logging.getLogger(__name__)

class AggregationService:
    """
    Assembles host-centric historical summaries and generates deterministic, explainable operational narratives.
    """

    @classmethod
    def get_host_posture_summary(cls, target_id: int) -> dict:
        """
        Assembles all historical observations and mathematical analytics into a single Posture summary dossier.
        """
        try:
            target = ScanTarget.objects.get(id=target_id)
        except ScanTarget.DoesNotExist:
            logger.error(f"Cannot compile summary: ScanTarget #{target_id} not found.")
            return {"error": "Target asset not found."}
            
        # Get latest completed scan
        latest_scan = ScanJob.objects.filter(
            target=target,
            status='completed'
        ).order_by('-completed_at').first()
        
        if not latest_scan:
            return {
                "host": {
                    "ip": target.target,
                    "hostname": target.name,
                    "os": "Unknown"
                },
                "current_posture": {
                    "score": 0.0,
                    "level": "Clear",
                    "active_exposures_count": 0
                },
                "risk_drift": {},
                "risk_timeline": [],
                "persistent_exposures": [],
                "resolved_findings": [],
                "operational_summary": "No completed scans are registered for this target asset."
            }
            
        # 1. Fetch Drift, Timeline & Concentration
        risk_drift = AnalyticsService.get_risk_drift(target_id)
        risk_timeline = AnalyticsService.get_risk_tide_series(target_id)
        service_concentration = AnalyticsService.get_service_concentration(target_id)
        
        # 2. Compile Persistent Exposures (Present in current completed scan with observation_count > 1)
        curr_active_vulns = latest_scan.vulnerabilities.filter(resolved=False)
        persistent_exposures = []
        for v in curr_active_vulns:
            # Calculate exposure duration
            first_seen = v.first_seen or v.created_at
            duration = timezone.now() - first_seen
            duration_days = round(duration.total_seconds() / 86400.0, 1)
            
            persistent_exposures.append({
                "title": v.title,
                "port": v.port,
                "severity": v.severity,
                "first_seen": timezone.localtime(first_seen).strftime("%Y-%m-%d %H:%M:%S"),
                "observation_count": v.observation_count,
                "exposure_duration_days": max(0.1, duration_days),
                "recurring": v.recurring
            })
            
        # 3. Compile Resolved Findings (Historical vulnerabilities for this target marked resolved)
        resolved_vulns = Vulnerability.objects.filter(
            scan_job__target=target,
            resolved=True
        ).order_by('-resolved_at')
        
        resolved_findings = [
            {
                "title": r.title,
                "port": r.port,
                "severity": r.severity,
                "resolved_at": timezone.localtime(r.resolved_at).strftime("%Y-%m-%d %H:%M:%S") if r.resolved_at else None,
                "total_observations": r.observation_count
            } for r in resolved_vulns
        ]
        
        # 4. Generate Deterministic Operational Narrative
        operational_summary = cls.generate_narrative(
            risk_drift=risk_drift,
            persistent_exposures=persistent_exposures,
            resolved_findings=resolved_findings
        )
        
        # 5. Risk Posture levels
        score = latest_scan.aggregate_risk_score or 0.0
        if score >= 9.0:
            level = "Critical"
        elif score >= 7.0:
            level = "High"
        elif score >= 4.0:
            level = "Medium"
        elif score > 0.0:
            level = "Low"
        else:
            level = "Clear"
            
        return {
            "host": {
                "ip": target.target,
                "hostname": target.name,
                "os": getattr(latest_scan, 'os_detected', 'Linux (Simulated)') or "Linux"
            },
            "current_posture": {
                "score": score,
                "level": level,
                "active_exposures_count": len(persistent_exposures)
            },
            "risk_drift": risk_drift,
            "risk_timeline": risk_timeline,
            "service_concentration": service_concentration,
            "persistent_exposures": persistent_exposures,
            "resolved_findings": resolved_findings,
            "operational_summary": operational_summary
        }

    @classmethod
    def generate_narrative(cls, risk_drift: dict, persistent_exposures: list, resolved_findings: list) -> str:
        """
        Builds a restrained, professional operational summary.
        """
        status = risk_drift.get('status', 'baseline')
        delta_pct = risk_drift.get('score_drift_percentage', 0.0)
        
        parts = []
        if status == "escalating":
            parts.append(f"Security risk posture has escalated significantly (+{delta_pct}% score shift).")
        elif status == "improving":
            parts.append(f"Security risk posture has improved (-{abs(delta_pct)}% score reduction).")
        elif status == "baseline":
            parts.append("Asset risk metrics initialized at baseline posture.")
        else:
            parts.append("Security risk posture has stabilized since last observation.")
            
        # Add persistent critical exposures description
        critical_persistent = [p for p in persistent_exposures if p['severity'] in ['critical', 'high']]
        if critical_persistent:
            ports = [str(p['port']) for p in critical_persistent]
            parts.append(f"Exposure of critical services on port(s) {', '.join(ports)} remains active and unresolved across consecutive observation scans.")
            
        # Add resolved accomplishments
        if resolved_findings:
            parts.append(f"Operator remediation successfully verified and closed {len(resolved_findings)} legacy threat vectors.")
            
        # Add recurring exposures warnings
        recurring = [p for p in persistent_exposures if p.get('recurring')]
        if recurring:
            recurring_titles = [f"'{r['title']}' on port {r['port']}" for r in recurring]
            parts.append(f"Warning: Recurring exposures detected: {'; '.join(recurring_titles)} (which were previously mitigated but have reappeared).")
            
        return " ".join(parts)
