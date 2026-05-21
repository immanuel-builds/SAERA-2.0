"""
Prioritization Service for SAERA.
Implements the explainable, capped priority scoring algorithm for exposures and port mappings.
"""
import logging
from django.utils import timezone
from apps.scanner.models import Vulnerability, PortScanResult

logger = logging.getLogger(__name__)

class PrioritizationService:
    """
    Manages deterministic urgency scores mapping to bounded categories (Low, Moderate, High, Critical).
    """

    @classmethod
    def calculate_vulnerability_priority(cls, vuln: Vulnerability) -> float:
        """
        Calculates transparency score for a specific vulnerability finding:
        Priority = min((CVSS * 1.0) + (Recurrence * 1.5) + (PersistenceDays * 0.2) + (AffectedHosts * 0.5), 100.0)
        """
        if vuln.is_suppressed:
            return 0.0

        # 1. CVSS Base Score (Fallback to severity weight if CVSS is absent)
        cvss = vuln.cvss_score or 0.0
        if cvss == 0.0:
            severity_weights = {'critical': 9.0, 'high': 7.0, 'medium': 4.5, 'low': 2.0, 'info': 0.0}
            cvss = severity_weights.get(vuln.severity, 0.0)

        # 2. Recurrence Count Multiplier
        recurrence_count = vuln.observation_count - 1 if vuln.recurring else 0

        # 3. Persistence Days Multiplier
        persistence_days = 0
        if vuln.first_seen:
            delta = timezone.now() - vuln.first_seen
            persistence_days = max(delta.days, 0)

        # 4. Affected Hosts Count (Blast Radius)
        # Count unique ScanTargets having this unresolved vulnerability title active currently
        affected_hosts = Vulnerability.objects.filter(
            title=vuln.title,
            resolved=False
        ).values('scan_job__target').distinct().count()
        affected_hosts = max(affected_hosts, 1)

        # Apply Capped Formula
        score = (cvss * 1.0) + (recurrence_count * 1.5) + (persistence_days * 0.2) + (affected_hosts * 0.5)
        return min(round(score, 1), 100.0)

    @classmethod
    def calculate_port_priority(cls, port_result: PortScanResult) -> float:
        """
        Calculates transparency score for a service exposure:
        Priority = min((BasePortScore * 1.0) + (Recurrence * 1.5) + (PersistenceDays * 0.2), 100.0)
        """
        if port_result.is_suppressed or port_result.state != 'open':
            return 0.0

        # Basic port importance weights
        critical_ports = {22, 23, 3389, 445, 139, 3306, 5432, 1521, 21}
        base_score = 8.0 if port_result.port in critical_ports else 3.0

        # Recurrence
        recurrence_count = port_result.observation_count - 1 if port_result.recurring else 0

        # Persistence
        persistence_days = 0
        if port_result.first_seen:
            delta = timezone.now() - port_result.first_seen
            persistence_days = max(delta.days, 0)

        score = (base_score * 1.0) + (recurrence_count * 1.5) + (persistence_days * 0.2)
        return min(round(score, 1), 100.0)

    @classmethod
    def update_scan_priorities(cls, scan_job):
        """
        Calculates and updates priority scores for all vulnerability and port findings in a scan.
        """
        logger.info(f"Recalculating prioritization urgency for ScanJob #{scan_job.id}")
        
        # Update Port Urgency Scores
        for port in scan_job.port_results.all():
            port.priority_score = cls.calculate_port_priority(port)
            port.save()

        # Update Vulnerability Urgency Scores
        for vuln in scan_job.vulnerabilities.all():
            vuln.priority_score = cls.calculate_vulnerability_priority(vuln)
            vuln.save()

        logger.info("[Prioritization] Successfully processed scan prioritization scores")
