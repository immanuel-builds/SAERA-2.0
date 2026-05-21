"""
Lifecycle Service for SAERA.
Coordinates deterministic operational state transitions for exposure items and service ports.
"""
import logging
from django.utils import timezone
from apps.scanner.models import ScanJob, Vulnerability, PortScanResult

logger = logging.getLogger(__name__)

class LifecycleService:
    """
    Coordinates state transitions strictly locked to the Small, Defensive State Model:
    ACTIVE, RECURRING, ESCALATED, RESOLVED, SUPPRESSED.
    """

    @classmethod
    def evaluate_scan_lifecycle(cls, scan_job: ScanJob):
        """
        Coordinates lifecycle state evaluations for ports and vulnerability exposures in a completed scan.
        """
        import time
        from apps.scanner.models import ObservatoryHealthLog
        
        start_time = time.perf_counter()
        logger.info(f"Initiating lifecycle evaluation state transitions for ScanJob #{scan_job.id}")
        target = scan_job.target
        
        try:
            # 1. Update PortScanResult Lifecycle States
            for port in scan_job.port_results.all():
                if port.is_suppressed:
                    port.lifecycle_state = 'suppressed'
                elif port.resolved:
                    port.lifecycle_state = 'resolved'
                elif port.recurring:
                    port.lifecycle_state = 'recurring'
                else:
                    port.lifecycle_state = 'active'
                port.save()

            # Fetch previous completed scan to check for severity escalations
            prev_scan = ScanJob.objects.filter(
                target=target,
                status='completed'
            ).exclude(id=scan_job.id).order_by('-completed_at').first()

            # 2. Update Vulnerability Exposure Lifecycle States
            for vuln in scan_job.vulnerabilities.all():
                if vuln.is_suppressed:
                    vuln.lifecycle_state = 'suppressed'
                elif vuln.resolved:
                    vuln.lifecycle_state = 'resolved'
                elif vuln.recurring:
                    vuln.lifecycle_state = 'recurring'
                else:
                    # Check for severity escalations since the previous observation
                    was_escalated = False
                    if prev_scan:
                        prev_vuln = prev_scan.vulnerabilities.filter(
                            title=vuln.title,
                            port=vuln.port
                        ).first()
                        if prev_vuln:
                            # Compare numeric severity levels
                            if vuln.severity_order > prev_vuln.severity_order:
                                was_escalated = True

                    if was_escalated:
                        vuln.lifecycle_state = 'escalated'
                    else:
                        vuln.lifecycle_state = 'active'
                
                vuln.save()

            duration_ms = (time.perf_counter() - start_time) * 1000.0
            try:
                ObservatoryHealthLog.objects.create(
                    metric_name='lifecycle_evaluation_duration',
                    duration_ms=round(duration_ms, 2),
                    status='success'
                )
            except Exception as log_err:
                logger.warning(f"Could not persist lifecycle health log: {str(log_err)}")
                
            logger.info("[Lifecycle] Completed exposure and service lifecycle evaluations")
        except Exception as e:
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            try:
                ObservatoryHealthLog.objects.create(
                    metric_name='lifecycle_evaluation_duration',
                    duration_ms=round(duration_ms, 2),
                    status='failure',
                    message=str(e)
                )
            except Exception:
                pass
            raise e

    @classmethod
    def toggle_suppression(cls, vulnerability_id: int, suppressed: bool, reason: str = "", analyst_name: str = "Analyst") -> Vulnerability:
        """
        Toggles suppression state on a specific vulnerability finding.
        """
        vuln = Vulnerability.objects.get(id=vulnerability_id)
        vuln.is_suppressed = suppressed
        if suppressed:
            vuln.suppressed_at = timezone.now()
            vuln.suppressed_reason = reason
            vuln.lifecycle_state = 'suppressed'
        else:
            vuln.suppressed_at = None
            vuln.suppressed_reason = ""
            # Fall back to base temporal attributes
            if vuln.resolved:
                vuln.lifecycle_state = 'resolved'
            elif vuln.recurring:
                vuln.lifecycle_state = 'recurring'
            else:
                vuln.lifecycle_state = 'active'
        
        vuln.save()
        
        # Trigger prioritization updates for this target's exposures
        from apps.scanner.services.prioritization_service import PrioritizationService
        vuln.priority_score = PrioritizationService.calculate_vulnerability_priority(vuln)
        vuln.save()
        
        logger.info(f"[Lifecycle] Suppressed state toggled for Vulnerability #{vulnerability_id} (Suppressed: {suppressed})")
        return vuln
