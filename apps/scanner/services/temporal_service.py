"""
Temporal Intelligence Service for SAERA.
Handles differential scan audits to track port/vulnerability resolutions and recurrences.
"""
import logging
from django.utils import timezone
from apps.scanner.models import ScanJob, PortScanResult, Vulnerability

logger = logging.getLogger(__name__)

class TemporalService:
    """
    Evaluates scan findings historically across observation epochs.
    Flags resolved vectors, tracks recurrence, and maps first/last observation counts.
    """

    @classmethod
    def evaluate_scan_job(cls, scan_job: ScanJob):
        """
        Main coordinator method. Evaluates resolutions and recurrence after scan completion.
        
        Args:
            scan_job: The completed ScanJob instance.
        """
        logger.info(f"Initiating temporal intelligence evaluation for ScanJob #{scan_job.id}")
        cls.evaluate_resolutions(scan_job)
        cls.detect_recurrence(scan_job)
        
        # Integrate Stage 4 Lifecycle and Prioritization engines
        from apps.scanner.services.lifecycle_service import LifecycleService
        from apps.scanner.services.prioritization_service import PrioritizationService
        
        LifecycleService.evaluate_scan_lifecycle(scan_job)
        PrioritizationService.update_scan_priorities(scan_job)

    @classmethod
    def evaluate_resolutions(cls, scan_job: ScanJob):
        """
        Compares findings of the current scan against the immediate previous completed scan.
        Any previous open port or vulnerability that has disappeared in the current scan
        is marked as resolved with a timestamp.
        """
        target = scan_job.target
        now = timezone.now()
        
        # Fetch the immediate previous COMPLETED scan for this target
        prev_scan = ScanJob.objects.filter(
            target=target,
            status='completed'
        ).exclude(id=scan_job.id).order_by('-completed_at').first()
        
        if not prev_scan:
            logger.info("No prior completed scans found; skipping resolution evaluation.")
            return
            
        # --- 1. Evaluate Port Scan Result Resolutions ---
        curr_ports = set(scan_job.port_results.filter(state='open').values_list('port', 'protocol'))
        prev_active_ports = prev_scan.port_results.filter(state='open', resolved=False)
        
        for prev_port in prev_active_ports:
            if (prev_port.port, prev_port.protocol) not in curr_ports:
                prev_port.resolved = True
                prev_port.resolved_at = now
                prev_port.save()
                logger.info(f"[Temporal] Port {prev_port.port}/{prev_port.protocol} marked as RESOLVED (closed/filtered)")

        # --- 2. Evaluate Vulnerability/Exposure Resolutions ---
        curr_vulns = set(scan_job.vulnerabilities.values_list('title', 'port'))
        prev_active_vulns = prev_scan.vulnerabilities.filter(resolved=False)
        
        for prev_vuln in prev_active_vulns:
            if (prev_vuln.title, prev_vuln.port) not in curr_vulns:
                prev_vuln.resolved = True
                prev_vuln.resolved_at = now
                prev_vuln.save()
                logger.info(f"[Temporal] Finding '{prev_vuln.title}' marked as RESOLVED")

    @classmethod
    def detect_recurrence(cls, scan_job: ScanJob):
        """
        Identifies whether any newly discovered open ports or vulnerabilities in the current scan
        were previously resolved, flagging them as recurring and preserving their historical first_seen.
        """
        target = scan_job.target
        
        # --- 1. Detect Port Recurrence ---
        for curr_port in scan_job.port_results.filter(state='open'):
            # Find if this exact port was previously open but resolved
            was_resolved = PortScanResult.objects.filter(
                scan_job__target=target,
                port=curr_port.port,
                protocol=curr_port.protocol,
                resolved=True
            ).order_by('-resolved_at').first()
            
            if was_resolved:
                curr_port.recurring = True
                curr_port.first_seen = was_resolved.first_seen or was_resolved.created_at
                curr_port.observation_count = was_resolved.observation_count + 1
                curr_port.save()
                logger.info(f"[Temporal] Recurring port exposure detected: Port {curr_port.port}/{curr_port.protocol} (Obs Count: {curr_port.observation_count})")

        # --- 2. Detect Vulnerability/Exposure Recurrence ---
        for curr_vuln in scan_job.vulnerabilities.all():
            # Find if this exact exposure was previously flagged but resolved
            was_resolved = Vulnerability.objects.filter(
                scan_job__target=target,
                title=curr_vuln.title,
                port=curr_vuln.port,
                resolved=True
            ).order_by('-resolved_at').first()
            
            if was_resolved:
                curr_vuln.recurring = True
                curr_vuln.first_seen = was_resolved.first_seen or was_resolved.created_at
                curr_vuln.observation_count = was_resolved.observation_count + 1
                curr_vuln.save()
                logger.info(f"[Temporal] Recurring exposure detected: '{curr_vuln.title}' (Obs Count: {curr_vuln.observation_count})")
