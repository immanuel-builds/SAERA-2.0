"""
Direct scan runner.

This module intentionally avoids an external task queue. A scan is executed
from the Django request flow so the project stays simple to install and explain.
"""
import logging

from django.utils import timezone

from .models import ScanJob

logger = logging.getLogger(__name__)


def run_scan_job(scan_job_id, ip_address="127.0.0.1", user_agent="NetVuln direct scan"):
    """Run one scan and persist its results."""
    try:
        from .services.scan_service import ScanService

        ScanService.execute_and_persist(scan_job_id)
        scan_job = ScanJob.objects.get(id=scan_job_id)

        from apps.accounts.models import AuditLog
        AuditLog.objects.create(
            user=scan_job.initiated_by,
            action='scan_completed',
            description=(
                f"Scan completed for {scan_job.target.target} ({scan_job.target.name}). "
                f"Found {scan_job.vulnerabilities.count()} findings across "
                f"{scan_job.open_ports_found} open ports."
            ),
            ip_address=ip_address,
            user_agent=user_agent,
        )

        logger.info("Scan job #%s completed successfully", scan_job_id)
        return {'status': 'success', 'scan_job_id': scan_job_id}

    except ScanJob.DoesNotExist:
        logger.error("Scan job #%s not found", scan_job_id)
        raise

    except Exception as exc:
        logger.error("Error in scan job #%s: %s", scan_job_id, exc)
        _mark_scan_failed(scan_job_id, exc, ip_address, user_agent)
        raise


def _mark_scan_failed(scan_job_id, exc, ip_address, user_agent):
    try:
        scan_job = ScanJob.objects.get(id=scan_job_id)
        scan_job.status = 'failed'
        scan_job.error_message = str(exc)
        scan_job.completed_at = timezone.now()
        scan_job.save(update_fields=['status', 'error_message', 'completed_at'])

        try:
            scan_job.log(f"Scan failed: {exc}")
        except Exception:
            logger.exception("Failed to write scan log for job #%s", scan_job_id)

        from apps.accounts.models import AuditLog
        AuditLog.objects.create(
            user=scan_job.initiated_by,
            action='scan_failed',
            description=(
                f"Scan failed for {scan_job.target.target} ({scan_job.target.name}). "
                f"Error: {exc}"
            ),
            ip_address=ip_address,
            user_agent=user_agent,
        )
    except Exception:
        logger.exception("Failed to mark scan job #%s as failed", scan_job_id)
