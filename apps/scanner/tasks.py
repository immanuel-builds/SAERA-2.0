"""
Celery Tasks for Asynchronous Vulnerability Scanning
"""
from celery import shared_task
from django.utils import timezone
from .models import ScanJob, Vulnerability, PortScanResult
from .scanners.port_scanner import PortScanner
from .scanners.service_scanner import ServiceScanner
from .scanners.vuln_detector import VulnerabilityDetector
from .scanners.cve_lookup import CVELookup
from django.conf import settings
import logging

logger = logging.getLogger(__name__)


@shared_task(bind=True)
def scan_target_task(self, scan_job_id):
    """
    Main scanning task orchestration
    
    Args:
        scan_job_id: ID of the ScanJob to execute
    """
    try:
        # Get the scan job
        scan_job = ScanJob.objects.get(id=scan_job_id)
        scan_job.status = 'running'
        scan_job.started_at = timezone.now()
        scan_job.celery_task_id = self.request.id
        scan_job.save()
        
        target = scan_job.target
        config = scan_job.configuration
        
        # Phase 1: Port Scanning
        scan_job.current_phase = 'Port Scanning'
        scan_job.progress = 10
        scan_job.save()
        
        port_scanner = PortScanner()
        port_results = port_scanner.scan_ports(
            target=target.target,
            ports=config.port_range if config else '1-1000',
            scan_type=config.scan_type if config else 'standard'
        )
        
        # Save port scan results
        _save_port_results(scan_job, port_results)
        
        scan_job.progress = 30
        scan_job.total_ports_scanned = port_results.get('total_ports_scanned', 0)
        scan_job.open_ports_found = port_results.get('open_ports', 0)
        scan_job.save()
        
        # Phase 2: Service Enumeration
        if config and config.enable_service_detection:
            scan_job.current_phase = 'Service Enumeration'
            scan_job.progress = 40
            scan_job.save()
            
            service_scanner = ServiceScanner()
            services = service_scanner.enumerate_services(port_results)
            
            # Check for outdated services
            outdated_services = service_scanner.get_outdated_services(services)
            for service in outdated_services:
                # Mark as outdated in the services list
                for s in services:
                    if s['port'] == service['port']:
                        s['outdated'] = True
                        s['recommended_version'] = service.get('recommended_version', '')
            
            scan_job.progress = 50
            scan_job.save()
        else:
            services = []
        
        # Phase 3: Vulnerability Detection
        if config and config.enable_vuln_detection:
            scan_job.current_phase = 'Vulnerability Detection'
            scan_job.progress = 60
            scan_job.save()
            
            vuln_detector = VulnerabilityDetector()
            open_ports = port_scanner.get_open_ports(port_results)
            vulnerabilities = vuln_detector.detect_vulnerabilities(services, open_ports)
            
            scan_job.progress = 70
            scan_job.save()
            
            # Phase 4: CVE Lookup (optional)
            if settings.NVD_API_KEY and services:
                scan_job.current_phase = 'CVE Lookup'
                scan_job.progress = 80
                scan_job.save()
                
                cve_lookup = CVELookup(api_key=settings.NVD_API_KEY)
                cve_vulns = cve_lookup.lookup_cves_for_services(services)
                vulnerabilities.extend(cve_vulns)
            
            # Save vulnerabilities
            _save_vulnerabilities(scan_job, vulnerabilities)
            
            # Update scan job statistics
            scan_job.vulnerabilities_found = len(vulnerabilities)
            scan_job.critical_vulns = len([v for v in vulnerabilities if v['severity'] == 'critical'])
            scan_job.high_vulns = len([v for v in vulnerabilities if v['severity'] == 'high'])
            scan_job.medium_vulns = len([v for v in vulnerabilities if v['severity'] == 'medium'])
            scan_job.low_vulns = len([v for v in vulnerabilities if v['severity'] == 'low'])
        
        # Complete the scan
        scan_job.status = 'completed'
        scan_job.progress = 100
        scan_job.current_phase = 'Completed'
        scan_job.completed_at = timezone.now()
        scan_job.save()
        
        logger.info(f"Scan job #{scan_job_id} completed successfully")
        return {
            'status': 'success',
            'scan_job_id': scan_job_id,
            'vulnerabilities_found': scan_job.vulnerabilities_found,
        }
        
    except ScanJob.DoesNotExist:
        logger.error(f"Scan job #{scan_job_id} not found")
        return {'status': 'error', 'message': 'Scan job not found'}
    
    except Exception as e:
        logger.error(f"Error in scan job #{scan_job_id}: {str(e)}")
        
        # Mark scan as failed
        try:
            scan_job = ScanJob.objects.get(id=scan_job_id)
            scan_job.status = 'failed'
            scan_job.error_message = str(e)
            scan_job.completed_at = timezone.now()
            scan_job.save()
        except:
            pass
        
        return {'status': 'error', 'message': str(e)}


def _save_port_results(scan_job, port_results):
    """Save port scan results to database"""
    for host, host_info in port_results.get('hosts', {}).items():
        for proto, ports_list in host_info.get('protocols', {}).items():
            for port_info in ports_list:
                PortScanResult.objects.update_or_create(
                    scan_job=scan_job,
                    port=port_info['port'],
                    protocol=proto,
                    defaults={
                        'state': port_info['state'],
                        'service': port_info.get('service', ''),
                        'service_version': f"{port_info.get('product', '')} {port_info.get('version', '')}".strip(),
                        'banner': f"{port_info.get('product', '')} {port_info.get('version', '')} {port_info.get('extrainfo', '')}".strip(),
                    },
                )


def _save_vulnerabilities(scan_job, vulnerabilities):
    """Save detected vulnerabilities to database"""
    for vuln in vulnerabilities:
        # Calculate CVSS if not provided
        cvss_score = vuln.get('cvss_score')
        if not cvss_score:
            detector = VulnerabilityDetector()
            cvss_score = detector.calculate_cvss_score(vuln)
        
        Vulnerability.objects.create(
            scan_job=scan_job,
            vuln_type=vuln.get('vuln_type', 'other'),
            severity=vuln.get('severity', 'medium'),
            cvss_score=cvss_score,
            title=vuln.get('title', 'Unknown Vulnerability'),
            description=vuln.get('description', ''),
            impact=vuln.get('impact', ''),
            recommendation=vuln.get('recommendation', ''),
            port=vuln.get('port'),
            protocol=vuln.get('protocol', 'tcp'),
            service=vuln.get('service', ''),
            service_version=vuln.get('service_version', ''),
            cve_id=vuln.get('cve_id', ''),
            cve_url=vuln.get('cve_url', ''),
            evidence=vuln.get('evidence', ''),
        )


@shared_task
def cleanup_old_scans():
    """Periodic task to clean up old scan results"""
    from datetime import timedelta
    cutoff_date = timezone.now() - timedelta(days=30)
    
    old_scans = ScanJob.objects.filter(created_at__lt=cutoff_date, status='completed')
    count = old_scans.count()
    old_scans.delete()
    
    logger.info(f"Cleaned up {count} old scan jobs")
    return {'cleaned': count}
