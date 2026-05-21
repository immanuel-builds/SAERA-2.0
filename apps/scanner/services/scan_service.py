"""
Scan service for running Nmap, parsing results, and saving findings.
"""
import logging
from django.utils import timezone
from apps.scanner.models import ScanJob, PortScanResult, Vulnerability
from apps.scanner.adapters.nmap_adapter import NmapAdapter
from apps.scanner.parsers.nmap_parser import NmapParser
from apps.scanner.enrichers.risk_enricher import RiskEnricher
from apps.api.schemas.intelligence_schema import CanonicalIntelligence

logger = logging.getLogger(__name__)

class ScanService:
    """Coordinates one network scan from execution to saved results."""
    
    @classmethod
    def execute_and_persist(cls, scan_job_id: int) -> CanonicalIntelligence:
        """
        Coordinates the scan pipeline:
        1. Run Nmap.
        2. Parse open ports and services.
        3. Classify basic risk.
        4. Save results to the database.
        
        Args:
            scan_job_id: The primary key of the target ScanJob.
        """
        try:
            scan_job = ScanJob.objects.get(id=scan_job_id)
        except ScanJob.DoesNotExist:
            logger.error(f"Cannot run scan: ScanJob #{scan_job_id} not found.")
            raise ValueError("Scan job does not exist.")
            
        # Initialize Scanning State
        scan_job.status = 'running'
        scan_job.started_at = timezone.now()
        scan_job.current_phase = 'ENUMERATION'
        scan_job.progress = 20
        scan_job.save()
        
        target = scan_job.target.target
        config = scan_job.configuration
        port_range = config.port_range if config else "1-1000"
        scan_type = config.scan_type if config else "standard"
        
        scan_job.log("Starting scan.")
        scan_job.log(f"Target locked: {target} (Ports: {port_range}, Mode: {scan_type.capitalize()}).")
        
        # --- 1. ADAPT LAYER ---
        logger.info(f"ScanJob #{scan_job_id} entering ADAPT phase.")
        scan_job.log("Running Nmap port scan.")
        adapter = NmapAdapter()
        raw_xml = adapter.execute_scan(target, port_range, scan_type)
        scan_job.log("Nmap scan completed successfully.")
        
        scan_job.current_phase = 'CORRELATION'
        scan_job.progress = 60
        scan_job.save()
        
        # --- 2. PARSE LAYER ---
        logger.info(f"ScanJob #{scan_job_id} entering PARSE phase.")
        scan_job.log("Parsing Nmap XML results.")
        cio = NmapParser.parse_xml(raw_xml)
        scan_job.log(f"XML parsing completed. Identified {len(cio.services)} active services.")
        
        scan_job.current_phase = 'SYNTHESIS'
        scan_job.progress = 80
        scan_job.save()
        
        # --- 3. ENRICH LAYER ---
        logger.info(f"ScanJob #{scan_job_id} entering ENRICH phase.")
        scan_job.log("Classifying findings and risk.")
        cio = RiskEnricher.enrich(cio)
        scan_job.log(f"Risk calculations completed. Posture status evaluated as: {cio.risk.level if cio.risk else 'Clear'}.")
        
        scan_job.current_phase = 'PERSISTENCE'
        scan_job.progress = 90
        scan_job.save()
        
        # --- 4. PERSISTENCE LAYER ---
        logger.info(f"ScanJob #{scan_job_id} entering PERSISTENCE phase.")
        scan_job.log("Saving ports and findings to the database.")
        cls._persist_cio(scan_job, cio)
        
        # Optional history check for repeated or resolved findings.
        from apps.scanner.services.temporal_service import TemporalService
        try:
            scan_job.log("Checking previous scan history for repeated findings.")
            TemporalService.evaluate_scan_job(scan_job)
        except Exception as te:
            logger.error(f"Temporal intelligence processing error: {str(te)}")
            scan_job.log(f"Temporal auditing warning: {str(te)}")
            
        # Finalize Scan
        scan_job.status = 'completed'
        scan_job.progress = 100
        scan_job.completed_at = timezone.now()
        scan_job.save()
        scan_job.log("Scan completed successfully.")
        
        logger.info(f"ScanJob #{scan_job_id} successfully processed and persisted.")
        return cio

    @classmethod
    def _persist_cio(cls, scan_job: ScanJob, cio: CanonicalIntelligence):
        """
        Maps parsed scan results onto the database models.
        """
        from django.db import transaction
        
        target = scan_job.target
        now = timezone.now()
        
        with transaction.atomic():
                # Find the most recent COMPLETED scan job for the exact same target (excluding current job)
            prev_scan = ScanJob.objects.filter(
                target=target, 
                status='completed'
            ).exclude(id=scan_job.id).order_by('-completed_at').first()
        
            # 1. Persist PortScanResult records
            scan_job.port_results.all().delete()
            for s in cio.services:
                first_seen_time = now
                obs_count = 1
            
                # Temporal Drift check
                if prev_scan:
                    prev_port = prev_scan.port_results.filter(
                        port=s.port, 
                        protocol=s.protocol
                    ).first()
                    if prev_port:
                        first_seen_time = prev_port.first_seen or prev_port.created_at or now
                        obs_count = prev_port.observation_count + 1
                    
                PortScanResult.objects.create(
                    scan_job=scan_job,
                    port=s.port,
                    protocol=s.protocol,
                    state=s.state,
                    service=s.service_name,
                    service_version=f"{s.product or ''} {s.version or ''}".strip(),
                    banner=s.extrainfo or "",
                    first_seen=first_seen_time,
                    last_seen=now,
                    observation_count=obs_count
                )
            
            # 2. Persist Exposure Findings (saved to Vulnerability model for operational backwards-compatibility)
            scan_job.vulnerabilities.all().delete()
            for exp in cio.exposures:
                first_seen_time = now
                obs_count = 1
            
                # Temporal Drift check
                if prev_scan:
                    prev_exp = prev_scan.vulnerabilities.filter(
                        title=exp.title, 
                        port=exp.port
                    ).first()
                    if prev_exp:
                        first_seen_time = prev_exp.first_seen or prev_exp.created_at or now
                        obs_count = prev_exp.observation_count + 1
                    
                Vulnerability.objects.create(
                    scan_job=scan_job,
                    title=exp.title,
                    vuln_type='port',
                    severity=exp.severity,
                    cvss_score=exp.score,
                    port=exp.port,
                    protocol='tcp',
                    service=exp.service_name or "",
                    description=exp.description,
                    recommendation=exp.remediation or "",
                    risk_score=exp.score,
                    risk_level=exp.severity.capitalize(),
                    first_seen=first_seen_time,
                    last_seen=now,
                    observation_count=obs_count
                )
            
            # 3. Persist Confirmed Vulnerabilities (from Knowledge Base)
            if hasattr(cio, 'vulnerabilities'):
                for vuln in cio.vulnerabilities:
                    first_seen_time = now
                    obs_count = 1

                    if prev_scan:
                        prev_vuln = prev_scan.vulnerabilities.filter(
                            title=vuln.title,
                            port=vuln.port
                        ).first()
                        if prev_vuln:
                            first_seen_time = prev_vuln.first_seen or prev_vuln.created_at or now
                            obs_count = prev_vuln.observation_count + 1

                    Vulnerability.objects.create(
                        scan_job=scan_job,
                        title=vuln.title,
                        vuln_type='cve',
                        severity=vuln.severity,
                        cvss_score=vuln.cvss_score,
                        epss_score=vuln.epss_score,
                        port=vuln.port,
                        protocol='tcp',
                        service=vuln.service_name or "",
                        description=vuln.description,
                        recommendation=vuln.remediation or "",
                        cve_id=vuln.cve_id,
                        risk_score=vuln.cvss_score,
                        risk_level=vuln.severity.capitalize(),
                        first_seen=first_seen_time,
                        last_seen=now,
                        observation_count=obs_count
                    )
            
            # 4. Persist Aggregated Summary Stats directly to ScanJob
            scan_job.total_ports_scanned = len(cio.services)
            scan_job.open_ports_found = len([s for s in cio.services if s.state == "open"])
            scan_job.vulnerabilities_found = len(cio.exposures) + len(getattr(cio, 'vulnerabilities', []))
            scan_job.aggregate_risk_score = cio.risk.score if cio.risk else 0.0
            scan_job.save()
