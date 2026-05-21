"""
Intelligence Service Orchestrator for SAERA.
Reconstructs the transient Canonical Intelligence Object (CIO) from database entities.
"""
from typing import Dict, Any, Optional
from apps.scanner.models import ScanJob
from apps.api.schemas.intelligence_schema import (
    CanonicalIntelligence, HostIdentity, PortServiceDetail,
    ExposureFinding, ConfirmedVulnerability, RiskPosture
)
from apps.scanner.enrichers.risk_enricher import RiskEnricher

class IntelligenceService:
    """
    The central orchestrator for SAERA's Intelligence Pipeline.
    Responsible for fetching, normalizing, and reconstructing the transient Canonical Intelligence.
    """

    @staticmethod
    def get_full_intelligence(scan_id: int) -> Optional[CanonicalIntelligence]:
        """
        Retrieves a canonical intelligence object for a specific scan,
        mapping database models directly back into the transient in-memory CIO structure.
        """
        try:
            scan = ScanJob.objects.prefetch_related(
                'target', 'vulnerabilities', 'port_results'
            ).get(id=scan_id)

            # Reconstruct Host details
            host = HostIdentity(
                ip=scan.target.target,
                hostname=scan.target.name,
                os=getattr(scan, 'os_detected', 'Unknown')
            )

            # Reconstruct Port & Service details with historical fields
            services = [
                PortServiceDetail(
                    port=p.port,
                    protocol=p.protocol,
                    state=p.state,
                    service_name=p.service,
                    product=p.service_version.split(' ')[0] if p.service_version else None,
                    version=' '.join(p.service_version.split(' ')[1:]) if p.service_version and len(p.service_version.split(' ')) > 1 else None,
                    extrainfo=p.banner,
                    cpe=[],
                    first_seen=str(p.first_seen) if p.first_seen else None,
                    last_seen=str(p.last_seen) if p.last_seen else None,
                    observation_count=p.observation_count
                ) for p in scan.port_results.all()
            ]

            # Reconstruct Exposure Findings
            exposures = [
                ExposureFinding(
                    title=v.title,
                    severity=v.severity,
                    score=v.cvss_score or 0.0,
                    description=v.description,
                    remediation=v.recommendation,
                    port=v.port,
                    service_name=v.service,
                    first_seen=str(v.first_seen) if v.first_seen else None,
                    last_seen=str(v.last_seen) if v.last_seen else None,
                    observation_count=v.observation_count
                ) for v in scan.vulnerabilities.filter(vuln_type='port')
            ]

            # Reconstruct Confirmed Vulnerabilities
            vulnerabilities = [
                ConfirmedVulnerability(
                    cve_id=v.cve_id or "UNKNOWN",
                    title=v.title,
                    severity=v.severity,
                    cvss_score=v.cvss_score or 0.0,
                    description=v.description,
                    remediation=v.recommendation,
                    port=v.port,
                    service_name=v.service,
                    first_seen=str(v.first_seen) if v.first_seen else None,
                    last_seen=str(v.last_seen) if v.last_seen else None,
                    observation_count=v.observation_count
                ) for v in scan.vulnerabilities.filter(vuln_type='cve')
            ]

            # Build and enrich transient object
            cio = CanonicalIntelligence(
                host=host,
                services=services,
                exposures=exposures,
                vulnerabilities=vulnerabilities,
                metadata={
                    "scan_id": scan.id,
                    "started_at": str(scan.started_at) if scan.started_at else None,
                    "completed_at": str(scan.completed_at) if scan.completed_at else None,
                    "duration": scan.duration,
                    "current_phase": scan.current_phase or "COMPLETED"
                }
            )

            # Enforce Risk Enrichment
            cio = RiskEnricher.enrich(cio)
            return cio

        except ScanJob.DoesNotExist:
            return None
