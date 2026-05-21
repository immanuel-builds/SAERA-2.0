"""
Risk & Exposure Enricher for SAERA.
Analyzes open ports and services, identifies exposure findings, and calculates a transparent host risk score.
"""
import logging
from typing import List
from apps.api.schemas.intelligence_schema import (
    CanonicalIntelligence, RiskPosture, ExposureFinding, ConfirmedVulnerability
)

logger = logging.getLogger(__name__)

class RiskEnricher:
    """Enriches the CanonicalIntelligence object with explainable risk metrics and exposure findings"""
    
    # Port criticality weights (Scale 0-10)
    CRITICAL_PORTS = {
        21: ("Insecure File Transfer Protocol (FTP)", 6.5, "high"),
        23: ("Legacy Unencrypted Telnet Terminal", 8.5, "high"),
        445: ("Server Message Block (SMB)", 9.5, "critical"),
        3389: ("Remote Desktop Protocol (RDP)", 8.0, "high"),
        3306: ("MySQL Database Service", 7.5, "high"),
        1433: ("Microsoft SQL Server Database Port", 7.5, "high"),
        9200: ("Elasticsearch Service", 8.5, "high"),
        2049: ("Network File System (NFS) Share", 7.0, "high"),
    }

    @classmethod
    def enrich(cls, cio: CanonicalIntelligence) -> CanonicalIntelligence:
        """
        Enriches a CanonicalIntelligence object by evaluating exposures and open services.
        
        Args:
            cio: The normalized CanonicalIntelligence object to enrich.
        """
        factors: List[str] = []
        critical_services: List[str] = []
        score_accumulator = 0.0
        max_seen_weight = 0.0
        
        # Filter for open ports/services
        open_services = [s for s in cio.services if s.state == "open"]
        
        # Reset and prepare the exposures and vulnerabilities lists
        cio.exposures = []
        
        for service in open_services:
            port = service.port
            service_name = service.service_name
            
            if port in cls.CRITICAL_PORTS:
                display_name, weight, severity = cls.CRITICAL_PORTS[port]
                critical_services.append(service_name)
                
                # Dynamic explaining factor
                factors.append(f"Exposed {display_name} (Port {port})")
                
                # Maintain weights
                score_accumulator += weight * 0.35
                max_seen_weight = max(max_seen_weight, weight)
                
                # Append standard exposure finding
                cio.exposures.append(ExposureFinding(
                    title=f"Critical Port Exposure: {display_name}",
                    severity=severity,
                    score=weight,
                    description=(
                        f"Port {port} ({service_name}) was found open and publicly reachable. "
                        f"Exposing high-criticality services directly to the WAN invites unauthorized access, "
                        f"credential brute forcing, and exploit attempts."
                    ),
                    remediation=(
                        f"Disable the service if not needed, bind it strictly to a local private interface "
                        f"(127.0.0.1), or apply IP-based access controls via software firewall rules."
                    ),
                    port=port,
                    service_name=service_name
                ))
            else:
                # Standard open port exposure (non-critical, e.g. standard HTTP/HTTPS/SSH)
                score_accumulator += 0.4
                
                # Provide lightweight exposure info for other standard ports
                cio.exposures.append(ExposureFinding(
                    title=f"Exposed Service: {service_name.upper()} (Port {port})",
                    severity="info",
                    score=1.5,
                    description=(
                        f"Service {service_name} is open and active on port {port}. "
                        f"This increases the general reconnaissance footprint of the host."
                    ),
                    remediation="Audit service necessity; limit visibility if possible.",
                    port=port,
                    service_name=service_name
                ))
                
        # NEW: Knowledge Base CPE Lookup & EPSS Integration
        cio.vulnerabilities = []
        from apps.knowledge.models import VulnerabilityReference
        from apps.scanner.risk_engine import calculate_risk
        from django.db.models import Q

        for service in open_services:
            # Simple substring matching for CPE or service name in the demo dataset
            queries = Q(references__icontains=service.service_name)
            for cpe in service.cpe:
                queries |= Q(references__icontains=cpe)

            if service.service_name or service.cpe:
                matches = VulnerabilityReference.objects.filter(queries).distinct()
                for match in matches:
                    # Calculate new defensible risk score
                    final_score, level = calculate_risk(match)

                    # Update aggregate tracker
                    score_accumulator += final_score * 0.5
                    max_seen_weight = max(max_seen_weight, final_score)
                    factors.append(f"Vulnerable {service.service_name} ({match.cve_id})")

                    cio.vulnerabilities.append(ConfirmedVulnerability(
                        cve_id=match.cve_id or "Unknown",
                        title=match.title,
                        severity=level.lower(),
                        cvss_score=final_score,
                        epss_score=match.epss_score or 0.0,
                        description=match.description,
                        remediation=match.remediation,
                        port=service.port,
                        service_name=service.service_name
                    ))

        # Aggregate Risk Score calculation:
        # We start with the highest critical port/vuln weight found, then add dampened weight
        # Capped cleanly at 10.0
        aggregate_score = min(10.0, max_seen_weight + (score_accumulator * 0.15))

        # Determine Severity Level
        if aggregate_score >= 9.0:
            level = "Critical"
        elif aggregate_score >= 7.0:
            level = "High"
        elif aggregate_score >= 4.0:
            level = "Medium"
        elif aggregate_score > 0.0:
            level = "Low"
        else:
            level = "Clear"
            factors.append("Host attack surface is fully minimized.")

        cio.risk = RiskPosture(
            score=round(aggregate_score, 1),
            level=level,
            factors=list(set(factors))[:5],  # Top 5 unique explainable factors
            critical_services=list(set(critical_services))
        )

        return cio
