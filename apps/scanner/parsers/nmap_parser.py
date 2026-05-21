"""
Nmap XML Parser for SAERA.
Parses Nmap XML output safely and normalizes it into the CanonicalIntelligence schema.
"""
import xml.etree.ElementTree as ET
import logging
from typing import List, Optional
from apps.api.schemas.intelligence_schema import CanonicalIntelligence, HostIdentity, PortServiceDetail

logger = logging.getLogger(__name__)

class NmapParser:
    """Parses raw Nmap XML data into a clean in-memory CIO structure"""
    
    @staticmethod
    def parse_xml(xml_content: str) -> CanonicalIntelligence:
        """
        Parses raw Nmap XML string.
        
        Args:
            xml_content: Raw XML output from Nmap.
        """
        import time
        from apps.scanner.models import ObservatoryHealthLog
        
        start_time = time.perf_counter()
        
        if not xml_content or not xml_content.strip():
            logger.error("Scan output was empty. Returning sterile skeleton.")
            skeleton_host = HostIdentity(ip="0.0.0.0", hostname="Sterile Posture Fallback")
            return CanonicalIntelligence(host=skeleton_host)
            
        try:
            # Neutralize XML External Entity (XXE) injection vulnerabilities
            # Python's standard ET.XMLParser is secure by default against XXE starting from Python 3.7+
            parser = ET.XMLParser()
            root = ET.fromstring(xml_content.strip(), parser=parser)
            
            host_elem = root.find("host")
            if host_elem is None:
                logger.warning("No hosts detected in the scan output.")
                # Return empty skeleton so downstream processing doesn't crash on sterile sweeps
                skeleton_host = HostIdentity(ip="0.0.0.0", hostname="Inactive Host")
                return CanonicalIntelligence(host=skeleton_host)
                
            # 1. Parse Host Identity
            ip_elem = host_elem.find("address[@addrtype='ipv4']")
            if ip_elem is None:
                # Fallback to general address search
                ip_elem = host_elem.find("address")
            ip = ip_elem.get("addr") if ip_elem is not None else "127.0.0.1"
            
            hostname_elem = host_elem.find("hostnames/hostname")
            hostname = hostname_elem.get("name") if hostname_elem is not None else None
            
            mac_elem = host_elem.find("address[@addrtype='mac']")
            mac = mac_elem.get("addr") if mac_elem is not None else None
            
            # OS Detection
            os_name = None
            os_elem = host_elem.find("os/osmatch")
            if os_elem is not None:
                os_name = os_elem.get("name")
                
            host_identity = HostIdentity(
                ip=ip,
                hostname=hostname,
                os=os_name,
                mac_address=mac
            )
            
            # 2. Parse Services & Ports
            services_list: List[PortServiceDetail] = []
            ports = host_elem.findall("ports/port")
            for port_elem in ports:
                port_id = int(port_elem.get("portid") or 0)
                protocol = port_elem.get("protocol", "tcp")
                
                state_elem = port_elem.find("state")
                state = state_elem.get("state") if state_elem is not None else "closed"
                
                service_elem = port_elem.find("service")
                service_name = "unknown"
                product = None
                version = None
                extrainfo = None
                cpes = []
                
                if service_elem is not None:
                    service_name = service_elem.get("name", "unknown")
                    product = service_elem.get("product")
                    version = service_elem.get("version")
                    extrainfo = service_elem.get("extrainfo")
                    
                    # Capture all CPE identifiers
                    cpes = [c.text for c in service_elem.findall("cpe") if c.text]
                    
                services_list.append(PortServiceDetail(
                    port=port_id,
                    protocol=protocol,
                    state=state,
                    service_name=service_name,
                    product=product,
                    version=version,
                    extrainfo=extrainfo,
                    cpe=cpes
                ))
                
            # 3. Parse Scan Metadata
            finished_elem = root.find("runstats/finished")
            scan_time = finished_elem.get("timestr") if finished_elem is not None else None
            nmap_args = root.get("args", "nmap")
            
            meta = {
                "nmap_args": nmap_args,
                "scan_time": scan_time,
                "nmap_version": root.get("version", "unknown")
            }
            
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            try:
                ObservatoryHealthLog.objects.create(
                    metric_name='parser_xml_duration',
                    duration_ms=round(duration_ms, 2),
                    status='success'
                )
            except Exception as log_err:
                logger.warning(f"Could not persist health log: {str(log_err)}")
            
            return CanonicalIntelligence(
                host=host_identity,
                services=services_list,
                metadata=meta
            )
        except Exception as e:
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            logger.error(f"Malformed or corrupted scan XML. Yielding sterile skeleton. Detail: {str(e)}")
            try:
                ObservatoryHealthLog.objects.create(
                    metric_name='parser_xml_duration',
                    duration_ms=round(duration_ms, 2),
                    status='failure',
                    message=str(e)
                )
            except Exception:
                pass
            skeleton_host = HostIdentity(ip="0.0.0.0", hostname="Corrupted Telemetry Fallback")
            return CanonicalIntelligence(host=skeleton_host)
