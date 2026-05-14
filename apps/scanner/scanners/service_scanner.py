"""
Service Enumeration Module
Identifies services, versions, and performs OS fingerprinting
"""
import logging
from typing import Dict, List
import re

logger = logging.getLogger(__name__)


class ServiceScanner:
    """Service enumeration and identification"""
    
    # Common service signatures and patterns
    SERVICE_SIGNATURES = {
        'ssh': {
            'ports': [22],
            'patterns': [r'SSH-[\d\.]+-OpenSSH_([\d\.]+)', r'SSH'],
        },
        'http': {
            'ports': [80, 8000, 8080, 8888],
            'patterns': [r'Apache/([\d\.]+)', r'nginx/([\d\.]+)', r'Microsoft-IIS/([\d\.]+)'],
        },
        'https': {
            'ports': [443, 8443],
            'patterns': [r'Apache/([\d\.]+)', r'nginx/([\d\.]+)'],
        },
        'ftp': {
            'ports': [21],
            'patterns': [r'vsftpd ([\d\.]+)', r'ProFTPD ([\d\.]+)', r'FileZilla'],
        },
        'smtp': {
            'ports': [25, 587],
            'patterns': [r'Postfix', r'Sendmail', r'Microsoft Exchange'],
        },
        'mysql': {
            'ports': [3306],
            'patterns': [r'MySQL ([\d\.]+)', r'MariaDB ([\d\.]+)'],
        },
        'postgresql': {
            'ports': [5432],
            'patterns': [r'PostgreSQL ([\d\.]+)'],
        },
        'rdp': {
            'ports': [3389],
            'patterns': [r'Remote Desktop'],
        },
        'telnet': {
            'ports': [23],
            'patterns': [r'telnet'],
        },
        'irc': {
            'ports': [6667, 6668, 6697],
            'patterns': [r'Unreal', r'irc'],
        },
        'smb': {
            'ports': [139, 445],
            'patterns': [r'Samba', r'SMB'],
        },
    }
    
    def enumerate_services(self, port_scan_results: Dict) -> List[Dict]:
        """
        Enumerate and classify services from port scan results
        
        Args:
            port_scan_results: Results from PortScanner
            
        Returns:
            List of identified services with details
        """
        services = []
        
        for host, host_info in port_scan_results.get('hosts', {}).items():
            for proto, ports_list in host_info.get('protocols', {}).items():
                for port_info in ports_list:
                    if port_info['state'] == 'open':
                        service = self._identify_service(port_info)
                        service['host'] = host
                        service['protocol'] = proto
                        services.append(service)
        
        logger.info(f"Enumerated {len(services)} services")
        return services
    
    def _identify_service(self, port_info: Dict) -> Dict:
        """
        Identify service details from port information
        """
        service_name = port_info.get('service', '').lower()
        product = port_info.get('product', '')
        version = port_info.get('version', '')
        extrainfo = port_info.get('extrainfo', '')
        port = port_info.get('port')
        banner = port_info.get('banner', '')
        
        # If product/version missing (socket scan), try to extract from banner
        if (not product or not version) and banner:
            for svc_type, svc_data in self.SERVICE_SIGNATURES.items():
                for pattern in svc_data.get('patterns', []):
                    match = re.search(pattern, banner, re.I)
                    if match:
                        service_name = svc_type
                        # If the pattern has a group, it's the version
                        if match.groups():
                            version = match.group(1)
                        # Extract product name from pattern or use default
                        product = prod_name = pattern.split('/')[0].split(' ')[0].replace('\\', '').replace('[', '').replace(']', '').replace('+', '')
                        break

        # Build service identifier
        service_id = self._classify_service_type(service_name, port)
        
        # Extract version information
        version_info = self._extract_version(product, version, extrainfo)
        if not version_info or version_info == 'Unknown Version':
            version_info = banner if banner else 'Unknown Version'
        
        return {
            'port': port,
            'service_type': service_id,
            'service_name': service_name or 'unknown',
            'product': product or service_name,
            'version': version,
            'version_info': version_info,
            'extrainfo': extrainfo,
            'is_encrypted': self._is_encrypted_service(service_name, port),
            'banner': banner,
        }
    
    def _classify_service_type(self, service_name: str, port: int) -> str:
        """Classify service type based on name and port"""
        # Check by service name first
        for svc_type, svc_data in self.SERVICE_SIGNATURES.items():
            if service_name and svc_type in service_name:
                return svc_type
        
        # Check by port number
        for svc_type, svc_data in self.SERVICE_SIGNATURES.items():
            if port in svc_data['ports']:
                return svc_type
        
        return 'unknown'
    
    def _extract_version(self, product: str, version: str, extrainfo: str) -> str:
        """Extract detailed version information"""
        parts = []
        if product:
            parts.append(product)
        if version:
            parts.append(version)
        if extrainfo:
            parts.append(extrainfo)
        
        return ' '.join(parts) if parts else 'Unknown Version'
    
    def _is_encrypted_service(self, service_name: str, port: int) -> bool:
        """Check if service uses encryption"""
        encrypted_services = ['https', 'ssh', 'ssl', 'tls', 'ftps', 'smtps']
        encrypted_ports = [443, 22, 8443, 990, 465, 587, 993, 995]
        
        return (any(enc in service_name.lower() for enc in encrypted_services) or 
                port in encrypted_ports)
    
    def get_outdated_services(self, services: List[Dict]) -> List[Dict]:
        """
        Identify potentially outdated services
        
        Args:
            services: List of service dictionaries
            
        Returns:
            List of services that may be outdated
        """
        # This is a simplified version - in production, you'd want to check against
        # a database of current versions
        outdated = []
        
        version_checks = {
            'Apache': {'min_version': '2.4', 'pattern': r'Apache/([\d\.]+)'},
            'nginx': {'min_version': '1.20', 'pattern': r'nginx/([\d\.]+)'},
            'OpenSSH': {'min_version': '8.0', 'pattern': r'OpenSSH_([\d\.]+)'},
            'MySQL': {'min_version': '8.0', 'pattern': r'MySQL ([\d\.]+)'},
        }
        
        for service in services:
            banner = service.get('banner', '')
            product = service.get('product', '')
            
            for prod_name, check_info in version_checks.items():
                if prod_name.lower() in product.lower() or prod_name.lower() in banner.lower():
                    match = re.search(check_info['pattern'], banner)
                    if match:
                        detected_version = match.group(1)
                        # Simple version comparison (not perfect, but functional)
                        if self._compare_versions(detected_version, check_info['min_version']) < 0:
                            service['outdated'] = True
                            service['recommended_version'] = check_info['min_version']
                            outdated.append(service)
        
        return outdated
    
    def _compare_versions(self, version1: str, version2: str) -> int:
        """
        Compare two version strings
        Returns: -1 if version1 < version2, 0 if equal, 1 if version1 > version2
        """
        try:
            v1_parts = [int(x) for x in version1.split('.')[:3]]
            v2_parts = [int(x) for x in version2.split('.')[:3]]
            
            # Pad with zeros if needed
            while len(v1_parts) < 3:
                v1_parts.append(0)
            while len(v2_parts) < 3:
                v2_parts.append(0)
            
            for i in range(3):
                if v1_parts[i] < v2_parts[i]:
                    return -1
                elif v1_parts[i] > v2_parts[i]:
                    return 1
            
            return 0
        except:
            return 0
