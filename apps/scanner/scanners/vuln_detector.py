"""
Vulnerability Detection Module
Identifies common vulnerabilities and misconfigurations
"""
import logging
from typing import Dict, List, Tuple

logger = logging.getLogger(__name__)


class VulnerabilityDetector:
    """Detect vulnerabilities and security misconfigurations"""
    
    # Insecure protocols and services
    INSECURE_PROTOCOLS = {
        'telnet': {
            'port': 23,
            'severity': 'high',
            'title': 'Unencrypted Telnet Service Detected',
            'description': 'Telnet transmits data in cleartext, including credentials.',
            'impact': 'Attackers can intercept credentials and session data through network sniffing.',
            'recommendation': 'Disable Telnet and use SSH (port 22) for secure remote access.',
        },
        'ftp': {
            'port': 21,
            'severity': 'medium',
            'title': 'Unencrypted FTP Service Detected',
            'description': 'FTP transmits credentials and data in cleartext.',
            'impact': 'Credentials and file transfers can be intercepted.',
            'recommendation': 'Use SFTP (SSH File Transfer Protocol) or FTPS instead.',
        },
        'http': {
            'ports': [80, 8000, 8080],
            'severity': 'medium',
            'title': 'Unencrypted HTTP Service Detected',
            'description': 'HTTP does not use encryption for data transmission.',
            'impact': 'Sensitive data transmitted over HTTP can be intercepted.',
            'recommendation': 'Implement HTTPS with valid SSL/TLS certificates.',
        },
        'smtp': {
            'port': 25,
            'severity': 'low',
            'title': 'Unencrypted SMTP Detected',
            'description': 'SMTP on port 25 typically does not use encryption.',
            'impact': 'Email content and credentials may be transmitted without encryption.',
            'recommendation': 'Use SMTPS (port 465) or SMTP with STARTTLS (port 587).',
        },
    }
    
    # High-risk ports that should not be publicly accessible
    HIGH_RISK_PORTS = {
        3389: {
            'service': 'RDP',
            'severity': 'critical',
            'title': 'Remote Desktop Protocol (RDP) Exposed',
            'description': 'RDP is exposed to the network and is a common attack vector.',
            'impact': 'Brute force attacks, exploitation of RDP vulnerabilities.',
            'recommendation': 'Restrict RDP access to specific IP addresses or use VPN.',
        },
        445: {
            'service': 'SMB',
            'severity': 'high',
            'title': 'SMB Service Exposed',
            'description': 'Server Message Block (SMB) is exposed to the network.',
            'impact': 'Vulnerable to EternalBlue and other SMB exploits.',
            'recommendation': 'Disable SMB if not needed or restrict access to trusted networks.',
        },
        1433: {
            'service': 'MSSQL',
            'severity': 'high',
            'title': 'Microsoft SQL Server Exposed',
            'description': 'MSSQL database is directly accessible from the network.',
            'impact': 'SQL injection, brute force attacks, data exfiltration.',
            'recommendation': 'Use firewall rules to restrict access to trusted IPs only.',
        },
        3306: {
            'service': 'MySQL',
            'severity': 'high',
            'title': 'MySQL Database Exposed',
            'description': 'MySQL database is directly accessible from the network.',
            'impact': 'Unauthorized access, data breach, brute force attacks.',
            'recommendation': 'Bind MySQL to localhost and use SSH tunneling for remote access.',
        },
        5432: {
            'service': 'PostgreSQL',
            'severity': 'high',
            'title': 'PostgreSQL Database Exposed',
            'description': 'PostgreSQL database is directly accessible from the network.',
            'impact': 'Unauthorized access, SQL injection, data exfiltration.',
            'recommendation': 'Configure pg_hba.conf to restrict access and use strong authentication.',
        },
    }
    
    # Specialized signatures for high-impact vulnerabilities (e.g. Metasploitable)
    SIGNATURE_VULNERABILITIES = [
        {
            'pattern': r'vsftpd 2\.3\.4',
            'severity': 'critical',
            'title': 'vsFTPd 2.3.4 Backdoor Detected',
            'description': 'The detected version of vsFTPd contains a malicious backdoor that allows remote command execution.',
            'impact': 'Attackers can gain full system access by sending a specific sequence to the FTP service.',
            'recommendation': 'Immediately update vsFTPd to a secure version or switch to a different FTP server.',
        },
        {
            'pattern': r'Unreal3\.2\.8\.1',
            'severity': 'critical',
            'title': 'UnrealIRCd 3.2.8.1 Backdoor Detected',
            'description': 'The detected version of UnrealIRCd contains a backdoor that allows remote code execution.',
            'impact': 'Total system compromise via the IRC service.',
            'recommendation': 'Update UnrealIRCd to the latest stable version.',
        },
        {
            'pattern': r'Samba 3\.0\.20',
            'severity': 'critical',
            'title': 'Samba 3.0.20-3.0.25rc3 Remote Code Execution',
            'description': 'The "username map script" vulnerability allows remote command execution.',
            'impact': 'Unauthorized root access to the system.',
            'recommendation': 'Update Samba to a non-vulnerable version.',
        },
        {
            'pattern': r'GNU bash 4\.',
            'severity': 'high',
            'title': 'Potential Shellshock Vulnerability',
            'description': 'Older versions of Bash are vulnerable to the Shellshock exploit (CVE-2014-6271).',
            'impact': 'Remote code execution via specifically crafted environment variables.',
            'recommendation': 'Update Bash to the latest version.',
        }
    ]

    def detect_vulnerabilities(self, services: List[Dict], port_results: List[Dict]) -> List[Dict]:
        """
        Detect vulnerabilities from enumerated services
        """
        vulnerabilities = []
        
        # Check for signature-based vulnerabilities (Metasploitable, etc)
        signature_vulns = self._check_signatures(services)
        vulnerabilities.extend(signature_vulns)

        # Check for insecure protocols
        insecure_protocol_vulns = self._check_insecure_protocols(services)
        vulnerabilities.extend(insecure_protocol_vulns)
        
        # Check for high-risk exposed ports
        exposed_port_vulns = self._check_high_risk_ports(port_results)
        vulnerabilities.extend(exposed_port_vulns)
        
        # Check for outdated services
        outdated_vulns = self._check_outdated_services(services)
        vulnerabilities.extend(outdated_vulns)
        
        # Check for default configurations
        default_config_vulns = self._check_default_configs(services)
        vulnerabilities.extend(default_config_vulns)
        
        # Check for unnecessary services
        unnecessary_vulns = self._check_unnecessary_services(port_results)
        vulnerabilities.extend(unnecessary_vulns)
        
        logger.info(f"Detected {len(vulnerabilities)} vulnerabilities")
        return vulnerabilities

    def _check_signatures(self, services: List[Dict]) -> List[Dict]:
        """Check services against known vulnerability signatures"""
        vulnerabilities = []
        import re
        
        for service in services:
            banner = service.get('banner', '')
            product = service.get('product', '')
            version = service.get('version_info', '')
            
            check_string = f"{banner} {product} {version}".strip()
            if not check_string:
                continue
                
            for sig in self.SIGNATURE_VULNERABILITIES:
                if re.search(sig['pattern'], check_string, re.I):
                    vulnerabilities.append({
                        'vuln_type': 'cve',
                        'severity': sig['severity'],
                        'title': sig['title'],
                        'description': sig['description'],
                        'impact': sig['impact'],
                        'recommendation': sig['recommendation'],
                        'port': service.get('port'),
                        'protocol': service.get('protocol', 'tcp'),
                        'service': service.get('service_name'),
                        'evidence': f"Signature match found: {check_string}",
                    })
        return vulnerabilities
    
    def _check_insecure_protocols(self, services: List[Dict]) -> List[Dict]:
        """Check for insecure protocols"""
        vulnerabilities = []
        
        for service in services:
            service_type = service.get('service_type', '').lower()
            service_name = service.get('service_name', '').lower()
            port = service.get('port')
            
            # Check if it's an insecure protocol
            for protocol, vuln_data in self.INSECURE_PROTOCOLS.items():
                if protocol in service_type or protocol in service_name:
                    vulnerabilities.append({
                        'vuln_type': 'protocol',
                        'severity': vuln_data['severity'],
                        'title': vuln_data['title'],
                        'description': vuln_data['description'],
                        'impact': vuln_data['impact'],
                        'recommendation': vuln_data['recommendation'],
                        'port': port,
                        'protocol': service.get('protocol', 'tcp'),
                        'service': service_name,
                        'evidence': f"{service_name} detected on port {port}",
                    })
        
        return vulnerabilities
    
    def _check_high_risk_ports(self, port_results: List[Dict]) -> List[Dict]:
        """Check for high-risk exposed ports"""
        vulnerabilities = []
        
        for port_info in port_results:
            port = port_info.get('port')
            state = port_info.get('state')
            
            if state == 'open' and port in self.HIGH_RISK_PORTS:
                vuln_data = self.HIGH_RISK_PORTS[port]
                vulnerabilities.append({
                    'vuln_type': 'port',
                    'severity': vuln_data['severity'],
                    'title': vuln_data['title'],
                    'description': vuln_data['description'],
                    'impact': vuln_data['impact'],
                    'recommendation': vuln_data['recommendation'],
                    'port': port,
                    'protocol': port_info.get('protocol', 'tcp'),
                    'service': vuln_data['service'],
                    'evidence': f"Port {port} ({vuln_data['service']}) is open and accessible",
                })
        
        return vulnerabilities
    
    def _check_outdated_services(self, services: List[Dict]) -> List[Dict]:
        """Check for outdated service versions"""
        vulnerabilities = []
        
        for service in services:
            if service.get('outdated', False):
                vulnerabilities.append({
                    'vuln_type': 'service',
                    'severity': 'medium',
                    'title': f"Outdated {service.get('product', 'Service')} Version Detected",
                    'description': f"{service.get('version_info', 'Unknown version')} is outdated and may contain known vulnerabilities.",
                    'impact': 'Outdated software may be vulnerable to known exploits and security issues.',
                    'recommendation': f"Update to version {service.get('recommended_version', 'latest')} or higher.",
                    'port': service.get('port'),
                    'protocol': service.get('protocol', 'tcp'),
                    'service': service.get('service_name'),
                    'service_version': service.get('version_info'),
                    'evidence': f"{service.get('banner', '')}",
                })
        
        return vulnerabilities
    
    def _check_default_configs(self, services: List[Dict]) -> List[Dict]:
        """Check for services running on default ports (potential default configs)"""
        vulnerabilities = []
        
        default_credential_services = {
            'mysql': 3306,
            'postgresql': 5432,
            'mongodb': 27017,
            'redis': 6379,
            'elasticsearch': 9200,
        }
        
        for service in services:
            service_type = service.get('service_type', '').lower()
            port = service.get('port')
            
            for svc, default_port in default_credential_services.items():
                if svc in service_type and port == default_port:
                    vulnerabilities.append({
                        'vuln_type': 'config',
                        'severity': 'medium',
                        'title': f'Potential Default Configuration - {svc.upper()}',
                        'description': f'{svc.upper()} is running on default port {default_port}, which may indicate default configuration.',
                        'impact': 'Default configurations often include weak or default credentials and insecure settings.',
                        'recommendation': 'Verify that default credentials have been changed and security hardening has been applied.',
                        'port': port,
                        'protocol': service.get('protocol', 'tcp'),
                        'service': service.get('service_name'),
                        'evidence': f'{svc} detected on default port {default_port}',
                    })
        
        return vulnerabilities
    
    def _check_unnecessary_services(self, port_results: List[Dict]) -> List[Dict]:
        """Check for potentially unnecessary open ports"""
        vulnerabilities = []
        
        # Ports that are commonly unnecessary or risky
        unnecessary_ports = {
            135: 'MS RPC',
            137: 'NetBIOS Name Service',
            138: 'NetBIOS Datagram Service',
            139: 'NetBIOS Session Service',
            161: 'SNMP',
            162: 'SNMP Trap',
        }
        
        for port_info in port_results:
            port = port_info.get('port')
            state = port_info.get('state')
            
            if state == 'open' and port in unnecessary_ports:
                vulnerabilities.append({
                    'vuln_type': 'config',
                    'severity': 'low',
                    'title': f'Potentially Unnecessary Service - {unnecessary_ports[port]}',
                    'description': f'Port {port} ({unnecessary_ports[port]}) is open but may not be necessary.',
                    'impact': 'Unnecessary services increase the attack surface.',
                    'recommendation': f'Disable {unnecessary_ports[port]} if not required, or restrict access.',
                    'port': port,
                    'protocol': port_info.get('protocol', 'tcp'),
                    'service': unnecessary_ports[port],
                    'evidence': f'Port {port} is open',
                })
        
        return vulnerabilities
    
    def calculate_cvss_score(self, vulnerability: Dict) -> float:
        """
        Calculate an estimated CVSS score based on severity and type
        This is a simplified version - real CVSS calculation is more complex
        """
        severity_scores = {
            'critical': 9.5,
            'high': 7.5,
            'medium': 5.0,
            'low': 2.5,
            'info': 0.0,
        }
        
        base_score = severity_scores.get(vulnerability.get('severity', 'low'), 0.0)
        
        # Adjust based on vulnerability type
        vuln_type = vulnerability.get('vuln_type', '')
        if vuln_type == 'cve':
            base_score = min(10.0, base_score + 1.0)
        elif vuln_type == 'protocol':
            base_score = min(10.0, base_score + 0.5)
        
        return round(base_score, 1)
