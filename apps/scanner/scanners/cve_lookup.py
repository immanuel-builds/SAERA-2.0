"""
CVE Lookup Module
Queries CVE databases for known vulnerabilities based on service versions
"""
import logging
import requests
from typing import Dict, List, Optional
import time

logger = logging.getLogger(__name__)


class CVELookup:
    """Query CVE databases for known vulnerabilities"""
    
    # NVD API endpoint
    NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize CVE lookup
        
        Args:
            api_key: Optional NVD API key for higher rate limits
        """
        self.api_key = api_key
        self.session = requests.Session()
        if api_key:
            self.session.headers.update({'apiKey': api_key})
    
    def lookup_cves_for_services(self, services: List[Dict]) -> List[Dict]:
        """
        Look up CVEs for all services
        
        Args:
            services: List of service dictionaries
            
        Returns:
            List of CVE vulnerabilities found
        """
        cve_vulnerabilities = []
        
        for service in services:
            product = service.get('product', '').lower()
            version = service.get('version', '')
            
            if product and version:
                # Add delay to respect rate limits
                time.sleep(0.6)  # NVD allows ~2 requests per second without API key
                
                cves = self._query_nvd(product, version)
                
                for cve in cves:
                    vuln = self._format_cve_vulnerability(cve, service)
                    cve_vulnerabilities.append(vuln)
        
        logger.info(f"Found {len(cve_vulnerabilities)} CVEs")
        return cve_vulnerabilities
    
    def _query_nvd(self, product: str, version: str) -> List[Dict]:
        """
        Query NVD API for CVEs
        
        Args:
            product: Product name (e.g., 'apache', 'openssh')
            version: Version string
            
        Returns:
            List of CVE data
        """
        try:
            # Clean product name for query
            product_clean = product.replace(' ', '_').lower()
            
            # Build query parameters
            params = {
                'keywordSearch': product_clean,
                'resultsPerPage': 10,  # Limit results
            }
            
            response = self.session.get(self.NVD_API_BASE, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get('vulnerabilities', [])
                
                # Filter CVEs relevant to the version
                relevant_cves = []
                for vuln in vulnerabilities:
                    cve_item = vuln.get('cve', {})
                    # Check if this CVE is relevant to our version
                    if self._is_version_affected(cve_item, version):
                        relevant_cves.append(cve_item)
                
                return relevant_cves[:5]  # Limit to top 5 most relevant
            else:
                logger.warning(f"NVD API returned status {response.status_code}")
                return []
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Error querying NVD API: {str(e)}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error in CVE lookup: {str(e)}")
            return []
    
    def _is_version_affected(self, cve_data: Dict, version: str) -> bool:
        """
        Check if a specific version is affected by a CVE
        This is a simplified check - production would need more sophisticated version matching
        """
        # For now, return True to show all potentially relevant CVEs
        # In production, you'd parse the CPE data and version ranges
        return True
    
    def _format_cve_vulnerability(self, cve_data: Dict, service: Dict) -> Dict:
        """
        Format CVE data into vulnerability dict
        
        Args:
            cve_data: CVE data from NVD
            service: Service information
            
        Returns:
            Formatted vulnerability dictionary
        """
        cve_id = cve_data.get('id', 'Unknown')
        
        # Extract description
        descriptions = cve_data.get('descriptions', [])
        description = ''
        for desc in descriptions:
            if desc.get('lang') == 'en':
                description = desc.get('value', '')
                break
        
        # Extract CVSS score
        metrics = cve_data.get('metrics', {})
        cvss_score = 0.0
        severity = 'medium'
        
        # Try to get CVSS v3.1 score first
        cvss_v31 = metrics.get('cvssMetricV31', [])
        if cvss_v31:
            cvss_data = cvss_v31[0].get('cvssData', {})
            cvss_score = cvss_data.get('baseScore', 0.0)
            severity = cvss_data.get('baseSeverity', 'MEDIUM').lower()
        else:
            # Fallback to CVSS v2
            cvss_v2 = metrics.get('cvssMetricV2', [])
            if cvss_v2:
                cvss_data = cvss_v2[0].get('cvssData', {})
                cvss_score = cvss_data.get('baseScore', 0.0)
                # Map v2 score to severity
                if cvss_score >= 9.0:
                    severity = 'critical'
                elif cvss_score >= 7.0:
                    severity = 'high'
                elif cvss_score >= 4.0:
                    severity = 'medium'
                else:
                    severity = 'low'
        
        # Build CVE URL
        cve_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        
        return {
            'vuln_type': 'cve',
            'severity': severity,
            'cvss_score': cvss_score,
            'title': f"{cve_id} - {service.get('product', 'Service')} Vulnerability",
            'description': description[:500],  # Truncate long descriptions
            'impact': f"This CVE affects {service.get('product', '')} {service.get('version', '')}",
            'recommendation': f"Apply security patches and update to a non-vulnerable version. See {cve_url} for details.",
            'cve_id': cve_id,
            'cve_url': cve_url,
            'port': service.get('port'),
            'protocol': service.get('protocol', 'tcp'),
            'service': service.get('service_name'),
            'service_version': service.get('version_info'),
            'evidence': f"Detected {service.get('product', '')} {service.get('version', '')} which is affected by {cve_id}",
        }
    
    def get_cve_details(self, cve_id: str) -> Optional[Dict]:
        """
        Get detailed information about a specific CVE
        
        Args:
            cve_id: CVE identifier (e.g., 'CVE-2021-44228')
            
        Returns:
            CVE details or None
        """
        try:
            url = f"{self.NVD_API_BASE}"
            params = {'cveId': cve_id}
            
            response = self.session.get(url, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get('vulnerabilities', [])
                if vulnerabilities:
                    return vulnerabilities[0].get('cve', {})
            
            return None
            
        except Exception as e:
            logger.error(f"Error getting CVE details for {cve_id}: {str(e)}")
            return None
