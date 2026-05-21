"""
Risk Scoring Engine for SAERA
Calculates vulnerability risk based on the industry standard CVSS + EPSS methodology.
"""

def get_epss_score(cve_id=None):
    """
    Mock EPSS lookup for demonstration.
    In a production system, this would query the FIRST EPSS API or a local Redis cache.
    Returns a probability score (0.0 to 1.0) of exploitation within 30 days.
    """
    if not cve_id:
        return 0.05  # Baseline probability if no CVE is specified
        
    # Seeded examples for academic demonstration
    epss_database = {
        "CVE-2021-44228": 0.95,  # Log4Shell - Highly exploited
        "CVE-2023-23397": 0.82,  # Outlook EoP
        "CVE-2020-1472": 0.88,   # Zerologon
    }
    
    return epss_database.get(cve_id, 0.15)  # Default moderate probability

def calculate_risk(vulnerability):
    """
    Calculate risk using CVSS * (1 + EPSS)
    """
    # Assuming vulnerability is a Django model instance or namedtuple that has cvss_score and optionally cve_id.
    cvss_base = getattr(vulnerability, 'cvss_score', 0.0) or 0.0
    cve_id = getattr(vulnerability, 'cve_id', None)
    
    epss_score = get_epss_score(cve_id)
    
    risk = min(cvss_base * (1 + epss_score), 10.0)
    final_score = round(risk, 1)
    
    if final_score >= 9.0:
        level = "Critical"
    elif final_score >= 7.0:
        level = "High"
    elif final_score >= 4.0:
        level = "Medium"
    else:
        level = "Low"
        
    return final_score, level
