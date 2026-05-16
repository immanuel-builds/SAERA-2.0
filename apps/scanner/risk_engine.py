"""
Risk Scoring Engine for SAERA
Calculates vulnerability risk based on multiple factors:
- CVSS Score
- Service Criticality
- Exposure
- Misconfiguration patterns
"""

def calculate_risk(cvss, service=None, is_public=False, has_default_creds=False, misconfigs=None):
    """
    Calculate a weighted risk score (0-10)
    Formula: (CVSS * 0.45) + (Exposure * 0.25) + (ServiceCriticality * 0.2) + (Misconfiguration * 0.1)
    """
    score = 0
    
    # 1. Base CVSS contribution (max 4.5)
    score += (cvss or 0) * 0.45
    
    # 2. Exposure contribution (max 2.5)
    if is_public:
        score += 2.5
        
    # 3. Service Criticality contribution (max 2.0)
    critical_services = ["ssh", "rdp", "smb", "ftp", "telnet", "database", "redis", "mongodb"]
    if service and any(s in service.lower() for s in critical_services):
        score += 2.0
        
    # 4. Misconfiguration contribution (max 1.0)
    if has_default_creds:
        score += 1.0  # Significant misconfig
    elif misconfigs and len(misconfigs) > 0:
        score += 0.5
        
    # Clamp score to 0-10 range
    final_score = round(min(score, 10), 1)
    
    # Determine risk level
    if final_score >= 9.0:
        level = "Critical"
    elif final_score >= 7.0:
        level = "High"
    elif final_score >= 4.0:
        level = "Medium"
    else:
        level = "Low"
        
    return final_score, level

def get_exploitability_factor(cvss, cve_id=None):
    """
    Determine exploitability factor (0-10)
    In a real scenario, this would query a threat intel feed.
    For now, we use CVSS exploitability subscore or heuristics.
    """
    if cvss >= 9.0:
        return 9
    if cvss >= 7.0:
        return 7
    if cvss >= 4.0:
        return 5
    return 2
