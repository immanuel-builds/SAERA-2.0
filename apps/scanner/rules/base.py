"""
Base Rule definitions for SAERA Misconfiguration Engine
"""

class BaseRule:
    name = ""
    description = ""
    severity = "low"
    
    def check(self, service_data):
        """
        Check if the rule is violated.
        Returns (is_violated, findings_dict)
        """
        raise NotImplementedError("Rules must implement check()")

class FTPAnonymousRule(BaseRule):
    name = "Anonymous FTP Enabled"
    description = "The FTP service allows anonymous login, potentially exposing sensitive files."
    severity = "high"
    
    def check(self, service_data):
        # In a real scanner, service_data would contain banner info or test results
        banner = service_data.get('banner', '').lower()
        if "220" in banner and ("anonymous" in banner or "welcome" in banner):
            return True, {
                "title": self.name,
                "description": self.description,
                "severity": self.severity,
                "vuln_type": "auth"
            }
        return False, None

class SMBv1Rule(BaseRule):
    name = "SMBv1 Protocol Enabled"
    description = "The legacy SMBv1 protocol is enabled, which is vulnerable to multiple exploits like EternalBlue."
    severity = "critical"
    
    def check(self, service_data):
        # Heuristic check for SMBv1
        if service_data.get('port') == 445 and service_data.get('protocol_version') == '1.0':
            return True, {
                "title": self.name,
                "description": self.description,
                "severity": self.severity,
                "vuln_type": "protocol"
            }
        return False, None

class RedisNoAuthRule(BaseRule):
    name = "Redis Without Authentication"
    description = "The Redis instance appears to accept connections without a password."
    severity = "critical"
    
    def check(self, service_data):
        if service_data.get('port') == 6379 and "redis" in service_data.get('service', '').lower():
            return True, {
                "title": self.name,
                "description": self.description,
                "severity": self.severity,
                "vuln_type": "auth"
            }
        return False, None
