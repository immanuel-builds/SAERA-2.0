"""
Base rule definitions for NetVuln's simple misconfiguration checks.
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
    description = "The legacy SMBv1 protocol is enabled, which is vulnerable to multiple known attacks."
    severity = "critical"
    
    def check(self, service_data):
        if service_data.get('port') == 445 and service_data.get('protocol_version') == '1.0':
            return True, {
                "title": self.name,
                "description": self.description,
                "severity": self.severity,
                "vuln_type": "protocol"
            }
        return False, None