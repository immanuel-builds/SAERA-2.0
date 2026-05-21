"""
Security validators and sanitization engine for scan targets
"""
import re
import ipaddress
from django.core.exceptions import ValidationError

def sanitize_input(value):
    """
    Sanitize input to prevent SQL Injection and XSS characters.
    """
    if not value:
        return value
    # Remove common SQL injection characters
    value = re.sub(r"[;'\"]", "", value)
    # Remove potential script tags
    value = re.sub(r"<script.*?>.*?</script>", "", value, flags=re.DOTALL | re.IGNORECASE)
    # Remove HTML tags entirely for safety
    value = re.sub(r"<.*?>", "", value)
    # Remove control characters
    value = "".join(char for char in value if ord(char) >= 32)
    return value.strip()

def validate_scan_target(target):
    """
    Hardened validation for scan targets.
    Prevents URL injection, SQL keywords, and restricted IP ranges.
    Automatically strips protocols, trailing ports, and paths for user convenience.
    """
    # 1. Basic Sanitization
    target = sanitize_input(target)

    # 1.1 Extract clean host/IP by stripping protocols, ports, and paths
    # e.g., "http://127.0.0.1:8000/dashboard" -> "127.0.0.1"
    target = re.sub(r'^https?://', '', target, flags=re.IGNORECASE)
    target = target.split('/')[0]
    target = re.sub(r':\d+$', '', target)
    target = target.strip()

    if not target:
        raise ValidationError("Target cannot be empty.")

    # 2. Check for path traversal or local file access
    if any(pattern in target for pattern in ['file://', '../', '/etc/', 'C:\\']):
        raise ValidationError("Invalid target: Path traversal or local file access detected.")

    # 3. Check for SQL keywords (Case Insensitive)
    sql_keywords = ['SELECT ', 'DROP ', 'INSERT ', 'DELETE ', 'UPDATE ', 'UNION ']
    if any(keyword in target.upper() for keyword in sql_keywords):
        raise ValidationError("Invalid target: Malicious SQL keywords detected.")

    # 4. Check for script injection patterns
    if 'javascript:' in target.lower():
        raise ValidationError("Invalid target: Script injection detected.")

    # 5. Format check (IP, Domain, or CIDR)
    is_ip = False
    is_network = False
    is_domain = False

    # Allow localhost explicitly
    if target.lower() == 'localhost':
        is_domain = True

    # Try IP
    if not is_domain:
        try:
            ip_obj = ipaddress.ip_address(target)
            is_ip = True
        except ValueError:
            pass

    # Try Network (CIDR)
    if not is_domain and not is_ip and '/' in target:
        try:
            net_obj = ipaddress.ip_network(target, strict=False)
            is_network = True

            # Limit range size to /16 (65536 hosts)
            if net_obj.prefixlen < 16:
                raise ValidationError("Network range too large. Maximum allowed is a /16 (65,536 hosts).")
        except ValueError:
            pass

    # Try Domain
    if not is_domain and not is_ip and not is_network:
        domain_pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        if re.match(domain_pattern, target):
            is_domain = True

    if not (is_ip or is_network or is_domain):
        raise ValidationError("Invalid target format. Enter a valid IP, Domain, or CIDR range.")

    # 6. Blacklist check (Restricted Operational Ranges)
    if is_ip:
        ip = ipaddress.ip_address(target)
        if ip.is_multicast or ip.is_unspecified:
            raise ValidationError(f"Access Denied: Target {target} is a restricted or unspecified address.")

    if is_network:
        net = ipaddress.ip_network(target, strict=False)
        if net.is_multicast:
            raise ValidationError("Access Denied: Network range includes restricted multicast addresses.")

    return target
