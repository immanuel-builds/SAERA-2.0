"""
Scanner Models for Vulnerability Detection and Scanning
"""
from django.db import models
from django.conf import settings
import json


class ScanTarget(models.Model):
    """Store information about scan targets"""
    
    TARGET_TYPE_CHOICES = [
        ('ip', 'IP Address'),
        ('domain', 'Domain Name'),
        ('range', 'IP Range (CIDR)'),
    ]
    
    name = models.CharField(max_length=255)
    target = models.CharField(max_length=255, help_text="IP address, domain, or CIDR range")
    target_type = models.CharField(max_length=10, choices=TARGET_TYPE_CHOICES)
    description = models.TextField(blank=True)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='scan_targets')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-created_at']
        unique_together = ['target', 'created_by']
    
    def __str__(self):
        return f"{self.name} ({self.target})"


class ScanConfiguration(models.Model):
    """Configuration settings for scans"""
    
    SCAN_TYPE_CHOICES = [
        ('quick', 'Quick Scan (Top 100 ports)'),
        ('standard', 'Standard Scan (Top 1000 ports)'),
        ('deep', 'Deep Scan (All 65535 ports)'),
        ('custom', 'Custom Scan'),
    ]
    
    name = models.CharField(max_length=255)
    scan_type = models.CharField(max_length=20, choices=SCAN_TYPE_CHOICES, default='standard')
    port_range = models.CharField(max_length=255, default='1-1000', help_text="e.g., 1-1000 or 80,443,8080")
    enable_service_detection = models.BooleanField(default=True)
    enable_os_detection = models.BooleanField(default=False)
    enable_vuln_detection = models.BooleanField(default=True)
    timeout = models.IntegerField(default=300, help_text="Timeout in seconds")
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    is_default = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.name} - {self.get_scan_type_display()}"


class ScanJob(models.Model):
    """Track scan execution and progress"""
    
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('running', 'Running'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('cancelled', 'Cancelled'),
    ]
    
    target = models.ForeignKey(ScanTarget, on_delete=models.CASCADE, related_name='scan_jobs')
    configuration = models.ForeignKey(ScanConfiguration, on_delete=models.SET_NULL, null=True)
    initiated_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='initiated_scans')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    progress = models.IntegerField(default=0, help_text="Progress percentage (0-100)")
    current_phase = models.CharField(max_length=100, blank=True, help_text="Current scan phase")
    celery_task_id = models.CharField(max_length=255, blank=True, null=True)
    
    # Results summary
    total_ports_scanned = models.IntegerField(default=0)
    open_ports_found = models.IntegerField(default=0)
    vulnerabilities_found = models.IntegerField(default=0)
    critical_vulns = models.IntegerField(default=0)
    high_vulns = models.IntegerField(default=0)
    medium_vulns = models.IntegerField(default=0)
    low_vulns = models.IntegerField(default=0)
    
    error_message = models.TextField(blank=True)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['-created_at']),
            models.Index(fields=['status', '-created_at']),
        ]
    
    def __str__(self):
        return f"Scan #{self.id} - {self.target.name} ({self.status})"
    
    @property
    def duration(self):
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None


class Vulnerability(models.Model):
    """Individual vulnerability findings"""
    
    SEVERITY_CHOICES = [
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
        ('info', 'Informational'),
    ]
    
    VULN_TYPE_CHOICES = [
        ('port', 'Open Port'),
        ('service', 'Service Vulnerability'),
        ('config', 'Misconfiguration'),
        ('cve', 'Known CVE'),
        ('protocol', 'Insecure Protocol'),
        ('auth', 'Weak Authentication'),
        ('other', 'Other'),
    ]
    
    scan_job = models.ForeignKey(ScanJob, on_delete=models.CASCADE, related_name='vulnerabilities')
    title = models.CharField(max_length=500)
    vuln_type = models.CharField(max_length=20, choices=VULN_TYPE_CHOICES)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES)
    cvss_score = models.FloatField(null=True, blank=True, help_text="CVSS Score (0-10)")
    
    # Technical details
    port = models.IntegerField(null=True, blank=True)
    protocol = models.CharField(max_length=10, blank=True)
    service = models.CharField(max_length=100, blank=True)
    service_version = models.CharField(max_length=255, blank=True)
    
    # Vulnerability information
    description = models.TextField()
    impact = models.TextField(blank=True)
    recommendation = models.TextField(blank=True)
    cve_id = models.CharField(max_length=50, blank=True, help_text="CVE ID if applicable")
    cve_url = models.URLField(blank=True)
    
    # New Risk Intelligence Fields
    risk_score = models.FloatField(default=0, help_text="Calculated Risk Score (0-10)")
    risk_level = models.CharField(max_length=20, default='Low', help_text="Calculated Risk Level")
    exploitability = models.IntegerField(default=0, help_text="Exploitability factor")
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-severity', '-cvss_score', '-created_at']
        indexes = [
            models.Index(fields=['scan_job', 'severity']),
            models.Index(fields=['severity', '-cvss_score']),
        ]
    
    def __str__(self):
        return f"[{self.severity.upper()}] {self.title}"
    
    @property
    def severity_order(self):
        """Return numeric severity for sorting"""
        severity_map = {
            'critical': 5,
            'high': 4,
            'medium': 3,
            'low': 2,
            'info': 1,
        }
        return severity_map.get(self.severity, 0)


class PortScanResult(models.Model):
    """Detailed port scan results"""
    
    PORT_STATE_CHOICES = [
        ('open', 'Open'),
        ('closed', 'Closed'),
        ('filtered', 'Filtered'),
    ]
    
    scan_job = models.ForeignKey(ScanJob, on_delete=models.CASCADE, related_name='port_results')
    port = models.IntegerField()
    protocol = models.CharField(max_length=10, default='tcp')
    state = models.CharField(max_length=20, choices=PORT_STATE_CHOICES)
    service = models.CharField(max_length=100, blank=True)
    service_version = models.CharField(max_length=255, blank=True)
    banner = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['port']
        unique_together = ['scan_job', 'port', 'protocol']
    
    def __str__(self):
        return f"Port {self.port}/{self.protocol} - {self.state}"
