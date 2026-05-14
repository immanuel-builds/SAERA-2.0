"""
User and Profile Models for Authentication and Access Control
"""
from django.contrib.auth.models import AbstractUser
from django.db import models


class User(AbstractUser):
    """Extended User model with additional fields"""
    
    ROLE_CHOICES = [
        ('admin', 'Administrator'),
        ('analyst', 'Security Analyst'),
    ]
    
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='analyst')
    organization = models.CharField(max_length=255, blank=True)
    department = models.CharField(max_length=255, blank=True)
    can_initiate_scans = models.BooleanField(default=True)
    can_export_reports = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-date_joined']
    
    def __str__(self):
        return f"{self.username} ({self.get_role_display()})"
    
    @property
    def is_admin(self):
        return self.role == 'admin' or self.is_superuser
    
    @property
    def is_analyst(self):
        return self.role in ['analyst', 'admin'] or self.is_superuser


class AuditLog(models.Model):
    """Track all security scanning activities"""
    
    ACTION_CHOICES = [
        ('scan_initiated', 'Scan Initiated'),
        ('scan_completed', 'Scan Completed'),
        ('scan_failed', 'Scan Failed'),
        ('report_generated', 'Report Generated'),
        ('report_exported', 'Report Exported'),
        ('user_login', 'User Login'),
        ('user_logout', 'User Logout'),
        ('user_signup', 'User Account Created'),
        ('user_deleted', 'User Account Decommissioned'),
        ('user_updated', 'User Account Modified'),
        ('security_event', 'Security Alert / Validation Failure'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='audit_logs')
    action = models.CharField(max_length=50, choices=ACTION_CHOICES)
    description = models.TextField()
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['-created_at']),
            models.Index(fields=['user', '-created_at']),
        ]
    
    def __str__(self):
        return f"{self.user} - {self.get_action_display()} at {self.created_at}"
