"""
Report Models for vulnerability report generation and export
"""
from django.db import models
from django.conf import settings
from apps.scanner.models import ScanJob
import os


class Report(models.Model):
    """Main report entity"""
    
    FORMAT_CHOICES = [
        ('pdf', 'PDF Document'),
        ('csv', 'CSV Export'),
        ('json', 'JSON Export'),
        ('html', 'HTML Report'),
    ]
    
    scan_job = models.ForeignKey(ScanJob, on_delete=models.CASCADE, related_name='reports')
    title = models.CharField(max_length=500)
    format = models.CharField(max_length=10, choices=FORMAT_CHOICES)
    file_path = models.CharField(max_length=500, blank=True)
    file_size = models.IntegerField(default=0, help_text="File size in bytes")
    
    generated_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='generated_reports')
    generated_at = models.DateTimeField(auto_now_add=True)
    
    # Report metadata
    executive_summary = models.TextField(blank=True)
    total_findings = models.IntegerField(default=0)
    
    class Meta:
        ordering = ['-generated_at']
        indexes = [
            models.Index(fields=['-generated_at']),
        ]
    
    def __str__(self):
        return f"{self.title} ({self.get_format_display()})"
    
    @property
    def file_size_mb(self):
        """Return file size in MB"""
        return round(self.file_size / (1024 * 1024), 2) if self.file_size > 0 else 0
    
    @property
    def filename(self):
        """Extract filename from path"""
        return os.path.basename(self.file_path) if self.file_path else ''


class ExportHistory(models.Model):
    """Track report exports and downloads"""
    
    report = models.ForeignKey(Report, on_delete=models.CASCADE, related_name='export_history')
    exported_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    exported_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-exported_at']
        verbose_name_plural = 'Export histories'
    
    def __str__(self):
        return f"{self.report.title} exported by {self.exported_by} at {self.exported_at}"
