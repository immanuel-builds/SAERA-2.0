from django.contrib import admin
from .models import ScanTarget, ScanConfiguration, ScanJob, Vulnerability, PortScanResult


@admin.register(ScanTarget)
class ScanTargetAdmin(admin.ModelAdmin):
    list_display = ['name', 'target', 'target_type', 'created_by', 'created_at']
    list_filter = ['target_type', 'created_at']
    search_fields = ['name', 'target', 'description']
    readonly_fields = ['created_at', 'updated_at']


@admin.register(ScanConfiguration)
class ScanConfigurationAdmin(admin.ModelAdmin):
    list_display = ['name', 'scan_type', 'is_default', 'created_by', 'created_at']
    list_filter = ['scan_type', 'is_default']
    search_fields = ['name']


@admin.register(ScanJob)
class ScanJobAdmin(admin.ModelAdmin):
    list_display = ['id', 'target', 'status', 'initiated_by', 'vulnerabilities_found', 'created_at']
    list_filter = ['status', 'created_at']
    search_fields = ['target__name', 'initiated_by__username']
    readonly_fields = ['celery_task_id', 'started_at', 'completed_at', 'created_at']

    fieldsets = (
        ('Scan Information', {
            'fields': ('target', 'configuration', 'initiated_by', 'status', 'progress', 'current_phase')
        }),
        ('Results Summary', {
            'fields': ('total_ports_scanned', 'open_ports_found', 'vulnerabilities_found',
                      'critical_vulns', 'high_vulns', 'medium_vulns', 'low_vulns')
        }),
        ('Timing', {
            'fields': ('started_at', 'completed_at', 'created_at')
        }),
        ('Technical', {
            'fields': ('celery_task_id', 'error_message'),
            'classes': ('collapse',)
        }),
    )


@admin.register(Vulnerability)
class VulnerabilityAdmin(admin.ModelAdmin):
    list_display = ['title', 'severity', 'vuln_type', 'port', 'service', 'scan_job', 'created_at']
    list_filter = ['severity', 'vuln_type', 'created_at']
    search_fields = ['title', 'description', 'cve_id', 'service']
    readonly_fields = ['created_at']

    fieldsets = (
        ('Vulnerability Details', {
            'fields': ('scan_job', 'title', 'vuln_type', 'severity', 'cvss_score')
        }),
        ('Technical Information', {
            'fields': ('port', 'protocol', 'service', 'service_version')
        }),
        ('Description & Impact', {
            'fields': ('description', 'impact', 'recommendation')
        }),
        ('CVE Information', {
            'fields': ('cve_id', 'cve_url'),
            'classes': ('collapse',)
        }),
        ('Evidence', {
            'fields': ('evidence', 'raw_output'),
            'classes': ('collapse',)
        }),
    )


@admin.register(PortScanResult)
class PortScanResultAdmin(admin.ModelAdmin):
    list_display = ['scan_job', 'port', 'protocol', 'state', 'service', 'created_at']
    list_filter = ['state', 'protocol']
    search_fields = ['port', 'service']
