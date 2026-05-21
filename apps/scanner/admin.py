from django.contrib import admin
from .models import (
    ScanTarget, ScanConfiguration, ScanJob,
    Vulnerability, PortScanResult, ScanLog, ObservatoryHealthLog
)


@admin.register(ScanTarget)
class ScanTargetAdmin(admin.ModelAdmin):
    list_display = ['name', 'target', 'target_type', 'created_by', 'created_at']
    list_filter = ['target_type', 'created_at']
    search_fields = ['name', 'target', 'description']
    readonly_fields = ['created_at', 'updated_at']


@admin.register(ScanConfiguration)
class ScanConfigurationAdmin(admin.ModelAdmin):
    list_display = ['name', 'scan_type', 'port_range', 'is_default', 'created_by', 'created_at']
    list_filter = ['scan_type', 'is_default']
    search_fields = ['name']
    readonly_fields = ['created_at']


@admin.register(ScanJob)
class ScanJobAdmin(admin.ModelAdmin):
    list_display = ['id', 'target', 'status', 'initiated_by', 'progress',
                    'vulnerabilities_found', 'aggregate_risk_score', 'created_at']
    list_filter = ['status', 'created_at']
    search_fields = ['target__name', 'target__target', 'initiated_by__username']
    readonly_fields = ['started_at', 'completed_at', 'created_at']

    fieldsets = (
        ('Scan Information', {
            'fields': ('target', 'configuration', 'initiated_by', 'status', 'progress', 'current_phase')
        }),
        ('Results Summary', {
            'fields': (
                'total_ports_scanned', 'open_ports_found', 'vulnerabilities_found',
                'critical_vulns', 'high_vulns', 'medium_vulns', 'low_vulns',
                'aggregate_risk_score',
            )
        }),
        ('Timing', {
            'fields': ('started_at', 'completed_at', 'created_at')
        }),
        ('Error Details', {
            'fields': ('error_message',),
            'classes': ('collapse',)
        }),
    )


@admin.register(Vulnerability)
class VulnerabilityAdmin(admin.ModelAdmin):
    list_display = ['title', 'severity', 'vuln_type', 'port', 'service',
                    'risk_score', 'lifecycle_state', 'investigation_state', 'scan_job', 'created_at']
    list_filter = ['severity', 'vuln_type', 'lifecycle_state', 'investigation_state',
                   'is_suppressed', 'resolved', 'recurring', 'created_at']
    search_fields = ['title', 'description', 'cve_id', 'service']
    readonly_fields = ['created_at', 'first_seen', 'last_seen']

    fieldsets = (
        ('Core Details', {
            'fields': ('scan_job', 'title', 'vuln_type', 'severity', 'cvss_score',
                       'risk_score', 'risk_level', 'exploitability', 'priority_score')
        }),
        ('Technical Information', {
            'fields': ('port', 'protocol', 'service', 'service_version')
        }),
        ('Description & Impact', {
            'fields': ('description', 'impact', 'recommendation', 'cve_id', 'cve_url')
        }),
        ('Lifecycle & Workflow', {
            'fields': ('lifecycle_state', 'investigation_state', 'analyst_annotation', 'remediation_note')
        }),
        ('Suppression', {
            'fields': ('is_suppressed', 'suppressed_at', 'suppressed_reason'),
            'classes': ('collapse',)
        }),
        ('Historical Tracking', {
            'fields': ('first_seen', 'last_seen', 'observation_count', 'reappeared_count',
                       'resolved', 'resolved_at', 'recurring', 'created_at'),
            'classes': ('collapse',)
        }),
    )


@admin.register(PortScanResult)
class PortScanResultAdmin(admin.ModelAdmin):
    list_display = ['scan_job', 'port', 'protocol', 'state', 'service',
                    'lifecycle_state', 'observation_count', 'created_at']
    list_filter = ['state', 'protocol', 'lifecycle_state', 'is_suppressed']
    search_fields = ['port', 'service', 'scan_job__target__name']
    readonly_fields = ['created_at', 'first_seen', 'last_seen']


@admin.register(ScanLog)
class ScanLogAdmin(admin.ModelAdmin):
    list_display = ['scan_job', 'message', 'timestamp']
    list_filter = ['timestamp']
    search_fields = ['message', 'scan_job__target__name']
    readonly_fields = ['timestamp']

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


@admin.register(ObservatoryHealthLog)
class ObservatoryHealthLogAdmin(admin.ModelAdmin):
    list_display = ['metric_name', 'duration_ms', 'status', 'created_at']
    list_filter = ['status', 'metric_name', 'created_at']
    search_fields = ['metric_name', 'message']
    readonly_fields = ['created_at']

    def has_add_permission(self, request):
        return False
