from django.contrib import admin
from .models import Report, ExportHistory


@admin.register(Report)
class ReportAdmin(admin.ModelAdmin):
    list_display = ['title', 'format', 'scan_job', 'generated_by', 'total_findings', 'generated_at']
    list_filter = ['format', 'generated_at']
    search_fields = ['title', 'scan_job__target__name']
    readonly_fields = ['generated_at', 'file_size']


@admin.register(ExportHistory)
class ExportHistoryAdmin(admin.ModelAdmin):
    list_display = ['report', 'exported_by', 'ip_address', 'exported_at']
    list_filter = ['exported_at']
    search_fields = ['report__title', 'exported_by__username']
    readonly_fields = ['exported_at']
