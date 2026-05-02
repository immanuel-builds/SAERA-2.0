"""
Dashboard app views
"""
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.db.models import Count, Q
from apps.scanner.models import ScanJob, Vulnerability
from apps.reports.models import Report


@login_required
def dashboard(request):
    """Main dashboard view"""
    user = request.user
    
    # Get statistics
    total_scans = ScanJob.objects.filter(initiated_by=user).count()
    completed_scans = ScanJob.objects.filter(initiated_by=user, status='completed').count()
    running_scans = ScanJob.objects.filter(initiated_by=user, status='running').count()
    
    total_vulnerabilities = Vulnerability.objects.filter(scan_job__initiated_by=user).count()
    critical_vulns = Vulnerability.objects.filter(scan_job__initiated_by=user, severity='critical').count()
    high_vulns = Vulnerability.objects.filter(scan_job__initiated_by=user, severity='high').count()
    
    # Recent scans
    recent_scans = ScanJob.objects.filter(initiated_by=user).select_related('target')[:5]
    
    # Recent critical vulnerabilities
    recent_vulns = Vulnerability.objects.filter(
        scan_job__initiated_by=user,
        severity='critical',
    ).select_related('scan_job', 'scan_job__target').order_by('-created_at')[:10]
    
    # Vulnerability distribution
    vuln_distribution = Vulnerability.objects.filter(
        scan_job__initiated_by=user
    ).values('severity').annotate(count=Count('id'))
    
    # Convert to dictionary for easy template access
    severity_counts = {
        'critical': 0,
        'high': 0,
        'medium': 0,
        'low': 0,
        'info': 0,
    }
    for item in vuln_distribution:
        severity_counts[item['severity']] = item['count']
    
    context = {
        'total_scans': total_scans,
        'completed_scans': completed_scans,
        'running_scans': running_scans,
        'total_vulnerabilities': total_vulnerabilities,
        'critical_vulns': critical_vulns,
        'high_vulns': high_vulns,
        'recent_scans': recent_scans,
        'recent_vulns': recent_vulns,
        'severity_counts': severity_counts,
    }
    
    return render(request, 'dashboard/index.html', context)
