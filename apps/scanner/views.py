"""
Scanner app views
"""
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import JsonResponse, HttpResponseForbidden
from django.views.decorators.http import require_http_methods
from django.db.models import Q, Count
from .models import ScanTarget, ScanJob, Vulnerability, ScanConfiguration, PortScanResult
from .forms import ScanTargetForm, QuickScanForm, ScanConfigurationForm
from .tasks import scan_target_task
from apps.accounts.decorators import analyst_or_admin, admin_only
from apps.accounts.views import get_client_ip
import re
import ipaddress


@login_required
def scan_list(request):
    """List all scans for the current user"""
    scans = ScanJob.objects.filter(initiated_by=request.user).select_related('target', 'configuration')
    
    # Filter by status if provided
    status_filter = request.GET.get('status')
    if status_filter:
        scans = scans.filter(status=status_filter)
    
    context = {
        'scans': scans,
        'status_filter': status_filter,
    }
    return render(request, 'scanner/scan_list.html', context)


@login_required
@analyst_or_admin
def scan_create(request):
    """Create and initiate a new scan"""
    if not request.user.can_initiate_scans:
        messages.error(request, "You don't have permission to initiate scans.")
        return redirect('scan_list')
    
    if request.method == 'POST':
        form = QuickScanForm(request.POST)
        if form.is_valid():
            target_input = form.cleaned_data['target']
            scan_type = form.cleaned_data['scan_type']
            
            # Determine target type
            target_type = _determine_target_type(target_input)
            
            # Create or get scan target
            target, created = ScanTarget.objects.get_or_create(
                target=target_input,
                created_by=request.user,
                defaults={
                    'name': target_input,
                    'target_type': target_type,
                }
            )
            
            # Create or reuse a scan configuration
            port_ranges = {
                'quick': '1-100',
                'standard': '1-1000',
                'deep': '1-65535',
            }
            port_range = port_ranges.get(scan_type, '1-1000')
            enable_service_detection = form.cleaned_data.get('enable_service_detection', True)
            enable_vuln_detection = form.cleaned_data.get('enable_vuln_detection', True)
            
            config = ScanConfiguration.objects.filter(
                scan_type=scan_type,
                created_by=request.user,
                port_range=port_range,
                enable_service_detection=enable_service_detection,
                enable_vuln_detection=enable_vuln_detection,
            ).first()

            if config is None:
                config = ScanConfiguration.objects.create(
                    name=f"{scan_type.capitalize()} Scan",
                    scan_type=scan_type,
                    created_by=request.user,
                    port_range=port_range,
                    enable_service_detection=enable_service_detection,
                    enable_vuln_detection=enable_vuln_detection,
                )
            
            # Create scan job
            scan_job = ScanJob.objects.create(
                target=target,
                configuration=config,
                initiated_by=request.user,
                status='pending',
            )
            
            # Start the scan task
            try:
                scan_target_task.delay(scan_job.id)
            except Exception as broker_exc:
                error_str = str(broker_exc)
                broker_keywords = ('ConnectionError', 'ConnectionRefused', 'connect', '10061', 'redis')
                if any(k.lower() in error_str.lower() for k in broker_keywords):
                    scan_job.delete()
                    messages.error(request, "Cannot reach the task broker (Redis).")
                    return render(request, 'scanner/scan_create.html', {'form': form})
                raise

            messages.success(request, f"Scan initiated successfully! Scan ID: #{scan_job.id}")
            return redirect('scan_progress', scan_id=scan_job.id)
        else:
            # Security Event: Log validation failure
            from apps.accounts.models import AuditLog
            AuditLog.objects.create(
                user=request.user,
                action='security_event',
                description=f"Security Alert: Validation failed for scan target input. Errors: {form.errors.as_text()}",
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )
            messages.error(request, "Security Validation Failed. Your attempt has been logged.")
    else:
        form = QuickScanForm()
    
    context = {'form': form}
    return render(request, 'scanner/scan_create.html', context)


@login_required
def scan_detail(request, scan_id):
    """View detailed scan results"""
    scan = get_object_or_404(ScanJob, id=scan_id, initiated_by=request.user)
    
    # Get vulnerabilities grouped by severity
    vulnerabilities = scan.vulnerabilities.all()
    
    # Get port scan results
    open_ports = scan.port_results.filter(state='open').order_by('port')
    
    context = {
        'scan': scan,
        'vulnerabilities': vulnerabilities,
        'open_ports': open_ports,
        'critical_vulns': vulnerabilities.filter(severity='critical'),
        'high_vulns': vulnerabilities.filter(severity='high'),
        'medium_vulns': vulnerabilities.filter(severity='medium'),
        'low_vulns': vulnerabilities.filter(severity='low'),
    }
    return render(request, 'scanner/scan_detail.html', context)


@login_required
def scan_progress(request, scan_id):
    """View scan progress in real-time"""
    scan = get_object_or_404(ScanJob, id=scan_id, initiated_by=request.user)
    
    context = {'scan': scan}
    return render(request, 'scanner/scan_progress.html', context)


@login_required
@require_http_methods(["GET"])
def scan_progress_api(request, scan_id):
    """API endpoint for real-time scan progress"""
    scan = get_object_or_404(ScanJob, id=scan_id, initiated_by=request.user)
    
    # Get latest logs (e.g., last 10)
    # Assuming scan_job has a logs relation or we can fetch them
    # For now, let's assume we fetch them from an AuditLog or similar if available, 
    # or just return a placeholder if not implemented.
    # Based on the template, it expects 'logs' and 'vulnerability_count'
    
    data = {
        'status': scan.status,
        'progress': scan.progress,
        'current_phase': scan.current_phase,
        'total_ports_scanned': scan.total_ports_scanned,
        'open_ports_found': scan.open_ports_found,
        'vulnerability_count': scan.vulnerabilities.count(),
        'error_message': scan.error_message,
        'logs': [log.message for log in scan.logs.all().order_by('-timestamp')[:5]][::-1] if hasattr(scan, 'logs') else ["Observing sector...", "Signal locked."]
    }
    
    return JsonResponse(data)


@login_required
def vulnerability_list(request):
    """List all vulnerabilities from user's scans"""
    vulnerabilities = Vulnerability.objects.filter(
        scan_job__initiated_by=request.user
    ).select_related('scan_job', 'scan_job__target')
    
    # Filter by severity
    severity_filter = request.GET.get('severity')
    if severity_filter:
        vulnerabilities = vulnerabilities.filter(severity=severity_filter)
    
    # Search
    search_query = request.GET.get('q')
    if search_query:
        vulnerabilities = vulnerabilities.filter(
            Q(title__icontains=search_query) | 
            Q(description__icontains=search_query) |
            Q(cve_id__icontains=search_query)
        )
    
    context = {
        'vulnerabilities': vulnerabilities,
        'severity_filter': severity_filter,
        'search_query': search_query,
    }
    return render(request, 'scanner/vulnerability_list.html', context)


@login_required
def target_drift(request, target_id):
    """Temporal analysis of a target's risk posture over time (Chronicle Drift)"""
    from apps.api.services.analytics_service import AnalyticsService
    target = get_object_or_404(ScanTarget, id=target_id)
    
    # Check permissions
    if not request.user.is_admin and target.created_by != request.user:
        return HttpResponseForbidden("You do not have access to this target's chronicle.")
    
    # Get last two completed scans for metrics
    scans = ScanJob.objects.filter(target=target, status='completed').order_by('-created_at')[:2]
    if scans.count() < 2:
        messages.info(request, "Insufficient data in the chronicle for temporal analysis.")
        return redirect('dashboard')

    # Leverage the centralized AnalyticsService
    drift_data = AnalyticsService.get_drift_analysis(target_id)
    
    # We still need the scan objects for the UI context
    current_scan = scans[0]
    previous_scan = scans[1]
    
    # Fetch emergent vulnerabilities for display
    new_vulnerabilities = current_scan.vulnerabilities.filter(title__in=drift_data['emergent'])
    
    # Historical risk scores for the trend cards
    avg_curr = current_scan.vulnerabilities.aggregate(avg=Count('id'))['avg'] # Simplified for this pass
    # Actually, let's keep the risk score calculation
    from django.db.models import Avg
    avg_curr = current_scan.vulnerabilities.aggregate(avg=Avg('risk_score'))['avg'] or 0
    avg_prev = previous_scan.vulnerabilities.aggregate(avg=Avg('risk_score'))['avg'] or 0

    context = {
        'target': target,
        'current_scan': current_scan,
        'previous_scan': previous_scan,
        'new_vulnerabilities': new_vulnerabilities,
        'resolved_count': len(drift_data['resolved']),
        'risk_drift': round(avg_curr - avg_prev, 2),
        'avg_curr': round(avg_curr, 1),
        'avg_prev': round(avg_prev, 1),
    }
    
    return render(request, 'scanner/target_drift.html', context)


def _validate_target(target):
    """Validate scan target"""
    # Check if it's a valid IP address
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass
    
    # Check if it's a valid CIDR range
    try:
        ipaddress.ip_network(target, strict=False)
        return True
    except ValueError:
        pass
    
    # Check if it's a valid domain name
    domain_pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    if re.match(domain_pattern, target):
        return True
    
    return False


def _determine_target_type(target):
    """Determine the type of target"""
    try:
        ipaddress.ip_address(target)
        return 'ip'
    except ValueError:
        pass
    
    try:
        ipaddress.ip_network(target, strict=False)
        return 'range'
    except ValueError:
        pass
    
    return 'domain'
