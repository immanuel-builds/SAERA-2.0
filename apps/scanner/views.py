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
            
            # Validate target
            if not _validate_target(target_input):
                messages.error(request, "Invalid target. Please enter a valid IP address, domain, or CIDR range.")
                return render(request, 'scanner/scan_create.html', {'form': form})
            
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
            
            # Create or reuse a scan configuration that exactly matches this request.
            # Reusing only by scan type causes later checkbox changes to be ignored.
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
                # Broker (Redis) not reachable — can happen if Redis stopped after startup.
                # settings.py auto-detection handles the startup case; this catches runtime failures.
                error_str = str(broker_exc)
                broker_keywords = (
                    'ConnectionError', 'ConnectionRefused', 'connect',
                    '10061', 'refused', 'OperationalError', 'No such file',
                    'Transport', 'channel', 'redis',
                )
                if any(k.lower() in error_str.lower() for k in broker_keywords):
                    scan_job.delete()
                    messages.error(
                        request,
                        "Cannot reach the task broker (Redis). "
                        "Either start Redis or set CELERY_TASK_ALWAYS_EAGER=True in your "
                        ".env file, then restart the server. "
                        "The app will then run scans synchronously without Redis."
                    )
                    return render(request, 'scanner/scan_create.html', {'form': form})
                raise

            messages.success(request, f"Scan initiated successfully! Scan ID: #{scan_job.id}")
            return redirect('scan_progress', scan_id=scan_job.id)
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
    
    data = {
        'status': scan.status,
        'progress': scan.progress,
        'current_phase': scan.current_phase,
        'total_ports_scanned': scan.total_ports_scanned,
        'open_ports_found': scan.open_ports_found,
        'vulnerabilities_found': scan.vulnerabilities_found,
        'error_message': scan.error_message,
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
