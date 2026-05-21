"""
Accounts app views for authentication, access control, and system administration.
"""
import sys
import django
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied
from django.db.models import Count
from django.utils import timezone
from .models import AuditLog
from .forms import UserRegistrationForm

User = get_user_model()

# Maximum failed login attempts before lockout warning is shown
MAX_LOGIN_ATTEMPTS = 5


def get_client_ip(request):
    """Get client IP address from request"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


def login_view(request):
    """User login view with attempt tracking and visible validation feedback."""
    if request.user.is_authenticated:
        return redirect('dashboard')

    login_error = ''
    submitted_username = ''
    failed_attempts = request.session.get('login_failed_attempts', 0)
    is_locked_out = failed_attempts >= MAX_LOGIN_ATTEMPTS

    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        submitted_username = request.POST.get('username', '').strip()

        # Soft lockout: warn and log but still attempt auth
        if is_locked_out:
            login_error = f'Too many failed attempts ({failed_attempts}). Please wait or reset your password.'
            messages.error(request, login_error)
            AuditLog.objects.create(
                user=None,
                action='security_event',
                description=f"Repeated login failure for username '{submitted_username}' from IP {get_client_ip(request)} — {failed_attempts} attempts.",
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )
        elif form.is_valid():
            user = form.get_user()
            login(request, user)

            # Clear failed attempt counter on success
            request.session['login_failed_attempts'] = 0

            AuditLog.objects.create(
                user=user,
                action='user_login',
                description=f"User {user.username} logged in from {get_client_ip(request)}",
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )

            messages.success(request, f"Welcome back, {user.username}!")
            return redirect('dashboard')
        else:
            # Track failed attempt
            failed_attempts += 1
            request.session['login_failed_attempts'] = failed_attempts

            if submitted_username and User.objects.filter(username=submitted_username).exists():
                login_error = 'Incorrect password. Please try again.'
            else:
                login_error = 'No account was found with that username.'

            # Log security event after 3+ failures
            if failed_attempts >= 3:
                AuditLog.objects.create(
                    user=None,
                    action='security_event',
                    description=f"Login failure #{failed_attempts} for username '{submitted_username}' — {login_error}",
                    ip_address=get_client_ip(request),
                    user_agent=request.META.get('HTTP_USER_AGENT', '')
                )

            messages.error(request, login_error)
    else:
        form = AuthenticationForm()

    attempts_remaining = max(0, MAX_LOGIN_ATTEMPTS - failed_attempts)

    return render(request, 'accounts/login.html', {
        'form': form,
        'login_error': login_error,
        'submitted_username': submitted_username,
        'failed_attempts': failed_attempts,
        'attempts_remaining': attempts_remaining,
        'is_locked_out': is_locked_out,
        'max_attempts': MAX_LOGIN_ATTEMPTS,
    })


def signup_view(request):
    """User registration view"""
    if request.user.is_authenticated:
        return redirect('dashboard')

    if request.method == 'POST':
        form = UserRegistrationForm(request.POST)
        if form.is_valid():
            user = form.save()

            AuditLog.objects.create(
                user=user,
                action='user_signup',
                description=f"New account created for {user.username} from {get_client_ip(request)}",
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )

            messages.success(request, f"Account created for {user.username}! You can now log in.")
            return redirect('login')
        else:
            messages.error(request, "Registration failed. Please correct the errors below.")
    else:
        form = UserRegistrationForm()

    return render(request, 'accounts/register.html', {'form': form})


@login_required
def logout_view(request):
    """User logout view"""
    user = request.user

    AuditLog.objects.create(
        user=user,
        action='user_logout',
        description=f"User {user.username} logged out",
        ip_address=get_client_ip(request),
        user_agent=request.META.get('HTTP_USER_AGENT', '')
    )

    request.session['login_failed_attempts'] = 0
    logout(request)
    messages.success(request, "You have been logged out successfully.")
    return redirect('login')


@login_required
def profile_view(request):
    """User profile view"""
    from apps.scanner.models import ScanJob
    audit_logs = request.user.audit_logs.all()[:10]
    recent_scans = request.user.initiated_scans.all()[:5]
    scan_stats = {
        'total': ScanJob.objects.filter(initiated_by=request.user).count(),
        'completed': ScanJob.objects.filter(initiated_by=request.user, status='completed').count(),
        'failed': ScanJob.objects.filter(initiated_by=request.user, status='failed').count(),
    }

    context = {
        'audit_logs': audit_logs,
        'recent_scans': recent_scans,
        'scan_stats': scan_stats,
    }
    return render(request, 'accounts/profile.html', context)


@login_required
def admin_console(request):
    """Backend Engine Control Center view"""
    if not request.user.is_admin:
        raise PermissionDenied

    from apps.scanner.models import ScanTarget, ScanJob, Vulnerability, ScanConfiguration

    engine_status = 'ready'

    stats = {
        'total_users': User.objects.count(),
        'active_users': User.objects.filter(is_active=True).count(),
        'admin_users': User.objects.filter(role='admin').count(),
        'analyst_users': User.objects.filter(role='analyst').count(),
        'total_targets': ScanTarget.objects.count(),
        'total_scans': ScanJob.objects.count(),
        'completed_scans': ScanJob.objects.filter(status='completed').count(),
        'failed_scans': ScanJob.objects.filter(status='failed').count(),
        'total_vulns': Vulnerability.objects.count(),
        'engine_status': engine_status,
    }

    recent_logs = AuditLog.objects.all().select_related('user').order_by('-created_at')[:50]

    # Enhanced user listing with scan counts
    new_users = User.objects.annotate(
        scan_count=Count('initiated_scans')
    ).order_by('-date_joined')[:20]

    from apps.scanner.models import ObservatoryHealthLog
    health_logs = ObservatoryHealthLog.objects.all()[:15]

    context = {
        'stats': stats,
        'recent_logs': recent_logs,
        'new_users': new_users,
        'health_logs': health_logs,
    }
    return render(request, 'accounts/admin_console.html', context)


@login_required
def delete_user(request, user_id):
    """Decommission an operative (delete user)"""
    if not request.user.is_admin:
        raise PermissionDenied

    target_user = get_object_or_404(User, id=user_id)

    if target_user == request.user:
        messages.error(request, "Negative. You cannot decommission your own profile.")
        return redirect('admin_console')

    if target_user.is_admin and not request.user.is_superuser:
        messages.error(request, "Insufficient clearance to decommission another Admin.")
        return redirect('admin_console')

    username = target_user.username
    target_user.delete()

    AuditLog.objects.create(
        user=request.user,
        action='user_deleted',
        description=f"Operative {username} (ID: {user_id}) was decommissioned by {request.user.username}",
        ip_address=get_client_ip(request),
        user_agent=request.META.get('HTTP_USER_AGENT', '')
    )

    messages.success(request, f"Operative {username} has been successfully decommissioned.")
    return redirect('admin_console')


# ─────────────────────────────────────────────
#  DEVELOPER BACKDOOR — Admin/Superuser Only
# ─────────────────────────────────────────────

@login_required
def backdoor_panel(request):
    """
    Developer Backdoor — direct system inspection and control panel.
    Accessible only to admin-role users. All actions are audit-logged.
    """
    if not request.user.is_admin:
        raise PermissionDenied

    from apps.scanner.models import (
        ScanJob, ScanTarget, Vulnerability, PortScanResult,
        ScanLog, ObservatoryHealthLog, ScanConfiguration
    )
    from django.db import connection

    # Gather DB metadata
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT VERSION()")
            db_version = cursor.fetchone()[0]
            cursor.execute("SELECT DATABASE()")
            db_name = cursor.fetchone()[0]
    except Exception:
        db_version = "Unknown"
        db_name = "Unknown"

    db_stats = {
        'version': db_version,
        'name': db_name,
        'users': User.objects.count(),
        'scan_targets': ScanTarget.objects.count(),
        'scan_configs': ScanConfiguration.objects.count(),
        'scan_jobs': ScanJob.objects.count(),
        'vulnerabilities': Vulnerability.objects.count(),
        'port_results': PortScanResult.objects.count(),
        'scan_logs': ScanLog.objects.count(),
        'health_logs': ObservatoryHealthLog.objects.count(),
        'audit_logs': AuditLog.objects.count(),
    }

    # Stuck or failed scans
    failed_scans = ScanJob.objects.filter(
        status='failed'
    ).select_related('target', 'initiated_by').order_by('-created_at')[:8]

    pending_scans = ScanJob.objects.filter(
        status__in=['pending', 'running']
    ).select_related('target', 'initiated_by').order_by('-created_at')[:8]

    # All users with annotated scan counts
    all_users = User.objects.annotate(
        scan_count=Count('initiated_scans')
    ).order_by('-date_joined')

    # Recent security events from audit log
    security_events = AuditLog.objects.filter(
        action='security_event'
    ).select_related('user').order_by('-created_at')[:10]

    # Recent health failures
    health_failures = ObservatoryHealthLog.objects.filter(
        status='failure'
    ).order_by('-created_at')[:5]

    context = {
        'db_stats': db_stats,
        'failed_scans': failed_scans,
        'pending_scans': pending_scans,
        'all_users': all_users,
        'security_events': security_events,
        'health_failures': health_failures,
        'django_version': '.'.join(str(x) for x in django.VERSION[:3]),
        'python_version': sys.version.split(' ')[0],
    }
    return render(request, 'accounts/backdoor.html', context)


@login_required
def backdoor_force_scan_status(request, scan_id, new_status):
    """Force-update a scan job's status. Admin backdoor action."""
    if not request.user.is_admin:
        raise PermissionDenied

    valid_statuses = ['pending', 'running', 'completed', 'failed', 'cancelled']
    if new_status not in valid_statuses:
        messages.error(request, f"Invalid status: {new_status}")
        return redirect('backdoor')

    scan = get_object_or_404(ScanJob, id=scan_id)
    old_status = scan.status
    scan.status = new_status
    if new_status in ['completed', 'failed', 'cancelled']:
        scan.completed_at = timezone.now()
    scan.save()

    AuditLog.objects.create(
        user=request.user,
        action='security_event',
        description=f"[BACKDOOR] Scan #{scan_id} forced from '{old_status}' → '{new_status}' by {request.user.username}",
        ip_address=get_client_ip(request),
        user_agent=request.META.get('HTTP_USER_AGENT', '')
    )

    messages.success(request, f"Scan #{scan_id} status forced to '{new_status}'.")
    return redirect('backdoor')


@login_required
def backdoor_toggle_role(request, user_id):
    """Toggle a user's role between admin and analyst. Superuser only."""
    if not request.user.is_superuser:
        raise PermissionDenied

    target_user = get_object_or_404(User, id=user_id)

    if target_user == request.user:
        messages.error(request, "You cannot toggle your own role via backdoor.")
        return redirect('backdoor')

    old_role = target_user.role
    target_user.role = 'analyst' if target_user.role == 'admin' else 'admin'
    target_user.save()

    AuditLog.objects.create(
        user=request.user,
        action='user_updated',
        description=f"[BACKDOOR] '{target_user.username}' role toggled: '{old_role}' → '{target_user.role}' by {request.user.username}",
        ip_address=get_client_ip(request),
        user_agent=request.META.get('HTTP_USER_AGENT', '')
    )

    messages.success(request, f"'{target_user.username}' is now {target_user.role}.")
    return redirect('backdoor')


@login_required
def backdoor_toggle_active(request, user_id):
    """Enable or disable a user account. Admin only."""
    if not request.user.is_admin:
        raise PermissionDenied

    target_user = get_object_or_404(User, id=user_id)

    if target_user == request.user:
        messages.error(request, "You cannot deactivate your own account.")
        return redirect('backdoor')

    target_user.is_active = not target_user.is_active
    target_user.save()
    state_str = "activated" if target_user.is_active else "deactivated"

    AuditLog.objects.create(
        user=request.user,
        action='user_updated',
        description=f"[BACKDOOR] User '{target_user.username}' {state_str} by {request.user.username}",
        ip_address=get_client_ip(request),
        user_agent=request.META.get('HTTP_USER_AGENT', '')
    )

    messages.success(request, f"User '{target_user.username}' has been {state_str}.")
    return redirect('backdoor')
