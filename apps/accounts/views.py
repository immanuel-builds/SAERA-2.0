"""
Accounts app views for authentication
"""
from django.shortcuts import render, redirect
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied
from django.db.models import Count
from .models import AuditLog
from .forms import UserRegistrationForm

User = get_user_model()


def get_client_ip(request):
    """Get client IP address from request"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


def login_view(request):
    """User login view"""
    if request.user.is_authenticated:
        return redirect('dashboard')
    
    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(username=username, password=password)
            
            if user is not None:
                login(request, user)
                
                # Create audit log
                AuditLog.objects.create(
                    user=user,
                    action='user_login',
                    description=f"User {username} logged in",
                    ip_address=get_client_ip(request),
                    user_agent=request.META.get('HTTP_USER_AGENT', '')
                )
                
                messages.success(request, f"Welcome back, {username}!")
                return redirect('dashboard')
        else:
            messages.error(request, "Invalid username or password.")
    else:
        form = AuthenticationForm()
    
    return render(request, 'accounts/login.html', {'form': form})


def signup_view(request):
    """User registration view"""
    if request.user.is_authenticated:
        return redirect('dashboard')
    
    if request.method == 'POST':
        form = UserRegistrationForm(request.POST)
        if form.is_valid():
            user = form.save()
            
            # Create audit log
            AuditLog.objects.create(
                user=user,
                action='user_signup',
                description=f"New account created for {user.username}",
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
    
    # Create audit log
    AuditLog.objects.create(
        user=user,
        action='user_logout',
        description=f"User {user.username} logged out",
        ip_address=get_client_ip(request),
        user_agent=request.META.get('HTTP_USER_AGENT', '')
    )
    
    logout(request)
    messages.success(request, "You have been logged out successfully.")
    return redirect('login')




@login_required
def profile_view(request):
    """User profile view"""
    audit_logs = request.user.audit_logs.all()[:10]
    recent_scans = request.user.initiated_scans.all()[:5]
    
    context = {
        'audit_logs': audit_logs,
        'recent_scans': recent_scans,
    }
    return render(request, 'accounts/profile.html', context)


@login_required
def admin_console(request):
    """Backend Engine Control Center view"""
    if not request.user.is_admin:
        raise PermissionDenied
    
    from apps.scanner.models import ScanTarget, ScanJob, Vulnerability, ScanConfiguration
    from apps.reports.models import Report
    
    # Engine Health Simulation/Check
    try:
        from config.celery import app as celery_app
        inspector = celery_app.control.inspect()
        active_workers = inspector.active()
        engine_status = 'online' if active_workers else 'degraded'
    except:
        engine_status = 'unknown'

    # Get overall statistics
    stats = {
        'total_users': User.objects.count(),
        'active_users': User.objects.filter(is_active=True).count(),
        'admin_users': User.objects.filter(role='admin').count(),
        'total_targets': ScanTarget.objects.count(),
        'total_scans': ScanJob.objects.count(),
        'total_vulns': Vulnerability.objects.count(),
        'total_reports': Report.objects.count(),
        'engine_status': engine_status,
    }
    
    # Get recent audit logs
    recent_logs = AuditLog.objects.all().select_related('user').order_by('-created_at')[:50]
    
    # Get recent user registrations
    new_users = User.objects.all().order_by('-date_joined')[:10]
    
    context = {
        'stats': stats,
        'recent_logs': recent_logs,
        'new_users': new_users,
    }
    return render(request, 'accounts/admin_console.html', context)


@login_required
def delete_user(request, user_id):
    """Decommission an operative (delete user)"""
    if not request.user.is_admin:
        raise PermissionDenied
    
    target_user = get_object_or_404(User, id=user_id)
    
    # Prevent self-deletion
    if target_user == request.user:
        messages.error(request, "Negative. You cannot decommission your own profile.")
        return redirect('admin_console')
    
    # Prevent deleting other admins if current user is not superuser
    if target_user.is_admin and not request.user.is_superuser:
        messages.error(request, "Insufficient clearance to decommission another Admin.")
        return redirect('admin_console')
        
    username = target_user.username
    target_user.delete()
    
    # Create audit log
    AuditLog.objects.create(
        user=request.user,
        action='user_deleted', # Need to ensure this choice exists or use a generic one
        description=f"Operative {username} (ID: {user_id}) was decommissioned by {request.user.username}",
        ip_address=get_client_ip(request),
        user_agent=request.META.get('HTTP_USER_AGENT', '')
    )
    
    messages.success(request, f"Operative {username} has been successfully decommissioned.")
    return redirect('admin_console')
