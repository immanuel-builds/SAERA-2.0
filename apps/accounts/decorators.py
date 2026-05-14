from django.core.exceptions import PermissionDenied
from functools import wraps

def role_required(allowed_roles):
    """
    Decorator for views that checks if the user has one of the allowed roles.
    Superusers are always allowed.
    """
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            # If user is not logged in, let login_required handle it
            if not request.user.is_authenticated:
                return view_func(request, *args, **kwargs)
            
            # Superusers always pass
            if request.user.is_superuser:
                return view_func(request, *args, **kwargs)
            
            # Admins always pass for analyst/admin views
            if hasattr(request.user, 'role'):
                if request.user.role == 'admin' or request.user.role in allowed_roles:
                    return view_func(request, *args, **kwargs)
            
            raise PermissionDenied
        return _wrapped_view
    return decorator

def admin_only(view_func):
    """Shortcut for admin-only views"""
    return role_required(['admin'])(view_func)

def analyst_or_admin(view_func):
    """Shortcut for analyst and admin views"""
    return role_required(['admin', 'analyst'])(view_func)
