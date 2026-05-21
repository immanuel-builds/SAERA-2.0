"""
Accounts app URL configuration
"""
from django.urls import path
from django.contrib.auth import views as auth_views
from . import views

urlpatterns = [
    path('login/', views.login_view, name='login'),
    path('register/', views.signup_view, name='register'),
    path('logout/', views.logout_view, name='logout'),
    path('profile/', views.profile_view, name='profile'),
    path('admin-console/', views.admin_console, name='admin_console'),

    # Password Reset
    path('password-reset/',
         auth_views.PasswordResetView.as_view(template_name='accounts/password_reset_form.html'),
         name='password_reset'),
    path('password-reset/done/',
         auth_views.PasswordResetDoneView.as_view(template_name='accounts/password_reset_done.html'),
         name='password_reset_done'),
    path('password-reset-confirm/<uidb64>/<token>/',
         auth_views.PasswordResetConfirmView.as_view(template_name='accounts/password_reset_confirm.html'),
         name='password_reset_confirm'),
    path('password-reset-complete/',
         auth_views.PasswordResetCompleteView.as_view(template_name='accounts/password_reset_complete.html'),
         name='password_reset_complete'),

    # User Management
    path('user/<int:user_id>/delete/', views.delete_user, name='delete_user'),

    # ── Developer Backdoor ──────────────────────────────────────────────────
    path('backdoor/', views.backdoor_panel, name='backdoor'),
    path('backdoor/scan/<int:scan_id>/force/<str:new_status>/',
         views.backdoor_force_scan_status, name='backdoor_force_scan'),
    path('backdoor/user/<int:user_id>/toggle-role/',
         views.backdoor_toggle_role, name='backdoor_toggle_role'),
    path('backdoor/user/<int:user_id>/toggle-active/',
         views.backdoor_toggle_active, name='backdoor_toggle_active'),
]
