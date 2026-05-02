"""
Scanner app URL configuration
"""
from django.urls import path
from . import views

urlpatterns = [
    path('', views.scan_list, name='scan_list'),
    path('create/', views.scan_create, name='scan_create'),
    path('<int:scan_id>/', views.scan_detail, name='scan_detail'),
    path('<int:scan_id>/progress/', views.scan_progress, name='scan_progress'),
    path('api/progress/<int:scan_id>/', views.scan_progress_api, name='scan_progress_api'),
    path('vulnerabilities/', views.vulnerability_list, name='vulnerability_list'),
]
