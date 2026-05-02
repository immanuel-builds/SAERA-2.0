"""
Reports app URL configuration
"""
from django.urls import path
from . import views

urlpatterns = [
    path('', views.report_list, name='report_list'),
    path('generate/<int:scan_id>/', views.report_generate, name='report_generate'),
    path('download/<int:report_id>/', views.report_download, name='report_download'),
]
