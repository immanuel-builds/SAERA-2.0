"""
Dashboard app URL configuration
"""
from django.urls import path
from . import views

urlpatterns = [
    path('', views.landing, name='landing'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('network-map/', views.network_map, name='network_map'),
]
