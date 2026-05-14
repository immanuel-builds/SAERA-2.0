from django.urls import path
from . import views

app_name = 'knowledge'

urlpatterns = [
    path('', views.reference_list, name='list'),
    path('<slug:slug>/', views.reference_detail, name='detail'),
]
