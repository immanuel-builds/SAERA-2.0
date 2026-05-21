from django.urls import path, include
from rest_framework.routers import DefaultRouter
from apps.api.views.intelligence import IntelligenceViewSet
from apps.api.views.analytics import AnalyticsViewSet
from apps.api.views.workflows import VulnerabilityWorkflowViewSet

router = DefaultRouter()
router.register(r'intelligence', IntelligenceViewSet, basename='intelligence')
router.register(r'analytics', AnalyticsViewSet, basename='analytics')
router.register(r'workflows/vulnerability', VulnerabilityWorkflowViewSet, basename='vulnerability-workflow')

urlpatterns = [
    path('', include(router.urls)),
]
