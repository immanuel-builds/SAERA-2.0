from rest_framework import viewsets, response, status
from rest_framework.decorators import action
from apps.scanner.models import ScanJob
from apps.api.serializers.intelligence import IntelligenceObjectSerializer
from apps.api.services.intelligence_service import IntelligenceService
from apps.api.services.analytics_service import AnalyticsService

class IntelligenceViewSet(viewsets.ReadOnlyModelViewSet):
    """
    The primary entry point for SAERA's Intelligence API.
    Provides canonical, enriched scan data for all platform consumers.
    """
    queryset = ScanJob.objects.all()
    serializer_class = IntelligenceObjectSerializer

    def retrieve(self, request, *args, **kwargs):
        """Fetch a single enriched intelligence object"""
        instance = IntelligenceService.get_full_intelligence(kwargs.get('pk'))
        if not instance:
            return response.Response(status=status.HTTP_404_NOT_FOUND)
        
        serializer = self.get_serializer(instance)
        return response.Response(serializer.data)

    @action(detail=True, methods=['get'])
    def topology(self, request, pk=None):
        """Dedicated endpoint for network topography relationship data"""
        instance = IntelligenceService.get_full_intelligence(pk)
        if not instance:
            return response.Response(status=status.HTTP_404_NOT_FOUND)
        
        return response.Response(instance.topology_data)

    @action(detail=True, methods=['get'])
    def analytics(self, request, pk=None):
        """Historical risk trends for the target associated with this scan"""
        scan = self.get_object()
        trends = AnalyticsService.get_target_risk_trend(scan.target.id)
        return response.Response(trends)

    @action(detail=True, methods=['get'])
    def drift(self, request, pk=None):
        """Temporal drift analysis (New vs Resolved threats) for this scan"""
        scan = self.get_object()
        drift = AnalyticsService.get_drift_analysis(scan.target.id)
        return response.Response(drift)
