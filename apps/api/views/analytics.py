"""
Analytics Views for SAERA.
Provides RESTful visual-ready endpoints for risk drift, tides, posture dossiers, and concentrations.
"""
from rest_framework import viewsets, response, status
from rest_framework.decorators import action
from apps.scanner.services.analytics_service import AnalyticsService
from apps.scanner.services.aggregation_service import AggregationService
from apps.api.serializers.analytics import HostPostureSummarySerializer

class AnalyticsViewSet(viewsets.ViewSet):
    """
    Exposes premium historical cyber risk analytics and temporal trends.
    Provides visualization-ready, pre-calculated payloads directly to dashboard components.
    """

    @action(detail=True, methods=['get'], url_path='posture')
    def posture(self, request, pk=None):
        """
        Retrieves the complete HostPostureSummary dossier.
        Endpoint: /api/v1/analytics/<target_id>/posture/
        """
        try:
            target_id = int(pk)
        except ValueError:
            return response.Response({"error": "Invalid asset primary key identifier."}, status=status.HTTP_400_BAD_REQUEST)
            
        summary = AggregationService.get_host_posture_summary(target_id)
        if "error" in summary:
            return response.Response(summary, status=status.HTTP_404_NOT_FOUND)
            
        serializer = HostPostureSummarySerializer(summary)
        return response.Response(serializer.data)

    @action(detail=True, methods=['get'], url_path='tide')
    def tide(self, request, pk=None):
        """
        Retrieves chronological tide-series data for risk score line charts.
        Endpoint: /api/v1/analytics/<target_id>/tide/
        """
        try:
            target_id = int(pk)
        except ValueError:
            return response.Response({"error": "Invalid asset primary key identifier."}, status=status.HTTP_400_BAD_REQUEST)
            
        tide = AnalyticsService.get_risk_tide_series(target_id)
        return response.Response(tide)

    @action(detail=True, methods=['get'], url_path='drift')
    def drift(self, request, pk=None):
        """
        Retrieves precise scan-over-scan posture delta tracking.
        Endpoint: /api/v1/analytics/<target_id>/drift/
        """
        try:
            target_id = int(pk)
        except ValueError:
            return response.Response({"error": "Invalid asset primary key identifier."}, status=status.HTTP_400_BAD_REQUEST)
            
        drift = AnalyticsService.get_risk_drift(target_id)
        return response.Response(drift)

    @action(detail=True, methods=['get'], url_path='concentration')
    def concentration(self, request, pk=None):
        """
        Retrieves open service concentration metrics for threat breakdown charts.
        Endpoint: /api/v1/analytics/<target_id>/concentration/
        """
        try:
            target_id = int(pk)
        except ValueError:
            return response.Response({"error": "Invalid asset primary key identifier."}, status=status.HTTP_400_BAD_REQUEST)
            
        concentration = AnalyticsService.get_service_concentration(target_id)
        return response.Response(concentration)
