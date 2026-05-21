"""
Intelligence View Set for SAERA.
Exposes RESTful endpoints for retrieving normalized, transient Canonical Intelligence data.
"""
from rest_framework import viewsets, response, status
from rest_framework.decorators import action
from apps.scanner.models import ScanJob
from apps.api.serializers.intelligence import (
    CanonicalIntelligenceSerializer, ScanJobSummarySerializer
)
from apps.api.services.intelligence_service import IntelligenceService

class IntelligenceViewSet(viewsets.ReadOnlyModelViewSet):
    """
    The primary entry point for SAERA's Intelligence API.
    Provides canonical, enriched transient scan data for all platform consumers.
    """
    queryset = ScanJob.objects.all()

    def get_serializer_class(self):
        """
        Dynamically select serializers based on request action:
        - List scans: Return concise database scan summary stats
        - Retrieve detail: Return transient fully-enriched Canonical Intelligence Object (CIO)
        """
        if self.action == 'retrieve':
            return CanonicalIntelligenceSerializer
        return ScanJobSummarySerializer

    def retrieve(self, request, *args, **kwargs):
        """Fetch and return the complete, transient Canonical Intelligence Object (CIO)"""
        instance = IntelligenceService.get_full_intelligence(kwargs.get('pk'))
        if not instance:
            return response.Response(
                {"error": "Intelligence dossier not found for specified scanning session."},
                status=status.HTTP_404_NOT_FOUND
            )

        serializer = self.get_serializer(instance)
        return response.Response(serializer.data)

    @action(detail=True, methods=['get'])
    def topology(self, request, pk=None):
        """Dedicated endpoint for network topology relationship data"""
        # Kept as a lightweight placeholder for future topology builder integration
        instance = IntelligenceService.get_full_intelligence(pk)
        if not instance:
            return response.Response(status=status.HTTP_404_NOT_FOUND)

        # Standardize basic node/link structure directly from the CIO
        nodes = [{"id": instance.host.ip, "label": instance.host.hostname or instance.host.ip, "group": "host"}]
        links = []

        for service in instance.services:
            node_id = f"{instance.host.ip}:{service.port}"
            nodes.append({
                "id": node_id,
                "label": f"{service.service_name} ({service.port})",
                "group": "service"
            })
            links.append({
                "from": instance.host.ip,
                "to": node_id
            })

        return response.Response({
            "nodes": nodes,
            "edges": links
        })
