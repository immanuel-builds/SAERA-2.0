"""
Workflow Views for SAERA.
Provides endpoints for analysts to toggle suppressions, save annotations, and transition states.
"""
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated

from apps.scanner.models import Vulnerability
from apps.api.serializers.intelligence import VulnerabilitySerializer
from apps.api.serializers.workflows import (
    SuppressionSerializer, AnnotationSerializer, InvestigationStateSerializer
)
from apps.scanner.services.lifecycle_service import LifecycleService
from apps.scanner.services.prioritization_service import PrioritizationService

class VulnerabilityWorkflowViewSet(viewsets.ViewSet):
    """
    Analyst interface to transition states, annotate mitigation plans, and toggle suppressions.
    """
    permission_classes = [IsAuthenticated]

    @action(detail=True, methods=['post'], url_path='suppress')
    def suppress(self, request, pk=None):
        """
        POST /api/v1/workflows/vulnerability/<id>/suppress/
        """
        try:
            vuln = Vulnerability.objects.get(id=pk)
        except Vulnerability.DoesNotExist:
            return Response({"error": "Vulnerability not found"}, status=status.HTTP_404_NOT_FOUND)

        serializer = SuppressionSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        suppressed = serializer.validated_data['suppressed']
        reason = serializer.validated_data['reason']

        # Call service layer to perform deterministic state and prioritize update
        updated_vuln = LifecycleService.toggle_suppression(
            vulnerability_id=vuln.id,
            suppressed=suppressed,
            reason=reason,
            analyst_name=request.user.username
        )

        return Response(VulnerabilitySerializer(updated_vuln).data, status=status.HTTP_200_OK)

    @action(detail=True, methods=['post'], url_path='annotate')
    def annotate(self, request, pk=None):
        """
        POST /api/v1/workflows/vulnerability/<id>/annotate/
        """
        try:
            vuln = Vulnerability.objects.get(id=pk)
        except Vulnerability.DoesNotExist:
            return Response({"error": "Vulnerability not found"}, status=status.HTTP_404_NOT_FOUND)

        serializer = AnnotationSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        vuln.analyst_annotation = serializer.validated_data.get('analyst_annotation', vuln.analyst_annotation)
        vuln.remediation_note = serializer.validated_data.get('remediation_note', vuln.remediation_note)
        vuln.save()

        # Recalculate priority to ensure changes reflect immediately
        vuln.priority_score = PrioritizationService.calculate_vulnerability_priority(vuln)
        vuln.save()

        return Response(VulnerabilitySerializer(vuln).data, status=status.HTTP_200_OK)

    @action(detail=True, methods=['post'], url_path='state')
    def state(self, request, pk=None):
        """
        POST /api/v1/workflows/vulnerability/<id>/state/
        """
        try:
            vuln = Vulnerability.objects.get(id=pk)
        except Vulnerability.DoesNotExist:
            return Response({"error": "Vulnerability not found"}, status=status.HTTP_404_NOT_FOUND)

        serializer = InvestigationStateSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        vuln.investigation_state = serializer.validated_data['investigation_state']
        
        # If marked resolved, update the temporal field status as well
        if vuln.investigation_state == 'resolved':
            vuln.resolved = True
            vuln.lifecycle_state = 'resolved'
        elif vuln.investigation_state == 'mitigated':
            vuln.lifecycle_state = 'resolved'
        
        vuln.save()

        # Recalculate priority
        vuln.priority_score = PrioritizationService.calculate_vulnerability_priority(vuln)
        vuln.save()

        return Response(VulnerabilitySerializer(vuln).data, status=status.HTTP_200_OK)
