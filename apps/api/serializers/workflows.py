"""
Workflow Serializers for SAERA.
Handles validation for analyst annotations, suppressions, and state changes.
"""
from rest_framework import serializers
from apps.scanner.models import Vulnerability

class SuppressionSerializer(serializers.Serializer):
    """Validates parameters when suppressing or unsuppressing a finding"""
    suppressed = serializers.BooleanField(required=True)
    reason = serializers.CharField(required=False, allow_blank=True, default="")

class AnnotationSerializer(serializers.Serializer):
    """Validates parameters for analyst comments and annotations"""
    analyst_annotation = serializers.CharField(required=False, allow_blank=True, default="")
    remediation_note = serializers.CharField(required=False, allow_blank=True, default="")

class InvestigationStateSerializer(serializers.Serializer):
    """Validates state transition inputs"""
    investigation_state = serializers.ChoiceField(
        choices=[
            ('open', 'Open'),
            ('observed', 'Observed'),
            ('investigating', 'Investigating'),
            ('mitigated', 'Mitigated'),
            ('resolved', 'Resolved'),
        ],
        required=True
    )
