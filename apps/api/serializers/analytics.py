"""
Analytics Serializers for SAERA.
Handles serialization for host-centric risk postures, timelines, and drift metrics.
"""
from rest_framework import serializers

class HostIdentitySerializer(serializers.Serializer):
    ip = serializers.IPAddressField()
    hostname = serializers.CharField(allow_null=True, required=False)
    os = serializers.CharField(allow_null=True, required=False)

class PostureMetricsSerializer(serializers.Serializer):
    score = serializers.FloatField()
    level = serializers.CharField()
    active_exposures_count = serializers.IntegerField()

class RiskTimelineEntrySerializer(serializers.Serializer):
    scan_id = serializers.IntegerField()
    date = serializers.CharField()
    score = serializers.FloatField()
    threats = serializers.IntegerField()
    phase = serializers.CharField()

class ExposureDetailsSerializer(serializers.Serializer):
    title = serializers.CharField()
    port = serializers.IntegerField(allow_null=True, required=False)
    severity = serializers.CharField()
    first_seen = serializers.CharField()
    observation_count = serializers.IntegerField()
    exposure_duration_days = serializers.FloatField()
    recurring = serializers.BooleanField()

class ResolvedDetailsSerializer(serializers.Serializer):
    title = serializers.CharField()
    port = serializers.IntegerField(allow_null=True, required=False)
    severity = serializers.CharField()
    resolved_at = serializers.CharField(allow_null=True, required=False)
    total_observations = serializers.IntegerField()

class HostPostureSummarySerializer(serializers.Serializer):
    """Authoritative serializer for HostPostureSummary dossier"""
    host = HostIdentitySerializer()
    current_posture = PostureMetricsSerializer()
    risk_drift = serializers.DictField()
    risk_timeline = RiskTimelineEntrySerializer(many=True)
    persistent_exposures = ExposureDetailsSerializer(many=True)
    resolved_findings = ResolvedDetailsSerializer(many=True)
    operational_summary = serializers.CharField()
