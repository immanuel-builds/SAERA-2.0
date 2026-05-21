from rest_framework import serializers
from apps.scanner.models import ScanTarget, ScanJob, Vulnerability, PortScanResult

class TargetSerializer(serializers.ModelSerializer):
    """Refined representation of a network asset"""
    class Meta:
        model = ScanTarget
        fields = ['id', 'name', 'target', 'target_type', 'description', 'created_at']

class ScanJobSummarySerializer(serializers.ModelSerializer):
    """Concise representation of scan execution history"""
    target_name = serializers.CharField(source='target.name', read_only=True)
    target_ip = serializers.CharField(source='target.target', read_only=True)

    class Meta:
        model = ScanJob
        fields = [
            'id', 'target_name', 'target_ip', 'status', 'progress', 'current_phase',
            'open_ports_found', 'vulnerabilities_found', 'aggregate_risk_score',
            'started_at', 'completed_at'
        ]


class ServiceSerializer(serializers.ModelSerializer):
    """Detailed service and version identification with temporal parameters"""
    class Meta:
        model = PortScanResult
        fields = [
            'port', 'protocol', 'state', 'service', 'service_version', 'banner',
            'first_seen', 'last_seen', 'observation_count', 'lifecycle_state',
            'priority_score', 'is_suppressed', 'created_at'
        ]


class VulnerabilitySerializer(serializers.ModelSerializer):
    """Standardized exposure and vulnerability findings with temporal parameters"""
    class Meta:
        model = Vulnerability
        fields = [
            'id', 'title', 'vuln_type', 'severity', 'cvss_score',
            'risk_score', 'risk_level', 'exploitability',
            'port', 'service', 'description', 'recommendation',
            'first_seen', 'last_seen', 'observation_count',
            'lifecycle_state', 'investigation_state', 'remediation_note',
            'analyst_annotation', 'priority_score', 'is_suppressed',
            'suppressed_at', 'suppressed_reason', 'reappeared_count', 'created_at'
        ]


# --- Canonical Intelligence Object (CIO) Serializers ---

class HostIdentitySerializer(serializers.Serializer):
    ip = serializers.IPAddressField()
    hostname = serializers.CharField(allow_null=True, required=False)
    os = serializers.CharField(allow_null=True, required=False)
    mac_address = serializers.CharField(allow_null=True, required=False)


class PortServiceDetailSerializer(serializers.Serializer):
    port = serializers.IntegerField()
    protocol = serializers.CharField()
    state = serializers.CharField()
    service_name = serializers.CharField()
    product = serializers.CharField(allow_null=True, required=False)
    version = serializers.CharField(allow_null=True, required=False)
    extrainfo = serializers.CharField(allow_null=True, required=False)
    cpe = serializers.ListField(child=serializers.CharField())
    first_seen = serializers.CharField(allow_null=True, required=False)
    last_seen = serializers.CharField(allow_null=True, required=False)
    observation_count = serializers.IntegerField(default=1)


class ExposureFindingSerializer(serializers.Serializer):
    title = serializers.CharField()
    severity = serializers.CharField()
    score = serializers.FloatField()
    description = serializers.CharField()
    remediation = serializers.CharField(allow_null=True, required=False)
    port = serializers.IntegerField(allow_null=True, required=False)
    service_name = serializers.CharField(allow_null=True, required=False)
    first_seen = serializers.CharField(allow_null=True, required=False)
    last_seen = serializers.CharField(allow_null=True, required=False)
    observation_count = serializers.IntegerField(default=1)


class ConfirmedVulnerabilitySerializer(serializers.Serializer):
    cve_id = serializers.CharField()
    title = serializers.CharField()
    severity = serializers.CharField()
    cvss_score = serializers.FloatField()
    description = serializers.CharField()
    remediation = serializers.CharField(allow_null=True, required=False)
    port = serializers.IntegerField(allow_null=True, required=False)
    service_name = serializers.CharField(allow_null=True, required=False)
    first_seen = serializers.CharField(allow_null=True, required=False)
    last_seen = serializers.CharField(allow_null=True, required=False)
    observation_count = serializers.IntegerField(default=1)


class RiskPostureSerializer(serializers.Serializer):
    score = serializers.FloatField()
    level = serializers.CharField()
    factors = serializers.ListField(child=serializers.CharField())
    critical_services = serializers.ListField(child=serializers.CharField())


class CanonicalIntelligenceSerializer(serializers.Serializer):
    """Serializes the transient in-memory CanonicalIntelligence object directly"""
    host = HostIdentitySerializer()
    services = PortServiceDetailSerializer(many=True)
    exposures = ExposureFindingSerializer(many=True)
    vulnerabilities = ConfirmedVulnerabilitySerializer(many=True)
    risk = RiskPostureSerializer()
    metadata = serializers.DictField()
