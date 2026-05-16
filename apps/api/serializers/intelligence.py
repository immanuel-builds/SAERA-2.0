from rest_framework import serializers
from apps.scanner.models import ScanTarget, ScanJob, Vulnerability, PortScanResult

class TargetSerializer(serializers.ModelSerializer):
    """Refined representation of a network asset"""
    class Meta:
        model = ScanTarget
        fields = ['id', 'name', 'target', 'target_type', 'description', 'created_at']

class ServiceSerializer(serializers.ModelSerializer):
    """Detailed service and version identification"""
    class Meta:
        model = PortScanResult
        fields = ['port', 'protocol', 'state', 'service', 'service_version', 'banner']

class VulnerabilitySerializer(serializers.ModelSerializer):
    """Standardized vulnerability and risk metric object"""
    class Meta:
        model = Vulnerability
        fields = [
            'id', 'title', 'vuln_type', 'severity', 'cvss_score', 
            'risk_score', 'risk_level', 'exploitability',
            'port', 'service', 'description', 'impact', 'recommendation',
            'cve_id', 'cve_url', 'created_at'
        ]

class IntelligenceObjectSerializer(serializers.ModelSerializer):
    """The canonical SAERA Intelligence Object: A unified view of target posture"""
    target = TargetSerializer(read_only=True)
    services = ServiceSerializer(many=True, source='port_results', read_only=True)
    vulnerabilities = VulnerabilitySerializer(many=True, read_only=True)
    
    risk_summary = serializers.SerializerMethodField()
    prediction = serializers.SerializerMethodField()
    topology = serializers.SerializerMethodField()

    class Meta:
        model = ScanJob
        fields = [
            'id', 'status', 'progress', 'target', 
            'services', 'vulnerabilities', 
            'risk_summary', 'prediction', 'topology',
            'started_at', 'completed_at', 'duration'
        ]

    def get_risk_summary(self, obj):
        """Aggregate risk metrics for decision support"""
        return {
            "score": getattr(obj, 'avg_risk_score', 0), # To be added to model or calculated
            "critical_count": obj.critical_vulns,
            "high_count": obj.high_vulns,
            "medium_count": obj.medium_vulns,
            "low_count": obj.low_vulns,
            "total_threats": obj.vulnerabilities_found
        }

    def get_prediction(self, obj):
        """Future risk forecasting data"""
        # This will be populated by the PredictionService
        return getattr(obj, 'prediction_data', None)

    def get_topology(self, obj):
        """Graph relationship data for visualization"""
        # This will be populated by the TopologyService
        return getattr(obj, 'topology_data', None)
