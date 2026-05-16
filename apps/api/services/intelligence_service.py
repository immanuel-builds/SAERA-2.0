from apps.scanner.models import ScanJob
from apps.api.serializers.intelligence import IntelligenceObjectSerializer
from apps.api.services.topology_service import TopologyBuilderService

class IntelligenceService:
    """
    The central orchestrator for SAERA's Intelligence Pipeline.
    Responsible for fetching, normalizing, and enriching scan data.
    """

    @staticmethod
    def get_full_intelligence(scan_id):
        """
        Retrieves a canonical intelligence object for a specific scan,
        enriched with risk, topology, and prediction layers.
        """
        try:
            scan = ScanJob.objects.prefetch_related(
                'target', 'vulnerabilities', 'port_results'
            ).get(id=scan_id)
            
            # 1. Enrichment Layer: Risk
            scan = IntelligenceService.enrich_with_risk(scan)
            
            # 2. Enrichment Layer: Topology
            scan = IntelligenceService.enrich_with_topology(scan)
            
            # 3. Enrichment Layer: Prediction
            scan = IntelligenceService.enrich_with_prediction(scan)
            
            return scan
        except ScanJob.DoesNotExist:
            return None

    @staticmethod
    def enrich_with_risk(scan):
        """Calculates aggregate risk posture for the scan"""
        vulns = scan.vulnerabilities.all()
        if vulns.exists():
            scan.avg_risk_score = sum(v.risk_score for v in vulns) / vulns.count()
        else:
            scan.avg_risk_score = 0
        return scan

    @staticmethod
    def enrich_with_topology(scan):
        """Generates relationship data for network mapping"""
        scan.topology_data = TopologyBuilderService.build_scan_graph(scan)
        return scan

    @staticmethod
    def enrich_with_prediction(scan):
        """Forecasts future risk trajectories"""
        # Placeholder for ThreatPredictor integration
        # In a real scenario, this calls apps/scanner/prediction_engine.py
        scan.prediction_data = {
            "forecast_level": "Stable" if scan.vulnerabilities_found < 3 else "Rising",
            "confidence": 85,
            "next_sweep_recommendation": "Perform deep scan in 24h"
        }
        return scan
