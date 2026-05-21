from unittest.mock import patch
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from apps.accounts.models import User
from apps.scanner.models import ScanConfiguration, ScanJob, ScanTarget, PortScanResult, Vulnerability
from apps.scanner.parsers.nmap_parser import NmapParser
from apps.scanner.enrichers.risk_enricher import RiskEnricher
from apps.scanner.services.scan_service import ScanService
from apps.scanner.services.temporal_service import TemporalService
from apps.scanner.services.analytics_service import AnalyticsService
from apps.scanner.services.aggregation_service import AggregationService

MOCK_NMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun args="nmap -oX - -p 1-1000 -sV 192.168.1.105" version="7.92">
  <host>
    <status state="up" reason="arp-response" reason_ttl="0"/>
    <address addr="192.168.1.105" addrtype="ipv4"/>
    <address addr="00:11:22:33:44:55" addrtype="mac" vendor="Intel"/>
    <hostnames>
      <hostname name="observatory-core.local" type="user"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack" reason_ttl="64"/>
        <service name="ssh" product="OpenSSH" version="8.2p1" extrainfo="Ubuntu Linux" ostype="Linux" method="probed" conf="10">
          <cpe>cpe:/a:openbsd:openssh:8.2p1</cpe>
          <cpe>cpe:/o:linux:linux_kernel</cpe>
        </service>
      </port>
      <port protocol="tcp" portid="445">
        <state state="open" reason="syn-ack" reason_ttl="128"/>
        <service name="microsoft-ds" product="Windows SMB" method="probed" conf="10"/>
      </port>
    </ports>
    <os>
      <osmatch name="Linux 5.x" accuracy="96" line="68000"/>
    </os>
  </host>
  <runstats>
    <finished timestr="Sun May 17 21:00:00 2026"/>
  </runstats>
</nmaprun>
"""

class NmapParserTests(TestCase):
    """Verifies that raw Nmap XML parses safely and matches the transient Canonical Intelligence schema"""

    def test_safe_xml_parsing_with_valid_telemetry(self):
        cio = NmapParser.parse_xml(MOCK_NMAP_XML)

        # Verify Host Identification
        self.assertEqual(cio.host.ip, "192.168.1.105")
        self.assertEqual(cio.host.hostname, "observatory-core.local")
        self.assertEqual(cio.host.os, "Linux 5.x")
        self.assertEqual(cio.host.mac_address, "00:11:22:33:44:55")

        # Verify Port & Services Details
        self.assertEqual(len(cio.services), 2)
        ssh_service = next(s for s in cio.services if s.port == 22)
        self.assertEqual(ssh_service.protocol, "tcp")
        self.assertEqual(ssh_service.state, "open")
        self.assertEqual(ssh_service.service_name, "ssh")
        self.assertEqual(ssh_service.product, "OpenSSH")
        self.assertEqual(ssh_service.version, "8.2p1")
        self.assertIn("cpe:/a:openbsd:openssh:8.2p1", ssh_service.cpe)

    def test_sterile_xml_output_parsing(self):
        sterile_xml = """<?xml version="1.0" encoding="UTF-8"?>
        <nmaprun args="nmap -F 192.168.1.1" version="7.92">
          <runstats>
            <finished timestr="Sun May 17 21:00:00 2026"/>
          </runstats>
        </nmaprun>
        """
        # A sterile sweep (no hosts up) should gracefully yield a fallback shell instead of crashing
        cio = NmapParser.parse_xml(sterile_xml)
        self.assertEqual(cio.host.ip, "0.0.0.0")
        self.assertEqual(len(cio.services), 0)


class RiskEnricherTests(TestCase):
    """Verifies explainable threat risk calculations and exposure classifications"""

    def test_explainable_scoring_for_critical_port_exposure(self):
        cio = NmapParser.parse_xml(MOCK_NMAP_XML)
        self.assertEqual(len(cio.exposures), 0)

        # Enrich
        cio = RiskEnricher.enrich(cio)

        # Port 445 (SMB) must trigger a Critical Severity Exposure finding
        self.assertGreater(len(cio.exposures), 0)
        smb_finding = next(e for e in cio.exposures if e.port == 445)
        self.assertEqual(smb_finding.severity, "critical")
        self.assertEqual(smb_finding.score, 9.5)

        # Host Posture evaluation
        self.assertEqual(cio.risk.level, "Critical")
        self.assertGreaterEqual(cio.risk.score, 9.5)
        self.assertIn("Exposed Server Message Block (SMB) (Port 445)", cio.risk.factors)


class ScanCreateTests(TestCase):
    """Verifies scanning view orchestrations"""

    def setUp(self):
        self.user = User.objects.create_user(
            username="scanner",
            password="password",
            can_initiate_scans=True,
        )
        self.client.force_login(self.user)

    @patch("apps.scanner.views.run_scan_job")
    def test_scan_create_preserves_distinct_detection_options(self, run_scan_job):
        first_response = self.client.post(
            reverse("scan_create"),
            {
                "target": "127.0.0.1",
                "scan_type": "quick",
                "enable_service_detection": "on",
                "enable_vuln_detection": "on",
            },
        )
        second_response = self.client.post(
            reverse("scan_create"),
            {
                "target": "127.0.0.2",
                "scan_type": "quick",
                "enable_service_detection": "on",
            },
        )

        self.assertEqual(first_response.status_code, 302)
        self.assertEqual(second_response.status_code, 302)
        self.assertEqual(run_scan_job.call_count, 2)

        configs = ScanConfiguration.objects.filter(created_by=self.user, scan_type="quick")
        self.assertEqual(configs.count(), 2)
        self.assertTrue(configs.get(enable_vuln_detection=True).enable_service_detection)
        self.assertTrue(configs.get(enable_vuln_detection=True).enable_vuln_detection)
        self.assertTrue(configs.get(enable_vuln_detection=False).enable_service_detection)
        self.assertFalse(configs.get(enable_vuln_detection=False).enable_vuln_detection)


class TemporalIntelligenceTests(TestCase):
    """Verifies historical exposure resolution and recurring vulnerability tracking"""

    def setUp(self):
        self.user = User.objects.create_user(
            username="analyst_temporal",
            password="password",
            can_initiate_scans=True,
        )
        self.target = ScanTarget.objects.create(
            name="Observatory Primary",
            target="192.168.1.200",
            target_type="ip",
            created_by=self.user
        )

        # 1. Create Baseline completed ScanJob (Port 445 Open, SMB exposed)
        self.scan1 = ScanJob.objects.create(
            target=self.target,
            status='completed',
            aggregate_risk_score=9.5,
            vulnerabilities_found=1,
            initiated_by=self.user,
            completed_at=timezone.now() - timezone.timedelta(days=2)
        )
        self.port1 = PortScanResult.objects.create(
            scan_job=self.scan1,
            port=445,
            protocol="tcp",
            state="open",
            service="microsoft-ds",
            first_seen=self.scan1.completed_at
        )
        self.vuln1 = Vulnerability.objects.create(
            scan_job=self.scan1,
            title="Critical Port Exposure: Server Message Block (SMB)",
            port=445,
            severity="critical",
            cvss_score=9.5,
            resolved=False,
            first_seen=self.scan1.completed_at
        )

    def test_exposure_gets_resolved_when_absent_in_second_scan(self):
        # 2. Create Second completed ScanJob (Target patched: Port 445 is closed)
        scan2 = ScanJob.objects.create(
            target=self.target,
            status='completed',
            aggregate_risk_score=0.0,
            vulnerabilities_found=0,
            initiated_by=self.user,
            completed_at=timezone.now() - timezone.timedelta(days=1)
        )

        # Evaluate resolutions
        TemporalService.evaluate_resolutions(scan2)

        # Check that baseline scan results were marked resolved
        self.port1.refresh_from_db()
        self.vuln1.refresh_from_db()

        self.assertTrue(self.port1.resolved)
        self.assertTrue(self.vuln1.resolved)
        self.assertIsNotNone(self.port1.resolved_at)
        self.assertIsNotNone(self.vuln1.resolved_at)

    def test_exposure_marked_recurring_if_reopened_in_third_scan(self):
        # Resolve scan 1 first
        scan2 = ScanJob.objects.create(
            target=self.target,
            status='completed',
            initiated_by=self.user,
            completed_at=timezone.now() - timezone.timedelta(days=1)
        )
        TemporalService.evaluate_resolutions(scan2)

        # 3. Create Third scan job where Port 445 is re-opened (Threat Recurrence)
        scan3 = ScanJob.objects.create(
            target=self.target,
            initiated_by=self.user,
            status='running'
        )
        port3 = PortScanResult.objects.create(
            scan_job=scan3,
            port=445,
            protocol="tcp",
            state="open",
            service="microsoft-ds"
        )
        vuln3 = Vulnerability.objects.create(
            scan_job=scan3,
            title="Critical Port Exposure: Server Message Block (SMB)",
            port=445,
            severity="critical",
            cvss_score=9.5
        )

        # Run recurrence detection
        TemporalService.detect_recurrence(scan3)

        port3.refresh_from_db()
        vuln3.refresh_from_db()

        self.assertTrue(port3.recurring)
        self.assertTrue(vuln3.recurring)
        self.assertEqual(port3.observation_count, 2)
        self.assertEqual(vuln3.observation_count, 2)


class AnalyticsServiceTests(TestCase):
    """Verifies mathematical risk drift, timeline trends, and posture aggregation summaries"""

    def setUp(self):
        self.user = User.objects.create_user(
            username="analyst_analytics",
            password="password",
            can_initiate_scans=True,
        )
        self.target = ScanTarget.objects.create(
            name="Observatory Primary",
            target="192.168.1.200",
            target_type="ip",
            created_by=self.user
        )

        # Baseline scan (Low risk)
        self.scan1 = ScanJob.objects.create(
            target=self.target,
            status='completed',
            aggregate_risk_score=2.5,
            vulnerabilities_found=1,
            initiated_by=self.user,
            completed_at=timezone.now() - timezone.timedelta(days=2)
        )
        Vulnerability.objects.create(
            scan_job=self.scan1,
            title="Exposed HTTP Port",
            port=80,
            severity="info",
            cvss_score=2.5
        )

        # Recent scan (High risk - Escalated SMB exposure added)
        self.scan2 = ScanJob.objects.create(
            target=self.target,
            status='completed',
            aggregate_risk_score=9.5,
            vulnerabilities_found=2,
            initiated_by=self.user,
            completed_at=timezone.now() - timezone.timedelta(days=1)
        )
        Vulnerability.objects.create(
            scan_job=self.scan2,
            title="Exposed HTTP Port",
            port=80,
            severity="info",
            cvss_score=2.5
        )
        Vulnerability.objects.create(
            scan_job=self.scan2,
            title="Critical Port Exposure: Server Message Block (SMB)",
            port=445,
            severity="critical",
            cvss_score=9.5
        )

    def test_drift_calculations_identify_escalation(self):
        drift = AnalyticsService.get_risk_drift(self.target.id)

        self.assertEqual(drift["status"], "escalating")
        self.assertEqual(drift["score_delta"], 7.0)
        self.assertEqual(drift["score_drift_percentage"], 280.0) # (7.0 / 2.5) * 100
        self.assertEqual(drift["threats_delta"], 1)
        self.assertEqual(len(drift["new_exposures"]), 1)
        self.assertEqual(drift["new_exposures"][0]["port"], 445)

    def test_posture_aggregation_generates_narratives(self):
        posture = AggregationService.get_host_posture_summary(self.target.id)

        self.assertEqual(posture["host"]["ip"], "192.168.1.200")
        self.assertEqual(posture["current_posture"]["score"], 9.5)
        self.assertEqual(posture["current_posture"]["level"], "Critical")
        self.assertGreater(len(posture["risk_timeline"]), 0)

        # Verify narrative content contains escalation details
        self.assertIn("Security risk posture has escalated significantly", posture["operational_summary"])
        self.assertIn("port(s) 445", posture["operational_summary"])


class Stage4LifecyclePrioritizationTests(TestCase):
    """
    Verifies Phase 6 requirements: Priority scores, suppressions, and state transitions.
    """

    def setUp(self):
        self.user = User.objects.create_user(
            username="analyst_stage4",
            password="password",
            can_initiate_scans=True,
        )
        self.target = ScanTarget.objects.create(
            name="Stage 4 Observational Target",
            target="10.0.0.5",
            target_type="ip",
            created_by=self.user
        )

        self.scan1 = ScanJob.objects.create(
            target=self.target,
            status='completed',
            initiated_by=self.user,
            completed_at=timezone.now() - timezone.timedelta(days=5)
        )
        self.port1 = PortScanResult.objects.create(
            scan_job=self.scan1,
            port=22,
            protocol="tcp",
            state="open",
            first_seen=self.scan1.completed_at
        )
        self.vuln1 = Vulnerability.objects.create(
            scan_job=self.scan1,
            title="SSH Weak Cryptography",
            port=22,
            severity="high",
            cvss_score=7.5,
            first_seen=self.scan1.completed_at
        )

    def test_priority_score_and_suppression_mechanics(self):
        from apps.scanner.services.prioritization_service import PrioritizationService
        from apps.scanner.services.lifecycle_service import LifecycleService

        # 1. Verify priority calculation
        # Priority = min((CVSS * 1) + (Recurrence * 1.5) + (PersistenceDays * 0.2) + (AffectedHosts * 0.5), 100.0)
        # CVSS = 7.5
        # Recurrence = 0 (observation_count=1)
        # PersistenceDays = 5 days (from setUp completed_at)
        # AffectedHosts = 1
        # Formula: 7.5*1.0 + 0*1.5 + 5*0.2 + 1*0.5 = 7.5 + 1.0 + 0.5 = 9.0
        score = PrioritizationService.calculate_vulnerability_priority(self.vuln1)
        self.assertEqual(score, 9.0)

        # 2. Toggle suppression: Check that it zeros out the score immediately
        LifecycleService.toggle_suppression(self.vuln1.id, suppressed=True, reason="Acceptable risk inside bastion host")
        self.vuln1.refresh_from_db()

        self.assertTrue(self.vuln1.is_suppressed)
        self.assertEqual(self.vuln1.lifecycle_state, 'suppressed')
        self.assertEqual(self.vuln1.priority_score, 0.0)

        # 3. Untoggle suppression: Check that it recalculates back to active state and correct priority
        LifecycleService.toggle_suppression(self.vuln1.id, suppressed=False)
        self.vuln1.refresh_from_db()

        self.assertFalse(self.vuln1.is_suppressed)
        self.assertEqual(self.vuln1.lifecycle_state, 'active')
        self.assertEqual(self.vuln1.priority_score, 9.0)

    def test_lifecycle_state_machine_transitions(self):
        from apps.scanner.services.lifecycle_service import LifecycleService

        # Initial state should evaluate to active after evaluate_scan_lifecycle
        LifecycleService.evaluate_scan_lifecycle(self.scan1)
        self.vuln1.refresh_from_db()
        self.assertEqual(self.vuln1.lifecycle_state, 'active')

        # Escalation transition check: Create a second scan where severity changes from high to critical
        scan2 = ScanJob.objects.create(
            target=self.target,
            status='completed',
            initiated_by=self.user,
            completed_at=timezone.now()
        )
        vuln2 = Vulnerability.objects.create(
            scan_job=scan2,
            title="SSH Weak Cryptography",
            port=22,
            severity="critical",
            cvss_score=9.8
        )

        LifecycleService.evaluate_scan_lifecycle(scan2)
        vuln2.refresh_from_db()

        self.assertEqual(vuln2.lifecycle_state, 'escalated')
