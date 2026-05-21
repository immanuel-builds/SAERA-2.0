from django.test import TestCase
from django.contrib.auth import get_user_model
from apps.scanner.models import ScanTarget, ScanConfiguration, ScanJob
from apps.scanner.services.scan_service import ScanService
from unittest.mock import patch

class ScanIntegrationTest(TestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user(username='test_analyst', password='testpassword', role='analyst')
        
        self.target = ScanTarget.objects.create(
            target='127.0.0.1',
            name='Localhost Integration Target',
            created_by=self.user,
            target_type='ip'
        )
        
        self.config = ScanConfiguration.objects.create(
            name='Quick Integration Scan',
            scan_type='quick',
            port_range='80,443',
            created_by=self.user
        )

    @patch('apps.scanner.adapters.nmap_adapter.NmapAdapter.execute_scan')
    def test_end_to_end_scan(self, mock_execute):
        # Mocking the raw XML output that Nmap would return
        mock_execute.return_value = '''<?xml version="1.0" encoding="UTF-8"?>
        <nmaprun scanner="nmap" args="nmap -oX - -Pn -sT -F -sV 127.0.0.1">
            <host>
                <status state="up" reason="localhost-response" reason_ttl="0"/>
                <address addr="127.0.0.1" addrtype="ipv4"/>
                <ports>
                    <port protocol="tcp" portid="80">
                        <state state="open" reason="syn-ack" reason_ttl="0"/>
                        <service name="http" method="table" conf="3"/>
                    </port>
                </ports>
            </host>
            <runstats><finished timestr="integration_test"/></runstats>
        </nmaprun>'''

        # Create the job
        scan_job = ScanJob.objects.create(
            target=self.target,
            configuration=self.config,
            initiated_by=self.user,
            status='pending'
        )
        
        # Execute the full pipeline (Scan -> Parse -> Enrich -> Persist)
        cio = ScanService.execute_and_persist(scan_job.id)
        
        # Refresh from db
        scan_job.refresh_from_db()
        
        # Verify persistence and state changes
        self.assertEqual(scan_job.status, 'completed')
        self.assertEqual(scan_job.progress, 100)
        
        # Verify that the port result was saved correctly
        self.assertEqual(scan_job.port_results.count(), 1)
        self.assertEqual(scan_job.port_results.first().port, 80)
        self.assertEqual(scan_job.port_results.first().state, 'open')
        
        # Ensure that exposure findings were generated and persisted to vulnerabilities
        self.assertGreater(scan_job.vulnerabilities.count(), 0)
