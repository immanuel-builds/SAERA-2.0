from django.test import TestCase
from django.urls import reverse

from apps.accounts.models import User
from apps.scanner.models import ScanConfiguration, ScanJob, ScanTarget, Vulnerability


class DashboardTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="analyst", password="password")
        self.target = ScanTarget.objects.create(
            name="Localhost",
            target="127.0.0.1",
            target_type="ip",
            created_by=self.user,
        )
        self.config = ScanConfiguration.objects.create(
            name="Quick Scan",
            scan_type="quick",
            port_range="1-100",
            created_by=self.user,
        )
        self.scan = ScanJob.objects.create(
            target=self.target,
            configuration=self.config,
            initiated_by=self.user,
            status="completed",
        )
        self.client.force_login(self.user)

    def test_dashboard_critical_alerts_only_show_critical_findings(self):
        Vulnerability.objects.create(
            scan_job=self.scan,
            title="Critical Issue",
            vuln_type="port",
            severity="critical",
            description="Critical finding",
        )
        Vulnerability.objects.create(
            scan_job=self.scan,
            title="High Issue",
            vuln_type="port",
            severity="high",
            description="High finding",
        )

        response = self.client.get(reverse("dashboard"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Critical Issue")
        self.assertNotContains(response, "High Issue")
