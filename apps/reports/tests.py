from django.test import TestCase
from django.urls import reverse

from apps.accounts.models import User
from apps.reports.models import Report
from apps.scanner.models import ScanConfiguration, ScanJob, ScanTarget


class ReportPermissionTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="viewer",
            password="password",
            can_export_reports=False,
        )
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

    def test_report_generate_requires_export_permission(self):
        response = self.client.get(reverse("report_generate", args=[self.scan.id]))

        self.assertRedirects(response, reverse("scan_detail", args=[self.scan.id]))
        self.assertEqual(Report.objects.count(), 0)

    def test_report_download_requires_export_permission(self):
        report = Report.objects.create(
            scan_job=self.scan,
            title="Blocked report",
            format="json",
            file_path="",
            generated_by=self.user,
        )

        response = self.client.get(reverse("report_download", args=[report.id]))

        self.assertEqual(response.status_code, 403)
