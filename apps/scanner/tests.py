from unittest.mock import patch

from django.test import SimpleTestCase, TestCase
from django.urls import reverse

from apps.accounts.models import User
from apps.scanner.models import ScanConfiguration
from apps.scanner.scanners.port_scanner import (
    MAX_FALLBACK_HOSTS,
    _parse_port_range,
    _resolve_targets,
)


class PortScannerUtilityTests(SimpleTestCase):
    def test_parse_port_range_filters_invalid_values(self):
        self.assertEqual(_parse_port_range("0-3,80,443,70000,bad"), [1, 2, 3, 80, 443])

    def test_resolve_targets_supports_small_cidr_ranges(self):
        self.assertEqual(
            _resolve_targets("127.0.0.0/30"),
            [("127.0.0.1", "127.0.0.1"), ("127.0.0.2", "127.0.0.2")],
        )

    def test_resolve_targets_rejects_large_cidr_ranges_for_fallback(self):
        with self.assertRaisesMessage(ValueError, f"supports up to {MAX_FALLBACK_HOSTS} hosts"):
            _resolve_targets("10.0.0.0/16")


class ScanCreateTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="scanner",
            password="password",
            can_initiate_scans=True,
        )
        self.client.force_login(self.user)

    @patch("apps.scanner.views.scan_target_task.delay")
    def test_scan_create_preserves_distinct_detection_options(self, delay):
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
        self.assertEqual(delay.call_count, 2)

        configs = ScanConfiguration.objects.filter(created_by=self.user, scan_type="quick")
        self.assertEqual(configs.count(), 2)
        self.assertTrue(configs.get(enable_vuln_detection=True).enable_service_detection)
        self.assertTrue(configs.get(enable_vuln_detection=True).enable_vuln_detection)
        self.assertTrue(configs.get(enable_vuln_detection=False).enable_service_detection)
        self.assertFalse(configs.get(enable_vuln_detection=False).enable_vuln_detection)
