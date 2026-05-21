import datetime
from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from django.utils import timezone
from apps.scanner.models import ScanTarget, ScanConfiguration, ScanJob, Vulnerability, PortScanResult
from apps.scanner.services.prioritization_service import PrioritizationService
from apps.scanner.services.lifecycle_service import LifecycleService

User = get_user_model()

class Command(BaseCommand):
    help = "Seeds the database with high-density, multi-cycle historical scan data for academic presentation."

    def handle(self, *args, **options):
        self.stdout.write(self.style.WARNING("Starting operational seeding sequence..."))

        # 1. Ensure Operatives exist
        immanuel, created = User.objects.get_or_create(
            username="Immanuel",
            defaults={
                "email": "immanuel@saera.internal",
                "role": "admin",
                "is_staff": True,
                "is_superuser": True
            }
        )
        if created:
            immanuel.set_password("Observatory2026!")
            immanuel.save()
            self.stdout.write(self.style.SUCCESS("Created administrator profile 'Immanuel'"))
        else:
            self.stdout.write("Operative 'Immanuel' already registered.")

        # 2. Setup standard scan configuration
        config, _ = ScanConfiguration.objects.get_or_create(
            name="Standard Sweep",
            created_by=immanuel,
            defaults={
                "scan_type": "standard",
                "port_range": "1-1000",
                "enable_service_detection": True,
                "enable_vuln_detection": True
            }
        )

        # 3. Define Targets
        targets_data = [
            {
                "name": "Observatory Core Bastion",
                "target": "192.168.1.1",
                "type": "ip",
                "desc": "Hardened primary server housing the observation archive.",
                "ports": [
                    {"port": 22, "service": "ssh", "version": "OpenSSH 8.9p1", "vuln": None},
                    {"port": 443, "service": "https", "version": "Nginx 1.22.1", "vuln": None}
                ]
            },
            {
                "name": "Internal Active Directory Server",
                "target": "192.168.10.15",
                "type": "ip",
                "desc": "Core personnel directory showing active legacy threat vectors.",
                "ports": [
                    {"port": 139, "service": "netbios-ssn", "version": "Samba 4.2", "vuln": None},
                    {
                        "port": 445, 
                        "service": "microsoft-ds", 
                        "version": "Windows RPC SMB v1", 
                        "vuln": {
                            "title": "Remote Code Execution (MS17-010 EternalBlue)",
                            "severity": "critical",
                            "cvss": 9.3,
                            "desc": "Allows remote attackers to execute arbitrary code on the target system via crafted SMBv1 packets."
                        }
                    },
                    {
                        "port": 3389,
                        "service": "ms-wbt-server",
                        "version": "Microsoft Terminal Services",
                        "vuln": {
                            "title": "Remote Desktop Services Denial of Service",
                            "severity": "high",
                            "cvss": 7.5,
                            "desc": "Allows unauthenticated remote attackers to trigger a system crash via malformed RDP connection requests."
                        }
                    }
                ]
            },
            {
                "name": "DMZ Public Access Gateway",
                "target": "172.16.50.4",
                "type": "ip",
                "desc": "Public-facing bridge server exposing segmented port vectors.",
                "ports": [
                    {"port": 80, "service": "http", "version": "Apache httpd 2.4.41", "vuln": None},
                    {
                        "port": 21,
                        "service": "ftp",
                        "version": "vsftpd 2.3.4 Backdoor",
                        "vuln": {
                            "title": "vsftpd 2.3.4 Backdoor Execution",
                            "severity": "critical",
                            "cvss": 10.0,
                            "desc": "Malicious backdoor inserted into the vsftpd distribution package allows command execution on port 6200."
                        }
                    }
                ]
            }
        ]

        # 4. Generate 5 chronological observation sweeps (Risk Tides history)
        base_time = timezone.now() - datetime.timedelta(days=20)

        for i in range(5):
            sweep_time = base_time + datetime.timedelta(days=i * 4)
            self.stdout.write(f"Generating observation sweep cycle #{i+1} (Date: {sweep_time.strftime('%Y-%m-%d')})")

            for t_data in targets_data:
                target_obj, _ = ScanTarget.objects.get_or_create(
                    target=t_data["target"],
                    created_by=immanuel,
                    defaults={
                        "name": t_data["name"],
                        "target_type": t_data["type"],
                        "description": t_data["desc"]
                    }
                )

                # Simulate a Completed Scan Job
                job = ScanJob.objects.create(
                    target=target_obj,
                    configuration=config,
                    initiated_by=immanuel,
                    status="completed",
                    progress=100,
                    current_phase="Ingestion complete",
                    started_at=sweep_time - datetime.timedelta(minutes=15),
                    completed_at=sweep_time,
                    created_at=sweep_time
                )

                # Seed Ports and Vulns
                has_critical = False
                has_high = False
                vulns_found_count = 0
                max_score = 1.0

                for port_info in t_data["ports"]:
                    # Create Port Scan Result
                    p_res = PortScanResult.objects.create(
                        scan_job=job,
                        port=port_info["port"],
                        protocol="tcp",
                        state="open",
                        service=port_info["service"],
                        service_version=port_info["version"],
                        created_at=sweep_time
                    )

                    vuln_info = port_info["vuln"]
                    if vuln_info:
                        # To show a 'Resolved' state, we resolve FTP on DMZ in the final cycle (cycle 5)
                        if i == 4 and target_obj.name == "DMZ Public Access Gateway" and port_info["port"] == 21:
                            p_res.state = "closed"
                            p_res.resolved = True
                            p_res.resolved_at = sweep_time
                            p_res.save()
                            continue

                        # To show a 'Recurring' state, we resolve SMBv1 in cycle 3 (i=2), so when it reappears in cycle 4 (i=3) it gets marked recurring!
                        if i == 2 and target_obj.name == "Internal Active Directory Server" and port_info["port"] == 445:
                            p_res.state = "closed"
                            p_res.resolved = True
                            p_res.resolved_at = sweep_time
                            p_res.save()
                            continue

                        # Create Vulnerability record
                        v_obj = Vulnerability.objects.create(
                            scan_job=job,
                            title=vuln_info["title"],
                            vuln_type="cve",
                            severity=vuln_info["severity"],
                            cvss_score=vuln_info["cvss"],
                            risk_score=vuln_info["cvss"],
                            risk_level=vuln_info["severity"].capitalize(),
                            exploitability=8,
                            port=port_info["port"],
                            service=port_info["service"],
                            description=vuln_info["desc"],
                            recommendation="Deploy software security updates or isolate target vectors.",
                            created_at=sweep_time
                        )
                        vulns_found_count += 1
                        max_score = max(max_score, vuln_info["cvss"])

                        if vuln_info["severity"] == "critical":
                            has_critical = True
                        elif vuln_info["severity"] == "high":
                            has_high = True

                # Compute aggregate score for this sweep
                if target_obj.name == "Observatory Core Bastion":
                    job.aggregate_risk_score = 1.2
                else:
                    base_agg = max_score
                    if has_critical:
                        base_agg += 0.8
                    if has_high:
                        base_agg += 0.4
                    job.aggregate_risk_score = min(round(base_agg, 1), 10.0)

                job.total_ports_scanned = 1000
                job.open_ports_found = len(t_data["ports"])
                job.vulnerabilities_found = vulns_found_count
                job.save()

                # Trigger Lifecycle Service evaluations to transition states recurring/active
                LifecycleService.evaluate_scan_lifecycle(job)

                # Recalculate Prioritizations for all vulnerabilities
                for v in job.vulnerabilities.all():
                    v.priority_score = PrioritizationService.calculate_vulnerability_priority(v)
                    v.save()

        # 5. Apply a suppression to DMZ Public Gateway FTP vector to demonstrate action panel
        dmz_target = ScanTarget.objects.get(name="DMZ Public Access Gateway")
        dmz_vuln = Vulnerability.objects.filter(scan_job__target=dmz_target, port=21).first()
        if dmz_vuln:
            LifecycleService.toggle_suppression(
                vulnerability_id=dmz_vuln.id,
                suppressed=True,
                reason="Acceptable risk inside a segregated, firewalled sandbox network zone.",
                analyst_name="Immanuel"
            )
            self.stdout.write(self.style.SUCCESS(f"Toggled administrative suppression override on: {dmz_vuln.title}"))

        self.stdout.write(self.style.SUCCESS("Database seeded with magnificent temporal data! SAERA is ready for live defense."))
