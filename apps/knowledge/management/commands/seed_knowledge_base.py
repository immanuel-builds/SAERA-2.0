import json
from django.core.management.base import BaseCommand
from apps.knowledge.models import VulnerabilityReference
from django.utils.text import slugify

CVE_DATA = [
    {
        "cve_id": "CVE-2017-0144",
        "title": "EternalBlue SMBv1 Remote Code Execution",
        "category": "Windows",
        "severity": "critical",
        "cvss_score": 9.3,
        "epss_score": 0.95,
        "description": "A remote code execution vulnerability exists in Microsoft Server Message Block 1.0 (SMBv1)...",
        "remediation": "Disable SMBv1, apply MS17-010 patch, or block ports 445/139 at the firewall.",
        "references": "https://nvd.nist.gov/vuln/detail/CVE-2017-0144 cpe:/a:microsoft:windows_server"
    },
    {
        "cve_id": "CVE-2021-44228",
        "title": "Log4Shell",
        "category": "Java",
        "severity": "critical",
        "cvss_score": 10.0,
        "epss_score": 0.97,
        "description": "Apache Log4j2 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints.",
        "remediation": "Update to Log4j 2.15.0 or later, or set log4j2.formatMsgNoLookups=true.",
        "references": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228 cpe:/a:apache:log4j"
    },
    {
        "cve_id": "CVE-2014-0160",
        "title": "Heartbleed (OpenSSL)",
        "category": "Linux",
        "severity": "high",
        "cvss_score": 7.5,
        "epss_score": 0.89,
        "description": "The (1) TLS and (2) DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do not properly handle Heartbeat Extension packets.",
        "remediation": "Upgrade OpenSSL to 1.0.1g or later.",
        "references": "https://nvd.nist.gov/vuln/detail/CVE-2014-0160 cpe:/a:openssl:openssl"
    },
    {
        "cve_id": "CVE-2019-0708",
        "title": "BlueKeep (RDP)",
        "category": "Windows",
        "severity": "critical",
        "cvss_score": 9.8,
        "epss_score": 0.92,
        "description": "A remote code execution vulnerability exists in Remote Desktop Services formerly known as Terminal Services when an unauthenticated attacker connects to the target system using RDP.",
        "remediation": "Apply Microsoft security patches for BlueKeep and disable RDP if not needed.",
        "references": "https://nvd.nist.gov/vuln/detail/CVE-2019-0708 ms-wbt-server"
    },
    {
        "cve_id": "CVE-2020-0796",
        "title": "SMBGhost",
        "category": "Windows",
        "severity": "critical",
        "cvss_score": 10.0,
        "epss_score": 0.88,
        "description": "A remote code execution vulnerability exists in the way that the Microsoft Server Message Block 3.1.1 (SMBv3) protocol handles certain requests.",
        "remediation": "Apply Microsoft security patches and disable SMBv3 compression.",
        "references": "https://nvd.nist.gov/vuln/detail/CVE-2020-0796 cpe:/o:microsoft:windows_10"
    },
    {
        "cve_id": "CVE-2019-19781",
        "title": "Citrix ADC",
        "category": "Network",
        "severity": "critical",
        "cvss_score": 9.8,
        "epss_score": 0.85,
        "description": "An issue was discovered in Citrix Application Delivery Controller (ADC) and Gateway 10.5, 11.1, 12.0, 12.1, and 13.0.",
        "remediation": "Apply Citrix patches for CVE-2019-19781.",
        "references": "https://nvd.nist.gov/vuln/detail/CVE-2019-19781"
    },
    {
        "cve_id": "CVE-2018-11776",
        "title": "Apache Struts",
        "category": "Web",
        "severity": "critical",
        "cvss_score": 9.8,
        "epss_score": 0.91,
        "description": "Apache Struts versions 2.3 to 2.3.34 and 2.5 to 2.5.16 suffer from possible Remote Code Execution when alwaysSelectFullNamespace is true.",
        "remediation": "Upgrade to Apache Struts 2.3.35 or 2.5.17.",
        "references": "https://nvd.nist.gov/vuln/detail/CVE-2018-11776 cpe:/a:apache:struts"
    },
    {
        "cve_id": "CVE-2017-5638",
        "title": "Apache Struts 2",
        "category": "Web",
        "severity": "critical",
        "cvss_score": 10.0,
        "epss_score": 0.94,
        "description": "The Jakarta Multipart parser in Apache Struts 2 2.3.x before 2.3.32 and 2.5.x before 2.5.10.1 has incorrect exception handling and error-message generation.",
        "remediation": "Upgrade Apache Struts 2 to version 2.3.32 or 2.5.10.1.",
        "references": "https://nvd.nist.gov/vuln/detail/CVE-2017-5638"
    },
    {
        "cve_id": "CVE-2020-1472",
        "title": "Zerologon (Netlogon)",
        "category": "Windows",
        "severity": "critical",
        "cvss_score": 10.0,
        "epss_score": 0.96,
        "description": "An elevation of privilege vulnerability exists when an attacker establishes a vulnerable Netlogon secure channel connection to a domain controller.",
        "remediation": "Apply the August 2020 Microsoft security updates.",
        "references": "https://nvd.nist.gov/vuln/detail/CVE-2020-1472"
    },
    {
        "cve_id": "CVE-2021-34473",
        "title": "Microsoft Exchange (ProxyShell)",
        "category": "Windows",
        "severity": "critical",
        "cvss_score": 9.8,
        "epss_score": 0.93,
        "description": "Microsoft Exchange Server Remote Code Execution Vulnerability. This CVE ID is unique from CVE-2021-31196, CVE-2021-31206.",
        "remediation": "Install the latest Exchange Server Cumulative Updates.",
        "references": "https://nvd.nist.gov/vuln/detail/CVE-2021-34473 cpe:/a:microsoft:exchange_server"
    },
    {
        "cve_id": "CVE-2018-15473",
        "title": "OpenSSH user enumeration",
        "category": "Linux",
        "severity": "medium",
        "cvss_score": 5.0,
        "epss_score": 0.45,
        "description": "OpenSSH through 7.7 is prone to a user enumeration vulnerability due to not delaying bailout for an invalid authenticating user until after the packet containing the request has been fully parsed.",
        "remediation": "Upgrade OpenSSH to version 7.8 or later.",
        "references": "https://nvd.nist.gov/vuln/detail/CVE-2018-15473 cpe:/a:openbsd:openssh"
    },
    {
        "cve_id": "CVE-2022-22965",
        "title": "Spring4Shell",
        "category": "Java",
        "severity": "critical",
        "cvss_score": 9.8,
        "epss_score": 0.90,
        "description": "A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding.",
        "remediation": "Upgrade to Spring Framework 5.3.18 or 5.2.20.",
        "references": "https://nvd.nist.gov/vuln/detail/CVE-2022-22965 cpe:/a:vmware:spring_framework"
    },
    {
        "cve_id": "CVE-2021-26855",
        "title": "Exchange SSRF",
        "category": "Windows",
        "severity": "critical",
        "cvss_score": 9.1,
        "epss_score": 0.88,
        "description": "Microsoft Exchange Server Remote Code Execution Vulnerability. This CVE ID is unique from CVE-2021-26412, CVE-2021-26854.",
        "remediation": "Install the Microsoft Exchange Server updates released on March 2, 2021.",
        "references": "https://nvd.nist.gov/vuln/detail/CVE-2021-26855"
    }
]

class Command(BaseCommand):
    help = "Seed the Knowledge Base with representative CVE data for demo"

    def handle(self, *args, **options):
        for data in CVE_DATA:
            slug = slugify(data["title"])[:50]
            # Ensure unique slug
            base_slug = slug
            counter = 1
            while VulnerabilityReference.objects.filter(slug=slug).exclude(cve_id=data["cve_id"]).exists():
                slug = f"{base_slug}-{counter}"
                counter += 1
                
            obj, created = VulnerabilityReference.objects.update_or_create(
                cve_id=data["cve_id"],
                defaults={
                    "title": data["title"],
                    "slug": slug,
                    "category": data["category"],
                    "severity": data["severity"],
                    "cvss_score": data["cvss_score"],
                    "epss_score": data["epss_score"],
                    "description": data["description"],
                    "remediation": data["remediation"],
                    "references": data["references"],
                }
            )
            self.stdout.write(self.style.SUCCESS(f"{'Created' if created else 'Updated'}: {obj.cve_id} - {obj.title}"))
