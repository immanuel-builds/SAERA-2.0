"""
JSON Report Generator
"""
import json
from django.conf import settings
import os
from datetime import datetime
from ..models import Report


def generate_json_report(scan_job, user):
    """
    Generate a JSON report for a completed scan
    
    Args:
        scan_job: ScanJob instance
        user: User who requested the report
        
    Returns:
        File path of the generated JSON
    """
    # Create reports directory
    reports_dir = os.path.join(settings.MEDIA_ROOT, 'reports')
    os.makedirs(reports_dir, exist_ok=True)
    
    # Generate filename
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"scan_report_{scan_job.id}_{timestamp}.json"
    filepath = os.path.join(reports_dir, filename)
    
    # Build JSON structure
    report_data = {
        'scan_info': {
            'scan_id': scan_job.id,
            'target_name': scan_job.target.name,
            'target_address': scan_job.target.target,
            'target_type': scan_job.target.target_type,
            'scan_date': scan_job.created_at.isoformat(),
            'scan_duration': scan_job.duration if scan_job.duration else None,
            'status': scan_job.status,
        },
        'summary': {
            'total_ports_scanned': scan_job.total_ports_scanned,
            'open_ports_found': scan_job.open_ports_found,
            'total_vulnerabilities': scan_job.vulnerabilities_found,
            'critical_vulnerabilities': scan_job.critical_vulns,
            'high_vulnerabilities': scan_job.high_vulns,
            'medium_vulnerabilities': scan_job.medium_vulns,
            'low_vulnerabilities': scan_job.low_vulns,
        },
        'vulnerabilities': [],
        'open_ports': [],
    }
    
    # Add vulnerabilities
    vulnerabilities = scan_job.vulnerabilities.all().order_by('-severity', '-cvss_score')
    for vuln in vulnerabilities:
        vuln_data = {
            'id': vuln.id,
            'severity': vuln.severity,
            'cvss_score': float(vuln.cvss_score) if vuln.cvss_score else None,
            'title': vuln.title,
            'type': vuln.vuln_type,
            'port': vuln.port,
            'protocol': vuln.protocol,
            'service': vuln.service,
            'service_version': vuln.service_version,
            'description': vuln.description,
            'impact': vuln.impact,
            'recommendation': vuln.recommendation,
            'cve_id': vuln.cve_id,
            'cve_url': vuln.cve_url,
            'evidence': vuln.evidence,
        }
        report_data['vulnerabilities'].append(vuln_data)
    
    # Add open ports
    open_ports = scan_job.port_results.filter(state='open').order_by('port')
    for port in open_ports:
        port_data = {
            'port': port.port,
            'protocol': port.protocol,
            'state': port.state,
            'service': port.service,
            'service_version': port.service_version,
            'banner': port.banner,
        }
        report_data['open_ports'].append(port_data)
    
    # Write JSON file
    with open(filepath, 'w', encoding='utf-8') as jsonfile:
        json.dump(report_data, jsonfile, indent=2, ensure_ascii=False)
    
    # Save report to database
    report = Report.objects.create(
        scan_job=scan_job,
        title=f"Vulnerability Report JSON - {scan_job.target.name}",
        format='json',
        file_path=filepath,
        file_size=os.path.getsize(filepath),
        generated_by=user,
        executive_summary=f"JSON export of scan results for {scan_job.target.name}",
        total_findings=scan_job.vulnerabilities_found,
    )
    
    return filepath
