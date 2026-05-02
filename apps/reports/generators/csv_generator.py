"""
CSV Report Generator
"""
import csv
from django.conf import settings
import os
from datetime import datetime
from ..models import Report


def generate_csv_report(scan_job, user):
    """
    Generate a CSV report for a completed scan
    
    Args:
        scan_job: ScanJob instance
        user: User who requested the report
        
    Returns:
        File path of the generated CSV
    """
    # Create reports directory
    reports_dir = os.path.join(settings.MEDIA_ROOT, 'reports')
    os.makedirs(reports_dir, exist_ok=True)
    
    # Generate filename
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"scan_report_{scan_job.id}_{timestamp}.csv"
    filepath = os.path.join(reports_dir, filename)
    
    # Write CSV
    with open(filepath, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        
        # Header
        writer.writerow(['Vulnerability Scan Report'])
        writer.writerow(['Target', scan_job.target.name])
        writer.writerow(['IP/Domain', scan_job.target.target])
        writer.writerow(['Scan Date', scan_job.created_at.strftime('%Y-%m-%d %H:%M:%S')])
        writer.writerow(['Total Vulnerabilities', scan_job.vulnerabilities_found])
        writer.writerow([])
        
        # Vulnerability data
        writer.writerow(['Severity', 'Title', 'Port', 'Service', 'CVSS Score', 'CVE ID', 'Description', 'Recommendation'])
        
        vulnerabilities = scan_job.vulnerabilities.all().order_by('-severity', '-cvss_score')
        for vuln in vulnerabilities:
            writer.writerow([
                vuln.severity.upper(),
                vuln.title,
                vuln.port if vuln.port else 'N/A',
                vuln.service if vuln.service else 'N/A',
                vuln.cvss_score if vuln.cvss_score else 'N/A',
                vuln.cve_id if vuln.cve_id else 'N/A',
                vuln.description,
                vuln.recommendation,
            ])
    
    # Save report to database
    report = Report.objects.create(
        scan_job=scan_job,
        title=f"Vulnerability Report CSV - {scan_job.target.name}",
        format='csv',
        file_path=filepath,
        file_size=os.path.getsize(filepath),
        generated_by=user,
        executive_summary=f"CSV export of scan results for {scan_job.target.name}",
        total_findings=scan_job.vulnerabilities_found,
    )
    
    return filepath
