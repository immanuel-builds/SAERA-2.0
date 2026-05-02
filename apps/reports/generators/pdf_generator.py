"""
PDF Report Generator using ReportLab
"""
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from datetime import datetime
from django.conf import settings
import os
from ..models import Report


def generate_pdf_report(scan_job, user):
    """
    Generate a PDF report for a completed scan
    
    Args:
        scan_job: ScanJob instance
        user: User who requested the report
        
    Returns:
        File path of the generated PDF
    """
    # Create reports directory if it doesn't exist
    reports_dir = os.path.join(settings.MEDIA_ROOT, 'reports')
    os.makedirs(reports_dir, exist_ok=True)
    
    # Generate filename
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"scan_report_{scan_job.id}_{timestamp}.pdf"
    filepath = os.path.join(reports_dir, filename)
    
    # Create PDF document
    doc = SimpleDocTemplate(filepath, pagesize=letter)
    story = []
    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        textColor=colors.HexColor('#1a1a2e'),
        spaceAfter=30,
        alignment=TA_CENTER,
    )
    
    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading2'],
        fontSize=16,
        textColor=colors.HexColor('#0f3460'),
        spaceAfter=12,
    )
    
    # Title
    story.append(Paragraph("Vulnerability Scan Report", title_style))
    story.append(Spacer(1, 0.2*inch))
    
    # Executive Summary
    story.append(Paragraph("Executive Summary", heading_style))
    
    summary_data = [
        ['Target:', scan_job.target.name],
        ['IP/Domain:', scan_job.target.target],
        ['Scan Date:', scan_job.created_at.strftime('%Y-%m-%d %H:%M:%S')],
        ['Scan Duration:', f"{scan_job.duration if scan_job.duration else 'N/A'} seconds"],
        ['Total Vulnerabilities:', str(scan_job.vulnerabilities_found)],
        ['Critical Issues:', str(scan_job.critical_vulns)],
        ['High Issues:', str(scan_job.high_vulns)],
        ['Medium Issues:', str(scan_job.medium_vulns)],
        ['Low Issues:', str(scan_job.low_vulns)],
    ]
    
    summary_table = Table(summary_data, colWidths=[2*inch, 4*inch])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#e8f4f8')),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('GRID', (0, 0), (-1, -1), 1, colors.grey),
    ]))
    
    story.append(summary_table)
    story.append(Spacer(1, 0.3*inch))
    
    # Vulnerability Findings
    story.append(Paragraph("Vulnerability Findings", heading_style))
    
    vulnerabilities = scan_job.vulnerabilities.all().order_by('-severity', '-cvss_score')
    
    if vulnerabilities:
        for vuln in vulnerabilities:
            # Severity color mapping
            severity_colors = {
                'critical': colors.HexColor('#d32f2f'),
                'high': colors.HexColor('#f57c00'),
                'medium': colors.HexColor('#fbc02d'),
                'low': colors.HexColor('#388e3c'),
                'info': colors.HexColor('#1976d2'),
            }
            
            vuln_data = [
                [Paragraph(f"<b>[{vuln.severity.upper()}] {vuln.title}</b>", styles['Normal'])],
                [Paragraph(f"<b>Port:</b> {vuln.port if vuln.port else 'N/A'} | <b>Service:</b> {vuln.service if vuln.service else 'N/A'}", styles['Normal'])],
                [Paragraph(f"<b>CVSS Score:</b> {vuln.cvss_score if vuln.cvss_score else 'N/A'}", styles['Normal'])],
                [Paragraph(f"<b>Description:</b> {vuln.description}", styles['Normal'])],
                [Paragraph(f"<b>Impact:</b> {vuln.impact}", styles['Normal'])],
                [Paragraph(f"<b>Recommendation:</b> {vuln.recommendation}", styles['Normal'])],
            ]
            
            if vuln.cve_id:
                vuln_data.append([Paragraph(f"<b>CVE:</b> {vuln.cve_id}", styles['Normal'])])
            
            vuln_table = Table(vuln_data, colWidths=[6.5*inch])
            vuln_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), severity_colors.get(vuln.severity, colors.grey)),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ]))
            
            story.append(vuln_table)
            story.append(Spacer(1, 0.2*inch))
    else:
        story.append(Paragraph("No vulnerabilities detected.", styles['Normal']))
    
    # Build PDF
    doc.build(story)
    
    # Save report to database
    report = Report.objects.create(
        scan_job=scan_job,
        title=f"Vulnerability Report - {scan_job.target.name}",
        format='pdf',
        file_path=filepath,
        file_size=os.path.getsize(filepath),
        generated_by=user,
        executive_summary=f"Scan of {scan_job.target.name} found {scan_job.vulnerabilities_found} vulnerabilities",
        total_findings=scan_job.vulnerabilities_found,
    )
    
    return filepath
